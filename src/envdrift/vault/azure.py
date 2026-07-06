"""Azure Key Vault client implementation."""

from __future__ import annotations

import os
from typing import Any

from envdrift.vault.base import (
    AuthenticationError,
    SecretNotFoundError,
    SecretValue,
    VaultClient,
    VaultError,
)

try:
    from azure.core.exceptions import (
        AzureError,
        ClientAuthenticationError,
        HttpResponseError,
        ResourceNotFoundError,
    )
    from azure.identity import DefaultAzureCredential as _DefaultAzureCredential
    from azure.keyvault.secrets import SecretClient as _SecretClient

    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False
    _DefaultAzureCredential = None
    _SecretClient = None
    ResourceNotFoundError = Exception  # type: ignore[misc, assignment]
    ClientAuthenticationError = Exception  # type: ignore[misc, assignment]
    HttpResponseError = Exception  # type: ignore[misc, assignment]
    AzureError = Exception  # type: ignore[misc, assignment]


VERIFY_CHALLENGE_RESOURCE_ENV = "ENVDRIFT_AZURE_VERIFY_CHALLENGE_RESOURCE"

_TRUTHY_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSY_VALUES = frozenset({"0", "false", "no", "off"})


def _verify_challenge_resource() -> bool:
    """Resolve the Key Vault challenge-resource verification toggle.

    The Azure SDK verifies that the authentication challenge returned by the
    vault matches the vault's domain and refuses to authenticate otherwise.
    That is the right default for ``*.vault.azure.net``, but it can never
    succeed against Key Vault emulators or other non-public-cloud domains
    (e.g. Lowkey Vault on ``localhost``), where the challenge resource is the
    vault host itself. Set ``ENVDRIFT_AZURE_VERIFY_CHALLENGE_RESOURCE`` to
    ``0``/``false``/``no``/``off`` to disable the check for such vaults.

    Defaults to enabled (secure). A malformed value fails loudly with
    ``ValueError`` instead of being coerced to either behavior.
    """
    raw = os.environ.get(VERIFY_CHALLENGE_RESOURCE_ENV)
    if raw is None or not raw.strip():
        return True
    value = raw.strip().lower()
    if value in _TRUTHY_VALUES:
        return True
    if value in _FALSY_VALUES:
        return False
    raise ValueError(
        f"Invalid {VERIFY_CHALLENGE_RESOURCE_ENV}={raw!r}: expected one of "
        "1/true/yes/on or 0/false/no/off"
    )


def _get_azure_classes() -> tuple[Any, Any]:
    """Get Azure classes, raising ImportError if not available."""
    if not AZURE_AVAILABLE or _DefaultAzureCredential is None or _SecretClient is None:
        raise ImportError("Azure SDK not installed. Install with: pip install envdrift[azure]")
    return _DefaultAzureCredential, _SecretClient


def _map_azure_error(e: Exception, *, denied_msg: str) -> Exception:
    """Translate an Azure SDK exception into a domain error.

    Shared by get/list/set so each delegates instead of repeating the
    auth-then-HTTP-then-transport catch ladder:

    - ``ClientAuthenticationError`` (mid-session 401, a subclass of
      ``HttpResponseError``, so it must be checked first) -> ``AuthenticationError``.
    - ``HttpResponseError`` / any other ``AzureError`` (incl. transport failures
      like ``ServiceRequestError`` that are *not* ``HttpResponseError``)
      -> ``VaultError``.
    """
    if isinstance(e, ClientAuthenticationError):
        return AuthenticationError(denied_msg)
    return VaultError(f"Azure Key Vault error: {e}")


class AzureKeyVaultClient(VaultClient):
    """Azure Key Vault implementation.

    Uses DefaultAzureCredential which supports:
    - Environment variables (AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID)
    - Managed Identity
    - Azure CLI credentials
    - VS Code credentials
    - Interactive browser login
    """

    def __init__(self, vault_url: str):
        """
        Create an Azure Key Vault client bound to the provided vault URL.

        Parameters:
            vault_url (str): Vault URL (e.g., "https://my-vault.vault.azure.net/").

        Raises:
            ImportError: If the Azure SDK is not installed (install with `pip install envdrift[azure]`).
        """
        _get_azure_classes()  # Verify Azure SDK is available
        self.vault_url = vault_url
        self._client: Any = None
        self._credential: Any = None

    def authenticate(self) -> None:
        """
        Authenticate to Azure Key Vault using DefaultAzureCredential and initialize the SecretClient.

        On success sets self._credential to the created credential and self._client to a ready SecretClient.
        Raises AuthenticationError if credential acquisition fails or when
        ENVDRIFT_AZURE_VERIFY_CHALLENGE_RESOURCE holds a malformed value, and VaultError for HTTP-related
        Key Vault errors.
        """
        credential_cls, client_cls = _get_azure_classes()
        try:
            verify_challenge_resource = _verify_challenge_resource()
        except ValueError as e:
            # Surface the config error through the domain hierarchy so CLI
            # callers that catch VaultError/AuthenticationError show a clean
            # message instead of a raw ValueError traceback.
            raise AuthenticationError(str(e)) from e
        try:
            self._credential = credential_cls()
            self._client = client_cls(
                vault_url=self.vault_url,
                credential=self._credential,
                # Challenge-resource verification can never succeed against
                # emulators / non-public-cloud vault domains; see
                # _verify_challenge_resource() for the opt-out env var.
                verify_challenge_resource=verify_challenge_resource,
            )
            # Test authentication by actually consuming one item from the iterator.
            # The iterator is lazy and won't authenticate until iterated.
            #
            # A *list* probe is not a least-privilege check: an identity granted
            # only Get/Set on secrets (no List) authenticates fine but is forbidden
            # to enumerate secrets. Mirroring the AWS backend (which probes with STS
            # get_caller_identity rather than list_secrets to avoid requiring extra
            # permissions, see aws.py), we distinguish a genuine *authentication*
            # failure from a mere *authorization* (List) denial: a 403/Forbidden on
            # the list probe means the credential authenticated but lacks List, so we
            # keep the client and let get_secret/set_secret proceed (#359).
            secrets_iter = self._client.list_properties_of_secrets()
            next(iter(secrets_iter), None)  # Consume one item to verify auth
        except ClientAuthenticationError as e:
            # Genuine credential/authentication failure (e.g. bad credential / 401):
            # discard the half-initialized client and credential so is_authenticated()
            # reports False and ensure_authenticated() re-attempts authentication on
            # the next operation.
            self._client = None
            self._credential = None
            raise AuthenticationError(f"Azure authentication failed: {e}") from e
        except HttpResponseError as e:
            # 403/Forbidden = authenticated but not authorized to *list* secrets.
            # This is exactly the least-privilege Get/Set identity case: the
            # credential is valid, so keep self._client and let get_secret/set_secret
            # surface any per-secret read denial later (#359). Any other HTTP error
            # is a real Key Vault failure and is surfaced as a VaultError.
            if getattr(e, "status_code", None) == 403:
                return
            self._client = None
            self._credential = None
            raise VaultError(f"Azure Key Vault error: {e}") from e
        except AzureError as e:
            # Transport-layer failure that is not an HttpResponseError -- e.g.
            # ServiceRequestError (DNS/TLS/connectivity). This is a genuine
            # failure, not a least-privilege List denial, so discard the
            # half-initialized client and surface it as a VaultError (matching
            # how get_secret/list_secrets/set_secret map transport errors), rather
            # than letting the raw SDK exception escape the domain hierarchy.
            self._client = None
            self._credential = None
            raise VaultError(f"Azure Key Vault error: {e}") from e
        except Exception as e:
            # The SDK also raises OUTSIDE the AzureError hierarchy -- e.g. the
            # challenge policy's resource verification raises a plain
            # ``ValueError`` ("The challenge resource ... does not match the
            # requested domain") for any Key Vault behind a proxy, custom
            # domain, or emulator. The base-class contract is that
            # authenticate() failures surface as VaultError, so map anything
            # unexpected instead of letting raw SDK exceptions escape to the
            # CLI as Rich tracebacks (#487).
            self._client = None
            self._credential = None
            raise VaultError(f"Azure Key Vault error: {e}") from e

    def is_authenticated(self) -> bool:
        """
        Return whether the client has an initialized SecretClient and is ready for operations.

        Returns:
            `true` if the internal client is initialized, `false` otherwise.
        """
        return self._client is not None

    def get_secret(self, name: str) -> SecretValue:
        """
        Retrieve a secret from the configured Azure Key Vault.

        Parameters:
            name (str): The name of the secret to retrieve.

        Returns:
            SecretValue: Contains the secret's name, value, version, and metadata (keys: "enabled", "created_on", "updated_on", "content_type").

        Raises:
            SecretNotFoundError: If no secret with the given name exists in the vault.
            VaultError: For other Azure Key Vault HTTP errors.
        """
        self.ensure_authenticated()

        try:
            secret = self._client.get_secret(name)
            props = secret.properties
            created = str(props.created_on) if props.created_on else None
            updated = str(props.updated_on) if props.updated_on else None
            return SecretValue(
                name=name,
                value=secret.value or "",
                version=props.version,
                metadata={
                    "enabled": props.enabled,
                    "created_on": created,
                    "updated_on": updated,
                    "content_type": props.content_type,
                },
            )
        except ResourceNotFoundError as e:
            raise SecretNotFoundError(f"Secret '{name}' not found in vault") from e
        except AzureError as e:
            raise _map_azure_error(e, denied_msg=f"Access denied to secret '{name}': {e}") from e

    def list_secrets(self, prefix: str = "") -> list[str]:
        """
        List secret names in the vault, optionally filtered by a prefix.

        Parameters:
            prefix (str): Optional string; include only secret names that start with this prefix.

        Returns:
            list[str]: Sorted list of secret names that match the prefix.
        """
        self.ensure_authenticated()

        try:
            secrets = []
            for secret_properties in self._client.list_properties_of_secrets():
                name = secret_properties.name
                if name and (not prefix or name.startswith(prefix)):
                    secrets.append(name)
            return sorted(secrets)
        except AzureError as e:
            raise _map_azure_error(e, denied_msg=f"Access denied to list secrets: {e}") from e

    def set_secret(self, name: str, value: str) -> SecretValue:
        """
        Store or update a secret in Azure Key Vault.

        Returns:
            SecretValue containing the stored secret's name, value, version, and metadata (includes `enabled`).
        """
        self.ensure_authenticated()

        try:
            secret = self._client.set_secret(name, value)
            return SecretValue(
                name=name,
                value=secret.value or "",
                version=secret.properties.version,
                metadata={
                    "enabled": secret.properties.enabled,
                },
            )
        except AzureError as e:
            raise _map_azure_error(
                e, denied_msg=f"Access denied to write secret '{name}': {e}"
            ) from e
