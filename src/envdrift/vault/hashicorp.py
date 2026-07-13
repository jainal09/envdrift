"""HashiCorp Vault client implementation."""

from __future__ import annotations

import json
import os
from typing import Any

from envdrift.vault.base import (
    AuthenticationError,
    SecretNotFoundError,
    SecretValue,
    VaultClient,
    VaultError,
)
from envdrift.vault.keymaterial import DOTENV_PRIVATE_KEY_NAME_RE

try:
    import hvac as _hvac
    from hvac.exceptions import Forbidden, InvalidPath, Unauthorized

    HVAC_AVAILABLE = True
except ImportError:
    HVAC_AVAILABLE = False
    _hvac = None
    InvalidPath = Exception  # type: ignore[misc, assignment]
    Forbidden = Exception  # type: ignore[misc, assignment]
    Unauthorized = Exception  # type: ignore[misc, assignment]


def _coerce_secret_value(secret_data: dict[str, Any]) -> str:
    """Render KV-v2 secret data as the single string ``SecretValue.value`` requires.

    A lone ``value`` key is returned as-is when already a string; KV stores
    arbitrary JSON, so a non-string single ``value`` (int/bool/list/dict) is
    JSON-encoded. A payload whose key lives under its own field name — exactly
    one string ``DOTENV_PRIVATE_KEY_<ENV>`` field, the shape produced by
    ``vault kv put secret/x DOTENV_PRIVATE_KEY_PROD=<hex>`` — is surfaced as the
    full ``DOTENV_PRIVATE_KEY_<ENV>=<key>`` line so downstream key flows parse
    it like a pushed key instead of installing a JSON blob (#480). Any other
    multi-key payload is JSON-encoded; ``SecretValue.value`` must always be a
    str, or the sync engine and vault-pull crash downstream.
    """
    if "value" in secret_data and len(secret_data) == 1:
        value = secret_data["value"]
        return value if isinstance(value, str) else json.dumps(value)
    dotenv_fields = [
        (key, val)
        for key, val in secret_data.items()
        if isinstance(val, str) and DOTENV_PRIVATE_KEY_NAME_RE.fullmatch(key)
    ]
    if len(dotenv_fields) == 1:
        key, val = dotenv_fields[0]
        return f"{key}={val}"
    return json.dumps(secret_data)


def _get_hvac() -> Any:
    """Get hvac module, raising ImportError if not available."""
    if not HVAC_AVAILABLE or _hvac is None:
        raise ImportError("hvac not installed. Install with: pip install envdrift[hashicorp]")
    return _hvac


class HashiCorpVaultClient(VaultClient):
    """HashiCorp Vault implementation.

    Supports KV v2 secrets engine (the default in modern Vault).

    Authentication methods supported:
    - Token only, sourced from the ``token`` parameter or the ``VAULT_TOKEN``
      environment variable.

    Other hvac auth methods (AppRole, OIDC, Kubernetes, etc.) are NOT supported.
    A ``token`` placed under the ``[vault.hashicorp]`` TOML section is NOT read:
    the token must be passed to ``token`` or set via ``VAULT_TOKEN``.
    """

    def __init__(
        self,
        url: str,
        token: str | None = None,
        mount_point: str = "secret",
    ):
        """
        Create a HashiCorp Vault client configured to use the KV v2 secrets engine.

        Parameters:
            url (str): Vault server URL (e.g., "https://vault.example.com:8200").
            token (str | None): Authentication token; if omitted, the VAULT_TOKEN environment variable is used.
            mount_point (str): KV secrets engine mount point (default "secret").
        """
        _get_hvac()  # Verify hvac is available
        self.url = url
        self.token = token or os.environ.get("VAULT_TOKEN")
        self.mount_point = mount_point
        self._client: Any = None

    def authenticate(self) -> None:
        """
        Authenticate the client against HashiCorp Vault using the configured token.

        This initializes and verifies the underlying hvac client and stores it on the instance
        when authentication succeeds.

        Raises:
                AuthenticationError: If no token was provided, the token is invalid, expired, or Vault
                        rejects authentication (including Unauthorized or Forbidden responses).
                VaultError: For other connection or unexpected errors communicating with Vault.
        """
        if not self.token:
            # No CLI command exposes a --token flag, so the old "or pass token
            # parameter" remedy pointed at a flag that does not exist (#441 audit).
            raise AuthenticationError(
                "No Vault token provided. Set the VAULT_TOKEN environment variable."
            )

        hvac = _get_hvac()
        try:
            self._client = hvac.Client(url=self.url, token=self.token)

            if not self._client.is_authenticated():
                raise AuthenticationError("Vault token is invalid or expired")
        except AuthenticationError:
            # The invalid/expired-token case raises AuthenticationError above;
            # let it propagate instead of being re-wrapped as a VaultError by the
            # broad `except Exception` below. Clear the half-initialized client so
            # the unauthenticated-state invariant holds (mirrors gcp/azure).
            self._client = None
            raise
        except (Unauthorized, Forbidden) as e:
            self._client = None
            raise AuthenticationError(f"Vault authentication failed: {e}") from e
        except Exception as e:
            self._client = None
            raise VaultError(f"Vault connection error: {e}") from e

    def is_authenticated(self) -> bool:
        """
        Return whether the stored hvac client is currently authenticated.

        Returns:
            bool: `True` if an internal hvac client exists and reports it is authenticated, `False` otherwise.
        """
        if self._client is None:
            return False
        try:
            return self._client.is_authenticated()
        except Exception:
            return False

    def get_secret(self, name: str) -> SecretValue:
        """
        Retrieve a secret from Vault at the given path relative to the client's mount point.

        If the stored secret data contains only a single key named "value", that value is returned; otherwise the entire secret data dict is JSON-encoded and returned as the value. The returned SecretValue includes the secret's version and metadata (created_time, deletion_time, destroyed, custom_metadata).

        Parameters:
            name: Secret path relative to the configured mount point.

        Returns:
            A SecretValue containing the secret's value, version, and metadata.

        Raises:
            SecretNotFoundError: If the secret path does not exist.
            AuthenticationError: If access to the secret is denied or the client is unauthenticated.
            VaultError: For other Vault-related errors.
        """
        self.ensure_authenticated()

        try:
            response = self._client.secrets.kv.v2.read_secret_version(
                path=name,
                mount_point=self.mount_point,
            )

            data = response.get("data", {})
            secret_data = data.get("data", {})
            metadata = data.get("metadata", {})

            # A single "value" key returns that value; otherwise the whole dict is
            # JSON-encoded. Coercion lives in a helper to keep this method simple.
            value = _coerce_secret_value(secret_data)

            return SecretValue(
                name=name,
                value=value,
                version=str(metadata.get("version", "")),
                metadata={
                    "created_time": metadata.get("created_time"),
                    "deletion_time": metadata.get("deletion_time"),
                    "destroyed": metadata.get("destroyed", False),
                    "custom_metadata": metadata.get("custom_metadata", {}),
                },
            )
        except InvalidPath as e:
            raise SecretNotFoundError(f"Secret '{name}' not found in Vault") from e
        except (Unauthorized, Forbidden) as e:
            raise AuthenticationError(f"Access denied to secret '{name}': {e}") from e
        except Exception as e:
            raise VaultError(f"Vault error: {e}") from e

    def list_secrets(self, prefix: str = "") -> list[str]:
        """List secret paths in HashiCorp Vault.

        Args:
            prefix: Path prefix to list under

        Returns:
            List of secret paths
        """
        self.ensure_authenticated()

        try:
            response = self._client.secrets.kv.v2.list_secrets(
                path=prefix,
                mount_point=self.mount_point,
            )

            keys = response.get("data", {}).get("keys", [])
            return sorted(keys)
        except InvalidPath:
            # Path doesn't exist, return empty list
            return []
        except (Unauthorized, Forbidden) as e:
            raise AuthenticationError(f"Access denied to list secrets: {e}") from e
        except Exception as e:
            raise VaultError(f"Vault error: {e}") from e

    def create_or_update_secret(self, name: str, data: dict) -> SecretValue:
        """
        Create or update a secret at the given Vault path.

        Parameters:
            name (str): Secret path in the KV v2 engine.
            data (dict): Dictionary of key-value pairs to store for the secret.

        Returns:
            SecretValue: The stored secret representation containing the secret `name`, a string `value` (JSON-encoded when multiple keys), the secret `version`, and metadata including `created_time`.

        Raises:
            AuthenticationError: If the client is not authorized to write the secret.
            VaultError: For other Vault-related errors.
        """
        self.ensure_authenticated()

        try:
            response = self._client.secrets.kv.v2.create_or_update_secret(
                path=name,
                secret=data,
                mount_point=self.mount_point,
            )

            metadata = response.get("data", {})

            # Same string-coercion as get_secret so the returned SecretValue.value
            # is always a str even when the caller stored a non-string single value.
            value = _coerce_secret_value(data)

            return SecretValue(
                name=name,
                value=value,
                version=str(metadata.get("version", "")),
                metadata={
                    "created_time": metadata.get("created_time"),
                },
            )
        except (Unauthorized, Forbidden) as e:
            raise AuthenticationError(f"Access denied to write secret: {e}") from e
        except Exception as e:
            raise VaultError(f"Vault error: {e}") from e

    def set_secret(self, name: str, value: str) -> SecretValue:
        """
        Set a string secret at the given path.

        Parameters:
            name (str): Secret path in Vault.
            value (str): Secret string to store.

        Returns:
            SecretValue: The created or updated secret, including its stored value and metadata.
        """
        return self.create_or_update_secret(name, {"value": value})
