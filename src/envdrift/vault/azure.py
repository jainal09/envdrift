"""Azure Key Vault client implementation."""

from __future__ import annotations

from envdrift.vault.base import (
    AuthenticationError,
    SecretNotFoundError,
    SecretValue,
    VaultClient,
    VaultError,
)

try:
    from azure.core.exceptions import (
        ClientAuthenticationError,
        HttpResponseError,
        ResourceNotFoundError,
    )
    from azure.identity import DefaultAzureCredential
    from azure.keyvault.secrets import SecretClient

    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False
    DefaultAzureCredential = None
    SecretClient = None
    ResourceNotFoundError = Exception
    ClientAuthenticationError = Exception
    HttpResponseError = Exception


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
        if not AZURE_AVAILABLE:
            raise ImportError("Azure SDK not installed. Install with: pip install envdrift[azure]")

        self.vault_url = vault_url
        self._client: SecretClient | None = None
        self._credential = None

    def authenticate(self) -> None:
        """
        Authenticate to Azure Key Vault using DefaultAzureCredential and initialize the SecretClient.

        On success sets self._credential to the created credential and self._client to a ready SecretClient.
        Raises AuthenticationError if credential acquisition fails and VaultError for HTTP-related Key Vault errors.
        """
        try:
            self._credential = DefaultAzureCredential()
            self._client = SecretClient(
                vault_url=self.vault_url,
                credential=self._credential,
            )
            # Test authentication by actually consuming one item from the iterator
            # The iterator is lazy and won't authenticate until iterated
            secrets_iter = self._client.list_properties_of_secrets()
            next(iter(secrets_iter), None)  # Consume one item to verify auth
        except ClientAuthenticationError as e:
            raise AuthenticationError(f"Azure authentication failed: {e}") from e
        except HttpResponseError as e:
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
        except HttpResponseError as e:
            raise VaultError(f"Azure Key Vault error: {e}") from e

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
        except HttpResponseError as e:
            raise VaultError(f"Azure Key Vault error: {e}") from e

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
        except HttpResponseError as e:
            raise VaultError(f"Azure Key Vault error: {e}") from e
