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
        """Initialize Azure Key Vault client.

        Args:
            vault_url: The vault URL (e.g., "https://my-vault.vault.azure.net/")
        """
        if not AZURE_AVAILABLE:
            raise ImportError(
                "Azure SDK not installed. Install with: pip install envdrift[azure]"
            )

        self.vault_url = vault_url
        self._client: SecretClient | None = None
        self._credential = None

    def authenticate(self) -> None:
        """Authenticate using DefaultAzureCredential."""
        try:
            self._credential = DefaultAzureCredential()
            self._client = SecretClient(
                vault_url=self.vault_url,
                credential=self._credential,
            )
            # Test authentication by listing secrets
            # Just get the iterator, don't consume it
            _ = self._client.list_properties_of_secrets()
        except ClientAuthenticationError as e:
            raise AuthenticationError(f"Azure authentication failed: {e}") from e
        except HttpResponseError as e:
            raise VaultError(f"Azure Key Vault error: {e}") from e

    def is_authenticated(self) -> bool:
        """Check if client is authenticated."""
        return self._client is not None

    def get_secret(self, name: str) -> SecretValue:
        """Retrieve a secret from Azure Key Vault.

        Args:
            name: The secret name

        Returns:
            SecretValue with the secret data
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
        """List secret names in the vault.

        Args:
            prefix: Optional prefix to filter secrets

        Returns:
            List of secret names
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
        """Set a secret in Azure Key Vault.

        Args:
            name: The secret name
            value: The secret value

        Returns:
            SecretValue with the created/updated secret
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
