"""Vault client interfaces for multiple backends."""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING

from envdrift.vault.base import AuthenticationError, SecretValue, VaultClient, VaultError

if TYPE_CHECKING:
    pass


class VaultProvider(Enum):
    """Supported vault providers."""

    AZURE = "azure"
    AWS = "aws"
    HASHICORP = "hashicorp"


def get_vault_client(provider: VaultProvider | str, **config) -> VaultClient:
    """Factory to create vault client.

    Args:
        provider: The vault provider to use
        **config: Provider-specific configuration

    Returns:
        Configured VaultClient instance

    Raises:
        ImportError: If the required optional dependencies are not installed
        ValueError: If provider is not supported
    """
    if isinstance(provider, str):
        provider = VaultProvider(provider)

    if provider == VaultProvider.AZURE:
        try:
            from envdrift.vault.azure import AzureKeyVaultClient
        except ImportError as e:
            raise ImportError(
                "Azure vault support requires additional dependencies. "
                "Install with: pip install envdrift[azure]"
            ) from e
        return AzureKeyVaultClient(vault_url=config["vault_url"])

    elif provider == VaultProvider.AWS:
        try:
            from envdrift.vault.aws import AWSSecretsManagerClient
        except ImportError as e:
            raise ImportError(
                "AWS vault support requires additional dependencies. "
                "Install with: pip install envdrift[aws]"
            ) from e
        return AWSSecretsManagerClient(region=config.get("region", "us-east-1"))

    elif provider == VaultProvider.HASHICORP:
        try:
            from envdrift.vault.hashicorp import HashiCorpVaultClient
        except ImportError as e:
            raise ImportError(
                "HashiCorp Vault support requires additional dependencies. "
                "Install with: pip install envdrift[hashicorp]"
            ) from e
        return HashiCorpVaultClient(
            url=config["url"],
            token=config.get("token"),
        )

    raise ValueError(f"Unsupported vault provider: {provider}")


__all__ = [
    "AuthenticationError",
    "SecretValue",
    "VaultClient",
    "VaultError",
    "VaultProvider",
    "get_vault_client",
]
