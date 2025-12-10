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
    """
    Create and return a provider-specific VaultClient configured from the provided keyword arguments.

    Parameters:
        provider (VaultProvider | str): Vault provider enum or provider name ("azure", "aws", "hashicorp").
        **config: Provider-specific configuration:
            - For "azure": `vault_url` (str) — required.
            - For "aws": `region` (str) — optional, defaults to "us-east-1".
            - For "hashicorp": `url` (str) — required; `token` (str) — optional.

    Returns:
        VaultClient: A configured client instance for the requested provider.

    Raises:
        ImportError: If the provider's optional dependencies are not installed.
        ValueError: If the provider is unsupported or cannot be converted to a VaultProvider.
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
        vault_url = config.get("vault_url")
        if not vault_url:
            raise ValueError("Azure vault requires 'vault_url' configuration")
        return AzureKeyVaultClient(vault_url=vault_url)

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
        url = config.get("url")
        if not url:
            raise ValueError("HashiCorp Vault requires 'url' configuration")
        return HashiCorpVaultClient(
            url=url,
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
