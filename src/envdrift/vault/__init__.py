"""Vault client interfaces for multiple backends."""

from __future__ import annotations

import difflib
from enum import Enum
from typing import TYPE_CHECKING, Any

from envdrift.vault.base import AuthenticationError, SecretValue, VaultClient, VaultError

if TYPE_CHECKING:
    pass


class VaultProvider(Enum):
    """Supported vault providers."""

    AZURE = "azure"
    AWS = "aws"
    HASHICORP = "hashicorp"
    GCP = "gcp"


def _coerce_provider(provider: str) -> VaultProvider:
    """Convert a provider name to a VaultProvider with a user-facing error.

    The bare enum error ("'azur' is not a valid VaultProvider") leaked an
    internal type name with no valid-options list (#441 audit).
    """
    try:
        return VaultProvider(provider)
    except ValueError:
        valid = [p.value for p in VaultProvider]
        close = difflib.get_close_matches(provider, valid, n=1, cutoff=0.6)
        hint = f" (did you mean '{close[0]}'?)" if close else ""
        raise ValueError(
            f"Unknown vault provider '{provider}'{hint}. Valid providers: {', '.join(valid)}"
        ) from None


def _build_azure_client(config: dict[str, Any]) -> VaultClient:
    """Build an Azure Key Vault client from ``vault_url``."""
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
    if not vault_url.lower().startswith("https://"):
        # A schemeless URL used to surface as the Azure SDK's cryptic
        # "Bearer token authentication is not permitted for non-TLS
        # protected (non-https) URLs" much later (#441 audit).
        raise ValueError(f"Azure vault_url must start with https:// (got '{vault_url}')")
    return AzureKeyVaultClient(vault_url=vault_url)


def _build_aws_client(config: dict[str, Any]) -> VaultClient:
    """Build an AWS Secrets Manager client from an optional ``region``."""
    try:
        from envdrift.vault.aws import AWSSecretsManagerClient
    except ImportError as e:
        raise ImportError(
            "AWS vault support requires additional dependencies. "
            "Install with: pip install envdrift[aws]"
        ) from e
    return AWSSecretsManagerClient(region=config.get("region", "us-east-1"))


def _build_hashicorp_client(config: dict[str, Any]) -> VaultClient:
    """Build a HashiCorp Vault client from ``url`` and an optional ``token``."""
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


def _build_gcp_client(config: dict[str, Any]) -> VaultClient:
    """Build a GCP Secret Manager client from ``project_id``."""
    try:
        from envdrift.vault.gcp import GCPSecretManagerClient
    except ImportError as e:
        raise ImportError(
            "GCP Secret Manager support requires additional dependencies. "
            "Install with: pip install envdrift[gcp]"
        ) from e
    project_id = config.get("project_id")
    if not project_id:
        raise ValueError("GCP Secret Manager requires 'project_id' configuration")
    return GCPSecretManagerClient(project_id=project_id)


_CLIENT_BUILDERS = {
    VaultProvider.AZURE: _build_azure_client,
    VaultProvider.AWS: _build_aws_client,
    VaultProvider.HASHICORP: _build_hashicorp_client,
    VaultProvider.GCP: _build_gcp_client,
}


def get_vault_client(provider: VaultProvider | str, **config) -> VaultClient:
    """
    Create and return a provider-specific VaultClient configured from the provided keyword arguments.

    Parameters:
        provider (VaultProvider | str): Vault provider enum or provider name ("azure", "aws", "hashicorp", "gcp").
        **config: Provider-specific configuration:
            - For "azure": `vault_url` (str) — required, must be an https:// URL.
            - For "aws": `region` (str) — optional, defaults to "us-east-1".
            - For "hashicorp": `url` (str) — required; `token` (str) — optional.
            - For "gcp": `project_id` (str) — required.

    Returns:
        VaultClient: A configured client instance for the requested provider.

    Raises:
        ImportError: If the provider's optional dependencies are not installed.
        ValueError: If the provider is unsupported or cannot be converted to a VaultProvider.
    """
    if isinstance(provider, str):
        provider = _coerce_provider(provider)

    builder = _CLIENT_BUILDERS.get(provider)
    if builder is None:
        raise ValueError(f"Unsupported vault provider: {provider}")
    return builder(config)


__all__ = [
    "AuthenticationError",
    "SecretValue",
    "VaultClient",
    "VaultError",
    "VaultProvider",
    "get_vault_client",
]
