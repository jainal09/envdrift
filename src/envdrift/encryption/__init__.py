"""Encryption backend interfaces for multiple encryption tools."""

from __future__ import annotations

from enum import Enum
from pathlib import Path

from envdrift.encryption.base import (
    EncryptionBackend,
    EncryptionBackendError,
    EncryptionNotFoundError,
)


class EncryptionProvider(Enum):
    """Supported encryption providers."""

    DOTENVX = "dotenvx"
    SOPS = "sops"


def get_encryption_backend(provider: EncryptionProvider | str, **config) -> EncryptionBackend:
    """
    Create and return a provider-specific EncryptionBackend.

    Parameters:
        provider (EncryptionProvider | str): Encryption provider enum or name ("dotenvx", "sops").
        **config: Provider-specific configuration:
            - For "dotenvx": `auto_install` (bool) - optional, defaults to False.
            - For "sops": `config_file` (str) - optional path to .sops.yaml.
                        `age_key` (str) - optional age private key (SOPS_AGE_KEY).
                        `age_key_file` (str) - optional age key file path (SOPS_AGE_KEY_FILE).
                        `auto_install` (bool) - optional, defaults to False.

    Returns:
        EncryptionBackend: A configured backend instance for the requested provider.

    Raises:
        ValueError: If the provider is unsupported.
    """
    if isinstance(provider, str):
        provider = EncryptionProvider(provider)

    if provider == EncryptionProvider.DOTENVX:
        from envdrift.encryption.dotenvx import DotenvxEncryptionBackend

        return DotenvxEncryptionBackend(
            auto_install=config.get("auto_install", False),
        )

    elif provider == EncryptionProvider.SOPS:
        from envdrift.encryption.sops import SOPSEncryptionBackend

        return SOPSEncryptionBackend(
            config_file=config.get("config_file"),
            age_key=config.get("age_key"),
            age_key_file=config.get("age_key_file"),
            auto_install=config.get("auto_install", False),
        )

    raise ValueError(f"Unsupported encryption provider: {provider}")


# dotenvx header markers — either marks a file dotenvx wrote / can encrypt.
_DOTENVX_FILE_MARKERS = ("#/---BEGIN DOTENV ENCRYPTED---/", "DOTENV_PUBLIC_KEY")


def _content_is_sops_encrypted(content: str) -> bool:
    """True if ``content`` carries a genuine SOPS encrypted-value or metadata block.

    A SOPS-encrypted file has an ``ENC[AES256_GCM,`` encrypted-value envelope or a
    line-anchored metadata block (``sops:`` / ``"sops":`` / ``sops_version=`` /
    ``sops_mac=``). Reuse the SOPS backend's structure-aware patterns so a
    plaintext value that merely contains the substring ``sops:`` (e.g.
    ``VAULT_ADDR=https://sops:8200``) is NOT misclassified as SOPS (#413).
    """
    from envdrift.encryption.sops import SOPSEncryptionBackend

    if "ENC[AES256_GCM," in content:
        return True
    return any(p.search(content) for p in SOPSEncryptionBackend.SOPS_METADATA_PATTERNS)


def detect_encryption_provider(file_path) -> EncryptionProvider | None:
    """
    Auto-detect which encryption provider was used to encrypt a file.

    Parameters:
        file_path: Path to the encrypted file.

    Returns:
        EncryptionProvider if detected, None if file is not encrypted or unknown format.
    """
    path = Path(file_path)
    if not path.exists():
        return None

    content = path.read_text(encoding="utf-8")

    # Check for dotenvx markers first (most common).
    if any(marker in content for marker in _DOTENVX_FILE_MARKERS):
        return EncryptionProvider.DOTENVX

    if _content_is_sops_encrypted(content):
        return EncryptionProvider.SOPS

    # A nearby ``.sops.yaml`` config alone does not prove the file is encrypted, so
    # we do not infer a provider from it (avoids false positives on plaintext).
    return None


__all__ = [
    "EncryptionBackend",
    "EncryptionBackendError",
    "EncryptionNotFoundError",
    "EncryptionProvider",
    "detect_encryption_provider",
    "get_encryption_backend",
]
