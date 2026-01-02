"""Encryption backend interfaces for multiple encryption tools."""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING

from envdrift.encryption.base import (
    EncryptionBackend,
    EncryptionBackendError,
    EncryptionNotFoundError,
)

if TYPE_CHECKING:
    pass


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
            - For "dotenvx": `auto_install` (bool) - optional, defaults to True.
            - For "sops": `config_file` (str) - optional path to .sops.yaml.

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
            auto_install=config.get("auto_install", True),
        )

    elif provider == EncryptionProvider.SOPS:
        from envdrift.encryption.sops import SOPSEncryptionBackend

        return SOPSEncryptionBackend(
            config_file=config.get("config_file"),
        )

    raise ValueError(f"Unsupported encryption provider: {provider}")


def detect_encryption_provider(file_path) -> EncryptionProvider | None:
    """
    Auto-detect which encryption provider was used to encrypt a file.

    Parameters:
        file_path: Path to the encrypted file.

    Returns:
        EncryptionProvider if detected, None if file is not encrypted or unknown format.
    """
    from pathlib import Path

    path = Path(file_path)
    if not path.exists():
        return None

    content = path.read_text(encoding="utf-8")

    # Check for dotenvx markers first (most common)
    dotenvx_markers = ["#/---BEGIN DOTENV ENCRYPTED---/", "DOTENV_PUBLIC_KEY"]
    for marker in dotenvx_markers:
        if marker in content:
            return EncryptionProvider.DOTENVX

    # Check for SOPS markers
    # SOPS encrypted files have "sops" key in YAML/JSON or ENC[] markers in dotenv
    sops_markers = [
        "sops:",  # YAML format
        '"sops":',  # JSON format
        "ENC[AES256_GCM,",  # SOPS encrypted value marker
    ]
    for marker in sops_markers:
        if marker in content:
            return EncryptionProvider.SOPS

    # Check for .sops.yaml in same directory or parent
    sops_config_locations = [
        path.parent / ".sops.yaml",
        path.parent.parent / ".sops.yaml",
    ]
    for sops_config in sops_config_locations:
        if sops_config.exists():
            # File might be intended for SOPS even if not yet encrypted
            return None  # Can't determine without actual encryption markers

    return None


__all__ = [
    "EncryptionBackend",
    "EncryptionBackendError",
    "EncryptionNotFoundError",
    "EncryptionProvider",
    "detect_encryption_provider",
    "get_encryption_backend",
]
