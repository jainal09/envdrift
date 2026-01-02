"""Helpers for resolving encryption backends from config."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import TYPE_CHECKING

from envdrift.config import ConfigNotFoundError, find_config, load_config
from envdrift.encryption import EncryptionProvider, get_encryption_backend

if TYPE_CHECKING:
    from envdrift.config import EncryptionConfig
    from envdrift.encryption.base import EncryptionBackend


def resolve_encryption_backend(
    config_file: Path | None,
) -> tuple[EncryptionBackend, EncryptionProvider, EncryptionConfig | None]:
    """
    Resolve the encryption backend using an explicit config file or auto-discovery.

    Returns the instantiated backend, selected provider, and the encryption config
    (if available).
    """
    config_path = None
    if config_file is not None and config_file.suffix.lower() == ".toml":
        config_path = config_file
    elif config_file is None:
        config_path = find_config()

    envdrift_config = None
    if config_path:
        try:
            envdrift_config = load_config(config_path)
        except (ConfigNotFoundError, tomllib.TOMLDecodeError):
            envdrift_config = None

    encryption_config = getattr(envdrift_config, "encryption", None) if envdrift_config else None
    backend_name = encryption_config.backend if encryption_config else "dotenvx"
    provider = EncryptionProvider(backend_name)

    backend_config: dict[str, object] = {}
    if provider == EncryptionProvider.DOTENVX:
        backend_config["auto_install"] = (
            encryption_config.dotenvx_auto_install if encryption_config else False
        )
    else:
        backend_config["auto_install"] = (
            encryption_config.sops_auto_install if encryption_config else False
        )
        if encryption_config:
            if encryption_config.sops_config_file:
                backend_config["config_file"] = encryption_config.sops_config_file
            if encryption_config.sops_age_key_file:
                backend_config["age_key_file"] = encryption_config.sops_age_key_file

    backend = get_encryption_backend(provider, **backend_config)
    return backend, provider, encryption_config


def build_sops_encrypt_kwargs(encryption_config: EncryptionConfig | None) -> dict[str, str]:
    """Build SOPS encryption kwargs from config."""
    if not encryption_config:
        return {}

    kwargs: dict[str, str] = {}
    if encryption_config.sops_age_recipients:
        kwargs["age_recipients"] = encryption_config.sops_age_recipients
    if encryption_config.sops_kms_arn:
        kwargs["kms_arn"] = encryption_config.sops_kms_arn
    if encryption_config.sops_gcp_kms:
        kwargs["gcp_kms"] = encryption_config.sops_gcp_kms
    if encryption_config.sops_azure_kv:
        kwargs["azure_kv"] = encryption_config.sops_azure_kv
    return kwargs


def is_encrypted_content(
    provider: EncryptionProvider,
    backend: EncryptionBackend,
    content: str,
) -> bool:
    """Determine if file content is encrypted for the selected backend."""
    if backend.has_encrypted_header(content):
        return True
    if provider == EncryptionProvider.DOTENVX:
        return "encrypted:" in content.lower()
    return False
