"""Tests for encryption helper utilities."""

from __future__ import annotations

import logging
from textwrap import dedent

from envdrift.cli_commands.encryption_helpers import (
    build_sops_encrypt_kwargs,
    is_encrypted_content,
    resolve_encryption_backend,
)
from envdrift.config import EncryptionConfig
from envdrift.encryption import EncryptionProvider
from tests.helpers import DummyEncryptionBackend


def test_resolve_encryption_backend_dotenvx_auto_install(tmp_path, monkeypatch):
    """resolve_encryption_backend should pass dotenvx auto_install to factory."""
    config_file = tmp_path / "envdrift.toml"
    config_file.write_text(
        dedent(
            """
            [encryption]
            backend = "dotenvx"

            [encryption.dotenvx]
            auto_install = true
            """
        ).lstrip()
    )

    captured: dict[str, object] = {}

    def fake_get_backend(provider, **config):
        captured["provider"] = provider
        captured["config"] = config
        return DummyEncryptionBackend(name=provider.value)

    monkeypatch.setattr(
        "envdrift.cli_commands.encryption_helpers.get_encryption_backend",
        fake_get_backend,
    )

    backend, provider, encryption_config = resolve_encryption_backend(config_file)

    assert backend.name == "dotenvx"
    assert provider == EncryptionProvider.DOTENVX
    assert encryption_config is not None
    assert captured["config"]["auto_install"] is True


def test_resolve_encryption_backend_sops_config(tmp_path, monkeypatch):
    """resolve_encryption_backend should pass sops options to factory."""
    config_file = tmp_path / "envdrift.toml"
    config_file.write_text(
        dedent(
            """
            [encryption]
            backend = "sops"

            [encryption.sops]
            auto_install = true
            config_file = ".sops.yaml"
            age_key_file = ".agekey"
            """
        ).lstrip()
    )

    captured: dict[str, object] = {}

    def fake_get_backend(provider, **config):
        captured["provider"] = provider
        captured["config"] = config
        return DummyEncryptionBackend(name=provider.value)

    monkeypatch.setattr(
        "envdrift.cli_commands.encryption_helpers.get_encryption_backend",
        fake_get_backend,
    )

    resolve_encryption_backend(config_file)

    assert captured["provider"] == EncryptionProvider.SOPS
    assert captured["config"]["auto_install"] is True
    assert captured["config"]["config_file"] == ".sops.yaml"
    assert captured["config"]["age_key_file"] == ".agekey"


def test_resolve_encryption_backend_warns_on_bad_config(tmp_path, caplog):
    """resolve_encryption_backend should warn when config load fails."""
    config_file = tmp_path / "envdrift.toml"
    config_file.write_text("invalid = [")

    caplog.set_level(logging.WARNING)
    resolve_encryption_backend(config_file)

    assert "Failed to load config" in caplog.text


def test_build_sops_encrypt_kwargs():
    """build_sops_encrypt_kwargs should include configured keys."""
    config = EncryptionConfig(
        sops_age_recipients="age1abc",
        sops_kms_arn="arn:aws:kms:us-east-1:123:key/abc",
        sops_gcp_kms="projects/p/locations/l/keyRings/r/cryptoKeys/k",
        sops_azure_kv="https://vault.vault.azure.net/keys/key/1",
    )

    assert build_sops_encrypt_kwargs(config) == {
        "age_recipients": "age1abc",
        "kms_arn": "arn:aws:kms:us-east-1:123:key/abc",
        "gcp_kms": "projects/p/locations/l/keyRings/r/cryptoKeys/k",
        "azure_kv": "https://vault.vault.azure.net/keys/key/1",
    }


def test_is_encrypted_content_checks_dotenvx_marker():
    """is_encrypted_content should catch dotenvx value markers."""
    backend = DummyEncryptionBackend(name="dotenvx", has_encrypted_header=lambda _c: False)
    content = "API_KEY=encrypted:abc123"

    assert is_encrypted_content(EncryptionProvider.DOTENVX, backend, content) is True
