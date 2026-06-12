"""Tests for encryption helper utilities."""

from __future__ import annotations

from textwrap import dedent
from typing import Any, cast

from envdrift.cli_commands.encryption_helpers import (
    build_sops_encrypt_kwargs,
    is_encrypted_content,
    resolve_encryption_backend,
)
from envdrift.config import EncryptionConfig
from envdrift.encryption import EncryptionProvider
from envdrift.encryption.base import EncryptionBackend
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

    captured: dict[str, Any] = {}

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

    captured: dict[str, Any] = {}

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
    # #348a: relative sops paths are resolved against the config file's dir
    # (tmp_path here), not passed through as raw cwd-relative strings.
    assert captured["config"]["config_file"] == str(tmp_path / ".sops.yaml")
    assert captured["config"]["age_key_file"] == str(tmp_path / ".agekey")


def test_resolve_encryption_backend_raises_on_bad_config(tmp_path):
    """resolve_encryption_backend raises when config load fails (#491).

    The pre-#491 behavior — log a warning and fall back to the default dotenvx
    backend — silently encrypted SOPS-configured projects with the wrong
    backend. CLI callers convert the raised error into a clean exit 1.
    """
    import pytest

    from envdrift.config import ConfigLoadError

    config_file = tmp_path / "envdrift.toml"
    config_file.write_text("invalid = [", encoding="utf-8")

    with pytest.raises(ConfigLoadError, match="TOML syntax error"):
        resolve_encryption_backend(config_file)


def test_resolve_encryption_backend_defaults_when_no_config_discovered(tmp_path, monkeypatch):
    """Auto-discovery finding no config falls back to the dotenvx default."""
    monkeypatch.chdir(tmp_path)

    _backend, provider, encryption_config = resolve_encryption_backend(None)

    assert provider == EncryptionProvider.DOTENVX
    assert encryption_config is None


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
    backend = cast(
        EncryptionBackend,
        DummyEncryptionBackend(name="dotenvx", has_encrypted_header=lambda _c: False),
    )
    content = "API_KEY=encrypted:abc123"

    assert is_encrypted_content(EncryptionProvider.DOTENVX, backend, content) is True


def test_is_encrypted_content_dotenvx_header_but_plaintext_values():
    """is_encrypted_content should return False when DOTENVX has header but no encrypted values.

    This tests the critical case where a .secret file has a DOTENV_PUBLIC_KEY header
    (from a previous partial merge) but the actual values are still plaintext.
    The function should NOT treat this as "already encrypted".
    """
    backend = cast(
        EncryptionBackend,
        DummyEncryptionBackend(
            name="dotenvx",
            has_encrypted_header=lambda _c: True,  # Header IS present
        ),
    )
    # Content has header but values are plaintext (no "encrypted:" prefix)
    content = """\
#/-------------------[DOTENV_PUBLIC_KEY]--------------------/
#/            public-key encryption for .env files          /
#/       [how it works](https://dotenvx.com/encryption)     /
#/----------------------------------------------------------/
DOTENV_PUBLIC_KEY_SECRET="034c65f520ec607225d1344fdbace9c31b06c1c8095f413c9cc50abb105f7124e3"

# .env.soak.secret
API_KEY=plaintext_secret_value
DATABASE_PASSWORD=another_plaintext_value
"""
    # Should return False because there are no "encrypted:" values
    assert is_encrypted_content(EncryptionProvider.DOTENVX, backend, content) is False


def test_is_encrypted_content_dotenvx_header_with_encrypted_values():
    """is_encrypted_content should return True when DOTENVX has header AND encrypted values."""
    backend = cast(
        EncryptionBackend,
        DummyEncryptionBackend(
            name="dotenvx",
            has_encrypted_header=lambda _c: True,
        ),
    )
    content = """\
#/-------------------[DOTENV_PUBLIC_KEY]--------------------/
DOTENV_PUBLIC_KEY_SECRET="034c65f520ec607225d1344fdbace9c31b06c1c8095f413c9cc50abb105f7124e3"

API_KEY=encrypted:BJxUJmUB/UdA5MEUSduzwIrW20EM9mQegxI0t5/Urj83ZEKcbPok4ntuCgE6o6aXmRNdbn
DATABASE_PASSWORD=encrypted:BDMo6jyFdvRLdd2nkCk6l/7yPmULsTQtXuIIP4j7vrZewJ4bMVXIiEHHGWKBHHS0Mz5a
"""
    assert is_encrypted_content(EncryptionProvider.DOTENVX, backend, content) is True


def test_is_encrypted_content_sops_uses_header():
    """For SOPS provider, is_encrypted_content should use has_encrypted_header."""
    # SOPS with header = encrypted
    backend_with_header = cast(
        EncryptionBackend,
        DummyEncryptionBackend(
            name="sops",
            has_encrypted_header=lambda _c: True,
        ),
    )
    assert is_encrypted_content(EncryptionProvider.SOPS, backend_with_header, "any") is True

    # SOPS without header = not encrypted
    backend_no_header = cast(
        EncryptionBackend,
        DummyEncryptionBackend(
            name="sops",
            has_encrypted_header=lambda _c: False,
        ),
    )
    assert is_encrypted_content(EncryptionProvider.SOPS, backend_no_header, "any") is False
