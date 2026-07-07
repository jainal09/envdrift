"""Tests for encryption helper utilities."""

from __future__ import annotations

import logging
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


def test_resolve_encryption_backend_warns_on_bad_config(tmp_path, caplog):
    """resolve_encryption_backend should warn when config load fails."""
    config_file = tmp_path / "envdrift.toml"
    config_file.write_text("invalid = [")

    caplog.set_level(logging.WARNING)
    resolve_encryption_backend(config_file)

    assert "Failed to load config" in caplog.text
    assert any(record.levelno == logging.WARNING for record in caplog.records)


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


def test_is_encrypted_content_sops_mixed_file_stays_backend_managed():
    """A SOPS-metadata-bearing file with a surviving plaintext value IS still
    backend-managed content: `lock` must route it to the precise mixed-state
    handling ("plaintext values remain", #470) and the backend's encrypt()
    refuses to bless it (#475) — not to the generic "not encrypted" path."""
    from envdrift.encryption.sops import SOPSEncryptionBackend

    backend = SOPSEncryptionBackend()
    content = (
        "NEW_SECRET=plaintextleak999\n"
        "DB_PASSWORD=ENC[AES256_GCM,data:abc,iv:def,tag:ghi,type:str]\n"
        "sops_age__list_0__map_recipient=age1abc\n"
        "sops_unencrypted_suffix=_unencrypted\n"
        "sops_version=3.13.1\n"
    )

    assert is_encrypted_content(EncryptionProvider.SOPS, backend, content) is True
    # The surviving plaintext is still visible to the post-state checks that
    # keep the mixed file loud downstream.
    assert backend.has_plaintext_values(content) is True


def test_is_encrypted_content_sops_fully_encrypted_is_true():
    """A genuinely fully-encrypted SOPS dotenv (including intentionally-plaintext
    ``*_unencrypted`` keys and empty values) still counts as encrypted."""
    from envdrift.encryption.sops import SOPSEncryptionBackend

    backend = SOPSEncryptionBackend()
    content = (
        "DB_PASSWORD=ENC[AES256_GCM,data:abc,iv:def,tag:ghi,type:str]\n"
        "FEATURE_FLAG_unencrypted=on\n"
        "EMPTY_VALUE=\n"
        "sops_age__list_0__map_recipient=age1abc\n"
        "sops_mac=ENC[AES256_GCM,data:mac,iv:def,tag:ghi,type:str]\n"
        "sops_unencrypted_suffix=_unencrypted\n"
        "sops_version=3.13.1\n"
    )

    assert is_encrypted_content(EncryptionProvider.SOPS, backend, content) is True


def test_should_attempt_decryption_sops_mixed_file_is_true():
    """Regression for #475: in the decrypt direction, a mixed SOPS file (metadata
    block + surviving plaintext value) must still be handed to sops — `pull`
    silently skipping it as "not encrypted" (exit 0, profile even activated)
    while its values are still ciphertext is a false success."""
    from envdrift.cli_commands.encryption_helpers import should_attempt_decryption
    from envdrift.encryption.sops import SOPSEncryptionBackend

    backend = SOPSEncryptionBackend()
    mixed = (
        "NEW_SECRET=plaintextleak999\n"
        "DB_PASSWORD=ENC[AES256_GCM,data:abc,iv:def,tag:ghi,type:str]\n"
        "sops_age__list_0__map_recipient=age1abc\n"
        "sops_unencrypted_suffix=_unencrypted\n"
        "sops_version=3.13.1\n"
    )

    # The decrypt-direction predicate routes the mixed file to sops.
    assert should_attempt_decryption(EncryptionProvider.SOPS, backend, mixed) is True

    # A file with no SOPS markers at all genuinely has nothing to decrypt.
    plain = "API_KEY=hunter2\n"
    assert should_attempt_decryption(EncryptionProvider.SOPS, backend, plain) is False


def test_should_attempt_decryption_dotenvx_matches_encrypted_values_only():
    """For dotenvx the decrypt-direction predicate keys off actual ``=encrypted:``
    values: a decrypted file that kept its public-key header must stay skipped
    (and profile-activated) exactly as before (#413)."""
    from envdrift.cli_commands.encryption_helpers import should_attempt_decryption

    backend = cast(
        EncryptionBackend,
        DummyEncryptionBackend(name="dotenvx", has_encrypted_header=lambda _c: True),
    )
    decrypted_with_header = 'DOTENV_PUBLIC_KEY="abc"\nAPI_KEY=hunter2\n'
    encrypted = 'DOTENV_PUBLIC_KEY="abc"\nAPI_KEY=encrypted:BDqDBJ\n'

    assert should_attempt_decryption(EncryptionProvider.DOTENVX, backend, encrypted) is True
    assert (
        should_attempt_decryption(EncryptionProvider.DOTENVX, backend, decrypted_with_header)
        is False
    )


def test_sops_bare_enc_token_without_metadata_is_neither_encrypted_nor_decryptable():
    """A plaintext file that merely mentions ``ENC[AES256_GCM,`` in a value
    carries no SOPS metadata block: `lock` must not bless it as encrypted (it
    would be undecryptable) and `pull` must skip it cleanly instead of handing
    it to sops for an avoidable decrypt failure."""
    from envdrift.cli_commands.encryption_helpers import should_attempt_decryption
    from envdrift.encryption.sops import SOPSEncryptionBackend

    backend = SOPSEncryptionBackend()
    stray_token = "API_KEY=ENC[AES256_GCM,data:x,iv:y,tag:z,type:str]\nOTHER=plain\n"

    assert is_encrypted_content(EncryptionProvider.SOPS, backend, stray_token) is False
    assert should_attempt_decryption(EncryptionProvider.SOPS, backend, stray_token) is False

    # With the genuine metadata block the same predicates engage: fully
    # encrypted content is blessed, and mixed content stays decryptable-loud.
    encrypted = (
        "DB_PASSWORD=ENC[AES256_GCM,data:abc,iv:def,tag:ghi,type:str]\n"
        "sops_age__list_0__map_recipient=age1abc\n"
        "sops_unencrypted_suffix=_unencrypted\n"
        "sops_version=3.13.1\n"
    )
    assert is_encrypted_content(EncryptionProvider.SOPS, backend, encrypted) is True
    assert should_attempt_decryption(EncryptionProvider.SOPS, backend, encrypted) is True
