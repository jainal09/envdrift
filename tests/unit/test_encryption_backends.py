"""Tests for encryption backends (dotenvx and SOPS)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from envdrift.encryption import (
    EncryptionProvider,
    detect_encryption_provider,
    get_encryption_backend,
)
from envdrift.encryption.base import (
    EncryptionBackendError,
    EncryptionNotFoundError,
    EncryptionResult,
    EncryptionStatus,
)
from envdrift.encryption.dotenvx import DotenvxEncryptionBackend
from envdrift.encryption.sops import SOPSEncryptionBackend


class TestEncryptionProvider:
    """Tests for EncryptionProvider enum."""

    def test_dotenvx_value(self):
        """Test dotenvx provider value."""
        assert EncryptionProvider.DOTENVX.value == "dotenvx"

    def test_sops_value(self):
        """Test sops provider value."""
        assert EncryptionProvider.SOPS.value == "sops"


class TestGetEncryptionBackend:
    """Tests for get_encryption_backend factory function."""

    def test_get_dotenvx_backend_from_string(self):
        """Test getting dotenvx backend from string."""
        backend = get_encryption_backend("dotenvx")
        assert isinstance(backend, DotenvxEncryptionBackend)
        assert backend.name == "dotenvx"

    def test_get_dotenvx_backend_from_enum(self):
        """Test getting dotenvx backend from enum."""
        backend = get_encryption_backend(EncryptionProvider.DOTENVX)
        assert isinstance(backend, DotenvxEncryptionBackend)

    def test_get_sops_backend_from_string(self):
        """Test getting SOPS backend from string."""
        backend = get_encryption_backend("sops")
        assert isinstance(backend, SOPSEncryptionBackend)
        assert backend.name == "sops"

    def test_get_sops_backend_from_enum(self):
        """Test getting SOPS backend from enum."""
        backend = get_encryption_backend(EncryptionProvider.SOPS)
        assert isinstance(backend, SOPSEncryptionBackend)

    def test_unknown_backend_raises(self):
        """Test unknown backend raises ValueError."""
        with pytest.raises(ValueError):
            get_encryption_backend("unknown")

    def test_dotenvx_backend_with_config(self):
        """Test dotenvx backend respects config."""
        backend = get_encryption_backend("dotenvx", auto_install=False)
        assert isinstance(backend, DotenvxEncryptionBackend)
        assert backend._auto_install is False

    def test_sops_backend_with_config(self, tmp_path):
        """Test SOPS backend respects config."""
        config_file = tmp_path / ".sops.yaml"
        backend = get_encryption_backend("sops", config_file=str(config_file))
        assert isinstance(backend, SOPSEncryptionBackend)
        assert backend._config_file == config_file

    def test_sops_backend_with_age_key_file(self, tmp_path):
        """Test SOPS backend respects age key file config."""
        age_key_file = tmp_path / "age.txt"
        backend = get_encryption_backend("sops", age_key_file=str(age_key_file))
        assert isinstance(backend, SOPSEncryptionBackend)
        assert backend._age_key_file == age_key_file

    def test_sops_backend_with_auto_install(self):
        """Test SOPS backend respects auto_install setting."""
        backend = get_encryption_backend("sops", auto_install=True)
        assert isinstance(backend, SOPSEncryptionBackend)
        assert backend._auto_install is True


class TestDetectEncryptionProvider:
    """Tests for detect_encryption_provider function."""

    def test_detect_dotenvx(self, tmp_path):
        """Test detecting dotenvx encrypted file."""
        env_file = tmp_path / ".env"
        env_file.write_text("""#/---BEGIN DOTENV ENCRYPTED---/
DOTENV_PUBLIC_KEY_PRODUCTION="03abc..."
KEY="encrypted:xyz"
""")
        assert detect_encryption_provider(env_file) == EncryptionProvider.DOTENVX

    def test_detect_sops(self, tmp_path):
        """Test detecting SOPS encrypted file."""
        env_file = tmp_path / ".env"
        env_file.write_text('KEY="ENC[AES256_GCM,data:abc,iv:xyz,tag:123,type:str]"')
        assert detect_encryption_provider(env_file) == EncryptionProvider.SOPS

    def test_detect_plaintext_returns_none(self, tmp_path):
        """Test plaintext file returns None."""
        env_file = tmp_path / ".env"
        env_file.write_text("KEY=value\nOTHER=123")
        assert detect_encryption_provider(env_file) is None

    def test_plaintext_with_sops_substring_returns_none(self, tmp_path):
        """#413 — a bare ``sops:`` substring in a plaintext value is NOT SOPS.

        ``detect_encryption_provider`` used unanchored ``"sops:" in content``
        substring matching, so ``VAULT_ADDR=https://sops:8200`` was misclassified
        as SOPS-encrypted. Detection is now line-anchored.
        """
        env_file = tmp_path / ".env"
        env_file.write_text("VAULT_ADDR=https://sops:8200\nAPI_KEY=plain")
        assert detect_encryption_provider(env_file) is None

    def test_detect_sops_metadata_block(self, tmp_path):
        """A genuine line-anchored SOPS metadata block is still detected as SOPS."""
        env_file = tmp_path / ".env"
        env_file.write_text("API_KEY=plain\nsops_version=3.13.1\n")
        assert detect_encryption_provider(env_file) == EncryptionProvider.SOPS

    def test_detect_nonexistent_returns_none(self, tmp_path):
        """Test nonexistent file returns None."""
        assert detect_encryption_provider(tmp_path / "nonexistent") is None


class TestDotenvxEncryptionBackend:
    """Tests for DotenvxEncryptionBackend."""

    def test_name(self):
        """Test backend name."""
        backend = DotenvxEncryptionBackend()
        assert backend.name == "dotenvx"

    def test_encrypted_value_prefix(self):
        """Test encrypted value prefix."""
        backend = DotenvxEncryptionBackend()
        assert backend.encrypted_value_prefix == "encrypted:"

    def test_detect_encryption_status_encrypted(self):
        """Test detecting encrypted value."""
        backend = DotenvxEncryptionBackend()
        status = backend.detect_encryption_status("encrypted:abc123xyz")
        assert status == EncryptionStatus.ENCRYPTED

    def test_detect_encryption_status_plaintext(self):
        """Test detecting plaintext value."""
        backend = DotenvxEncryptionBackend()
        status = backend.detect_encryption_status("plain_value")
        assert status == EncryptionStatus.PLAINTEXT

    def test_detect_encryption_status_empty(self):
        """Test detecting empty value."""
        backend = DotenvxEncryptionBackend()
        status = backend.detect_encryption_status("")
        assert status == EncryptionStatus.EMPTY

    def test_has_encrypted_header_true(self):
        """Test has_encrypted_header with dotenvx markers."""
        backend = DotenvxEncryptionBackend()
        content = "#/---BEGIN DOTENV ENCRYPTED---/\nKEY=value"
        assert backend.has_encrypted_header(content) is True

    def test_has_encrypted_header_false(self):
        """Test has_encrypted_header with plaintext."""
        backend = DotenvxEncryptionBackend()
        content = "KEY=value\nOTHER=123"
        assert backend.has_encrypted_header(content) is False

    def test_is_file_encrypted(self, tmp_path):
        """Test is_file_encrypted method."""
        backend = DotenvxEncryptionBackend()

        encrypted_file = tmp_path / ".env.encrypted"
        encrypted_file.write_text("#/---BEGIN DOTENV ENCRYPTED---/\nKEY=value")
        assert backend.is_file_encrypted(encrypted_file) is True

        plain_file = tmp_path / ".env.plain"
        plain_file.write_text("KEY=value")
        assert backend.is_file_encrypted(plain_file) is False

    def test_is_value_encrypted(self):
        """Test is_value_encrypted convenience method."""
        backend = DotenvxEncryptionBackend()
        assert backend.is_value_encrypted("encrypted:abc") is True
        assert backend.is_value_encrypted("plain") is False

    @patch("envdrift.integrations.dotenvx.DotenvxWrapper")
    def test_is_installed(self, mock_wrapper_class):
        """Test is_installed checks wrapper."""
        mock_wrapper = MagicMock()
        mock_wrapper.is_installed.return_value = True
        mock_wrapper_class.return_value = mock_wrapper

        backend = DotenvxEncryptionBackend()
        assert backend.is_installed() is True

    def test_is_installed_handles_wrapper_error(self, monkeypatch):
        """Wrapper errors should return False for is_installed."""
        backend = DotenvxEncryptionBackend()

        def boom():
            raise RuntimeError("bad wrapper")

        monkeypatch.setattr(backend, "_get_wrapper", boom)
        assert backend.is_installed() is False

    def test_get_version_returns_none_when_not_installed(self, monkeypatch):
        """get_version should return None when dotenvx is unavailable."""
        backend = DotenvxEncryptionBackend()
        monkeypatch.setattr(backend, "is_installed", lambda: False)
        assert backend.get_version() is None

    def test_get_version_handles_wrapper_error(self, monkeypatch):
        """get_version should return None on wrapper errors."""
        backend = DotenvxEncryptionBackend()
        monkeypatch.setattr(backend, "is_installed", lambda: True)

        class DummyWrapper:
            def get_version(self):
                raise RuntimeError("boom")

        monkeypatch.setattr(backend, "_get_wrapper", lambda: DummyWrapper())
        assert backend.get_version() is None

    @patch("envdrift.integrations.dotenvx.DotenvxWrapper")
    def test_encrypt_success(self, mock_wrapper_class, tmp_path):
        """Test successful encryption."""
        mock_wrapper = MagicMock()
        mock_wrapper.is_installed.return_value = True
        mock_wrapper_class.return_value = mock_wrapper

        env_file = tmp_path / ".env"
        env_file.write_text("KEY=value")

        # The mock must model the seam's real effect: a genuine dotenvx encrypt
        # rewrites the file with ciphertext. The backend now verifies the
        # on-disk outcome (envdrift #443), so a no-op mock would correctly read
        # as "encryption did not take effect". Make the mock honest.
        def _fake_encrypt(**_kwargs):
            env_file.write_text('KEY="encrypted:BExampleCiphertext"')

        mock_wrapper.encrypt.side_effect = _fake_encrypt

        backend = DotenvxEncryptionBackend()
        result = backend.encrypt(env_file)

        assert result.success is True
        assert "Encrypted" in result.message
        mock_wrapper.encrypt.assert_called_once()

    def test_encrypt_not_installed(self, monkeypatch, tmp_path):
        """encrypt should raise when dotenvx is not installed."""
        backend = DotenvxEncryptionBackend()
        monkeypatch.setattr(backend, "is_installed", lambda: False)

        env_file = tmp_path / ".env"
        env_file.write_text("KEY=value")

        with pytest.raises(EncryptionNotFoundError):
            backend.encrypt(env_file)

    def test_encrypt_file_not_found(self, tmp_path):
        """Test encrypt with nonexistent file."""
        backend = DotenvxEncryptionBackend()
        result = backend.encrypt(tmp_path / "nonexistent")

        assert result.success is False
        assert "not found" in result.message

    def test_encrypt_filename_with_space_refused_preserves_plaintext(self, tmp_path):
        """#23: a filename dotenvx can't turn into a valid key name must be refused.

        ``my secrets.env`` makes dotenvx derive a private-key variable name with a
        space (``DOTENV_PRIVATE_KEY_MY SECRETS...``): the value encrypts and exits
        0, but the file is then permanently undecryptable and the original
        plaintext is destroyed — silent secret lockout. The backend must refuse
        pre-flight and leave the file byte-for-byte untouched.
        """
        env_file = tmp_path / "my secrets.env"
        env_file.write_text("SECRET=keepme\n")

        backend = DotenvxEncryptionBackend()
        result = backend.encrypt(env_file)

        assert result.success is False
        # Original plaintext preserved — not encrypted into an unrecoverable file.
        assert env_file.read_text() == "SECRET=keepme\n"

    def test_encrypt_unicode_filename_refused(self, tmp_path):
        """#23: a non-ASCII filename also yields an invalid dotenvx key name."""
        env_file = tmp_path / "café.env"
        env_file.write_text("SECRET=keepme\n")

        backend = DotenvxEncryptionBackend()
        result = backend.encrypt(env_file)

        assert result.success is False
        assert env_file.read_text() == "SECRET=keepme\n"

    @patch("envdrift.integrations.dotenvx.DotenvxWrapper")
    def test_decrypt_success(self, mock_wrapper_class, tmp_path):
        """Test successful decryption."""
        mock_wrapper = MagicMock()
        mock_wrapper.is_installed.return_value = True
        mock_wrapper_class.return_value = mock_wrapper

        env_file = tmp_path / ".env"
        env_file.write_text("KEY=encrypted:abc")

        # The mock must model the seam's real effect: a genuine dotenvx decrypt
        # replaces ciphertext with plaintext. The backend now verifies the on-disk
        # outcome (envdrift #443), so a no-op mock would correctly read as
        # "decryption did not take effect". Make the mock honest.
        def _fake_decrypt(**_kwargs):
            env_file.write_text("KEY=value")

        mock_wrapper.decrypt.side_effect = _fake_decrypt

        backend = DotenvxEncryptionBackend()
        result = backend.decrypt(env_file)

        assert result.success is True
        assert result.changed is True
        assert "Decrypted" in result.message

    def test_decrypt_noop_on_file_with_no_ciphertext(self, tmp_path):
        """#443: a file with no encrypted values is an honest no-op, not 'Decrypted'.

        The pre-check returns before dotenvx is consulted, so this needs no binary.
        """
        env_file = tmp_path / ".env"
        env_file.write_text("API_KEY=plainvalue\nPORT=8080\n")
        before = env_file.read_bytes()

        result = DotenvxEncryptionBackend().decrypt(env_file)

        assert result.success is True
        assert result.changed is False
        assert "nothing to decrypt" in result.message.lower()
        assert env_file.read_bytes() == before  # not rewritten

    @patch("envdrift.integrations.dotenvx.DotenvxWrapper")
    def test_decrypt_reports_failure_when_ciphertext_survives(self, mock_wrapper_class, tmp_path):
        """#443: dotenvx exiting 0 without decrypting must be caught by the outcome check.

        Models the silent-failure seam: the wrapper "succeeds" but leaves the
        ciphertext on disk (a missing/invalid key). The backend re-reads the file
        and reports failure instead of trusting the exit code.
        """
        mock_wrapper = MagicMock()
        mock_wrapper.is_installed.return_value = True
        mock_wrapper.decrypt.side_effect = lambda **_kwargs: None  # no-op: ciphertext stays
        mock_wrapper_class.return_value = mock_wrapper

        env_file = tmp_path / ".env"
        env_file.write_text('API_KEY="encrypted:BExampleCiphertext"')

        result = DotenvxEncryptionBackend().decrypt(env_file)

        assert result.success is False
        assert result.changed is False
        assert "did not take effect" in result.message.lower()
        assert "encrypted:" in env_file.read_text()  # ciphertext untouched, not lost

    @patch("envdrift.integrations.dotenvx.DotenvxWrapper")
    def test_encrypt_wraps_dotenvx_error(self, mock_wrapper_class, tmp_path):
        """encrypt should wrap dotenvx errors."""
        from envdrift.integrations.dotenvx import DotenvxError

        mock_wrapper = MagicMock()
        mock_wrapper.is_installed.return_value = True
        mock_wrapper.encrypt.side_effect = DotenvxError("boom")
        mock_wrapper_class.return_value = mock_wrapper

        env_file = tmp_path / ".env"
        env_file.write_text("KEY=value")

        backend = DotenvxEncryptionBackend()
        with pytest.raises(EncryptionBackendError):
            backend.encrypt(env_file)

    @patch("envdrift.integrations.dotenvx.DotenvxWrapper")
    def test_decrypt_wraps_dotenvx_error(self, mock_wrapper_class, tmp_path):
        """decrypt should wrap dotenvx errors."""
        from envdrift.integrations.dotenvx import DotenvxError

        mock_wrapper = MagicMock()
        mock_wrapper.is_installed.return_value = True
        mock_wrapper.decrypt.side_effect = DotenvxError("boom")
        mock_wrapper_class.return_value = mock_wrapper

        env_file = tmp_path / ".env"
        env_file.write_text("KEY=encrypted:abc")

        backend = DotenvxEncryptionBackend()
        with pytest.raises(EncryptionBackendError):
            backend.decrypt(env_file)

    def test_install_instructions(self):
        """Test install_instructions returns formatted string."""
        backend = DotenvxEncryptionBackend()
        instructions = backend.install_instructions()

        assert "dotenvx" in instructions
        assert "Option 1" in instructions


class TestSOPSEncryptionBackend:
    """Tests for SOPSEncryptionBackend."""

    def test_name(self):
        """Test backend name."""
        backend = SOPSEncryptionBackend()
        assert backend.name == "sops"

    def test_encrypted_value_prefix(self):
        """Test encrypted value prefix."""
        backend = SOPSEncryptionBackend()
        assert backend.encrypted_value_prefix == "ENC["

    def test_detect_encryption_status_encrypted(self):
        """Test detecting SOPS encrypted value."""
        backend = SOPSEncryptionBackend()
        value = "ENC[AES256_GCM,data:abc,iv:xyz,tag:123,type:str]"
        status = backend.detect_encryption_status(value)
        assert status == EncryptionStatus.ENCRYPTED

    def test_detect_encryption_status_plaintext(self):
        """Test detecting plaintext value."""
        backend = SOPSEncryptionBackend()
        status = backend.detect_encryption_status("plain_value")
        assert status == EncryptionStatus.PLAINTEXT

    def test_detect_encryption_status_empty(self):
        """Test detecting empty value."""
        backend = SOPSEncryptionBackend()
        status = backend.detect_encryption_status("")
        assert status == EncryptionStatus.EMPTY

    def test_has_encrypted_header_with_enc_marker(self):
        """Test has_encrypted_header with ENC[] marker."""
        backend = SOPSEncryptionBackend()
        content = 'KEY="ENC[AES256_GCM,data:abc,iv:xyz,tag:123,type:str]"'
        assert backend.has_encrypted_header(content) is True

    def test_has_encrypted_header_with_sops_yaml(self):
        """Test has_encrypted_header with a genuinely-encrypted YAML block.

        A real SOPS YAML file carries both an ``ENC[AES256_GCM,`` value and a
        col-0 ``sops:`` metadata mapping; the authoritative ``ENC[`` marker
        classifies it encrypted.
        """
        backend = SOPSEncryptionBackend()
        content = "key: ENC[AES256_GCM,data:abc,iv:xyz,tag:123,type:str]\nsops:\n  version: 3.8.1"
        assert backend.has_encrypted_header(content) is True

    def test_has_encrypted_header_metadata_only_no_enc_marker(self):
        """Metadata markers alone (no ``ENC[``) still classify as encrypted (#324).

        Pins the line-anchored ``SOPS_METADATA_PATTERNS`` branch — content that
        carries a genuine SOPS metadata block but no ``ENC[AES256_GCM,`` value
        (e.g. a file encrypted with ``--unencrypted-suffix``) must still be
        detected. Covers the YAML col-0 ``sops:`` mapping and the flat dotenv
        ``sops_version=`` / ``sops_mac=`` markers.
        """
        backend = SOPSEncryptionBackend()
        assert backend.has_encrypted_header("key: value\nsops:\n  version: 3.8.1\n") is True
        assert (
            backend.has_encrypted_header('{\n\t"sops": {\n\t\t"version": "3.13.1"\n\t}\n}') is True
        )
        assert backend.has_encrypted_header("FOO=bar\nsops_version=3.13.1\n") is True
        assert backend.has_encrypted_header("FOO=bar\nsops_mac=abc123\n") is True

    def test_has_encrypted_header_plaintext_sops_substring_not_encrypted(self):
        """Plaintext containing the substring 'sops:' is NOT encrypted (#324).

        The old unscoped ``"sops:" in content`` marker false-positived on any
        plaintext mentioning ``sops:`` (a URL, a comment, a value). The
        line-anchored patterns must reject these.
        """
        backend = SOPSEncryptionBackend()
        for plaintext in (
            "URL=https://sops:8200/v1\n",
            "REPO=https://github.com/getsops/sops:main\n",
            "# a comment about sops: usage\n",
            'JSON={"endpoint": "https://sops:8200"}\n',
        ):
            assert backend.has_encrypted_header(plaintext) is False, plaintext

    def test_has_encrypted_header_false(self):
        """Test has_encrypted_header with plaintext."""
        backend = SOPSEncryptionBackend()
        content = "KEY=value\nOTHER=123"
        assert backend.has_encrypted_header(content) is False

    def test_is_file_encrypted(self, tmp_path):
        """Test is_file_encrypted method."""
        backend = SOPSEncryptionBackend()

        encrypted_file = tmp_path / ".env.encrypted"
        encrypted_file.write_text('KEY="ENC[AES256_GCM,data:abc,iv:xyz,tag:123,type:str]"')
        assert backend.is_file_encrypted(encrypted_file) is True

        plain_file = tmp_path / ".env.plain"
        plain_file.write_text("KEY=value")
        assert backend.is_file_encrypted(plain_file) is False

    def test_is_value_encrypted(self):
        """Test is_value_encrypted convenience method."""
        backend = SOPSEncryptionBackend()
        assert backend.is_value_encrypted("ENC[AES256_GCM,data:abc]") is True
        assert backend.is_value_encrypted("plain") is False

    @patch("shutil.which")
    def test_is_installed_true(self, mock_which):
        """Test is_installed when SOPS is found."""
        mock_which.return_value = "/usr/local/bin/sops"
        backend = SOPSEncryptionBackend()
        assert backend.is_installed() is True

    @patch("shutil.which")
    def test_is_installed_false(self, mock_which, tmp_path):
        """Test is_installed when SOPS is not found."""
        mock_which.return_value = None
        with patch("envdrift.integrations.sops.get_sops_path") as mock_get_sops_path:
            mock_get_sops_path.return_value = tmp_path / "missing-sops"
            backend = SOPSEncryptionBackend()
            assert backend.is_installed() is False

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_get_version(self, mock_run, mock_which):
        """Test get_version returns version string."""
        mock_which.return_value = "/usr/local/bin/sops"
        mock_run.return_value = MagicMock(returncode=0, stdout="sops 3.8.1 (latest)")

        backend = SOPSEncryptionBackend()
        version = backend.get_version()

        assert version == "3.8.1"

    @patch("shutil.which")
    def test_get_version_not_installed(self, mock_which, tmp_path):
        """Test get_version when SOPS not installed."""
        mock_which.return_value = None
        with patch("envdrift.integrations.sops.get_sops_path") as mock_get_sops_path:
            mock_get_sops_path.return_value = tmp_path / "missing-sops"
            backend = SOPSEncryptionBackend()
            version = backend.get_version()

            assert version is None

    def test_encrypt_file_not_found(self, tmp_path):
        """Test encrypt with nonexistent file."""
        backend = SOPSEncryptionBackend()
        result = backend.encrypt(tmp_path / "nonexistent")

        assert result.success is False
        assert "not found" in result.message

    @patch("envdrift.encryption.sops.subprocess.run")
    def test_config_flag_precedes_path(self, mock_run, tmp_path):
        """Ensure --config is inserted before the env file path."""
        config_file = tmp_path / ".sops.yaml"
        config_file.write_text("creation_rules: []")
        env_file = tmp_path / ".env"
        env_file.write_text("KEY=value")
        binary = tmp_path / "sops"
        binary.write_text("")

        backend = SOPSEncryptionBackend(config_file=config_file)
        backend._binary_path = binary
        mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")

        backend.encrypt(env_file)

        cmd = mock_run.call_args[0][0]
        config_index = cmd.index("--config")
        env_index = cmd.index(str(env_file))
        assert config_index < env_index

    def test_decrypt_file_not_found(self, tmp_path):
        """Test decrypt with nonexistent file."""
        backend = SOPSEncryptionBackend()
        result = backend.decrypt(tmp_path / "nonexistent")

        assert result.success is False
        assert "not found" in result.message

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_encrypt_success(self, mock_run, mock_which, tmp_path):
        """Test successful SOPS encryption."""
        mock_which.return_value = "/usr/local/bin/sops"
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        env_file = tmp_path / ".env"
        env_file.write_text("KEY=value")

        backend = SOPSEncryptionBackend()
        result = backend.encrypt(env_file, age_recipients="age1abc...")

        assert result.success is True
        assert "Encrypted" in result.message

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_encrypt_failure(self, mock_run, mock_which, tmp_path):
        """Test SOPS encryption failure."""
        mock_which.return_value = "/usr/local/bin/sops"
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="No keys found")

        env_file = tmp_path / ".env"
        env_file.write_text("KEY=value")

        backend = SOPSEncryptionBackend()

        with pytest.raises(EncryptionBackendError):
            backend.encrypt(env_file)

    def test_encrypt_in_place_false_no_output_fails_without_running(self, tmp_path, monkeypatch):
        """Regression for #360: encrypt(in_place=False) with no output_file must
        report failure (not run sops at all) instead of streaming the ciphertext
        to discarded stdout while leaving the file plaintext and claiming success."""
        env_file = tmp_path / ".env"
        env_file.write_text("KEY=value")

        backend = SOPSEncryptionBackend()
        monkeypatch.setattr(backend, "is_installed", lambda: True)

        ran = {"called": False}

        def fake_run(args, env=None, cwd=None):
            ran["called"] = True
            return MagicMock(returncode=0, stderr="", stdout="ENC[AES256_GCM,data:zzz]")

        monkeypatch.setattr(backend, "_run", fake_run)

        result = backend.encrypt(env_file, in_place=False)

        # No false success and sops is never invoked (ciphertext would be lost).
        assert result.success is False
        assert "output_file" in result.message
        assert result.file_path == env_file
        assert ran["called"] is False
        # The on-disk file is left untouched (still plaintext, not silently lost).
        assert env_file.read_text() == "KEY=value"

    def test_encrypt_with_output_file(self, tmp_path, monkeypatch):
        """Regression for #360: encrypt(in_place=False, output_file=...) honors the
        output file via --output instead of discarding the ciphertext to stdout."""
        env_file = tmp_path / ".env"
        env_file.write_text("KEY=value")
        output_file = tmp_path / ".env.enc"

        backend = SOPSEncryptionBackend()
        monkeypatch.setattr(backend, "is_installed", lambda: True)

        captured = {}

        def fake_run(args, env=None, cwd=None):
            captured["args"] = args
            return MagicMock(returncode=0, stderr="", stdout="")

        monkeypatch.setattr(backend, "_run", fake_run)

        result = backend.encrypt(env_file, output_file=output_file)

        assert result.success is True
        assert result.file_path == output_file
        assert "--output" in captured["args"]
        assert str(output_file) in captured["args"]
        # In-place flag must NOT be emitted when writing to a separate output file.
        assert "--in-place" not in captured["args"]

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_decrypt_success(self, mock_run, mock_which, tmp_path):
        """Test successful SOPS decryption."""
        mock_which.return_value = "/usr/local/bin/sops"
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        env_file = tmp_path / ".env"
        env_file.write_text('KEY="ENC[AES256_GCM,data:abc]"')

        backend = SOPSEncryptionBackend()
        result = backend.decrypt(env_file)

        assert result.success is True
        assert "Decrypted" in result.message

    def test_decrypt_with_output_file(self, tmp_path, monkeypatch):
        """Decrypt should write to output_file when provided."""
        env_file = tmp_path / ".env"
        env_file.write_text('KEY="ENC[AES256_GCM,data:abc]"')
        output_file = tmp_path / ".env.dec"

        backend = SOPSEncryptionBackend()
        monkeypatch.setattr(backend, "is_installed", lambda: True)

        captured = {}

        def fake_run(args, env=None, cwd=None):
            captured["args"] = args
            return MagicMock(returncode=0, stderr="", stdout="")

        monkeypatch.setattr(backend, "_run", fake_run)

        result = backend.decrypt(env_file, output_file=output_file)

        assert result.success is True
        assert result.file_path == output_file
        assert "--output" in captured["args"]
        assert str(output_file) in captured["args"]

    @patch("shutil.which")
    def test_encrypt_not_installed(self, mock_which, tmp_path):
        """Test encrypt raises when SOPS not installed."""
        mock_which.return_value = None
        with patch("envdrift.integrations.sops.get_sops_path") as mock_get_sops_path:
            mock_get_sops_path.return_value = tmp_path / "missing-sops"
            env_file = tmp_path / ".env"
            env_file.write_text("KEY=value")

            backend = SOPSEncryptionBackend()

            with pytest.raises(EncryptionNotFoundError):
                backend.encrypt(env_file)

    def test_install_instructions(self):
        """Test install_instructions returns formatted string."""
        backend = SOPSEncryptionBackend()
        instructions = backend.install_instructions()

        assert "SOPS" in instructions
        assert "brew install sops" in instructions
        assert "age" in instructions

    def test_config_file_option(self, tmp_path):
        """Test SOPS backend with config file."""
        config_file = tmp_path / ".sops.yaml"
        config_file.write_text("creation_rules:\n  - age: age1abc...")

        backend = SOPSEncryptionBackend(config_file=config_file)
        assert backend._config_file == config_file

    def test_age_key_option(self):
        """Test SOPS backend with age key."""
        backend = SOPSEncryptionBackend(age_key="AGE-SECRET-KEY-1ABC...")
        assert backend._age_key == "AGE-SECRET-KEY-1ABC..."

    def test_age_key_file_env(self, tmp_path, monkeypatch):
        """Test SOPS backend sets SOPS_AGE_KEY_FILE."""
        monkeypatch.delenv("SOPS_AGE_KEY_FILE", raising=False)
        age_key_file = tmp_path / "age.txt"
        backend = SOPSEncryptionBackend(age_key_file=age_key_file)
        env = backend._build_env({})
        assert env["SOPS_AGE_KEY_FILE"] == str(age_key_file)

    def test_build_env_sets_age_key(self, monkeypatch):
        """Test SOPS backend sets SOPS_AGE_KEY when provided."""
        monkeypatch.delenv("SOPS_AGE_KEY", raising=False)
        backend = SOPSEncryptionBackend(age_key="AGE-SECRET-KEY-1ABC")
        env = backend._build_env({})
        assert env["SOPS_AGE_KEY"] == "AGE-SECRET-KEY-1ABC"

    def test_build_env_respects_existing_age_key(self):
        """Test SOPS backend does not override existing SOPS_AGE_KEY."""
        backend = SOPSEncryptionBackend(age_key="AGE-SECRET-KEY-1ABC")
        env = backend._build_env({"SOPS_AGE_KEY": "existing-key"})
        assert env["SOPS_AGE_KEY"] == "existing-key"

    @patch("envdrift.encryption.sops.shutil.which", return_value=None)
    def test_auto_install_uses_installer(self, mock_which, tmp_path, monkeypatch):
        """Auto-install should invoke SopsInstaller when missing."""
        fake_binary = tmp_path / "sops"
        fake_binary.write_text("")

        installer = MagicMock()
        installer.install.return_value = fake_binary
        monkeypatch.setattr("envdrift.integrations.sops.SopsInstaller", lambda: installer)
        monkeypatch.setattr(
            "envdrift.integrations.sops.get_sops_path", lambda: tmp_path / "missing"
        )

        backend = SOPSEncryptionBackend(auto_install=True)
        assert backend.is_installed() is True
        installer.install.assert_called_once()

    def test_exec_env_decrypts_to_memory_and_injects_into_argv(self, tmp_path, monkeypatch):
        """exec_env decrypts (sops -d) to memory and runs the command as argv with
        the secrets injected — no shell, so it is cross-platform-quoting-safe."""
        env_file = tmp_path / ".env"
        env_file.write_text('KEY="ENC[AES256_GCM,data:abc]"')

        backend = SOPSEncryptionBackend()
        monkeypatch.setattr(backend, "is_installed", lambda: True)

        captured = {}

        def fake_run(args, env=None, cwd=None):
            # sops is invoked to DECRYPT to stdout, not via exec-env.
            captured["args"] = args
            return MagicMock(returncode=0, stderr="", stdout="KEY=secretval\n")

        monkeypatch.setattr(backend, "_run", fake_run)

        # The child (a real, quick python subprocess — no external binary) prints
        # the injected secret, proving exec_env merged it into the environment.
        result = backend.exec_env(
            env_file,
            [sys.executable, "-c", "import os; print(os.environ.get('KEY', ''))"],
        )

        assert captured["args"][0] == "-d"
        assert str(env_file) in captured["args"]
        assert result.returncode == 0
        assert result.stdout.strip() == "secretval"

    def test_exec_env_child_stdout_decoded_as_utf8(self, tmp_path, monkeypatch):
        """The child's UTF-8 stdout must decode as UTF-8 on every platform.

        Regression for the Windows cp1252 default: without an explicit
        ``encoding="utf-8"`` on the child ``subprocess.run``, a non-ASCII byte
        (e.g. the UTF-8 of ``→``) would be mis-decoded as cp1252 mojibake (or
        raise). The child here writes raw UTF-8 *bytes* directly, so this asserts
        the PARENT decodes them correctly — the bug this commit fixes."""
        non_ascii = "café-→-μ"
        env_file = tmp_path / ".env"
        env_file.write_text('KEY="ENC[AES256_GCM,data:abc]"')

        backend = SOPSEncryptionBackend()
        monkeypatch.setattr(backend, "is_installed", lambda: True)
        monkeypatch.setattr(
            backend,
            "_run",
            lambda args, env=None, cwd=None: MagicMock(
                returncode=0, stderr="", stdout=f"KEY={non_ascii}\n"
            ),
        )

        # Child emits raw UTF-8 bytes (bypassing its own stdout encoding) so the
        # assertion isolates the parent's decode behaviour.
        result = backend.exec_env(
            env_file,
            [
                sys.executable,
                "-c",
                "import os, sys; sys.stdout.buffer.write(os.environ['KEY'].encode('utf-8'))",
            ],
        )

        assert result.returncode == 0
        assert result.stdout == non_ascii

    def test_exec_env_missing_file_raises(self, tmp_path, monkeypatch):
        """exec_env rejects a non-existent env file before touching sops."""
        backend = SOPSEncryptionBackend()
        monkeypatch.setattr(backend, "is_installed", lambda: True)

        with pytest.raises(EncryptionBackendError, match="File not found"):
            backend.exec_env(tmp_path / "missing.env", [sys.executable, "-c", "pass"])

    def test_exec_env_not_installed_raises(self, tmp_path, monkeypatch):
        """exec_env raises EncryptionNotFoundError when sops is absent."""
        env_file = tmp_path / ".env"
        env_file.write_text('KEY="ENC[AES256_GCM,data:abc]"', encoding="utf-8")

        backend = SOPSEncryptionBackend()
        monkeypatch.setattr(backend, "is_installed", lambda: False)

        with pytest.raises(EncryptionNotFoundError):
            backend.exec_env(env_file, [sys.executable, "-c", "pass"])

    def test_exec_env_decrypt_failure_raises(self, tmp_path, monkeypatch):
        """A non-zero sops decrypt surfaces its stderr as EncryptionBackendError."""
        env_file = tmp_path / ".env"
        env_file.write_text('KEY="ENC[AES256_GCM,data:abc]"', encoding="utf-8")

        backend = SOPSEncryptionBackend()
        monkeypatch.setattr(backend, "is_installed", lambda: True)
        monkeypatch.setattr(
            backend,
            "_run",
            lambda args, env=None, cwd=None: MagicMock(
                returncode=1, stderr="no key for this file", stdout=""
            ),
        )

        with pytest.raises(EncryptionBackendError, match="no key for this file"):
            backend.exec_env(env_file, [sys.executable, "-c", "pass"])

    def test_exec_env_merges_caller_env(self, tmp_path, monkeypatch):
        """A caller-supplied env var is injected into the child alongside the secrets."""
        env_file = tmp_path / ".env"
        env_file.write_text('KEY="ENC[AES256_GCM,data:abc]"', encoding="utf-8")

        backend = SOPSEncryptionBackend()
        monkeypatch.setattr(backend, "is_installed", lambda: True)
        monkeypatch.setattr(
            backend,
            "_run",
            lambda args, env=None, cwd=None: MagicMock(
                returncode=0, stderr="", stdout="KEY=secretval\n"
            ),
        )

        result = backend.exec_env(
            env_file,
            [sys.executable, "-c", "import os; print(os.environ['EXTRA'])"],
            env={"EXTRA": "from-caller"},
        )

        assert result.returncode == 0
        assert result.stdout.strip() == "from-caller"

    def test_exec_env_timeout_raises(self, tmp_path, monkeypatch):
        """A child that exceeds the timeout is reported as EncryptionBackendError."""
        env_file = tmp_path / ".env"
        env_file.write_text('KEY="ENC[AES256_GCM,data:abc]"', encoding="utf-8")

        backend = SOPSEncryptionBackend()
        monkeypatch.setattr(backend, "is_installed", lambda: True)
        monkeypatch.setattr(
            backend,
            "_run",
            lambda args, env=None, cwd=None: MagicMock(
                returncode=0, stderr="", stdout="KEY=secretval\n"
            ),
        )

        def boom(*args, **kwargs):
            raise subprocess.TimeoutExpired(cmd=args[0] if args else "cmd", timeout=1)

        monkeypatch.setattr("envdrift.encryption.sops.subprocess.run", boom)

        with pytest.raises(EncryptionBackendError, match="timed out"):
            backend.exec_env(env_file, [sys.executable, "-c", "pass"], timeout=1)

    def test_encrypt_includes_key_options(self, tmp_path, monkeypatch):
        """Encrypt should include provided key options in SOPS args."""
        env_file = tmp_path / ".env"
        env_file.write_text("KEY=value")

        backend = SOPSEncryptionBackend()
        monkeypatch.setattr(backend, "is_installed", lambda: True)

        captured = {}

        def fake_run(args, env=None, cwd=None):
            captured["args"] = args
            return MagicMock(returncode=0, stderr="", stdout="")

        monkeypatch.setattr(backend, "_run", fake_run)

        backend.encrypt(
            env_file,
            age_recipients="age1example",
            kms_arn="arn:aws:kms:us-east-1:123:key/abc",
            gcp_kms="projects/p/locations/l/keyRings/r/cryptoKeys/k",
            azure_kv="https://vault.vault.azure.net/keys/key",
        )

        args = captured["args"]
        assert "--age" in args
        assert "--kms" in args
        assert "--gcp-kms" in args
        assert "--azure-kv" in args


class TestEncryptionResult:
    """Tests for EncryptionResult dataclass."""

    def test_success_result(self):
        """Test successful result."""
        result = EncryptionResult(
            success=True,
            message="Encrypted file.env",
            file_path=Path(".env"),
        )
        assert result.success is True
        assert "Encrypted" in result.message
        assert result.file_path == Path(".env")

    def test_failure_result(self):
        """Test failure result."""
        result = EncryptionResult(
            success=False,
            message="File not found",
        )
        assert result.success is False
        assert result.file_path is None


class TestEncryptionStatus:
    """Tests for EncryptionStatus enum."""

    def test_encrypted_value(self):
        """Test encrypted status value."""
        assert EncryptionStatus.ENCRYPTED.value == "encrypted"

    def test_plaintext_value(self):
        """Test plaintext status value."""
        assert EncryptionStatus.PLAINTEXT.value == "plaintext"

    def test_empty_value(self):
        """Test empty status value."""
        assert EncryptionStatus.EMPTY.value == "empty"


class TestEncryptionExceptions:
    """Tests for encryption exception classes."""

    def test_encryption_backend_error(self):
        """Test EncryptionBackendError is an Exception."""
        err = EncryptionBackendError("encryption failed")
        assert isinstance(err, Exception)
        assert str(err) == "encryption failed"

    def test_encryption_not_found_error(self):
        """Test EncryptionNotFoundError is an EncryptionBackendError."""
        err = EncryptionNotFoundError("tool not found")
        assert isinstance(err, EncryptionBackendError)
        assert str(err) == "tool not found"
