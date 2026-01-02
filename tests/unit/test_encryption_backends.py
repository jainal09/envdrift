"""Tests for encryption backends (dotenvx and SOPS)."""

from __future__ import annotations

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

    @patch("envdrift.integrations.dotenvx.DotenvxWrapper")
    def test_encrypt_success(self, mock_wrapper_class, tmp_path):
        """Test successful encryption."""
        mock_wrapper = MagicMock()
        mock_wrapper.is_installed.return_value = True
        mock_wrapper_class.return_value = mock_wrapper

        env_file = tmp_path / ".env"
        env_file.write_text("KEY=value")

        backend = DotenvxEncryptionBackend()
        result = backend.encrypt(env_file)

        assert result.success is True
        assert "Encrypted" in result.message
        mock_wrapper.encrypt.assert_called_once()

    def test_encrypt_file_not_found(self, tmp_path):
        """Test encrypt with nonexistent file."""
        backend = DotenvxEncryptionBackend()
        result = backend.encrypt(tmp_path / "nonexistent")

        assert result.success is False
        assert "not found" in result.message

    @patch("envdrift.integrations.dotenvx.DotenvxWrapper")
    def test_decrypt_success(self, mock_wrapper_class, tmp_path):
        """Test successful decryption."""
        mock_wrapper = MagicMock()
        mock_wrapper.is_installed.return_value = True
        mock_wrapper_class.return_value = mock_wrapper

        env_file = tmp_path / ".env"
        env_file.write_text("KEY=encrypted:abc")

        backend = DotenvxEncryptionBackend()
        result = backend.decrypt(env_file)

        assert result.success is True
        assert "Decrypted" in result.message

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
        """Test has_encrypted_header with YAML sops: marker."""
        backend = SOPSEncryptionBackend()
        content = "key: value\nsops:\n  version: 3.8.1"
        assert backend.has_encrypted_header(content) is True

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
    def test_is_installed_false(self, mock_which):
        """Test is_installed when SOPS is not found."""
        mock_which.return_value = None
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
    def test_get_version_not_installed(self, mock_which):
        """Test get_version when SOPS not installed."""
        mock_which.return_value = None

        backend = SOPSEncryptionBackend()
        version = backend.get_version()

        assert version is None

    def test_encrypt_file_not_found(self, tmp_path):
        """Test encrypt with nonexistent file."""
        backend = SOPSEncryptionBackend()
        result = backend.encrypt(tmp_path / "nonexistent")

        assert result.success is False
        assert "not found" in result.message

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

    @patch("shutil.which")
    def test_encrypt_not_installed(self, mock_which, tmp_path):
        """Test encrypt raises when SOPS not installed."""
        mock_which.return_value = None

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
