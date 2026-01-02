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

    def test_exec_env_builds_command(self, tmp_path, monkeypatch):
        """exec_env should build SOPS exec-env arguments."""
        env_file = tmp_path / ".env"
        env_file.write_text('KEY="ENC[AES256_GCM,data:abc]"')

        backend = SOPSEncryptionBackend()
        monkeypatch.setattr(backend, "is_installed", lambda: True)

        captured = {}

        def fake_run(args, env=None, cwd=None):
            captured["args"] = args
            return MagicMock(returncode=0, stderr="", stdout="")

        monkeypatch.setattr(backend, "_run", fake_run)

        result = backend.exec_env(env_file, ["echo", "ok"])
        assert result.returncode == 0
        assert captured["args"][:4] == ["exec-env", "--input-type", "dotenv", str(env_file)]

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
