"""Tests for envdrift.integrations.dotenvx module."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from envdrift.integrations.dotenvx import (
    DOTENVX_VERSION,
    DOWNLOAD_URLS,
    DotenvxError,
    DotenvxInstaller,
    DotenvxInstallError,
    DotenvxNotFoundError,
    DotenvxWrapper,
    _get_dotenvx_version,
    _get_download_url_templates,
    _load_constants,
    get_dotenvx_path,
    get_platform_info,
    get_venv_bin_dir,
)


class TestExceptions:
    """Tests for dotenvx exception classes."""

    def test_dotenvx_not_found_error(self):
        """Test DotenvxNotFoundError is an Exception."""
        err = DotenvxNotFoundError("binary not found")
        assert isinstance(err, Exception)
        assert str(err) == "binary not found"

    def test_dotenvx_error(self):
        """Test DotenvxError is an Exception."""
        err = DotenvxError("command failed")
        assert isinstance(err, Exception)
        assert str(err) == "command failed"

    def test_dotenvx_install_error(self):
        """Test DotenvxInstallError is an Exception."""
        err = DotenvxInstallError("install failed")
        assert isinstance(err, Exception)
        assert str(err) == "install failed"


class TestLoadConstants:
    """Tests for constants loading functions."""

    def test_load_constants_returns_dict(self):
        """Test _load_constants returns a dictionary."""
        result = _load_constants()
        assert isinstance(result, dict)

    def test_get_dotenvx_version(self):
        """Test _get_dotenvx_version returns version string."""
        version = _get_dotenvx_version()
        assert isinstance(version, str)
        assert version == DOTENVX_VERSION

    def test_get_download_url_templates(self):
        """Test _get_download_url_templates returns URL dict."""
        templates = _get_download_url_templates()
        assert isinstance(templates, dict)
        assert "darwin_amd64" in templates or "Darwin" in str(templates)


class TestGetPlatformInfo:
    """Tests for get_platform_info function."""

    def test_returns_tuple(self):
        """Test get_platform_info returns a tuple."""
        result = get_platform_info()
        assert isinstance(result, tuple)
        assert len(result) == 2

    @patch("platform.system")
    @patch("platform.machine")
    def test_darwin_arm64(self, mock_machine, mock_system):
        """Test Darwin arm64 normalization."""
        mock_system.return_value = "Darwin"
        mock_machine.return_value = "arm64"

        system, machine = get_platform_info()
        assert system == "Darwin"
        assert machine == "arm64"

    @patch("platform.system")
    @patch("platform.machine")
    def test_linux_aarch64(self, mock_machine, mock_system):
        """Test Linux aarch64 normalization."""
        mock_system.return_value = "Linux"
        mock_machine.return_value = "aarch64"

        system, machine = get_platform_info()
        assert system == "Linux"
        assert machine == "aarch64"

    @patch("platform.system")
    @patch("platform.machine")
    def test_windows_amd64(self, mock_machine, mock_system):
        """Test Windows AMD64 normalization."""
        mock_system.return_value = "Windows"
        mock_machine.return_value = "AMD64"

        system, machine = get_platform_info()
        assert system == "Windows"
        assert machine == "AMD64"

    @patch("platform.system")
    @patch("platform.machine")
    def test_linux_x86_64_unchanged(self, mock_machine, mock_system):
        """Test x86_64 is unchanged on Linux."""
        mock_system.return_value = "Linux"
        mock_machine.return_value = "x86_64"

        system, machine = get_platform_info()
        assert system == "Linux"
        assert machine == "x86_64"


class TestGetVenvBinDir:
    """Tests for get_venv_bin_dir function."""

    def test_uses_virtual_env_var(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Test uses VIRTUAL_ENV environment variable."""
        venv_path = tmp_path / ".venv"
        venv_path.mkdir()
        monkeypatch.setenv("VIRTUAL_ENV", str(venv_path))

        with patch("platform.system", return_value="Linux"):
            result = get_venv_bin_dir()
            assert result == venv_path / "bin"

    def test_windows_returns_scripts(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Test returns Scripts dir on Windows."""
        venv_path = tmp_path / ".venv"
        venv_path.mkdir()
        monkeypatch.setenv("VIRTUAL_ENV", str(venv_path))

        with patch("platform.system", return_value="Windows"):
            result = get_venv_bin_dir()
            assert result == venv_path / "Scripts"

    def test_finds_venv_in_cwd(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Test finds .venv in current working directory."""
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.chdir(tmp_path)

        venv_path = tmp_path / ".venv"
        venv_path.mkdir()

        # Clear sys.path venv entries
        with patch("sys.path", []), patch("platform.system", return_value="Linux"):
            result = get_venv_bin_dir()
            assert result == venv_path / "bin"

    def test_raises_when_no_venv(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Test raises RuntimeError when no venv found."""
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.chdir(tmp_path)

        with patch("sys.path", []):
            with pytest.raises(RuntimeError) as exc_info:
                get_venv_bin_dir()
            assert "virtual environment" in str(exc_info.value)


class TestGetDotenvxPath:
    """Tests for get_dotenvx_path function."""

    def test_returns_binary_path(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Test returns path to dotenvx binary."""
        venv_path = tmp_path / ".venv"
        venv_path.mkdir()
        monkeypatch.setenv("VIRTUAL_ENV", str(venv_path))

        with patch("platform.system", return_value="Linux"):
            result = get_dotenvx_path()
            assert result.name == "dotenvx"
            assert result.parent.name == "bin"

    def test_windows_exe_extension(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Test returns .exe extension on Windows."""
        venv_path = tmp_path / ".venv"
        venv_path.mkdir()
        monkeypatch.setenv("VIRTUAL_ENV", str(venv_path))

        with patch("platform.system", return_value="Windows"):
            result = get_dotenvx_path()
            assert result.name == "dotenvx.exe"


class TestDotenvxInstaller:
    """Tests for DotenvxInstaller class."""

    def test_default_version(self):
        """Test installer uses default version."""
        installer = DotenvxInstaller()
        assert installer.version == DOTENVX_VERSION

    def test_custom_version(self):
        """Test installer accepts custom version."""
        installer = DotenvxInstaller(version="0.50.0")
        assert installer.version == "0.50.0"

    def test_progress_callback(self):
        """Test progress callback is called."""
        messages = []
        installer = DotenvxInstaller(progress_callback=messages.append)
        installer.progress("test message")
        assert "test message" in messages

    @patch("platform.system", return_value="Darwin")
    @patch("platform.machine", return_value="arm64")
    def test_get_download_url_darwin_arm64(self, mock_machine, mock_system):
        """Test get_download_url for Darwin arm64."""
        installer = DotenvxInstaller()
        url = installer.get_download_url()
        # URL template contains {version} placeholder or actual version
        assert "darwin" in url.lower() or "macos" in url.lower()
        assert "arm64" in url.lower()

    @patch("platform.system", return_value="Linux")
    @patch("platform.machine", return_value="x86_64")
    def test_get_download_url_linux_x86_64(self, mock_machine, mock_system):
        """Test get_download_url for Linux x86_64."""
        installer = DotenvxInstaller()
        url = installer.get_download_url()
        assert "linux" in url.lower()
        assert "amd64" in url.lower() or "x86_64" in url.lower()

    @patch("platform.system", return_value="FreeBSD")
    @patch("platform.machine", return_value="x86_64")
    def test_unsupported_platform_raises(self, mock_machine, mock_system):
        """Test unsupported platform raises error."""
        installer = DotenvxInstaller()
        with pytest.raises(DotenvxInstallError) as exc_info:
            installer.get_download_url()
        assert "Unsupported platform" in str(exc_info.value)


class TestDownloadUrls:
    """Tests for DOWNLOAD_URLS constant."""

    def test_has_darwin_x86_64(self):
        """Test Darwin x86_64 URL exists."""
        assert ("Darwin", "x86_64") in DOWNLOAD_URLS

    def test_has_darwin_arm64(self):
        """Test Darwin arm64 URL exists."""
        assert ("Darwin", "arm64") in DOWNLOAD_URLS

    def test_has_linux_x86_64(self):
        """Test Linux x86_64 URL exists."""
        assert ("Linux", "x86_64") in DOWNLOAD_URLS

    def test_has_linux_aarch64(self):
        """Test Linux aarch64 URL exists."""
        assert ("Linux", "aarch64") in DOWNLOAD_URLS

    def test_has_windows_amd64(self):
        """Test Windows AMD64 URL exists."""
        assert ("Windows", "AMD64") in DOWNLOAD_URLS


class TestDotenvxInstallerExtended:
    """Extended tests for DotenvxInstaller class."""

    @patch("envdrift.integrations.dotenvx.urllib.request.urlretrieve")
    @patch("envdrift.integrations.dotenvx.get_dotenvx_path")
    @patch("platform.system", return_value="Linux")
    @patch("platform.machine", return_value="x86_64")
    def test_download_and_extract_tar_gz(
        self, mock_machine, mock_system, mock_path, mock_urlretrieve, tmp_path
    ):
        """Test download_and_extract with tar.gz archive."""
        target = tmp_path / "dotenvx"
        mock_path.return_value = target

        # Create a mock tarfile
        import io
        import tarfile

        tar_path = tmp_path / "dotenvx.tar.gz"

        # Create tar.gz with dotenvx binary
        with tarfile.open(tar_path, "w:gz") as tar:
            # Add a fake dotenvx binary
            data = b"#!/bin/bash\necho 'mock dotenvx'"
            tarinfo = tarfile.TarInfo(name="dotenvx")
            tarinfo.size = len(data)
            tar.addfile(tarinfo, io.BytesIO(data))

        # Mock urlretrieve to copy our test tar
        def mock_download(_url, path):
            import shutil

            shutil.copy(tar_path, path)

        mock_urlretrieve.side_effect = mock_download

        installer = DotenvxInstaller()
        installer.download_and_extract(target)

        assert target.exists()

    @patch("envdrift.integrations.dotenvx.urllib.request.urlretrieve")
    @patch("envdrift.integrations.dotenvx.get_dotenvx_path")
    @patch("platform.system", return_value="Windows")
    @patch("platform.machine", return_value="AMD64")
    def test_download_and_extract_zip(
        self, mock_machine, mock_system, mock_path, mock_urlretrieve, tmp_path
    ):
        """Test download_and_extract with zip archive."""
        target = tmp_path / "dotenvx.exe"
        mock_path.return_value = target

        # Create a mock zip file
        import zipfile

        zip_path = tmp_path / "dotenvx.zip"

        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("dotenvx.exe", b"mock dotenvx binary")

        # Mock urlretrieve to copy our test zip
        def mock_download(_url, path):
            import shutil

            shutil.copy(zip_path, path)

        mock_urlretrieve.side_effect = mock_download

        installer = DotenvxInstaller()
        installer.download_and_extract(target)

        assert target.exists()

    @patch("envdrift.integrations.dotenvx.urllib.request.urlretrieve")
    @patch("platform.system", return_value="Linux")
    @patch("platform.machine", return_value="x86_64")
    def test_download_failed(self, mock_machine, mock_system, mock_urlretrieve, tmp_path):
        """Test download_and_extract handles download failure."""
        mock_urlretrieve.side_effect = Exception("Network error")

        installer = DotenvxInstaller()

        with pytest.raises(DotenvxInstallError) as exc_info:
            installer.download_and_extract(tmp_path / "dotenvx")

        assert "Download failed" in str(exc_info.value)

    @patch("envdrift.integrations.dotenvx.urllib.request.urlretrieve")
    @patch("platform.system", return_value="Linux")
    @patch("platform.machine", return_value="x86_64")
    def test_unknown_archive_format(self, mock_machine, mock_system, mock_urlretrieve, tmp_path):
        """Test download_and_extract raises for unknown archive format."""
        # Mock URL to return unknown format
        with patch.object(
            DotenvxInstaller, "get_download_url", return_value="https://example.com/dotenvx.unknown"
        ):
            mock_urlretrieve.return_value = None  # Success

            installer = DotenvxInstaller()

            with pytest.raises(DotenvxInstallError) as exc_info:
                installer.download_and_extract(tmp_path / "dotenvx")

            assert "Unknown archive format" in str(exc_info.value)

    @patch("envdrift.integrations.dotenvx.get_dotenvx_path")
    @patch("subprocess.run")
    def test_install_skips_when_version_matches(self, mock_run, mock_path, tmp_path):
        """Test install skips download when version matches."""
        target = tmp_path / "dotenvx"
        target.touch()
        mock_path.return_value = target

        mock_run.return_value = MagicMock(stdout=f"dotenvx v{DOTENVX_VERSION}")

        messages = []
        installer = DotenvxInstaller(progress_callback=messages.append)
        result = installer.install()

        assert result == target
        assert any("already installed" in msg for msg in messages)

    @patch("envdrift.integrations.dotenvx.get_dotenvx_path")
    @patch("subprocess.run")
    def test_install_force_reinstalls(self, mock_run, mock_path, tmp_path):
        """Test install force=True reinstalls."""
        target = tmp_path / "dotenvx"
        target.touch()
        mock_path.return_value = target

        mock_run.return_value = MagicMock(stdout=f"dotenvx v{DOTENVX_VERSION}")

        installer = DotenvxInstaller()

        with patch.object(installer, "download_and_extract") as mock_download:
            installer.install(force=True)
            mock_download.assert_called_once_with(target)


class TestDotenvxWrapper:
    """Tests for DotenvxWrapper class."""

    def test_init_defaults(self):
        """Test DotenvxWrapper default values."""
        wrapper = DotenvxWrapper()
        assert wrapper.auto_install is True
        assert wrapper.version == DOTENVX_VERSION
        assert wrapper._binary_path is None

    def test_init_custom_values(self):
        """Test DotenvxWrapper with custom values."""
        wrapper = DotenvxWrapper(auto_install=False, version="0.50.0")
        assert wrapper.auto_install is False
        assert wrapper.version == "0.50.0"

    @patch("envdrift.integrations.dotenvx.get_dotenvx_path")
    def test_find_binary_from_venv(self, mock_path, tmp_path):
        """Test _find_binary finds binary in venv."""
        binary_path = tmp_path / "dotenvx"
        binary_path.touch()
        mock_path.return_value = binary_path

        wrapper = DotenvxWrapper()
        result = wrapper._find_binary()

        assert result == binary_path
        assert wrapper._binary_path == binary_path

    @patch("envdrift.integrations.dotenvx.get_dotenvx_path")
    def test_find_binary_cached(self, mock_path, tmp_path):
        """Test _find_binary uses cached path."""
        binary_path = tmp_path / "dotenvx"
        binary_path.touch()

        wrapper = DotenvxWrapper()
        wrapper._binary_path = binary_path

        result = wrapper._find_binary()

        assert result == binary_path
        mock_path.assert_not_called()

    @patch("shutil.which")
    @patch("envdrift.integrations.dotenvx.get_dotenvx_path")
    def test_find_binary_from_system_path(self, mock_venv_path, mock_which, tmp_path):
        """Test _find_binary finds binary in system PATH."""
        mock_venv_path.side_effect = RuntimeError("No venv")

        system_path = tmp_path / "dotenvx"
        mock_which.return_value = str(system_path)

        wrapper = DotenvxWrapper()
        result = wrapper._find_binary()

        assert result == system_path

    @patch("shutil.which", return_value=None)
    @patch("envdrift.integrations.dotenvx.get_dotenvx_path")
    @patch("envdrift.integrations.dotenvx.DotenvxInstaller")
    def test_find_binary_auto_installs(
        self, mock_installer_class, mock_venv_path, mock_which, tmp_path
    ):
        """Test _find_binary auto-installs when enabled."""
        mock_venv_path.return_value = tmp_path / "not_exists"

        installed_path = tmp_path / "installed_dotenvx"
        mock_installer = MagicMock()
        mock_installer.install.return_value = installed_path
        mock_installer_class.return_value = mock_installer

        wrapper = DotenvxWrapper(auto_install=True)
        result = wrapper._find_binary()

        assert result == installed_path
        mock_installer_class.assert_called_once_with(version=DOTENVX_VERSION)

    @patch("shutil.which", return_value=None)
    @patch("envdrift.integrations.dotenvx.get_dotenvx_path")
    def test_find_binary_raises_when_not_found_and_no_auto_install(
        self, mock_venv_path, mock_which, tmp_path
    ):
        """Test _find_binary raises when binary not found and auto_install=False."""
        mock_venv_path.return_value = tmp_path / "not_exists"

        wrapper = DotenvxWrapper(auto_install=False)

        with pytest.raises(DotenvxNotFoundError) as exc_info:
            wrapper._find_binary()

        assert "dotenvx not found" in str(exc_info.value)

    @patch("shutil.which", return_value=None)
    @patch("envdrift.integrations.dotenvx.get_dotenvx_path")
    @patch("envdrift.integrations.dotenvx.DotenvxInstaller")
    def test_find_binary_raises_when_auto_install_fails(
        self, mock_installer_class, mock_venv_path, mock_which, tmp_path
    ):
        """Test _find_binary raises when auto-install fails."""
        mock_venv_path.return_value = tmp_path / "not_exists"

        mock_installer = MagicMock()
        mock_installer.install.side_effect = DotenvxInstallError("Install failed")
        mock_installer_class.return_value = mock_installer

        wrapper = DotenvxWrapper(auto_install=True)

        with pytest.raises(DotenvxNotFoundError) as exc_info:
            wrapper._find_binary()

        assert "auto-install failed" in str(exc_info.value)

    @patch("envdrift.integrations.dotenvx.get_dotenvx_path")
    def test_binary_path_property(self, mock_path, tmp_path):
        """Test binary_path property calls _find_binary."""
        binary_path = tmp_path / "dotenvx"
        binary_path.touch()
        mock_path.return_value = binary_path

        wrapper = DotenvxWrapper()
        result = wrapper.binary_path

        assert result == binary_path

    @patch("envdrift.integrations.dotenvx.get_dotenvx_path")
    def test_is_installed_true(self, mock_path, tmp_path):
        """Test is_installed returns True when binary exists."""
        binary_path = tmp_path / "dotenvx"
        binary_path.touch()
        mock_path.return_value = binary_path

        wrapper = DotenvxWrapper()
        assert wrapper.is_installed() is True

    @patch("shutil.which", return_value=None)
    @patch("envdrift.integrations.dotenvx.get_dotenvx_path")
    def test_is_installed_false(self, mock_venv_path, mock_which, tmp_path):
        """Test is_installed returns False when binary not found."""
        mock_venv_path.return_value = tmp_path / "not_exists"

        wrapper = DotenvxWrapper(auto_install=False)
        assert wrapper.is_installed() is False

    @patch("subprocess.run")
    @patch("envdrift.integrations.dotenvx.get_dotenvx_path")
    def test_get_version(self, mock_path, mock_run, tmp_path):
        """Test get_version returns version string."""
        binary_path = tmp_path / "dotenvx"
        binary_path.touch()
        mock_path.return_value = binary_path

        mock_run.return_value = MagicMock(returncode=0, stdout="1.2.3\n", stderr="")

        wrapper = DotenvxWrapper()
        result = wrapper.get_version()

        assert result == "1.2.3"

    @patch("subprocess.run")
    @patch("envdrift.integrations.dotenvx.get_dotenvx_path")
    def test_encrypt(self, mock_path, mock_run, tmp_path):
        """Test encrypt method."""
        binary_path = tmp_path / "dotenvx"
        binary_path.touch()
        mock_path.return_value = binary_path

        env_file = tmp_path / ".env"
        env_file.write_text("KEY=value")

        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        wrapper = DotenvxWrapper()
        wrapper.encrypt(env_file)

        mock_run.assert_called()
        call_args = mock_run.call_args[0][0]
        assert "encrypt" in call_args
        assert "-f" in call_args

    @patch("envdrift.integrations.dotenvx.get_dotenvx_path")
    def test_encrypt_file_not_found(self, mock_path, tmp_path):
        """Test encrypt raises when file not found."""
        binary_path = tmp_path / "dotenvx"
        binary_path.touch()
        mock_path.return_value = binary_path

        wrapper = DotenvxWrapper()

        with pytest.raises(DotenvxError) as exc_info:
            wrapper.encrypt(tmp_path / "nonexistent.env")

        assert "File not found" in str(exc_info.value)

    @patch("subprocess.run")
    @patch("envdrift.integrations.dotenvx.get_dotenvx_path")
    def test_decrypt(self, mock_path, mock_run, tmp_path):
        """Test decrypt method."""
        binary_path = tmp_path / "dotenvx"
        binary_path.touch()
        mock_path.return_value = binary_path

        env_file = tmp_path / ".env"
        env_file.write_text("ENCRYPTED_KEY=xyz")

        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        wrapper = DotenvxWrapper()
        wrapper.decrypt(env_file)

        mock_run.assert_called()
        call_args = mock_run.call_args[0][0]
        assert "decrypt" in call_args

    @patch("envdrift.integrations.dotenvx.get_dotenvx_path")
    def test_decrypt_file_not_found(self, mock_path, tmp_path):
        """Test decrypt raises when file not found."""
        binary_path = tmp_path / "dotenvx"
        binary_path.touch()
        mock_path.return_value = binary_path

        wrapper = DotenvxWrapper()

        with pytest.raises(DotenvxError) as exc_info:
            wrapper.decrypt(tmp_path / "nonexistent.env")

        assert "File not found" in str(exc_info.value)

    @patch("subprocess.run")
    @patch("envdrift.integrations.dotenvx.get_dotenvx_path")
    def test_run_command(self, mock_path, mock_run, tmp_path):
        """Test run method executes command with env file."""
        binary_path = tmp_path / "dotenvx"
        binary_path.touch()
        mock_path.return_value = binary_path

        env_file = tmp_path / ".env"

        mock_run.return_value = MagicMock(returncode=0, stdout="output", stderr="")

        wrapper = DotenvxWrapper()
        result = wrapper.run(env_file, ["python", "script.py"])

        assert result.returncode == 0
        call_args = mock_run.call_args[0][0]
        assert "run" in call_args
        assert "--" in call_args

    @patch("subprocess.run")
    @patch("envdrift.integrations.dotenvx.get_dotenvx_path")
    def test_get_key(self, mock_path, mock_run, tmp_path):
        """Test get method retrieves key value."""
        binary_path = tmp_path / "dotenvx"
        binary_path.touch()
        mock_path.return_value = binary_path

        env_file = tmp_path / ".env"

        mock_run.return_value = MagicMock(returncode=0, stdout="myvalue\n", stderr="")

        wrapper = DotenvxWrapper()
        result = wrapper.get(env_file, "MY_KEY")

        assert result == "myvalue"
        call_args = mock_run.call_args[0][0]
        assert "get" in call_args
        assert "MY_KEY" in call_args

    @patch("subprocess.run")
    @patch("envdrift.integrations.dotenvx.get_dotenvx_path")
    def test_get_key_not_found(self, mock_path, mock_run, tmp_path):
        """Test get returns None when key not found."""
        binary_path = tmp_path / "dotenvx"
        binary_path.touch()
        mock_path.return_value = binary_path

        env_file = tmp_path / ".env"

        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="not found")

        wrapper = DotenvxWrapper()
        result = wrapper.get(env_file, "NONEXISTENT_KEY")

        assert result is None

    @patch("subprocess.run")
    @patch("envdrift.integrations.dotenvx.get_dotenvx_path")
    def test_set_key(self, mock_path, mock_run, tmp_path):
        """Test set method sets key value."""
        binary_path = tmp_path / "dotenvx"
        binary_path.touch()
        mock_path.return_value = binary_path

        env_file = tmp_path / ".env"

        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        wrapper = DotenvxWrapper()
        wrapper.set(env_file, "NEW_KEY", "new_value")

        call_args = mock_run.call_args[0][0]
        assert "set" in call_args
        assert "NEW_KEY" in call_args
        assert "new_value" in call_args

    @patch("subprocess.run")
    @patch("envdrift.integrations.dotenvx.get_dotenvx_path")
    def test_run_command_failure(self, mock_path, mock_run, tmp_path):
        """Test _run raises on command failure when check=True."""
        binary_path = tmp_path / "dotenvx"
        binary_path.touch()
        mock_path.return_value = binary_path

        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error message")

        wrapper = DotenvxWrapper()

        with pytest.raises(DotenvxError) as exc_info:
            wrapper._run(["invalid"], check=True)

        assert "dotenvx command failed" in str(exc_info.value)

    @patch("subprocess.run")
    @patch("envdrift.integrations.dotenvx.get_dotenvx_path")
    def test_run_timeout(self, mock_path, mock_run, tmp_path):
        """Test _run raises on timeout."""
        binary_path = tmp_path / "dotenvx"
        binary_path.touch()
        mock_path.return_value = binary_path

        mock_run.side_effect = subprocess.TimeoutExpired(cmd="dotenvx", timeout=120)

        wrapper = DotenvxWrapper()

        with pytest.raises(DotenvxError) as exc_info:
            wrapper._run(["slow-command"])

        assert "timed out" in str(exc_info.value)

    @patch("subprocess.run")
    @patch("envdrift.integrations.dotenvx.get_dotenvx_path")
    def test_run_file_not_found(self, mock_path, mock_run, tmp_path):
        """Test _run raises on binary not found."""
        binary_path = tmp_path / "dotenvx"
        binary_path.touch()
        mock_path.return_value = binary_path

        mock_run.side_effect = FileNotFoundError("binary not found")

        wrapper = DotenvxWrapper()

        with pytest.raises(DotenvxNotFoundError):
            wrapper._run(["command"])

    def test_install_instructions(self):
        """Test install_instructions returns formatted string."""
        instructions = DotenvxWrapper.install_instructions()

        assert "dotenvx is not installed" in instructions
        assert "Option 1" in instructions
        assert "Option 2" in instructions
        assert "Option 3" in instructions
        assert DOTENVX_VERSION in instructions


class TestTarGzExtraction:
    """Tests for _extract_tar_gz method."""

    def test_extract_tar_gz_path_traversal_attack(self, tmp_path):
        """Test _extract_tar_gz prevents path traversal attacks."""
        import io
        import tarfile

        # Create a malicious tar with path traversal
        tar_path = tmp_path / "malicious.tar.gz"

        with tarfile.open(tar_path, "w:gz") as tar:
            # Add a file with path traversal
            data = b"malicious content"
            tarinfo = tarfile.TarInfo(name="../../../etc/passwd")
            tarinfo.size = len(data)
            tar.addfile(tarinfo, io.BytesIO(data))

        installer = DotenvxInstaller()
        target_dir = tmp_path / "extract"
        target_dir.mkdir()

        with pytest.raises(DotenvxInstallError) as exc_info:
            installer._extract_tar_gz(tar_path, target_dir)

        assert "Unsafe path" in str(exc_info.value)


class TestZipExtraction:
    """Tests for _extract_zip method."""

    def test_extract_zip_path_traversal_attack(self, tmp_path):
        """Test _extract_zip prevents path traversal attacks."""
        import zipfile

        # Create a malicious zip with path traversal
        zip_path = tmp_path / "malicious.zip"

        with zipfile.ZipFile(zip_path, "w") as zf:
            # Add a file with path traversal
            zf.writestr("../../../etc/passwd", "malicious content")

        installer = DotenvxInstaller()
        target_dir = tmp_path / "extract"
        target_dir.mkdir()

        with pytest.raises(DotenvxInstallError) as exc_info:
            installer._extract_zip(zip_path, target_dir)

        assert "Unsafe path" in str(exc_info.value)
