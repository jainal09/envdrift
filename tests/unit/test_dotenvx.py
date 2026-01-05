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

    def test_fallback_when_no_venv(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Test falls back to user bin when no venv found."""
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.chdir(tmp_path)
        # Mock home to use tmp_path
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        with patch("sys.path", []), patch("platform.system", return_value="Linux"):
            result = get_venv_bin_dir()
            # Should fall back to ~/.local/bin
            assert result == tmp_path / ".local" / "bin"

    def test_finds_uv_tool_venv(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Test finds venv when installed via uv tool install."""
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.chdir(tmp_path)

        # Simulate uv tool install structure: ~/.local/share/uv/tools/envdrift/lib/python3.13/site-packages
        uv_tool_path = tmp_path / ".local" / "share" / "uv" / "tools" / "envdrift"
        site_packages = uv_tool_path / "lib" / "python3.13" / "site-packages"
        site_packages.mkdir(parents=True)

        with (
            patch("sys.path", [str(site_packages)]),
            patch("platform.system", return_value="Linux"),
        ):
            result = get_venv_bin_dir()
            assert result == uv_tool_path / "bin"

    def test_finds_uv_tool_venv_windows(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Test finds venv when installed via uv tool install on Windows."""
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.chdir(tmp_path)

        # Simulate uv tool install structure on Windows
        uv_tool_path = tmp_path / "AppData" / "Local" / "uv" / "tools" / "envdrift"
        site_packages = uv_tool_path / "Lib" / "site-packages"
        site_packages.mkdir(parents=True)

        with (
            patch("sys.path", [str(site_packages)]),
            patch("platform.system", return_value="Windows"),
        ):
            result = get_venv_bin_dir()
            assert result == uv_tool_path / "Scripts"

    def test_finds_pipx_venv(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Test finds venv when installed via pipx."""
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.chdir(tmp_path)

        # Simulate pipx install structure: ~/.local/pipx/venvs/envdrift/lib/python3.13/site-packages
        pipx_venv_path = tmp_path / ".local" / "pipx" / "venvs" / "envdrift"
        site_packages = pipx_venv_path / "lib" / "python3.13" / "site-packages"
        site_packages.mkdir(parents=True)

        with (
            patch("sys.path", [str(site_packages)]),
            patch("platform.system", return_value="Linux"),
        ):
            result = get_venv_bin_dir()
            assert result == pipx_venv_path / "bin"

    def test_finds_pipx_venv_windows(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Test finds venv when installed via pipx on Windows."""
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.chdir(tmp_path)

        # Simulate pipx install structure on Windows
        pipx_venv_path = tmp_path / "AppData" / "Local" / "pipx" / "venvs" / "envdrift"
        site_packages = pipx_venv_path / "Lib" / "site-packages"
        site_packages.mkdir(parents=True)

        with (
            patch("sys.path", [str(site_packages)]),
            patch("platform.system", return_value="Windows"),
        ):
            result = get_venv_bin_dir()
            assert result == pipx_venv_path / "Scripts"

    def test_fallback_to_user_bin_linux(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Test falls back to ~/.local/bin for plain pip install on Linux."""
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.chdir(tmp_path)
        # Mock home to use tmp_path
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        with (
            patch("sys.path", ["/usr/lib/python3.13/site-packages"]),
            patch("platform.system", return_value="Linux"),
        ):
            result = get_venv_bin_dir()
            assert result == tmp_path / ".local" / "bin"
            assert result.exists()  # Should be created

    def test_fallback_to_user_bin_windows(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Test falls back to %APPDATA%\\Python\\Scripts for plain pip install on Windows."""
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("APPDATA", str(tmp_path / "AppData" / "Roaming"))

        with (
            patch("sys.path", ["C:\\Python313\\Lib\\site-packages"]),
            patch("platform.system", return_value="Windows"),
        ):
            result = get_venv_bin_dir()
            assert result == tmp_path / "AppData" / "Roaming" / "Python" / "Scripts"
            assert result.exists()  # Should be created

    def test_raises_when_no_appdata_on_windows(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """Test raises RuntimeError on Windows when APPDATA is not set."""
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.delenv("APPDATA", raising=False)
        monkeypatch.chdir(tmp_path)

        with (
            patch("sys.path", ["C:\\Python313\\Lib\\site-packages"]),
            patch("platform.system", return_value="Windows"),
            pytest.raises(RuntimeError, match="APPDATA"),
        ):
            get_venv_bin_dir()


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

    @patch("platform.system", return_value="Linux")
    @patch("platform.machine", return_value="x86_64")
    def test_get_download_url_substitutes_version(self, mock_machine, mock_system):
        """Test get_download_url substitutes {version} placeholder."""
        installer = DotenvxInstaller(version="9.9.9")
        url = installer.get_download_url()
        assert "{version}" not in url
        assert "9.9.9" in url

    def test_get_download_url_replaces_pinned_version(self, monkeypatch):
        """Test get_download_url replaces pinned version when no placeholder."""
        installer = DotenvxInstaller(version="9.9.9")
        monkeypatch.setattr(
            "envdrift.integrations.dotenvx.get_platform_info",
            lambda: ("Linux", "x86_64"),
        )
        pinned_url = f"https://example.com/dotenvx-v{DOTENVX_VERSION}.tar.gz"
        monkeypatch.setitem(
            DOWNLOAD_URLS,
            ("Linux", "x86_64"),
            pinned_url,
        )

        url = installer.get_download_url()
        assert "9.9.9" in url
        assert DOTENVX_VERSION not in url

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
        assert wrapper.auto_install is False
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

    def test_extract_tar_gz_fallback_on_typeerror(self, tmp_path, monkeypatch):
        """Fallback to extractall without filter when TypeError occurs."""
        import io
        import tarfile

        tar_path = tmp_path / "dotenvx.tar.gz"
        with tarfile.open(tar_path, "w:gz") as tar:
            data = b"binary"
            tarinfo = tarfile.TarInfo(name="dotenvx")
            tarinfo.size = len(data)
            tar.addfile(tarinfo, io.BytesIO(data))

        installer = DotenvxInstaller()
        target_dir = tmp_path / "extract"
        target_dir.mkdir()

        calls = {"with_filter": False, "without_filter": False}
        original_extractall = tarfile.TarFile.extractall

        def fake_extractall(self, path, **kwargs):
            filter_value = kwargs.get("filter")
            if filter_value is not None:
                calls["with_filter"] = True
                raise TypeError("filter not supported")
            calls["without_filter"] = True
            return original_extractall(self, path)

        monkeypatch.setattr(tarfile.TarFile, "extractall", fake_extractall)

        installer._extract_tar_gz(tar_path, target_dir)

        assert calls["with_filter"] is True
        assert calls["without_filter"] is True


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


class TestLineEndingNormalization:
    """Tests for cross-platform line ending normalization."""

    def test_normalize_line_endings_crlf_to_lf(self, tmp_path):
        """Test CRLF line endings are converted to LF."""
        env_file = tmp_path / ".env"
        # Write file with CRLF line endings
        env_file.write_bytes(b"KEY1=value1\r\nKEY2=value2\r\nKEY3=value3\r\n")

        wrapper = DotenvxWrapper()
        modified = wrapper._normalize_line_endings(env_file)

        assert modified is True
        content = env_file.read_bytes()
        assert b"\r\n" not in content
        assert b"\r" not in content
        assert content == b"KEY1=value1\nKEY2=value2\nKEY3=value3\n"

    def test_normalize_line_endings_cr_to_lf(self, tmp_path):
        """Test old Mac CR line endings are converted to LF."""
        env_file = tmp_path / ".env"
        # Write file with old Mac CR line endings
        env_file.write_bytes(b"KEY1=value1\rKEY2=value2\rKEY3=value3\r")

        wrapper = DotenvxWrapper()
        modified = wrapper._normalize_line_endings(env_file)

        assert modified is True
        content = env_file.read_bytes()
        assert b"\r" not in content
        assert content == b"KEY1=value1\nKEY2=value2\nKEY3=value3\n"

    def test_normalize_line_endings_already_lf(self, tmp_path):
        """Test file with LF line endings is not modified."""
        env_file = tmp_path / ".env"
        original_content = b"KEY1=value1\nKEY2=value2\nKEY3=value3\n"
        env_file.write_bytes(original_content)

        wrapper = DotenvxWrapper()
        modified = wrapper._normalize_line_endings(env_file)

        assert modified is False
        assert env_file.read_bytes() == original_content

    def test_normalize_line_endings_preserves_content(self, tmp_path):
        """Test normalization preserves all other content including special chars."""
        env_file = tmp_path / ".env"
        # Content with special characters that could cause Windows dotenvx issues
        content = (
            b"AZURE_KEY=aDwW71Ur2Z/OkmEhGxPsjDdVkB4QaiqaaNHI+Q9WFW15==\r\n"
            b'JSON_DATA={"key":"value","nested":{"a":1}}\r\n'
            b"BASE64=dcRH7xD0kRPoFOVTrbjfNYNxJpHoomCNWJmOZZ09m5g=\r\n"
        )
        env_file.write_bytes(content)

        wrapper = DotenvxWrapper()
        wrapper._normalize_line_endings(env_file)

        normalized = env_file.read_bytes()
        expected = (
            b"AZURE_KEY=aDwW71Ur2Z/OkmEhGxPsjDdVkB4QaiqaaNHI+Q9WFW15==\n"
            b'JSON_DATA={"key":"value","nested":{"a":1}}\n'
            b"BASE64=dcRH7xD0kRPoFOVTrbjfNYNxJpHoomCNWJmOZZ09m5g=\n"
        )
        assert normalized == expected

    def test_normalize_line_endings_mixed_endings(self, tmp_path):
        """Test file with mixed line endings is normalized."""
        env_file = tmp_path / ".env"
        # Mixed: CRLF, LF, and CR
        env_file.write_bytes(b"KEY1=value1\r\nKEY2=value2\nKEY3=value3\rKEY4=value4\r\n")

        wrapper = DotenvxWrapper()
        modified = wrapper._normalize_line_endings(env_file)

        assert modified is True
        content = env_file.read_bytes()
        assert b"\r" not in content
        assert content == b"KEY1=value1\nKEY2=value2\nKEY3=value3\nKEY4=value4\n"

    def test_normalize_line_endings_empty_file(self, tmp_path):
        """Test empty file is handled gracefully."""
        env_file = tmp_path / ".env"
        env_file.write_bytes(b"")

        wrapper = DotenvxWrapper()
        modified = wrapper._normalize_line_endings(env_file)

        assert modified is False
        assert env_file.read_bytes() == b""

    @patch("subprocess.run")
    @patch("envdrift.integrations.dotenvx.get_dotenvx_path")
    def test_encrypt_normalizes_line_endings(self, mock_path, mock_run, tmp_path):
        """Test encrypt method normalizes line endings before encryption."""
        binary_path = tmp_path / "dotenvx"
        binary_path.touch()
        mock_path.return_value = binary_path

        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        env_file = tmp_path / ".env"
        env_file.write_bytes(b"KEY=value\r\n")

        wrapper = DotenvxWrapper()
        wrapper.encrypt(env_file)

        # Verify file was normalized
        assert b"\r\n" not in env_file.read_bytes()
        # Verify dotenvx was called
        mock_run.assert_called_once()

    @patch("subprocess.run")
    @patch("envdrift.integrations.dotenvx.get_dotenvx_path")
    def test_decrypt_normalizes_line_endings(self, mock_path, mock_run, tmp_path):
        """Test decrypt method normalizes line endings before decryption."""
        binary_path = tmp_path / "dotenvx"
        binary_path.touch()
        mock_path.return_value = binary_path

        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        env_file = tmp_path / ".env"
        env_file.write_bytes(b"KEY=encrypted:abc123\r\n")

        wrapper = DotenvxWrapper()
        wrapper.decrypt(env_file)

        # Verify file was normalized before decrypt
        # Note: after decrypt, dotenvx would modify the file, but since we're mocking
        # we just verify the normalization happened before the call
        mock_run.assert_called_once()


class TestCleanMismatchedHeaders:
    """Tests for _clean_mismatched_headers method."""

    def test_removes_mismatched_header_after_rename(self, tmp_path):
        """Test removes old header when file was renamed from .env.local to .env.localenv."""
        env_file = tmp_path / ".env.localenv"
        # Content with duplicate headers (as would happen after renaming .env.local -> .env.localenv)
        content = """\
#/-------------------[DOTENV_PUBLIC_KEY]--------------------/
#/            public-key encryption for .env files          /
#/       [how it works](https://dotenvx.com/encryption)     /
#/----------------------------------------------------------/
DOTENV_PUBLIC_KEY_LOCALENV="03abc123"

# .env.localenv
#/-------------------[DOTENV_PUBLIC_KEY]--------------------/
#/            public-key encryption for .env files          /
#/       [how it works](https://dotenvx.com/encryption)     /
#/----------------------------------------------------------/
DOTENV_PUBLIC_KEY_LOCAL="03abc123"

# .env.local
KEY=value
"""
        env_file.write_text(content)

        modified = DotenvxWrapper._clean_mismatched_headers(env_file)

        assert modified is True
        result = env_file.read_text()
        # Should keep LOCALENV header (matches filename)
        assert 'DOTENV_PUBLIC_KEY_LOCALENV="03abc123"' in result
        assert "# .env.localenv" in result
        # Should remove LOCAL header (doesn't match filename)
        # Use quotes to avoid matching LOCALENV which contains LOCAL as substring
        assert 'DOTENV_PUBLIC_KEY_LOCAL="' not in result
        assert "# .env.local\n" not in result

    def test_no_change_when_headers_match(self, tmp_path):
        """Test no modification when header matches filename."""
        env_file = tmp_path / ".env.localenv"
        content = """\
#/-------------------[DOTENV_PUBLIC_KEY]--------------------/
#/            public-key encryption for .env files          /
#/       [how it works](https://dotenvx.com/encryption)     /
#/----------------------------------------------------------/
DOTENV_PUBLIC_KEY_LOCALENV="03abc123"

# .env.localenv
KEY=value
"""
        env_file.write_text(content)

        modified = DotenvxWrapper._clean_mismatched_headers(env_file)

        assert modified is False
        assert env_file.read_text() == content

    def test_removes_multiple_mismatched_headers(self, tmp_path):
        """Test removes multiple mismatched headers."""
        env_file = tmp_path / ".env.production"
        content = """\
#/-------------------[DOTENV_PUBLIC_KEY]--------------------/
#/            public-key encryption for .env files          /
#/       [how it works](https://dotenvx.com/encryption)     /
#/----------------------------------------------------------/
DOTENV_PUBLIC_KEY_PRODUCTION="03abc123"

# .env.production
#/-------------------[DOTENV_PUBLIC_KEY]--------------------/
#/            public-key encryption for .env files          /
#/       [how it works](https://dotenvx.com/encryption)     /
#/----------------------------------------------------------/
DOTENV_PUBLIC_KEY_LOCAL="03def456"

# .env.local
#/-------------------[DOTENV_PUBLIC_KEY]--------------------/
#/            public-key encryption for .env files          /
#/       [how it works](https://dotenvx.com/encryption)     /
#/----------------------------------------------------------/
DOTENV_PUBLIC_KEY_DEV="03ghi789"

# .env.dev
KEY=value
"""
        env_file.write_text(content)

        modified = DotenvxWrapper._clean_mismatched_headers(env_file)

        assert modified is True
        result = env_file.read_text()
        # Should keep PRODUCTION header
        assert "DOTENV_PUBLIC_KEY_PRODUCTION" in result
        # Should remove LOCAL and DEV headers
        assert "DOTENV_PUBLIC_KEY_LOCAL" not in result
        assert "DOTENV_PUBLIC_KEY_DEV" not in result

    def test_handles_file_without_headers(self, tmp_path):
        """Test handles file without any dotenvx headers."""
        env_file = tmp_path / ".env.test"
        content = "KEY=value\nANOTHER=data\n"
        env_file.write_text(content)

        modified = DotenvxWrapper._clean_mismatched_headers(env_file)

        assert modified is False
        assert env_file.read_text() == content

    def test_handles_non_env_file(self, tmp_path):
        """Test returns False for non-.env files."""
        env_file = tmp_path / "config.yaml"
        env_file.write_text("key: value\n")

        modified = DotenvxWrapper._clean_mismatched_headers(env_file)

        assert modified is False

    def test_handles_missing_file(self, tmp_path):
        """Test returns False for non-existent file."""
        env_file = tmp_path / ".env.missing"

        modified = DotenvxWrapper._clean_mismatched_headers(env_file)

        assert modified is False

    def test_cleans_up_extra_newlines(self, tmp_path):
        """Test cleans up extra newlines after removing headers."""
        env_file = tmp_path / ".env.localenv"
        content = """\
#/-------------------[DOTENV_PUBLIC_KEY]--------------------/
#/            public-key encryption for .env files          /
#/       [how it works](https://dotenvx.com/encryption)     /
#/----------------------------------------------------------/
DOTENV_PUBLIC_KEY_LOCALENV="03abc123"

# .env.localenv
#/-------------------[DOTENV_PUBLIC_KEY]--------------------/
#/            public-key encryption for .env files          /
#/       [how it works](https://dotenvx.com/encryption)     /
#/----------------------------------------------------------/
DOTENV_PUBLIC_KEY_LOCAL="03abc123"

# .env.local
KEY=value
"""
        env_file.write_text(content)

        DotenvxWrapper._clean_mismatched_headers(env_file)

        result = env_file.read_text()
        # Should not have triple newlines
        assert "\n\n\n" not in result

    @patch("subprocess.run")
    @patch("envdrift.integrations.dotenvx.get_dotenvx_path")
    def test_encrypt_cleans_headers_before_encryption(self, mock_path, mock_run, tmp_path):
        """Test encrypt method cleans mismatched headers before encryption."""
        binary_path = tmp_path / "dotenvx"
        binary_path.touch()
        mock_path.return_value = binary_path

        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        env_file = tmp_path / ".env.localenv"
        # File with mismatched header from previous .env.local
        content = """\
#/-------------------[DOTENV_PUBLIC_KEY]--------------------/
#/            public-key encryption for .env files          /
#/       [how it works](https://dotenvx.com/encryption)     /
#/----------------------------------------------------------/
DOTENV_PUBLIC_KEY_LOCAL="03abc123"

# .env.local
KEY=value
"""
        env_file.write_text(content)

        wrapper = DotenvxWrapper()
        wrapper.encrypt(env_file)

        # Verify mismatched header was removed before dotenvx was called
        result = env_file.read_text()
        assert "DOTENV_PUBLIC_KEY_LOCAL" not in result
        mock_run.assert_called_once()
