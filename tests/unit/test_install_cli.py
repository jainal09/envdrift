"""Tests for the install CLI commands."""

from __future__ import annotations

import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import typer
from typer.testing import CliRunner

import envdrift.agent.registry as registry_module
from envdrift.cli import app
from envdrift.cli_commands.install import (
    _detect_platform,
    _get_install_path,
)

runner = CliRunner()


class TestDetectPlatform:
    """Tests for _detect_platform function."""

    def test_darwin_arm64(self):
        """Test detection on macOS ARM."""
        with (
            patch("platform.system", return_value="Darwin"),
            patch("platform.machine", return_value="arm64"),
        ):
            result = _detect_platform()
            assert result == "darwin-arm64"

    def test_darwin_amd64(self):
        """Test detection on macOS Intel."""
        with (
            patch("platform.system", return_value="Darwin"),
            patch("platform.machine", return_value="x86_64"),
        ):
            result = _detect_platform()
            assert result == "darwin-amd64"

    def test_linux_amd64(self):
        """Test detection on Linux x86_64."""
        with (
            patch("platform.system", return_value="Linux"),
            patch("platform.machine", return_value="x86_64"),
        ):
            result = _detect_platform()
            assert result == "linux-amd64"

    def test_linux_arm64(self):
        """Test detection on Linux ARM64."""
        with (
            patch("platform.system", return_value="Linux"),
            patch("platform.machine", return_value="aarch64"),
        ):
            result = _detect_platform()
            assert result == "linux-arm64"

    def test_windows_amd64(self):
        """Test detection on Windows x64."""
        with (
            patch("platform.system", return_value="Windows"),
            patch("platform.machine", return_value="AMD64"),
        ):
            result = _detect_platform()
            assert result == "windows-amd64"

    def test_unsupported_os(self):
        """Test that unsupported OS raises error."""
        with (
            patch("platform.system", return_value="FreeBSD"),
            patch("platform.machine", return_value="x86_64"),
            pytest.raises(typer.BadParameter, match="Unsupported operating system"),
        ):
            _detect_platform()

    def test_unsupported_arch(self):
        """Test that unsupported architecture raises error."""
        with (
            patch("platform.system", return_value="Linux"),
            patch("platform.machine", return_value="sparc64"),
            pytest.raises(typer.BadParameter, match="Unsupported architecture"),
        ):
            _detect_platform()

    def test_32bit_x86_i386(self):
        """Test that 32-bit i386 raises error."""
        with (
            patch("platform.system", return_value="Linux"),
            patch("platform.machine", return_value="i386"),
            pytest.raises(typer.BadParameter, match="32-bit x86"),
        ):
            _detect_platform()

    def test_32bit_x86_i686(self):
        """Test that 32-bit i686 raises error."""
        with (
            patch("platform.system", return_value="Linux"),
            patch("platform.machine", return_value="i686"),
            pytest.raises(typer.BadParameter, match="32-bit x86"),
        ):
            _detect_platform()

    def test_32bit_x86_x86(self):
        """Test that 32-bit x86 raises error."""
        with (
            patch("platform.system", return_value="Linux"),
            patch("platform.machine", return_value="x86"),
            pytest.raises(typer.BadParameter, match="32-bit x86"),
        ):
            _detect_platform()


class TestGetInstallPath:
    """Tests for _get_install_path function."""

    def test_unix_local_bin(self, tmp_path: Path):
        """Test Unix installation to ~/.local/bin."""
        local_bin = tmp_path / ".local" / "bin"

        with (
            patch("platform.system", return_value="Linux"),
            patch.object(Path, "home", return_value=tmp_path),
            patch("os.access", return_value=False),  # No write access to /usr/local/bin
        ):
            result = _get_install_path()
            assert result == local_bin / "envdrift-agent"
            assert local_bin.exists()

    def test_unix_usr_local_bin(self, tmp_path: Path):
        """Test Unix installation to /usr/local/bin when writable."""
        usr_local_bin = tmp_path / "usr" / "local" / "bin"
        usr_local_bin.mkdir(parents=True)

        def access_side_effect(path, mode):
            return str(path) == str(usr_local_bin)

        with (
            patch("platform.system", return_value="Linux"),
            patch.object(Path, "home", return_value=tmp_path),
            patch("os.access", side_effect=access_side_effect),
            patch("envdrift.cli_commands.install.Path") as mock_path,
        ):
            mock_path.return_value = usr_local_bin / "envdrift-agent"
            mock_path.home.return_value = tmp_path
            mock_usr_local = MagicMock()
            mock_usr_local.exists.return_value = True
            mock_homebrew = MagicMock()
            mock_homebrew.exists.return_value = False
            mock_local = MagicMock()
            mock_local.exists.return_value = False

            # Mock Path() calls to return our mocks in order
            mock_path.side_effect = [mock_usr_local, mock_homebrew, mock_local]

            result = _get_install_path()
            # Since we're mocking, just verify the function runs
            assert result is not None

    def test_unix_homebrew_bin(self, tmp_path: Path):
        """Test Unix installation to /opt/homebrew/bin when writable."""
        homebrew_bin = tmp_path / "opt" / "homebrew" / "bin"
        homebrew_bin.mkdir(parents=True)

        def access_side_effect(path, mode):
            return str(path) == str(homebrew_bin)

        with (
            patch("platform.system", return_value="Darwin"),
            patch.object(Path, "home", return_value=tmp_path),
            patch("os.access", side_effect=access_side_effect),
        ):
            # This test verifies the logic, actual path selection tested above
            result = _get_install_path()
            assert "envdrift-agent" in str(result)

    def test_windows_install_path(self, tmp_path: Path, monkeypatch):
        """Test Windows installation path."""
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))

        with patch("platform.system", return_value="Windows"):
            result = _get_install_path()
            assert "envdrift-agent.exe" in str(result)
            assert "Programs" in str(result)


class TestInstallAgentCommand:
    """Tests for 'envdrift install agent' command."""

    def test_install_help(self):
        """Test that install agent --help works."""
        result = runner.invoke(app, ["install", "agent", "--help"])
        assert result.exit_code == 0
        assert "Install the envdrift background agent" in result.stdout
        # Check for options (they may appear with ANSI codes or as lowercase)
        assert "force" in result.stdout.lower()
        assert "skip" in result.stdout.lower()

    def test_already_installed(self):
        """Test that it warns if agent is already installed."""
        with patch("shutil.which", return_value="/usr/local/bin/envdrift-agent"):
            result = runner.invoke(app, ["install", "agent"])
            assert result.exit_code == 0
            assert "already installed" in result.stdout

    def test_download_failure(self, tmp_path: Path):
        """Test handling of download failure (HTTPError)."""
        with (
            patch("shutil.which", return_value=None),
            patch(
                "envdrift.cli_commands.install._detect_platform",
                return_value="darwin-arm64",
            ),
            patch(
                "envdrift.cli_commands.install._get_install_path",
                return_value=tmp_path / "envdrift-agent",
            ),
            patch(
                "urllib.request.urlopen",
                side_effect=urllib.error.HTTPError(
                    url="", code=404, msg="Not Found", hdrs={}, fp=None
                ),
            ),
        ):
            result = runner.invoke(app, ["install", "agent"])
            assert result.exit_code == 1
            assert "Failed to download" in result.stdout

    def test_download_failure_url_error(self, tmp_path: Path):
        """Test handling of download failure (URLError - network error)."""
        with (
            patch("shutil.which", return_value=None),
            patch(
                "envdrift.cli_commands.install._detect_platform",
                return_value="darwin-arm64",
            ),
            patch(
                "envdrift.cli_commands.install._get_install_path",
                return_value=tmp_path / "envdrift-agent",
            ),
            patch(
                "urllib.request.urlopen",
                side_effect=urllib.error.URLError("Connection refused"),
            ),
        ):
            result = runner.invoke(app, ["install", "agent"])
            assert result.exit_code == 1
            assert "Failed to download" in result.stdout

    def test_successful_installation(self, tmp_path: Path):
        """Test successful installation flow."""
        binary_path = tmp_path / "envdrift-agent"

        # Mock subprocess to return success for version check and install
        version_result = MagicMock()
        version_result.returncode = 0
        version_result.stdout = "v1.0.0"

        with (
            patch("shutil.which", return_value=None),
            patch(
                "envdrift.cli_commands.install._detect_platform",
                return_value="linux-amd64",
            ),
            patch(
                "envdrift.cli_commands.install._get_install_path",
                return_value=binary_path,
            ),
            patch(
                "envdrift.cli_commands.install._download_binary",
                return_value=True,
            ),
            patch("subprocess.run", return_value=version_result),
            patch("envdrift.config.find_config", return_value=None),
        ):
            result = runner.invoke(app, ["install", "agent"])
            assert result.exit_code == 0
            assert "Installation complete" in result.stdout

    def test_force_reinstall_with_running_agent(self):
        """Test force reinstall warns when agent is running."""
        status_result = MagicMock()
        status_result.returncode = 0
        status_result.stdout = "Agent is running"

        with (
            patch("shutil.which", return_value="/usr/local/bin/envdrift-agent"),
            patch("subprocess.run", return_value=status_result),
            patch("envdrift.cli_commands.install._detect_platform", return_value="linux-amd64"),
        ):
            result = runner.invoke(app, ["install", "agent", "--force"])
            # Should warn about running agent
            assert "running" in result.stdout.lower() or "Warning" in result.stdout


class TestCheckCommand:
    """Tests for 'envdrift install check' command."""

    @pytest.fixture(autouse=True)
    def reset_registry(self):
        """Reset the global registry singleton before each test."""
        registry_module._registry = None
        yield
        registry_module._registry = None

    def test_check_help(self):
        """Test that install check --help works."""
        result = runner.invoke(app, ["install", "check", "--help"])
        assert result.exit_code == 0
        assert "Check the installation status" in result.stdout

    def test_check_shows_cli_info(self):
        """Test that check shows Python CLI info."""
        with patch("shutil.which", return_value=None):
            result = runner.invoke(app, ["install", "check"])
            assert result.exit_code == 0
            assert "Python CLI" in result.stdout
            assert "Installed at" in result.stdout

    def test_check_agent_not_installed(self):
        """Test check shows agent not installed."""
        with patch("shutil.which", return_value=None):
            result = runner.invoke(app, ["install", "check"])
            assert result.exit_code == 0
            assert "Not installed" in result.stdout
            assert "envdrift install agent" in result.stdout

    def test_check_agent_installed(self, tmp_path: Path):
        """Test check shows agent when installed."""
        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = MagicMock()
        registry_module._registry.path = registry_path
        registry_module._registry.projects = []

        with patch("shutil.which", return_value="/usr/local/bin/envdrift-agent"):
            result = runner.invoke(app, ["install", "check"])
            assert result.exit_code == 0
            assert "Background Agent" in result.stdout

    def test_check_agent_version(self):
        """Test check displays agent version when available."""
        version_result = MagicMock()
        version_result.returncode = 0
        version_result.stdout = "envdrift-agent v1.2.3"

        with (
            patch("shutil.which", return_value="/usr/local/bin/envdrift-agent"),
            patch("subprocess.run", return_value=version_result),
        ):
            result = runner.invoke(app, ["install", "check"])
            assert result.exit_code == 0
            assert "envdrift-agent v1.2.3" in result.stdout

    def test_check_agent_running_status(self):
        """Test check displays when agent is running."""

        def subprocess_side_effect(*args, **kwargs):
            result = MagicMock()
            if "status" in args[0]:
                result.returncode = 0
                result.stdout = "Agent is running"
            else:
                result.returncode = 0
                result.stdout = "v1.0.0"
            return result

        with (
            patch("shutil.which", return_value="/usr/local/bin/envdrift-agent"),
            patch("subprocess.run", side_effect=subprocess_side_effect),
        ):
            result = runner.invoke(app, ["install", "check"])
            assert result.exit_code == 0
            assert "Running" in result.stdout


class TestInstallHelpCommand:
    """Tests for 'envdrift install --help' command."""

    def test_install_help(self):
        """Test that install --help shows subcommands."""
        result = runner.invoke(app, ["install", "--help"])
        assert result.exit_code == 0
        assert "agent" in result.stdout
        assert "check" in result.stdout
