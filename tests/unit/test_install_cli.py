"""Tests for the install CLI commands."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

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
        import typer

        with (
            patch("platform.system", return_value="FreeBSD"),
            patch("platform.machine", return_value="x86_64"),
            pytest.raises(typer.BadParameter, match="Unsupported operating system"),
        ):
            _detect_platform()

    def test_unsupported_arch(self):
        """Test that unsupported architecture raises error."""
        import typer

        with (
            patch("platform.system", return_value="Linux"),
            patch("platform.machine", return_value="sparc64"),
            pytest.raises(typer.BadParameter, match="Unsupported architecture"),
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
        import re

        result = runner.invoke(app, ["install", "agent", "--help"])
        ansi_escape = re.compile(r"\x1B\[[0-9;]*[A-Za-z]|\x1B[@-Z\\-_]")
        clean_output = ansi_escape.sub("", result.stdout)
        assert result.exit_code == 0
        assert "Install the envdrift background agent" in clean_output
        assert "--force" in clean_output
        assert "--skip-autostart" in clean_output
        assert "--skip-register" in clean_output

    def test_already_installed(self):
        """Test that it warns if agent is already installed."""
        with patch("shutil.which", return_value="/usr/local/bin/envdrift-agent"):
            result = runner.invoke(app, ["install", "agent"])
            assert result.exit_code == 0
            assert "already installed" in result.stdout

    def test_download_failure(self, tmp_path: Path):
        """Test handling of download failure."""
        import urllib.error

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


class TestCheckCommand:
    """Tests for 'envdrift install check' command."""

    @pytest.fixture(autouse=True)
    def reset_registry(self):
        """Reset the global registry singleton before each test."""
        import envdrift.agent.registry as registry_module

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
        import envdrift.agent.registry as registry_module

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = MagicMock()
        registry_module._registry.path = registry_path
        registry_module._registry.projects = []

        with patch("shutil.which", return_value="/usr/local/bin/envdrift-agent"):
            result = runner.invoke(app, ["install", "check"])
            assert result.exit_code == 0
            assert "Background Agent" in result.stdout


class TestInstallHelpCommand:
    """Tests for 'envdrift install --help' command."""

    def test_install_help(self):
        """Test that install --help shows subcommands."""
        result = runner.invoke(app, ["install", "--help"])
        assert result.exit_code == 0
        assert "agent" in result.stdout
        assert "check" in result.stdout
