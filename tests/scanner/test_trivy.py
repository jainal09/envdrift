"""Tests for trivy scanner integration."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from envdrift.scanner.base import FindingSeverity
from envdrift.scanner.trivy import (
    TrivyInstaller,
    TrivyInstallError,
    TrivyNotFoundError,
    TrivyScanner,
    get_platform_info,
    get_trivy_path,
)


class TestPlatformDetection:
    """Tests for platform detection utilities."""

    def test_get_platform_info_returns_tuple(self):
        """Test that get_platform_info returns system and machine."""
        system, machine = get_platform_info()
        assert isinstance(system, str)
        assert isinstance(machine, str)
        assert system in ("Darwin", "Linux", "Windows")

    @patch("platform.system", return_value="Darwin")
    @patch("platform.machine", return_value="arm64")
    def test_get_platform_info_darwin_arm64(self, mock_machine: MagicMock, mock_system: MagicMock):
        """Test platform detection for macOS ARM."""
        system, machine = get_platform_info()
        assert system == "Darwin"
        assert machine == "arm64"

    @patch("platform.system", return_value="Linux")
    @patch("platform.machine", return_value="x86_64")
    def test_get_platform_info_linux_amd64(self, mock_machine: MagicMock, mock_system: MagicMock):
        """Test platform detection for Linux AMD64."""
        system, machine = get_platform_info()
        assert system == "Linux"
        assert machine == "x86_64"


class TestGetTrivyPath:
    """Tests for trivy binary path detection."""

    @patch("envdrift.scanner.trivy.get_venv_bin_dir")
    @patch("platform.system", return_value="Linux")
    def test_returns_trivy_path_linux(self, mock_system: MagicMock, mock_bin_dir: MagicMock):
        """Test trivy path on Linux."""
        mock_bin_dir.return_value = Path("/venv/bin")
        path = get_trivy_path()
        assert path == Path("/venv/bin/trivy")

    @patch("envdrift.scanner.trivy.get_venv_bin_dir")
    @patch("platform.system", return_value="Windows")
    def test_returns_trivy_exe_on_windows(self, mock_system: MagicMock, mock_bin_dir: MagicMock):
        """Test trivy path on Windows includes .exe extension."""
        mock_bin_dir.return_value = Path("/venv/Scripts")
        path = get_trivy_path()
        assert path == Path("/venv/Scripts/trivy.exe")


class TestTrivyInstaller:
    """Tests for TrivyInstaller class."""

    def test_default_version_from_constants(self):
        """Test that installer uses version from constants."""
        installer = TrivyInstaller()
        assert installer.version == "0.58.0"

    def test_custom_version(self):
        """Test that custom version can be specified."""
        installer = TrivyInstaller(version="0.50.0")
        assert installer.version == "0.50.0"

    def test_progress_callback(self):
        """Test that progress callback is called."""
        messages: list[str] = []
        installer = TrivyInstaller(progress_callback=messages.append)
        installer.progress("test message")
        assert messages == ["test message"]

    @patch("envdrift.scanner.trivy.get_platform_info")
    def test_get_download_url_darwin_arm64(self, mock_platform: MagicMock):
        """Test download URL for macOS ARM."""
        mock_platform.return_value = ("Darwin", "arm64")
        installer = TrivyInstaller(version="0.58.0")
        url = installer.get_download_url()
        assert "macOS" in url or "darwin" in url.lower()
        assert "ARM64" in url or "arm64" in url.lower()
        assert "0.58.0" in url

    @patch("envdrift.scanner.trivy.get_platform_info")
    def test_get_download_url_linux_amd64(self, mock_platform: MagicMock):
        """Test download URL for Linux AMD64."""
        mock_platform.return_value = ("Linux", "x86_64")
        installer = TrivyInstaller(version="0.58.0")
        url = installer.get_download_url()
        assert "Linux" in url or "linux" in url.lower()
        assert "64bit" in url or "amd64" in url.lower()

    @patch("envdrift.scanner.trivy.get_platform_info")
    def test_get_download_url_windows(self, mock_platform: MagicMock):
        """Test download URL for Windows."""
        mock_platform.return_value = ("Windows", "x86_64")
        installer = TrivyInstaller(version="0.58.0")
        url = installer.get_download_url()
        assert "windows" in url.lower()
        assert ".zip" in url

    @patch("envdrift.scanner.trivy.get_platform_info")
    def test_unsupported_platform_raises_error(self, mock_platform: MagicMock):
        """Test that unsupported platform raises error."""
        mock_platform.return_value = ("FreeBSD", "x86_64")
        installer = TrivyInstaller()
        with pytest.raises(TrivyInstallError, match="Unsupported platform"):
            installer.get_download_url()

    def test_platform_map_completeness(self):
        """Test that all common platforms are supported."""
        expected_platforms = {
            ("Darwin", "x86_64"),
            ("Darwin", "arm64"),
            ("Linux", "x86_64"),
            ("Linux", "arm64"),
            ("Windows", "x86_64"),
        }
        assert set(TrivyInstaller.PLATFORM_MAP.keys()) == expected_platforms


class TestTrivyScanner:
    """Tests for TrivyScanner class."""

    def test_scanner_name(self):
        """Test scanner name property."""
        scanner = TrivyScanner(auto_install=False)
        assert scanner.name == "trivy"

    def test_scanner_description(self):
        """Test scanner description property."""
        scanner = TrivyScanner(auto_install=False)
        assert "trivy" in scanner.description.lower()

    @patch("shutil.which", return_value=None)
    @patch("envdrift.scanner.trivy.get_trivy_path")
    def test_is_installed_returns_false_when_not_found(
        self, mock_path: MagicMock, mock_which: MagicMock
    ):
        """Test is_installed returns False when binary not found."""
        mock_path.return_value = Path("/nonexistent/trivy")
        scanner = TrivyScanner(auto_install=False)
        assert scanner.is_installed() is False

    @patch("shutil.which", return_value="/usr/bin/trivy")
    def test_is_installed_returns_true_when_in_path(self, mock_which: MagicMock):
        """Test is_installed returns True when in PATH."""
        scanner = TrivyScanner(auto_install=False)
        assert scanner.is_installed() is True

    @patch("envdrift.scanner.trivy.get_trivy_path")
    def test_is_installed_returns_true_when_in_venv(self, mock_path: MagicMock, tmp_path: Path):
        """Test is_installed returns True when in venv."""
        binary = tmp_path / "trivy"
        binary.touch()
        mock_path.return_value = binary
        scanner = TrivyScanner(auto_install=False)
        assert scanner.is_installed() is True

    @patch("shutil.which", return_value=None)
    @patch("envdrift.scanner.trivy.get_trivy_path")
    def test_scan_returns_error_when_not_installed(
        self, mock_path: MagicMock, mock_which: MagicMock, tmp_path: Path
    ):
        """Test scan returns error result when trivy not installed."""
        mock_path.return_value = Path("/nonexistent/trivy")
        scanner = TrivyScanner(auto_install=False)
        result = scanner.scan([tmp_path])
        assert result.error is not None
        assert "not found" in result.error.lower()
        assert result.success is False

    def test_scan_with_nonexistent_path(self, tmp_path: Path):
        """Test scan handles nonexistent paths gracefully."""
        scanner = TrivyScanner(auto_install=False)
        scanner._binary_path = Path("/fake/trivy")
        with patch.object(scanner, "_find_binary", return_value=Path("/fake/trivy")):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(stdout="{}", stderr="", returncode=0)
                result = scanner.scan([tmp_path / "nonexistent"])
                assert result.success is True
                assert len(result.findings) == 0


class TestFindingParsing:
    """Tests for trivy finding parsing."""

    @pytest.fixture
    def scanner(self) -> TrivyScanner:
        """
        Creates a TrivyScanner configured for tests with auto-install disabled.
        
        Returns:
            TrivyScanner: Scanner instance with auto_install=False suitable for unit tests.
        """
        return TrivyScanner(auto_install=False)

    def test_parse_secret_basic(self, scanner: TrivyScanner, tmp_path: Path):
        """Test parsing a basic trivy secret."""
        secret: dict[str, Any] = {
            "RuleID": "aws-access-key-id",
            "Category": "AWS",
            "Title": "AWS Access Key ID",
            "Severity": "CRITICAL",
            "StartLine": 10,
            "Match": "AKIAIOSFODNN7EXAMPLE",
        }
        finding = scanner._parse_secret(secret, "test.py", tmp_path)

        assert finding is not None
        assert finding.rule_id == "trivy-aws-access-key-id"
        assert finding.rule_description == "AWS Access Key ID"
        assert finding.line_number == 10
        assert finding.severity == FindingSeverity.CRITICAL
        assert finding.scanner == "trivy"
        assert "****" in finding.secret_preview  # Redacted

    def test_parse_secret_high_severity(self, scanner: TrivyScanner, tmp_path: Path):
        """Test parsing a high severity secret."""
        secret: dict[str, Any] = {
            "RuleID": "github-pat",
            "Category": "GitHub",
            "Title": "GitHub Personal Access Token",
            "Severity": "HIGH",
            "StartLine": 5,
        }
        finding = scanner._parse_secret(secret, "config.py", tmp_path)

        assert finding is not None
        assert finding.severity == FindingSeverity.HIGH

    def test_parse_secret_medium_severity(self, scanner: TrivyScanner, tmp_path: Path):
        """Test parsing a medium severity secret."""
        secret: dict[str, Any] = {
            "RuleID": "generic-api-key",
            "Category": "Generic",
            "Title": "Generic API Key",
            "Severity": "MEDIUM",
        }
        finding = scanner._parse_secret(secret, "test.py", tmp_path)

        assert finding is not None
        assert finding.severity == FindingSeverity.MEDIUM

    def test_parse_output(self, scanner: TrivyScanner, tmp_path: Path):
        """Test parsing complete trivy output."""
        scan_data: dict[str, Any] = {
            "Results": [
                {
                    "Target": "secrets.py",
                    "Secrets": [
                        {
                            "RuleID": "aws-access-key-id",
                            "Category": "AWS",
                            "Title": "AWS Access Key ID",
                            "Severity": "CRITICAL",
                            "StartLine": 10,
                            "Match": "AKIAIOSFODNN7EXAMPLE",
                        }
                    ],
                }
            ]
        }
        findings, files_scanned = scanner._parse_output(scan_data, tmp_path)

        assert files_scanned == 1
        assert len(findings) == 1
        assert findings[0].rule_id == "trivy-aws-access-key-id"


class TestTrivyScanExecution:
    """Tests for trivy scan execution with mocked subprocess."""

    @pytest.fixture
    def mock_scanner(self, tmp_path: Path) -> TrivyScanner:
        """
        Create a TrivyScanner with a mocked trivy binary placed in the given temporary directory.
        
        Parameters:
            tmp_path (Path): Temporary directory in which a fake `trivy` binary file will be created.
        
        Returns:
            TrivyScanner: Scanner instance with its `_binary_path` set to the created fake binary.
        """
        scanner = TrivyScanner(auto_install=False)
        binary_path = tmp_path / "trivy"
        binary_path.touch()
        scanner._binary_path = binary_path
        return scanner

    def test_scan_parses_json_output(self, mock_scanner: TrivyScanner, tmp_path: Path):
        """Test that scan correctly parses JSON output."""
        output_json = json.dumps(
            {
                "Results": [
                    {
                        "Target": "test.py",
                        "Secrets": [
                            {
                                "RuleID": "aws-key",
                                "Category": "AWS",
                                "Title": "AWS Key",
                                "Severity": "CRITICAL",
                                "StartLine": 1,
                                "Match": "AKIAIOSFODNN7EXAMPLE",
                            }
                        ],
                    }
                ]
            }
        )

        with patch.object(mock_scanner, "_find_binary", return_value=mock_scanner._binary_path):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(stdout=output_json, stderr="", returncode=0)
                result = mock_scanner.scan([tmp_path])

        assert result.success is True
        assert len(result.findings) == 1
        assert result.findings[0].rule_id == "trivy-aws-key"

    def test_scan_handles_empty_output(self, mock_scanner: TrivyScanner, tmp_path: Path):
        """Test that scan handles empty output."""
        with patch.object(mock_scanner, "_find_binary", return_value=mock_scanner._binary_path):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    stdout="",
                    stderr="",
                    returncode=0,
                )
                result = mock_scanner.scan([tmp_path])

        assert result.success is True
        assert len(result.findings) == 0

    def test_scan_handles_invalid_json(self, mock_scanner: TrivyScanner, tmp_path: Path):
        """Test that scan handles invalid JSON gracefully."""
        with patch.object(mock_scanner, "_find_binary", return_value=mock_scanner._binary_path):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(stdout="not valid json", stderr="", returncode=0)
                result = mock_scanner.scan([tmp_path])

        assert result.success is True
        assert len(result.findings) == 0

    def test_scan_handles_timeout(self, mock_scanner: TrivyScanner, tmp_path: Path):
        """Test that scan handles subprocess timeout."""
        with patch.object(mock_scanner, "_find_binary", return_value=mock_scanner._binary_path):
            with patch("subprocess.run") as mock_run:
                mock_run.side_effect = subprocess.TimeoutExpired(cmd="trivy", timeout=300)
                result = mock_scanner.scan([tmp_path])

        assert "timed out" in result.error.lower()
        assert result.success is False

    def test_scan_multiple_paths(self, mock_scanner: TrivyScanner, tmp_path: Path):
        """Test scanning multiple paths."""
        path1 = tmp_path / "dir1"
        path2 = tmp_path / "dir2"
        path1.mkdir()
        path2.mkdir()

        with patch.object(mock_scanner, "_find_binary", return_value=mock_scanner._binary_path):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(stdout="{}", stderr="", returncode=0)
                result = mock_scanner.scan([path1, path2])

        assert result.success is True
        # Should be called once per existing path
        assert mock_run.call_count == 2


class TestTrivyAutoInstall:
    """Tests for trivy auto-installation."""

    @patch("shutil.which", return_value=None)
    @patch("envdrift.scanner.trivy.get_trivy_path")
    @patch.object(TrivyInstaller, "install")
    def test_auto_install_when_not_found(
        self,
        mock_install: MagicMock,
        mock_path: MagicMock,
        mock_which: MagicMock,
        tmp_path: Path,
    ):
        """Test that scanner auto-installs when binary not found."""
        mock_path.return_value = Path("/nonexistent/trivy")
        installed_path = tmp_path / "trivy"
        installed_path.touch()
        mock_install.return_value = installed_path

        scanner = TrivyScanner(auto_install=True)
        binary = scanner._find_binary()

        assert binary == installed_path
        mock_install.assert_called_once()

    @patch("shutil.which", return_value=None)
    @patch("envdrift.scanner.trivy.get_trivy_path")
    @patch.object(TrivyInstaller, "install")
    def test_auto_install_failure_raises_error(
        self,
        mock_install: MagicMock,
        mock_path: MagicMock,
        mock_which: MagicMock,
    ):
        """Test that auto-install failure raises appropriate error."""
        mock_path.return_value = Path("/nonexistent/trivy")
        mock_install.side_effect = TrivyInstallError("Download failed")

        scanner = TrivyScanner(auto_install=True)
        with pytest.raises(TrivyNotFoundError, match="auto-install failed"):
            scanner._find_binary()


class TestExceptionClasses:
    """Tests for exception classes."""

    def test_trivy_not_found_error(self):
        """Test TrivyNotFoundError."""
        error = TrivyNotFoundError("Binary not found")
        assert str(error) == "Binary not found"
        assert isinstance(error, Exception)

    def test_trivy_install_error(self):
        """Test TrivyInstallError."""
        error = TrivyInstallError("Download failed")
        assert str(error) == "Download failed"
        assert isinstance(error, Exception)


# Mark integration tests that require actual trivy installation
@pytest.mark.skipif(
    not TrivyScanner(auto_install=False).is_installed(),
    reason="trivy not installed",
)
class TestTrivyIntegration:
    """Integration tests that require trivy to be installed."""

    def test_scan_clean_directory(self, tmp_path: Path):
        """Test scanning a directory with no secrets."""
        # Create a clean file
        (tmp_path / "clean.py").write_text("# No secrets here\nx = 1 + 1\n")

        scanner = TrivyScanner(auto_install=False)
        result = scanner.scan([tmp_path])

        assert result.success is True