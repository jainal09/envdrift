"""Tests for talisman scanner integration."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from envdrift.scanner.base import FindingSeverity
from envdrift.scanner.talisman import (
    TalismanInstaller,
    TalismanInstallError,
    TalismanNotFoundError,
    TalismanScanner,
    get_platform_info,
    get_talisman_path,
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

    @patch("platform.system", return_value="Windows")
    @patch("platform.machine", return_value="AMD64")
    def test_get_platform_info_windows_normalizes_amd64(
        self, mock_machine: MagicMock, mock_system: MagicMock
    ):
        """Test that AMD64 is normalized to x86_64 on Windows."""
        system, machine = get_platform_info()
        assert system == "Windows"
        assert machine == "x86_64"


class TestGetTalismanPath:
    """Tests for talisman binary path detection."""

    @patch("envdrift.scanner.talisman.get_venv_bin_dir")
    @patch("platform.system", return_value="Linux")
    def test_returns_talisman_path_linux(self, mock_system: MagicMock, mock_bin_dir: MagicMock):
        """Test talisman path on Linux."""
        mock_bin_dir.return_value = Path("/venv/bin")
        path = get_talisman_path()
        assert path == Path("/venv/bin/talisman")

    @patch("envdrift.scanner.talisman.get_venv_bin_dir")
    @patch("platform.system", return_value="Windows")
    def test_returns_talisman_exe_on_windows(self, mock_system: MagicMock, mock_bin_dir: MagicMock):
        """Test talisman path on Windows includes .exe extension."""
        mock_bin_dir.return_value = Path("/venv/Scripts")
        path = get_talisman_path()
        assert path == Path("/venv/Scripts/talisman.exe")


class TestTalismanInstaller:
    """Tests for TalismanInstaller class."""

    def test_default_version_from_constants(self):
        """Test that installer uses version from constants."""
        installer = TalismanInstaller()
        assert installer.version == "1.32.0"

    def test_custom_version(self):
        """Test that custom version can be specified."""
        installer = TalismanInstaller(version="1.30.0")
        assert installer.version == "1.30.0"

    def test_progress_callback(self):
        """Test that progress callback is called."""
        messages: list[str] = []
        installer = TalismanInstaller(progress_callback=messages.append)
        installer.progress("test message")
        assert messages == ["test message"]

    @patch("envdrift.scanner.talisman.get_platform_info")
    def test_get_download_url_darwin_arm64(self, mock_platform: MagicMock):
        """Test download URL for macOS ARM."""
        mock_platform.return_value = ("Darwin", "arm64")
        installer = TalismanInstaller(version="1.32.0")
        url = installer.get_download_url()
        assert "darwin" in url
        assert "arm64" in url
        assert "1.32.0" in url

    @patch("envdrift.scanner.talisman.get_platform_info")
    def test_get_download_url_linux_amd64(self, mock_platform: MagicMock):
        """Test download URL for Linux AMD64."""
        mock_platform.return_value = ("Linux", "x86_64")
        installer = TalismanInstaller(version="1.32.0")
        url = installer.get_download_url()
        assert "linux" in url
        assert "amd64" in url

    @patch("envdrift.scanner.talisman.get_platform_info")
    def test_get_download_url_windows(self, mock_platform: MagicMock):
        """Test download URL for Windows."""
        mock_platform.return_value = ("Windows", "x86_64")
        installer = TalismanInstaller(version="1.32.0")
        url = installer.get_download_url()
        assert "windows" in url
        assert ".exe" in url

    @patch("envdrift.scanner.talisman.get_platform_info")
    def test_unsupported_platform_raises_error(self, mock_platform: MagicMock):
        """Test that unsupported platform raises error."""
        mock_platform.return_value = ("FreeBSD", "x86_64")
        installer = TalismanInstaller()
        with pytest.raises(TalismanInstallError, match="Unsupported platform"):
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
        assert set(TalismanInstaller.PLATFORM_MAP.keys()) == expected_platforms


class TestTalismanScanner:
    """Tests for TalismanScanner class."""

    def test_scanner_name(self):
        """Test scanner name property."""
        scanner = TalismanScanner(auto_install=False)
        assert scanner.name == "talisman"

    def test_scanner_description(self):
        """Test scanner description property."""
        scanner = TalismanScanner(auto_install=False)
        assert "talisman" in scanner.description.lower()

    @patch("shutil.which", return_value=None)
    @patch("envdrift.scanner.talisman.get_talisman_path")
    def test_is_installed_returns_false_when_not_found(
        self, mock_path: MagicMock, mock_which: MagicMock
    ):
        """Test is_installed returns False when binary not found."""
        mock_path.return_value = Path("/nonexistent/talisman")
        scanner = TalismanScanner(auto_install=False)
        assert scanner.is_installed() is False

    @patch("shutil.which", return_value="/usr/bin/talisman")
    def test_is_installed_returns_true_when_in_path(self, mock_which: MagicMock):
        """Test is_installed returns True when in PATH."""
        scanner = TalismanScanner(auto_install=False)
        assert scanner.is_installed() is True

    @patch("envdrift.scanner.talisman.get_talisman_path")
    def test_is_installed_returns_true_when_in_venv(self, mock_path: MagicMock, tmp_path: Path):
        """Test is_installed returns True when in venv."""
        binary = tmp_path / "talisman"
        binary.touch()
        mock_path.return_value = binary
        scanner = TalismanScanner(auto_install=False)
        assert scanner.is_installed() is True

    @patch("shutil.which", return_value=None)
    @patch("envdrift.scanner.talisman.get_talisman_path")
    def test_scan_returns_error_when_not_installed(
        self, mock_path: MagicMock, mock_which: MagicMock, tmp_path: Path
    ):
        """Test scan returns error result when talisman not installed."""
        mock_path.return_value = Path("/nonexistent/talisman")
        scanner = TalismanScanner(auto_install=False)
        result = scanner.scan([tmp_path])
        assert result.error is not None
        assert "not found" in result.error.lower()
        assert result.success is False

    def test_scan_with_nonexistent_path(self, tmp_path: Path):
        """Test scan handles nonexistent paths gracefully."""
        scanner = TalismanScanner(auto_install=False)
        scanner._binary_path = Path("/fake/talisman")
        with patch.object(scanner, "_find_binary", return_value=Path("/fake/talisman")):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
                result = scanner.scan([tmp_path / "nonexistent"])
                assert result.success is True
                assert len(result.findings) == 0


class TestFindingParsing:
    """Tests for talisman finding parsing."""

    @pytest.fixture
    def scanner(self) -> TalismanScanner:
        """
        Create a TalismanScanner configured for tests.

        Returns:
            TalismanScanner: Scanner instance with `auto_install` set to False.
        """
        return TalismanScanner(auto_install=False)

    def test_parse_failure_basic(self, scanner: TalismanScanner, tmp_path: Path):
        """Test parsing a basic talisman failure."""
        failure: dict[str, Any] = {
            "type": "filecontent",
            "message": "Potential secret detected in file",
            "severity": "high",
            "match": "AKIAIOSFODNN7EXAMPLE",
        }
        finding = scanner._parse_failure(failure, tmp_path / "test.py")

        assert finding is not None
        assert finding.rule_id == "talisman-filecontent"
        assert finding.severity == FindingSeverity.CRITICAL  # high maps to CRITICAL
        assert finding.scanner == "talisman"
        assert "****" in finding.secret_preview  # Redacted

    def test_parse_failure_medium_severity(self, scanner: TalismanScanner, tmp_path: Path):
        """Test parsing a medium severity failure."""
        failure: dict[str, Any] = {
            "type": "entropy",
            "message": "High entropy content detected",
            "severity": "medium",
        }
        finding = scanner._parse_failure(failure, tmp_path / "test.py")

        assert finding is not None
        assert finding.severity == FindingSeverity.HIGH  # medium maps to HIGH

    def test_parse_failure_low_severity(self, scanner: TalismanScanner, tmp_path: Path):
        """Test parsing a low severity failure."""
        failure: dict[str, Any] = {
            "type": "filename",
            "message": "Suspicious filename detected",
            "severity": "low",
        }
        finding = scanner._parse_failure(failure, tmp_path / "test.pem")

        assert finding is not None
        assert finding.severity == FindingSeverity.MEDIUM  # low maps to MEDIUM

    def test_parse_failure_warning(self, scanner: TalismanScanner, tmp_path: Path):
        """Test parsing a warning as medium severity."""
        failure: dict[str, Any] = {
            "type": "filesize",
            "message": "Large file detected",
        }
        finding = scanner._parse_failure(failure, tmp_path / "large.bin", is_warning=True)

        assert finding is not None
        assert finding.severity == FindingSeverity.MEDIUM

    def test_parse_report(self, scanner: TalismanScanner, tmp_path: Path):
        """Test parsing a complete report."""
        report_data: dict[str, Any] = {
            "results": [
                {
                    "filename": "secrets.py",
                    "failures": [
                        {
                            "type": "filecontent",
                            "message": "AWS Key detected",
                            "severity": "high",
                            "match": "AKIAIOSFODNN7EXAMPLE",
                        }
                    ],
                    "warnings": [],
                    "ignores": [],
                }
            ]
        }
        findings, files_scanned = scanner._parse_report(report_data, tmp_path)

        assert files_scanned == 1
        assert len(findings) == 1
        assert findings[0].rule_id == "talisman-filecontent"


class TestTalismanScanExecution:
    """Tests for talisman scan execution with mocked subprocess."""

    @pytest.fixture
    def mock_scanner(self, tmp_path: Path) -> TalismanScanner:
        """
        Create a TalismanScanner configured to use a mocked local binary.

        Parameters:
            tmp_path (Path): Temporary directory in which a fake `talisman` binary file will be created.

        Returns:
            TalismanScanner: Scanner instance with `auto_install=False` and `_binary_path` set to the created fake binary.
        """
        scanner = TalismanScanner(auto_install=False)
        binary_path = tmp_path / "talisman"
        binary_path.touch()
        scanner._binary_path = binary_path
        return scanner

    def test_scan_handles_empty_output(self, mock_scanner: TalismanScanner, tmp_path: Path):
        """Test that scan handles empty report."""
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

    def test_scan_handles_timeout(self, mock_scanner: TalismanScanner, tmp_path: Path):
        """Test that scan handles subprocess timeout."""
        with patch.object(mock_scanner, "_find_binary", return_value=mock_scanner._binary_path):
            with patch("subprocess.run") as mock_run:
                mock_run.side_effect = subprocess.TimeoutExpired(cmd="talisman", timeout=300)
                result = mock_scanner.scan([tmp_path])

        assert "timed out" in result.error.lower()
        assert result.success is False

    def test_scan_multiple_paths(self, mock_scanner: TalismanScanner, tmp_path: Path):
        """Test scanning multiple paths."""
        path1 = tmp_path / "dir1"
        path2 = tmp_path / "dir2"
        path1.mkdir()
        path2.mkdir()

        with patch.object(mock_scanner, "_find_binary", return_value=mock_scanner._binary_path):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
                result = mock_scanner.scan([path1, path2])

        assert result.success is True
        # Should be called once per existing path
        assert mock_run.call_count == 2


class TestTalismanAutoInstall:
    """Tests for talisman auto-installation."""

    @patch("shutil.which", return_value=None)
    @patch("envdrift.scanner.talisman.get_talisman_path")
    @patch.object(TalismanInstaller, "install")
    def test_auto_install_when_not_found(
        self,
        mock_install: MagicMock,
        mock_path: MagicMock,
        mock_which: MagicMock,
        tmp_path: Path,
    ):
        """Test that scanner auto-installs when binary not found."""
        mock_path.return_value = Path("/nonexistent/talisman")
        installed_path = tmp_path / "talisman"
        installed_path.touch()
        mock_install.return_value = installed_path

        scanner = TalismanScanner(auto_install=True)
        binary = scanner._find_binary()

        assert binary == installed_path
        mock_install.assert_called_once()

    @patch("shutil.which", return_value=None)
    @patch("envdrift.scanner.talisman.get_talisman_path")
    @patch.object(TalismanInstaller, "install")
    def test_auto_install_failure_raises_error(
        self,
        mock_install: MagicMock,
        mock_path: MagicMock,
        mock_which: MagicMock,
    ):
        """Test that auto-install failure raises appropriate error."""
        mock_path.return_value = Path("/nonexistent/talisman")
        mock_install.side_effect = TalismanInstallError("Download failed")

        scanner = TalismanScanner(auto_install=True)
        with pytest.raises(TalismanNotFoundError, match="auto-install failed"):
            scanner._find_binary()


class TestExceptionClasses:
    """Tests for exception classes."""

    def test_talisman_not_found_error(self):
        """Test TalismanNotFoundError."""
        error = TalismanNotFoundError("Binary not found")
        assert str(error) == "Binary not found"
        assert isinstance(error, Exception)

    def test_talisman_install_error(self):
        """Test TalismanInstallError."""
        error = TalismanInstallError("Download failed")
        assert str(error) == "Download failed"
        assert isinstance(error, Exception)


# Mark integration tests that require actual talisman installation
@pytest.mark.skipif(
    not TalismanScanner(auto_install=False).is_installed(),
    reason="talisman not installed",
)
class TestTalismanIntegration:
    """Integration tests that require talisman to be installed."""

    def test_scan_clean_directory(self, tmp_path: Path):
        """Test scanning a directory with no secrets."""
        # Create a clean file
        (tmp_path / "clean.py").write_text("# No secrets here\nx = 1 + 1\n")

        scanner = TalismanScanner(auto_install=False)
        result = scanner.scan([tmp_path])

        assert result.success is True
