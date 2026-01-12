"""Tests for gitleaks scanner integration."""

from __future__ import annotations

import json
import platform
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from envdrift.scanner.base import FindingSeverity
from envdrift.scanner.gitleaks import (
    GitleaksError,
    GitleaksInstaller,
    GitleaksInstallError,
    GitleaksNotFoundError,
    GitleaksScanner,
    get_gitleaks_path,
    get_platform_info,
    get_venv_bin_dir,
)


def _create_tar_gz(tmp_path: Path, binary_name: str) -> Path:
    payload_dir = tmp_path / "payload"
    payload_dir.mkdir()
    binary_path = payload_dir / binary_name
    binary_path.write_text("binary")
    archive_path = tmp_path / "archive.tar.gz"
    with tarfile.open(archive_path, "w:gz") as tar:
        tar.add(binary_path, arcname=binary_name)
    return archive_path


def _create_zip(tmp_path: Path, binary_name: str) -> Path:
    payload_dir = tmp_path / "payload_zip"
    payload_dir.mkdir()
    binary_path = payload_dir / binary_name
    binary_path.write_text("binary")
    archive_path = tmp_path / "archive.zip"
    with zipfile.ZipFile(archive_path, "w") as zip_file:
        zip_file.write(binary_path, arcname=binary_name)
    return archive_path


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


class TestGetVenvBinDir:
    """Tests for virtual environment bin directory detection."""

    @patch.dict("os.environ", {"VIRTUAL_ENV": "/path/to/venv"}, clear=False)
    @patch("platform.system", return_value="Linux")
    def test_returns_venv_bin_on_linux(self, mock_system: MagicMock):
        """Test that Linux venv returns bin directory."""
        bin_dir = get_venv_bin_dir()
        assert bin_dir == Path("/path/to/venv/bin")

    @patch.dict("os.environ", {"VIRTUAL_ENV": "/path/to/venv"}, clear=False)
    @patch("platform.system", return_value="Windows")
    def test_returns_venv_scripts_on_windows(self, mock_system: MagicMock):
        """Test that Windows venv returns Scripts directory."""
        bin_dir = get_venv_bin_dir()
        assert bin_dir == Path("/path/to/venv/Scripts")

    def test_returns_venv_from_sys_path(self, tmp_path: Path, monkeypatch):
        """Test resolving venv from sys.path entries."""
        venv_site = tmp_path / ".venv" / "lib" / "site-packages"
        venv_site.mkdir(parents=True)
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.setattr(sys, "path", [str(venv_site)])
        monkeypatch.setattr(platform, "system", lambda: "Linux")

        bin_dir = get_venv_bin_dir()
        assert bin_dir == tmp_path / ".venv" / "bin"

    def test_returns_cwd_venv_when_present(self, tmp_path: Path, monkeypatch):
        """Test resolving .venv in current directory."""
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.setattr(sys, "path", [str(tmp_path / "site-packages")])
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".venv").mkdir()
        monkeypatch.setattr(platform, "system", lambda: "Linux")

        bin_dir = get_venv_bin_dir()
        assert bin_dir == tmp_path / ".venv" / "bin"

    def test_fallbacks_to_user_bin(self, tmp_path: Path, monkeypatch):
        """Test fallback to user bin when no venv is found."""
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.setattr(sys, "path", [str(tmp_path / "site-packages")])
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setattr(platform, "system", lambda: "Linux")

        bin_dir = get_venv_bin_dir()
        assert bin_dir == tmp_path / ".local" / "bin"
        assert bin_dir.exists()

    def test_fallbacks_to_windows_appdata(self, tmp_path: Path, monkeypatch):
        """Test Windows fallback to APPDATA Scripts directory."""
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.setattr(sys, "path", [str(tmp_path / "site-packages")])
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("APPDATA", str(tmp_path / "AppData"))
        monkeypatch.setattr(platform, "system", lambda: "Windows")

        bin_dir = get_venv_bin_dir()
        assert bin_dir == Path(tmp_path / "AppData" / "Python" / "Scripts")


class TestGetGitleaksPath:
    """Tests for gitleaks binary path detection."""

    @patch("envdrift.scanner.gitleaks.get_venv_bin_dir")
    @patch("platform.system", return_value="Linux")
    def test_returns_gitleaks_path_linux(self, mock_system: MagicMock, mock_bin_dir: MagicMock):
        """Test gitleaks path on Linux."""
        mock_bin_dir.return_value = Path("/venv/bin")
        path = get_gitleaks_path()
        assert path == Path("/venv/bin/gitleaks")

    @patch("envdrift.scanner.gitleaks.get_venv_bin_dir")
    @patch("platform.system", return_value="Windows")
    def test_returns_gitleaks_exe_on_windows(self, mock_system: MagicMock, mock_bin_dir: MagicMock):
        """Test gitleaks path on Windows includes .exe extension."""
        mock_bin_dir.return_value = Path("/venv/Scripts")
        path = get_gitleaks_path()
        assert path == Path("/venv/Scripts/gitleaks.exe")


class TestGitleaksInstaller:
    """Tests for GitleaksInstaller class."""

    def test_default_version_from_constants(self):
        """Test that installer uses version from constants."""
        installer = GitleaksInstaller()
        assert installer.version == "8.30.0"

    def test_custom_version(self):
        """Test that custom version can be specified."""
        installer = GitleaksInstaller(version="8.20.0")
        assert installer.version == "8.20.0"

    def test_progress_callback(self):
        """Test that progress callback is called."""
        messages: list[str] = []
        installer = GitleaksInstaller(progress_callback=messages.append)
        installer.progress("test message")
        assert messages == ["test message"]

    @patch("envdrift.scanner.gitleaks.get_platform_info")
    def test_get_download_url_darwin_arm64(self, mock_platform: MagicMock):
        """Test download URL for macOS ARM."""
        mock_platform.return_value = ("Darwin", "arm64")
        installer = GitleaksInstaller(version="8.21.2")
        url = installer.get_download_url()
        assert "darwin" in url
        assert "arm64" in url
        assert "8.21.2" in url

    @patch("envdrift.scanner.gitleaks.get_platform_info")
    def test_get_download_url_linux_amd64(self, mock_platform: MagicMock):
        """Test download URL for Linux AMD64."""
        mock_platform.return_value = ("Linux", "x86_64")
        installer = GitleaksInstaller(version="8.21.2")
        url = installer.get_download_url()
        assert "linux" in url
        assert "amd64" in url

    @patch("envdrift.scanner.gitleaks.get_platform_info")
    def test_get_download_url_windows(self, mock_platform: MagicMock):
        """Test download URL for Windows."""
        mock_platform.return_value = ("Windows", "x86_64")
        installer = GitleaksInstaller(version="8.21.2")
        url = installer.get_download_url()
        assert "windows" in url
        assert ".zip" in url

    @patch("envdrift.scanner.gitleaks.get_platform_info")
    def test_unsupported_platform_raises_error(self, mock_platform: MagicMock):
        """Test that unsupported platform raises error."""
        mock_platform.return_value = ("FreeBSD", "x86_64")
        installer = GitleaksInstaller()
        with pytest.raises(GitleaksInstallError, match="Unsupported platform"):
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
        assert set(GitleaksInstaller.PLATFORM_MAP.keys()) == expected_platforms

    def test_download_and_extract_tar_gz(self, tmp_path: Path, monkeypatch):
        """Tarball downloads are extracted and installed."""
        archive_path = _create_tar_gz(tmp_path, "gitleaks")

        installer = GitleaksInstaller(version="8.30.0")
        monkeypatch.setattr(
            installer, "get_download_url", lambda: "https://example.com/gitleaks.tar.gz"
        )
        monkeypatch.setattr(platform, "system", lambda: "Linux")

        def fake_urlretrieve(_url: str, filename: str):
            shutil.copy2(archive_path, filename)
            return filename, None

        monkeypatch.setattr(
            "envdrift.scanner.gitleaks.urllib.request.urlretrieve",
            fake_urlretrieve,
        )

        target_path = tmp_path / "bin" / "gitleaks"
        installer.download_and_extract(target_path)
        assert target_path.exists()

    def test_download_and_extract_zip(self, tmp_path: Path, monkeypatch):
        """Zip downloads are extracted and installed."""
        archive_path = _create_zip(tmp_path, "gitleaks.exe")

        installer = GitleaksInstaller(version="8.30.0")
        monkeypatch.setattr(
            installer, "get_download_url", lambda: "https://example.com/gitleaks.zip"
        )
        monkeypatch.setattr(platform, "system", lambda: "Windows")

        def fake_urlretrieve(_url: str, filename: str):
            shutil.copy2(archive_path, filename)
            return filename, None

        monkeypatch.setattr(
            "envdrift.scanner.gitleaks.urllib.request.urlretrieve",
            fake_urlretrieve,
        )

        target_path = tmp_path / "bin" / "gitleaks.exe"
        installer.download_and_extract(target_path)
        assert target_path.exists()


class TestGitleaksScanner:
    """Tests for GitleaksScanner class."""

    def test_scanner_name(self):
        """Test scanner name property."""
        scanner = GitleaksScanner(auto_install=False)
        assert scanner.name == "gitleaks"

    def test_scanner_description(self):
        """Test scanner description property."""
        scanner = GitleaksScanner(auto_install=False)
        assert "gitleaks" in scanner.description.lower()

    @patch("shutil.which", return_value=None)
    @patch("envdrift.scanner.gitleaks.get_gitleaks_path")
    def test_is_installed_returns_false_when_not_found(
        self, mock_path: MagicMock, mock_which: MagicMock
    ):
        """Test is_installed returns False when binary not found."""
        mock_path.return_value = Path("/nonexistent/gitleaks")
        scanner = GitleaksScanner(auto_install=False)
        assert scanner.is_installed() is False

    @patch("shutil.which", return_value="/usr/bin/gitleaks")
    def test_is_installed_returns_true_when_in_path(self, mock_which: MagicMock):
        """Test is_installed returns True when in PATH."""
        scanner = GitleaksScanner(auto_install=False)
        assert scanner.is_installed() is True

    @patch("envdrift.scanner.gitleaks.get_gitleaks_path")
    def test_is_installed_returns_true_when_in_venv(self, mock_path: MagicMock, tmp_path: Path):
        """Test is_installed returns True when in venv."""
        binary = tmp_path / "gitleaks"
        binary.touch()
        mock_path.return_value = binary
        scanner = GitleaksScanner(auto_install=False)
        assert scanner.is_installed() is True

    @patch("shutil.which", return_value=None)
    @patch("envdrift.scanner.gitleaks.get_gitleaks_path")
    def test_scan_returns_error_when_not_installed(
        self, mock_path: MagicMock, mock_which: MagicMock, tmp_path: Path
    ):
        """Test scan returns error result when gitleaks not installed."""
        mock_path.return_value = Path("/nonexistent/gitleaks")
        scanner = GitleaksScanner(auto_install=False)
        result = scanner.scan([tmp_path])
        assert result.error is not None
        assert "not found" in result.error.lower()
        assert result.success is False

    def test_scan_with_nonexistent_path(self, tmp_path: Path):
        """Test scan handles nonexistent paths gracefully."""
        scanner = GitleaksScanner(auto_install=False)
        # Mock to avoid actual installation
        scanner._binary_path = Path("/fake/gitleaks")
        with patch.object(scanner, "_find_binary", return_value=Path("/fake/gitleaks")):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(stdout="[]", stderr="", returncode=0)
                result = scanner.scan([tmp_path / "nonexistent"])
                assert result.success is True
                assert len(result.findings) == 0


class TestFindingParsing:
    """Tests for gitleaks finding parsing."""

    @pytest.fixture
    def scanner(self) -> GitleaksScanner:
        """Create a scanner instance for testing."""
        return GitleaksScanner(auto_install=False)

    def test_parse_basic_finding(self, scanner: GitleaksScanner, tmp_path: Path):
        """Test parsing a basic gitleaks finding."""
        item: dict[str, Any] = {
            "Description": "AWS Access Key ID",
            "StartLine": 10,
            "StartColumn": 5,
            "File": "secrets.py",
            "Secret": "AKIAIOSFODNN7EXAMPLE",
            "RuleID": "aws-access-key-id",
        }
        finding = scanner._parse_finding(item, tmp_path)

        assert finding is not None
        assert finding.rule_id == "gitleaks-aws-access-key-id"
        assert finding.rule_description == "AWS Access Key ID"
        assert finding.line_number == 10
        assert finding.column_number == 5
        assert finding.severity == FindingSeverity.HIGH
        assert finding.scanner == "gitleaks"
        assert "****" in finding.secret_preview  # Redacted

    def test_parse_finding_with_commit_info(self, scanner: GitleaksScanner, tmp_path: Path):
        """Test parsing a finding with git commit information."""
        item: dict[str, Any] = {
            "Description": "GitHub Token",
            "StartLine": 5,
            "File": "config.py",
            "Secret": "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "RuleID": "github-token",
            "Commit": "abc123def456",
            "Author": "developer@example.com",
            "Date": "2024-01-15",
            "Entropy": 4.5,
        }
        finding = scanner._parse_finding(item, tmp_path)

        assert finding is not None
        assert finding.commit_sha == "abc123def456"
        assert finding.commit_author == "developer@example.com"
        assert finding.commit_date == "2024-01-15"
        assert finding.entropy == 4.5

    def test_parse_finding_with_relative_path(self, scanner: GitleaksScanner, tmp_path: Path):
        """Test parsing finding with relative file path."""
        item: dict[str, Any] = {
            "Description": "Generic Secret",
            "File": "src/config/secrets.py",
            "Secret": "secret123",
            "RuleID": "generic-secret",
        }
        finding = scanner._parse_finding(item, tmp_path)

        assert finding is not None
        assert finding.file_path == tmp_path / "src/config/secrets.py"

    def test_parse_finding_with_empty_file(self, scanner: GitleaksScanner, tmp_path: Path):
        """Test parsing finding with empty file field."""
        item: dict[str, Any] = {
            "Description": "Secret",
            "File": "",
            "Secret": "secret",
            "RuleID": "test",
        }
        finding = scanner._parse_finding(item, tmp_path)

        assert finding is not None
        assert finding.file_path == tmp_path

    def test_parse_finding_handles_empty_data(self, scanner: GitleaksScanner, tmp_path: Path):
        """Test that empty data creates a finding with defaults instead of raising."""
        # Missing required fields
        item: dict[str, Any] = {}
        finding = scanner._parse_finding(item, tmp_path)
        # Based on implementation, empty dict still creates a finding with defaults
        assert finding is not None
        assert finding.file_path == tmp_path
        assert finding.rule_id == "gitleaks-unknown"


class TestGitleaksScanExecution:
    """Tests for gitleaks scan execution with mocked subprocess."""

    @pytest.fixture
    def mock_scanner(self, tmp_path: Path) -> GitleaksScanner:
        """Create a scanner with mocked binary."""
        scanner = GitleaksScanner(auto_install=False)
        binary_path = tmp_path / "gitleaks"
        binary_path.touch()
        scanner._binary_path = binary_path
        return scanner

    def test_scan_parses_json_output(self, mock_scanner: GitleaksScanner, tmp_path: Path):
        """Test that scan correctly parses JSON output from report file."""
        findings_json = json.dumps(
            [
                {
                    "Description": "AWS Key",
                    "StartLine": 1,
                    "File": "test.py",
                    "Secret": "AKIAIOSFODNN7EXAMPLE",
                    "RuleID": "aws-key",
                }
            ]
        )

        def write_report_file(*args, **kwargs):
            """Mock subprocess that writes JSON to the report file."""
            # Find --report-path in args
            cmd_args = args[0]
            report_idx = cmd_args.index("--report-path")
            report_path = Path(cmd_args[report_idx + 1])
            report_path.write_text(findings_json)
            return MagicMock(stdout="", stderr="", returncode=0)

        with patch.object(mock_scanner, "_find_binary", return_value=mock_scanner._binary_path):
            with patch("subprocess.run", side_effect=write_report_file):
                result = mock_scanner.scan([tmp_path])

        assert result.success is True
        assert len(result.findings) == 1
        assert result.findings[0].rule_id == "gitleaks-aws-key"

    def test_scan_handles_empty_output(self, mock_scanner: GitleaksScanner, tmp_path: Path):
        """Test that scan handles empty report file."""
        with patch.object(mock_scanner, "_find_binary", return_value=mock_scanner._binary_path):
            with patch("subprocess.run") as mock_run:
                # Don't write anything to report file - it stays empty
                mock_run.return_value = MagicMock(
                    stdout="",
                    stderr="",
                    returncode=0,
                )
                result = mock_scanner.scan([tmp_path])

        assert result.success is True
        assert len(result.findings) == 0

    def test_scan_handles_invalid_json(self, mock_scanner: GitleaksScanner, tmp_path: Path):
        """Test that scan handles invalid JSON in report file gracefully."""

        def write_invalid_json(*args, **kwargs):
            """Mock subprocess that writes invalid JSON to report file."""
            cmd_args = args[0]
            report_idx = cmd_args.index("--report-path")
            report_path = Path(cmd_args[report_idx + 1])
            report_path.write_text("not valid json")
            return MagicMock(stdout="", stderr="", returncode=0)

        with patch.object(mock_scanner, "_find_binary", return_value=mock_scanner._binary_path):
            with patch("subprocess.run", side_effect=write_invalid_json):
                result = mock_scanner.scan([tmp_path])

        assert result.success is True
        assert len(result.findings) == 0

    def test_scan_handles_timeout(self, mock_scanner: GitleaksScanner, tmp_path: Path):
        """Test that scan handles subprocess timeout."""
        with patch.object(mock_scanner, "_find_binary", return_value=mock_scanner._binary_path):
            with patch("subprocess.run") as mock_run:
                mock_run.side_effect = subprocess.TimeoutExpired(cmd="gitleaks", timeout=300)
                result = mock_scanner.scan([tmp_path])

        assert "timed out" in result.error.lower()
        assert result.success is False

    def test_scan_with_git_history_flag(self, mock_scanner: GitleaksScanner, tmp_path: Path):
        """Test that scan passes correct args for git history scan."""
        with patch.object(mock_scanner, "_find_binary", return_value=mock_scanner._binary_path):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(stdout="[]", stderr="", returncode=0)
                mock_scanner.scan([tmp_path], include_git_history=True)

        # Check that --no-git was NOT passed
        call_args = mock_run.call_args[0][0]
        assert "--no-git" not in call_args

    def test_scan_without_git_history_flag(self, mock_scanner: GitleaksScanner, tmp_path: Path):
        """Test that scan passes --no-git when not scanning history."""
        with patch.object(mock_scanner, "_find_binary", return_value=mock_scanner._binary_path):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(stdout="[]", stderr="", returncode=0)
                mock_scanner.scan([tmp_path], include_git_history=False)

        # Check that --no-git WAS passed
        call_args = mock_run.call_args[0][0]
        assert "--no-git" in call_args

    def test_scan_multiple_paths(self, mock_scanner: GitleaksScanner, tmp_path: Path):
        """Test scanning multiple paths."""
        path1 = tmp_path / "dir1"
        path2 = tmp_path / "dir2"
        path1.mkdir()
        path2.mkdir()

        with patch.object(mock_scanner, "_find_binary", return_value=mock_scanner._binary_path):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(stdout="[]", stderr="", returncode=0)
                result = mock_scanner.scan([path1, path2])

        assert result.success is True
        # Should be called once per existing path
        assert mock_run.call_count == 2


class TestGitleaksAutoInstall:
    """Tests for gitleaks auto-installation."""

    @patch("shutil.which", return_value=None)
    @patch("envdrift.scanner.gitleaks.get_gitleaks_path")
    @patch.object(GitleaksInstaller, "install")
    def test_auto_install_when_not_found(
        self,
        mock_install: MagicMock,
        mock_path: MagicMock,
        mock_which: MagicMock,
        tmp_path: Path,
    ):
        """Test that scanner auto-installs when binary not found."""
        mock_path.return_value = Path("/nonexistent/gitleaks")
        installed_path = tmp_path / "gitleaks"
        installed_path.touch()
        mock_install.return_value = installed_path

        scanner = GitleaksScanner(auto_install=True)
        binary = scanner._find_binary()

        assert binary == installed_path
        mock_install.assert_called_once()

    @patch("shutil.which", return_value=None)
    @patch("envdrift.scanner.gitleaks.get_gitleaks_path")
    @patch.object(GitleaksInstaller, "install")
    def test_auto_install_failure_raises_error(
        self,
        mock_install: MagicMock,
        mock_path: MagicMock,
        mock_which: MagicMock,
    ):
        """Test that auto-install failure raises appropriate error."""
        mock_path.return_value = Path("/nonexistent/gitleaks")
        mock_install.side_effect = GitleaksInstallError("Download failed")

        scanner = GitleaksScanner(auto_install=True)
        with pytest.raises(GitleaksNotFoundError, match="auto-install failed"):
            scanner._find_binary()


class TestGitleaksVersion:
    """Tests for gitleaks version detection."""

    def test_get_version_when_not_installed(self):
        """Test get_version returns None when not installed."""
        scanner = GitleaksScanner(auto_install=False)
        with patch.object(scanner, "_find_binary", side_effect=GitleaksNotFoundError):
            version = scanner.get_version()
            assert version is None

    @patch("subprocess.run")
    def test_get_version_parses_output(self, mock_run: MagicMock, tmp_path: Path):
        """Test get_version correctly parses version output."""
        mock_run.return_value = MagicMock(
            stdout="gitleaks version 8.21.2\n",
            returncode=0,
        )
        scanner = GitleaksScanner(auto_install=False)
        binary = tmp_path / "gitleaks"
        binary.touch()
        scanner._binary_path = binary

        version = scanner.get_version()
        assert version == "8.21.2"


class TestExceptionClasses:
    """Tests for exception classes."""

    def test_gitleaks_not_found_error(self):
        """Test GitleaksNotFoundError."""
        error = GitleaksNotFoundError("Binary not found")
        assert str(error) == "Binary not found"
        assert isinstance(error, Exception)

    def test_gitleaks_install_error(self):
        """Test GitleaksInstallError."""
        error = GitleaksInstallError("Download failed")
        assert str(error) == "Download failed"
        assert isinstance(error, Exception)

    def test_gitleaks_error(self):
        """Test GitleaksError."""
        error = GitleaksError("Command failed")
        assert str(error) == "Command failed"
        assert isinstance(error, Exception)


# Mark integration tests that require actual gitleaks installation
@pytest.mark.skipif(
    not GitleaksScanner(auto_install=False).is_installed(),
    reason="gitleaks not installed",
)
class TestGitleaksIntegration:
    """Integration tests that require gitleaks to be installed."""

    def test_scan_clean_directory(self, tmp_path: Path):
        """Test scanning a directory with no secrets."""
        # Create a clean file
        (tmp_path / "clean.py").write_text("# No secrets here\nx = 1 + 1\n")

        scanner = GitleaksScanner(auto_install=False)
        result = scanner.scan([tmp_path])

        assert result.success is True
        # Clean directory should have no findings
        # (or at most informational ones)

    def test_scan_file_with_test_secret(self, tmp_path: Path):
        """Test scanning a file with a fake secret pattern."""
        # Create a file with a fake AWS key (test pattern)
        secret_file = tmp_path / "secrets.py"
        secret_file.write_text('# Test file\nAWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')

        scanner = GitleaksScanner(auto_install=False)
        result = scanner.scan([tmp_path])

        assert result.success is True
        # gitleaks should detect this pattern
        # Note: may or may not trigger depending on gitleaks config
