"""Tests for infisical scanner integration."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from envdrift.scanner.base import FindingSeverity
from envdrift.scanner.infisical import (
    InfisicalInstaller,
    InfisicalInstallError,
    InfisicalNotFoundError,
    InfisicalScanner,
    get_infisical_path,
    get_platform_info,
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


class TestGetInfisicalPath:
    """Tests for infisical binary path detection."""

    @patch("envdrift.scanner.infisical.get_venv_bin_dir")
    @patch("platform.system", return_value="Linux")
    def test_returns_infisical_path_linux(self, mock_system: MagicMock, mock_bin_dir: MagicMock):
        """Test infisical path on Linux."""
        mock_bin_dir.return_value = Path("/venv/bin")
        path = get_infisical_path()
        assert path == Path("/venv/bin/infisical")

    @patch("envdrift.scanner.infisical.get_venv_bin_dir")
    @patch("platform.system", return_value="Windows")
    def test_returns_infisical_exe_on_windows(
        self, mock_system: MagicMock, mock_bin_dir: MagicMock
    ):
        """Test infisical path on Windows includes .exe extension."""
        mock_bin_dir.return_value = Path("/venv/Scripts")
        path = get_infisical_path()
        assert path == Path("/venv/Scripts/infisical.exe")


class TestInfisicalInstaller:
    """Tests for InfisicalInstaller class."""

    def test_default_version_from_constants(self):
        """Test that installer uses version from constants."""
        installer = InfisicalInstaller()
        assert installer.version == "0.31.1"

    def test_custom_version(self):
        """Test that custom version can be specified."""
        installer = InfisicalInstaller(version="0.30.0")
        assert installer.version == "0.30.0"

    def test_progress_callback(self):
        """Test that progress callback is called."""
        messages: list[str] = []
        installer = InfisicalInstaller(progress_callback=messages.append)
        installer.progress("test message")
        assert messages == ["test message"]

    @patch("envdrift.scanner.infisical.get_platform_info")
    def test_get_download_url_darwin_arm64(self, mock_platform: MagicMock):
        """Test download URL for macOS ARM."""
        mock_platform.return_value = ("Darwin", "arm64")
        installer = InfisicalInstaller(version="0.31.1")
        url = installer.get_download_url()
        assert "darwin" in url.lower()
        assert "arm64" in url.lower()
        assert "0.31.1" in url

    @patch("envdrift.scanner.infisical.get_platform_info")
    def test_get_download_url_linux_amd64(self, mock_platform: MagicMock):
        """Test download URL for Linux AMD64."""
        mock_platform.return_value = ("Linux", "x86_64")
        installer = InfisicalInstaller(version="0.31.1")
        url = installer.get_download_url()
        assert "linux" in url.lower()
        assert "amd64" in url.lower()

    @patch("envdrift.scanner.infisical.get_platform_info")
    def test_get_download_url_windows(self, mock_platform: MagicMock):
        """Test download URL for Windows."""
        mock_platform.return_value = ("Windows", "x86_64")
        installer = InfisicalInstaller(version="0.31.1")
        url = installer.get_download_url()
        assert "windows" in url.lower()
        assert ".zip" in url

    @patch("envdrift.scanner.infisical.get_platform_info")
    def test_unsupported_platform_raises_error(self, mock_platform: MagicMock):
        """Test that unsupported platform raises error."""
        mock_platform.return_value = ("FreeBSD", "x86_64")
        installer = InfisicalInstaller()
        with pytest.raises(InfisicalInstallError, match="Unsupported platform"):
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
        assert set(InfisicalInstaller.PLATFORM_MAP.keys()) == expected_platforms


class TestInfisicalScanner:
    """Tests for InfisicalScanner class."""

    def test_scanner_name(self):
        """Test scanner name property."""
        scanner = InfisicalScanner(auto_install=False)
        assert scanner.name == "infisical"

    def test_scanner_description(self):
        """Test scanner description property."""
        scanner = InfisicalScanner(auto_install=False)
        assert "infisical" in scanner.description.lower()
        assert "140+" in scanner.description

    @patch("shutil.which", return_value=None)
    @patch("envdrift.scanner.infisical.get_infisical_path")
    def test_is_installed_returns_false_when_not_found(
        self, mock_path: MagicMock, mock_which: MagicMock
    ):
        """Test is_installed returns False when binary not found."""
        mock_path.return_value = Path("/nonexistent/infisical")
        scanner = InfisicalScanner(auto_install=False)
        assert scanner.is_installed() is False

    @patch("shutil.which", return_value="/usr/bin/infisical")
    def test_is_installed_returns_true_when_in_path(self, mock_which: MagicMock):
        """Test is_installed returns True when in PATH."""
        scanner = InfisicalScanner(auto_install=False)
        assert scanner.is_installed() is True

    @patch("envdrift.scanner.infisical.get_infisical_path")
    def test_is_installed_returns_true_when_in_venv(self, mock_path: MagicMock, tmp_path: Path):
        """Test is_installed returns True when in venv."""
        binary = tmp_path / "infisical"
        binary.touch()
        mock_path.return_value = binary
        scanner = InfisicalScanner(auto_install=False)
        assert scanner.is_installed() is True

    @patch("shutil.which", return_value=None)
    @patch("envdrift.scanner.infisical.get_infisical_path")
    def test_scan_returns_error_when_not_installed(
        self, mock_path: MagicMock, mock_which: MagicMock, tmp_path: Path
    ):
        """Test scan returns error result when infisical not installed."""
        mock_path.return_value = Path("/nonexistent/infisical")
        scanner = InfisicalScanner(auto_install=False)
        result = scanner.scan([tmp_path])
        assert result.error is not None
        assert "not found" in result.error.lower()
        assert result.success is False

    def test_scan_with_nonexistent_path(self, tmp_path: Path):
        """Test scan handles nonexistent paths gracefully."""
        scanner = InfisicalScanner(auto_install=False)
        scanner._binary_path = Path("/fake/infisical")
        with patch.object(scanner, "_find_binary", return_value=Path("/fake/infisical")):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(stdout="[]", stderr="", returncode=0)
                result = scanner.scan([tmp_path / "nonexistent"])
                assert result.success is True
                assert len(result.findings) == 0


class TestFindingParsing:
    """Tests for infisical finding parsing."""

    @pytest.fixture
    def scanner(self) -> InfisicalScanner:
        """
        Create an InfisicalScanner configured to not auto-install for use in tests.

        Returns:
            scanner (InfisicalScanner): An InfisicalScanner instance with auto_install set to False.
        """
        return InfisicalScanner(auto_install=False)

    def test_parse_basic_finding(self, scanner: InfisicalScanner, tmp_path: Path):
        """Test parsing a basic infisical finding."""
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
        assert finding.rule_id == "infisical-aws-access-key-id"
        assert finding.rule_description == "AWS Access Key ID"
        assert finding.line_number == 10
        assert finding.column_number == 5
        assert finding.severity == FindingSeverity.CRITICAL  # aws-access-key-id maps to CRITICAL
        assert finding.scanner == "infisical"
        assert "****" in finding.secret_preview  # Redacted

    def test_parse_finding_with_commit_info(self, scanner: InfisicalScanner, tmp_path: Path):
        """Test parsing a finding with git commit information."""
        item: dict[str, Any] = {
            "Description": "GitHub Token",
            "StartLine": 5,
            "File": "config.py",
            "Secret": "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "RuleID": "github-pat",
            "Commit": "abc123def456",
            "Author": "developer@example.com",
            "Email": "developer@example.com",
            "Date": "2024-01-15",
            "Entropy": 4.5,
        }
        finding = scanner._parse_finding(item, tmp_path)

        assert finding is not None
        assert finding.commit_sha == "abc123def456"
        assert finding.commit_author == "developer@example.com"
        assert finding.commit_date == "2024-01-15"
        assert finding.entropy == 4.5
        assert finding.severity == FindingSeverity.CRITICAL  # github-pat maps to CRITICAL

    def test_parse_finding_with_relative_path(self, scanner: InfisicalScanner, tmp_path: Path):
        """Test parsing finding with relative file path."""
        item: dict[str, Any] = {
            "Description": "Generic Secret",
            "File": "src/config/secrets.py",
            "Secret": "secret123",
            "RuleID": "generic-api-key",
        }
        finding = scanner._parse_finding(item, tmp_path)

        assert finding is not None
        assert finding.file_path == tmp_path / "src/config/secrets.py"
        assert finding.severity == FindingSeverity.HIGH  # generic-api-key maps to HIGH

    def test_parse_finding_with_empty_file(self, scanner: InfisicalScanner, tmp_path: Path):
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

    def test_parse_finding_handles_empty_data(self, scanner: InfisicalScanner, tmp_path: Path):
        """Test that empty data creates a finding with defaults."""
        item: dict[str, Any] = {}
        finding = scanner._parse_finding(item, tmp_path)
        assert finding is not None
        assert finding.file_path == tmp_path
        assert finding.rule_id == "infisical-unknown"

    def test_parse_finding_unknown_rule_gets_high_severity(
        self, scanner: InfisicalScanner, tmp_path: Path
    ):
        """Test that unknown rules get HIGH severity by default."""
        item: dict[str, Any] = {
            "Description": "Unknown Secret Type",
            "File": "test.py",
            "RuleID": "some-unknown-rule",
        }
        finding = scanner._parse_finding(item, tmp_path)

        assert finding is not None
        assert finding.severity == FindingSeverity.HIGH


class TestInfisicalScanExecution:
    """Tests for infisical scan execution with mocked subprocess."""

    @pytest.fixture
    def mock_scanner(self, tmp_path: Path) -> InfisicalScanner:
        """
        Create an InfisicalScanner instance whose binary path points to a temporary file.

        Parameters:
            tmp_path (Path): Temporary directory in which the mock infisical binary will be created.

        Returns:
            scanner (InfisicalScanner): Scanner with its `_binary_path` set to the created mock binary file.
        """
        scanner = InfisicalScanner(auto_install=False)
        binary_path = tmp_path / "infisical"
        binary_path.touch()
        scanner._binary_path = binary_path
        return scanner

    def test_scan_parses_json_output(self, mock_scanner: InfisicalScanner, tmp_path: Path):
        """Test that scan correctly parses JSON output from report file."""
        findings_json = json.dumps(
            [
                {
                    "Description": "AWS Key",
                    "StartLine": 1,
                    "File": "test.py",
                    "Secret": "AKIAIOSFODNN7EXAMPLE",
                    "RuleID": "aws-access-key-id",
                }
            ]
        )

        def write_report_file(*args, **kwargs):
            """
            Mock subprocess replacement that writes predefined JSON to the report file specified in the command arguments.

            Searches the provided command arguments for the "--report-path" flag, writes the module-level `findings_json` content to that path, and returns a process-like mock.

            Returns:
                process (unittest.mock.MagicMock): Mock process with `stdout` set to an empty string, `stderr` set to an empty string, and `returncode` set to 0.
            """
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
        assert result.findings[0].rule_id == "infisical-aws-access-key-id"

    def test_scan_handles_empty_output(self, mock_scanner: InfisicalScanner, tmp_path: Path):
        """Test that scan handles empty report file."""
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

    def test_scan_handles_invalid_json(self, mock_scanner: InfisicalScanner, tmp_path: Path):
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

    def test_scan_handles_timeout(self, mock_scanner: InfisicalScanner, tmp_path: Path):
        """Test that scan handles subprocess timeout."""
        with patch.object(mock_scanner, "_find_binary", return_value=mock_scanner._binary_path):
            with patch("subprocess.run") as mock_run:
                mock_run.side_effect = subprocess.TimeoutExpired(cmd="infisical", timeout=300)
                result = mock_scanner.scan([tmp_path])

        assert "timed out" in result.error.lower()
        assert result.success is False

    def test_scan_handles_nonzero_exit_code(self, mock_scanner: InfisicalScanner, tmp_path: Path):
        """Test that scan handles non-zero exit code with error."""
        with patch.object(mock_scanner, "_find_binary", return_value=mock_scanner._binary_path):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    stdout="",
                    stderr="infisical: command failed",
                    returncode=1,
                )
                result = mock_scanner.scan([tmp_path])

        assert result.success is False
        assert "command failed" in result.error.lower()

    def test_scan_uses_source_flag(self, mock_scanner: InfisicalScanner, tmp_path: Path):
        """Test that scan passes --source flag with correct path."""
        with patch.object(mock_scanner, "_find_binary", return_value=mock_scanner._binary_path):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(stdout="[]", stderr="", returncode=0)
                mock_scanner.scan([tmp_path])

        # Check that --source was passed with the correct path
        call_args = mock_run.call_args[0][0]
        assert "--source" in call_args
        source_idx = call_args.index("--source")
        assert call_args[source_idx + 1] == str(tmp_path)

    def test_scan_with_git_history_flag(self, mock_scanner: InfisicalScanner, tmp_path: Path):
        """Test that scan passes correct args for git history scan."""
        with patch.object(mock_scanner, "_find_binary", return_value=mock_scanner._binary_path):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(stdout="[]", stderr="", returncode=0)
                mock_scanner.scan([tmp_path], include_git_history=True)

        # Check that --no-git was NOT passed
        call_args = mock_run.call_args[0][0]
        assert "--no-git" not in call_args

    def test_scan_without_git_history_flag(self, mock_scanner: InfisicalScanner, tmp_path: Path):
        """Test that scan passes --no-git when not scanning history."""
        with patch.object(mock_scanner, "_find_binary", return_value=mock_scanner._binary_path):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(stdout="[]", stderr="", returncode=0)
                mock_scanner.scan([tmp_path], include_git_history=False)

        # Check that --no-git WAS passed
        call_args = mock_run.call_args[0][0]
        assert "--no-git" in call_args

    def test_scan_multiple_paths(self, mock_scanner: InfisicalScanner, tmp_path: Path):
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


class TestInfisicalAutoInstall:
    """Tests for infisical auto-installation."""

    @patch("shutil.which", return_value=None)
    @patch("envdrift.scanner.infisical.get_infisical_path")
    @patch.object(InfisicalInstaller, "install")
    def test_auto_install_when_not_found(
        self,
        mock_install: MagicMock,
        mock_path: MagicMock,
        mock_which: MagicMock,
        tmp_path: Path,
    ):
        """Test that scanner auto-installs when binary not found."""
        mock_path.return_value = Path("/nonexistent/infisical")
        installed_path = tmp_path / "infisical"
        installed_path.touch()
        mock_install.return_value = installed_path

        scanner = InfisicalScanner(auto_install=True)
        binary = scanner._find_binary()

        assert binary == installed_path
        mock_install.assert_called_once()

    @patch("shutil.which", return_value=None)
    @patch("envdrift.scanner.infisical.get_infisical_path")
    @patch.object(InfisicalInstaller, "install")
    def test_auto_install_failure_raises_error(
        self,
        mock_install: MagicMock,
        mock_path: MagicMock,
        mock_which: MagicMock,
    ):
        """Test that auto-install failure raises appropriate error."""
        mock_path.return_value = Path("/nonexistent/infisical")
        mock_install.side_effect = InfisicalInstallError("Download failed")

        scanner = InfisicalScanner(auto_install=True)
        with pytest.raises(InfisicalNotFoundError, match="auto-install failed"):
            scanner._find_binary()


class TestExceptionClasses:
    """Tests for exception classes."""

    def test_infisical_not_found_error(self):
        """Test InfisicalNotFoundError."""
        error = InfisicalNotFoundError("Binary not found")
        assert str(error) == "Binary not found"
        assert isinstance(error, Exception)

    def test_infisical_install_error(self):
        """Test InfisicalInstallError."""
        error = InfisicalInstallError("Download failed")
        assert str(error) == "Download failed"
        assert isinstance(error, Exception)


class TestInfisicalInstallerDownload:
    """Tests for InfisicalInstaller download functionality."""

    @patch("envdrift.scanner.platform_utils.platform.system", return_value="Darwin")
    @patch("envdrift.scanner.platform_utils.platform.machine", return_value="arm64")
    def test_get_download_url_darwin_arm64(self, mock_machine: MagicMock, mock_system: MagicMock):
        """Test download URL generation for macOS ARM64."""
        installer = InfisicalInstaller()
        url = installer.get_download_url()
        assert "darwin" in url.lower()
        assert "arm64" in url.lower()
        assert installer.version in url

    @patch("envdrift.scanner.platform_utils.platform.system", return_value="Linux")
    @patch("envdrift.scanner.platform_utils.platform.machine", return_value="x86_64")
    def test_get_download_url_linux_x64(self, mock_machine: MagicMock, mock_system: MagicMock):
        """Test download URL generation for Linux x86_64."""
        installer = InfisicalInstaller()
        url = installer.get_download_url()
        assert "linux" in url.lower()

    @patch("envdrift.scanner.platform_utils.platform.system", return_value="Windows")
    @patch("envdrift.scanner.platform_utils.platform.machine", return_value="AMD64")
    def test_get_download_url_windows(self, mock_machine: MagicMock, mock_system: MagicMock):
        """Test download URL generation for Windows."""
        installer = InfisicalInstaller()
        url = installer.get_download_url()
        assert "windows" in url.lower()
        assert url.endswith(".zip")

    @patch("envdrift.scanner.platform_utils.platform.system", return_value="FreeBSD")
    @patch("envdrift.scanner.platform_utils.platform.machine", return_value="x86_64")
    def test_get_download_url_unsupported_platform(
        self, mock_machine: MagicMock, mock_system: MagicMock
    ):
        """Test download URL raises error for unsupported platform."""
        installer = InfisicalInstaller()
        with pytest.raises(InfisicalInstallError, match="Unsupported platform"):
            installer.get_download_url()

    def test_installer_with_custom_version(self):
        """Test installer with custom version."""
        installer = InfisicalInstaller(version="0.30.0")
        assert installer.version == "0.30.0"

    def test_installer_with_progress_callback(self):
        """Test installer with progress callback."""
        messages: list[str] = []
        installer = InfisicalInstaller(progress_callback=messages.append)
        installer.progress("Test message")
        assert "Test message" in messages


class TestInfisicalInstallerExtraction:
    """Tests for InfisicalInstaller extraction methods."""

    def test_extract_tar_gz(self, tmp_path: Path):
        """Test tar.gz extraction."""
        import io
        import tarfile

        archive_path = tmp_path / "test.tar.gz"
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()

        test_file_content = b"test content"
        with tarfile.open(archive_path, "w:gz") as tar:
            info = tarfile.TarInfo(name="testfile.txt")
            info.size = len(test_file_content)
            tar.addfile(info, io.BytesIO(test_file_content))

        installer = InfisicalInstaller()
        installer._extract_tar_gz(archive_path, extract_dir)

        assert (extract_dir / "testfile.txt").exists()
        assert (extract_dir / "testfile.txt").read_bytes() == test_file_content

    def test_extract_zip(self, tmp_path: Path):
        """Test zip extraction."""
        import zipfile

        archive_path = tmp_path / "test.zip"
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()

        with zipfile.ZipFile(archive_path, "w") as zf:
            zf.writestr("testfile.txt", "test content")

        installer = InfisicalInstaller()
        installer._extract_zip(archive_path, extract_dir)

        assert (extract_dir / "testfile.txt").exists()
        assert (extract_dir / "testfile.txt").read_text() == "test content"

    def test_extract_tar_gz_path_traversal_blocked(self, tmp_path: Path):
        """Test that path traversal attacks are blocked in tar.gz."""
        import io
        import tarfile

        archive_path = tmp_path / "malicious.tar.gz"
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()

        with tarfile.open(archive_path, "w:gz") as tar:
            info = tarfile.TarInfo(name="../../../etc/passwd")
            info.size = 4
            tar.addfile(info, io.BytesIO(b"test"))

        installer = InfisicalInstaller()
        with pytest.raises(InfisicalInstallError, match="Unsafe path"):
            installer._extract_tar_gz(archive_path, extract_dir)

    def test_extract_zip_path_traversal_blocked(self, tmp_path: Path):
        """Test that path traversal attacks are blocked in zip."""
        import zipfile

        archive_path = tmp_path / "malicious.zip"
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()

        with zipfile.ZipFile(archive_path, "w") as zf:
            zf.writestr("../../../etc/passwd", "test")

        installer = InfisicalInstaller()
        with pytest.raises(InfisicalInstallError, match="Unsafe path"):
            installer._extract_zip(archive_path, extract_dir)


class TestInfisicalInstallerInstall:
    """Tests for InfisicalInstaller.install method."""

    @patch("envdrift.scanner.infisical.get_infisical_path")
    @patch("urllib.request.urlretrieve")
    @patch("envdrift.scanner.platform_utils.platform.system", return_value="Linux")
    @patch("envdrift.scanner.platform_utils.platform.machine", return_value="x86_64")
    def test_install_success(
        self,
        mock_machine: MagicMock,
        mock_system: MagicMock,
        mock_urlretrieve: MagicMock,
        mock_get_path: MagicMock,
        tmp_path: Path,
    ):
        """Test successful installation."""
        import io
        import tarfile

        target_path = tmp_path / "bin" / "infisical"
        target_path.parent.mkdir(parents=True, exist_ok=True)
        mock_get_path.return_value = target_path

        def fake_download(url: str, dest: str) -> None:
            with tarfile.open(dest, "w:gz") as tar:
                info = tarfile.TarInfo(name="infisical")
                info.size = 4
                tar.addfile(info, io.BytesIO(b"fake"))

        mock_urlretrieve.side_effect = fake_download

        installer = InfisicalInstaller()
        result = installer.install()

        assert result == target_path
        assert target_path.exists()

    @patch("envdrift.scanner.infisical.get_infisical_path")
    @patch("urllib.request.urlretrieve")
    @patch("envdrift.scanner.platform_utils.platform.system", return_value="Linux")
    @patch("envdrift.scanner.platform_utils.platform.machine", return_value="x86_64")
    def test_install_download_failure(
        self,
        mock_machine: MagicMock,
        mock_system: MagicMock,
        mock_urlretrieve: MagicMock,
        mock_get_path: MagicMock,
        tmp_path: Path,
    ):
        """Test installation failure on download error."""
        mock_get_path.return_value = tmp_path / "infisical"
        mock_urlretrieve.side_effect = Exception("Network error")

        installer = InfisicalInstaller()
        with pytest.raises(InfisicalInstallError, match="Download failed"):
            installer.install()

    @patch("envdrift.scanner.infisical.get_infisical_path")
    @patch("urllib.request.urlretrieve")
    @patch("envdrift.scanner.platform_utils.platform.system", return_value="Linux")
    @patch("envdrift.scanner.platform_utils.platform.machine", return_value="x86_64")
    def test_install_binary_not_found_in_archive(
        self,
        mock_machine: MagicMock,
        mock_system: MagicMock,
        mock_urlretrieve: MagicMock,
        mock_get_path: MagicMock,
        tmp_path: Path,
    ):
        """Test installation failure when binary not found in archive."""
        import io
        import tarfile

        mock_get_path.return_value = tmp_path / "infisical"

        def fake_download(url: str, dest: str) -> None:
            with tarfile.open(dest, "w:gz") as tar:
                info = tarfile.TarInfo(name="other_file.txt")
                info.size = 4
                tar.addfile(info, io.BytesIO(b"test"))

        mock_urlretrieve.side_effect = fake_download

        installer = InfisicalInstaller()
        with pytest.raises(InfisicalInstallError, match="not found in archive"):
            installer.install()


# Mark integration tests that require actual infisical installation
@pytest.mark.skipif(
    not InfisicalScanner(auto_install=False).is_installed(),
    reason="infisical not installed",
)
class TestInfisicalIntegration:
    """Integration tests that require infisical to be installed."""

    def test_scan_clean_directory(self, tmp_path: Path):
        """Test scanning a directory with no secrets."""
        # Create a clean file
        (tmp_path / "clean.py").write_text("# No secrets here\nx = 1 + 1\n")

        scanner = InfisicalScanner(auto_install=False)
        result = scanner.scan([tmp_path])

        assert result.success is True
