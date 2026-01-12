"""Tests for trufflehog scanner integration."""

from __future__ import annotations

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
from envdrift.scanner.trufflehog import (
    TrufflehogError,
    TrufflehogInstaller,
    TrufflehogInstallError,
    TrufflehogNotFoundError,
    TrufflehogScanner,
    get_platform_info,
    get_trufflehog_path,
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


class TestGetTrufflehogPath:
    """Tests for trufflehog binary path detection."""

    @patch("envdrift.scanner.trufflehog.get_venv_bin_dir")
    @patch("platform.system", return_value="Linux")
    def test_returns_trufflehog_path_linux(self, mock_system: MagicMock, mock_bin_dir: MagicMock):
        """Test trufflehog path on Linux."""
        mock_bin_dir.return_value = Path("/venv/bin")
        path = get_trufflehog_path()
        assert path == Path("/venv/bin/trufflehog")

    @patch("envdrift.scanner.trufflehog.get_venv_bin_dir")
    @patch("platform.system", return_value="Windows")
    def test_returns_trufflehog_exe_on_windows(
        self, mock_system: MagicMock, mock_bin_dir: MagicMock
    ):
        """Test trufflehog path on Windows includes .exe extension."""
        mock_bin_dir.return_value = Path("/venv/Scripts")
        path = get_trufflehog_path()
        assert path == Path("/venv/Scripts/trufflehog.exe")


class TestTrufflehogInstaller:
    """Tests for TrufflehogInstaller class."""

    def test_default_version_from_constants(self):
        """Test that installer uses version from constants."""
        installer = TrufflehogInstaller()
        assert installer.version == "3.92.4"

    def test_custom_version(self):
        """Test that custom version can be specified."""
        installer = TrufflehogInstaller(version="3.80.0")
        assert installer.version == "3.80.0"

    def test_progress_callback(self):
        """Test that progress callback is called."""
        messages: list[str] = []
        installer = TrufflehogInstaller(progress_callback=messages.append)
        installer.progress("test message")
        assert messages == ["test message"]

    @patch("envdrift.scanner.trufflehog.get_platform_info")
    def test_get_download_url_darwin_arm64(self, mock_platform: MagicMock):
        """Test download URL for macOS ARM."""
        mock_platform.return_value = ("Darwin", "arm64")
        installer = TrufflehogInstaller(version="3.88.3")
        url = installer.get_download_url()
        assert "darwin" in url
        assert "arm64" in url
        assert "3.88.3" in url

    @patch("envdrift.scanner.trufflehog.get_platform_info")
    def test_get_download_url_linux_amd64(self, mock_platform: MagicMock):
        """Test download URL for Linux AMD64."""
        mock_platform.return_value = ("Linux", "x86_64")
        installer = TrufflehogInstaller(version="3.88.3")
        url = installer.get_download_url()
        assert "linux" in url
        assert "amd64" in url

    @patch("envdrift.scanner.trufflehog.get_platform_info")
    def test_get_download_url_windows(self, mock_platform: MagicMock):
        """Test download URL for Windows."""
        mock_platform.return_value = ("Windows", "x86_64")
        installer = TrufflehogInstaller(version="3.88.3")
        url = installer.get_download_url()
        assert "windows" in url
        assert ".tar.gz" in url

    @patch("envdrift.scanner.trufflehog.get_platform_info")
    def test_unsupported_platform_raises_error(self, mock_platform: MagicMock):
        """Test that unsupported platform raises error."""
        mock_platform.return_value = ("FreeBSD", "x86_64")
        installer = TrufflehogInstaller()
        with pytest.raises(TrufflehogInstallError, match="Unsupported platform"):
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
        assert set(TrufflehogInstaller.PLATFORM_MAP.keys()) == expected_platforms

    def test_download_and_extract_tar_gz(self, tmp_path: Path, monkeypatch):
        """Tarball downloads are extracted and installed."""
        archive_path = _create_tar_gz(tmp_path, "trufflehog")

        installer = TrufflehogInstaller(version="3.92.4")
        monkeypatch.setattr(
            installer, "get_download_url", lambda: "https://example.com/trufflehog.tar.gz"
        )
        monkeypatch.setattr(platform, "system", lambda: "Linux")

        def fake_urlretrieve(_url: str, filename: str):
            shutil.copy2(archive_path, filename)
            return filename, None

        monkeypatch.setattr(
            "envdrift.scanner.trufflehog.urllib.request.urlretrieve",
            fake_urlretrieve,
        )

        target_path = tmp_path / "bin" / "trufflehog"
        installer.download_and_extract(target_path)
        assert target_path.exists()

    def test_download_and_extract_zip(self, tmp_path: Path, monkeypatch):
        """Zip downloads are extracted and installed."""
        archive_path = _create_zip(tmp_path, "trufflehog.exe")

        installer = TrufflehogInstaller(version="3.92.4")
        monkeypatch.setattr(
            installer, "get_download_url", lambda: "https://example.com/trufflehog.zip"
        )
        monkeypatch.setattr(platform, "system", lambda: "Windows")

        def fake_urlretrieve(_url: str, filename: str):
            shutil.copy2(archive_path, filename)
            return filename, None

        monkeypatch.setattr(
            "envdrift.scanner.trufflehog.urllib.request.urlretrieve",
            fake_urlretrieve,
        )

        target_path = tmp_path / "bin" / "trufflehog.exe"
        installer.download_and_extract(target_path)
        assert target_path.exists()


class TestTrufflehogScanner:
    """Tests for TrufflehogScanner class."""

    def test_scanner_name(self):
        """Test scanner name property."""
        scanner = TrufflehogScanner(auto_install=False)
        assert scanner.name == "trufflehog"

    def test_scanner_description(self):
        """Test scanner description property."""
        scanner = TrufflehogScanner(auto_install=False)
        assert "trufflehog" in scanner.description.lower()

    def test_scanner_description_with_verify(self):
        """Test scanner description includes verification when enabled."""
        scanner = TrufflehogScanner(auto_install=False, verify=True)
        assert "verification" in scanner.description.lower()

    @patch("shutil.which", return_value=None)
    @patch("envdrift.scanner.trufflehog.get_trufflehog_path")
    def test_is_installed_returns_false_when_not_found(
        self, mock_path: MagicMock, mock_which: MagicMock
    ):
        """Test is_installed returns False when binary not found."""
        mock_path.return_value = Path("/nonexistent/trufflehog")
        scanner = TrufflehogScanner(auto_install=False)
        assert scanner.is_installed() is False

    @patch("shutil.which", return_value="/usr/bin/trufflehog")
    def test_is_installed_returns_true_when_in_path(self, mock_which: MagicMock):
        """Test is_installed returns True when in PATH."""
        scanner = TrufflehogScanner(auto_install=False)
        assert scanner.is_installed() is True

    @patch("envdrift.scanner.trufflehog.get_trufflehog_path")
    def test_is_installed_returns_true_when_in_venv(self, mock_path: MagicMock, tmp_path: Path):
        """Test is_installed returns True when in venv."""
        binary = tmp_path / "trufflehog"
        binary.touch()
        mock_path.return_value = binary
        scanner = TrufflehogScanner(auto_install=False)
        assert scanner.is_installed() is True

    @patch("shutil.which", return_value=None)
    @patch("envdrift.scanner.trufflehog.get_trufflehog_path")
    def test_scan_returns_error_when_not_installed(
        self, mock_path: MagicMock, mock_which: MagicMock, tmp_path: Path
    ):
        """Test scan returns error result when trufflehog not installed."""
        mock_path.return_value = Path("/nonexistent/trufflehog")
        scanner = TrufflehogScanner(auto_install=False)
        result = scanner.scan([tmp_path])
        assert result.error is not None
        assert "not found" in result.error.lower()
        assert result.success is False

    def test_scan_with_nonexistent_path(self, tmp_path: Path):
        """Test scan handles nonexistent paths gracefully."""
        scanner = TrufflehogScanner(auto_install=False)
        scanner._binary_path = Path("/fake/trufflehog")
        with patch.object(scanner, "_find_binary", return_value=Path("/fake/trufflehog")):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
                result = scanner.scan([tmp_path / "nonexistent"])
                assert result.success is True
                assert len(result.findings) == 0


class TestFindingParsing:
    """Tests for trufflehog finding parsing."""

    @pytest.fixture
    def scanner(self) -> TrufflehogScanner:
        """Create a scanner instance for testing."""
        return TrufflehogScanner(auto_install=False)

    def test_parse_filesystem_finding(self, scanner: TrufflehogScanner, tmp_path: Path):
        """Test parsing a filesystem finding."""
        item: dict[str, Any] = {
            "SourceMetadata": {
                "Data": {
                    "Filesystem": {
                        "file": "secrets.py",
                        "line": 10,
                    }
                }
            },
            "Raw": "AKIAIOSFODNN7EXAMPLE",
            "DetectorName": "AWS",
            "DetectorType": 1,
            "Verified": False,
        }
        finding = scanner._parse_finding(item, tmp_path)

        assert finding is not None
        assert finding.rule_id == "trufflehog-aws"
        assert finding.rule_description == "AWS"
        assert finding.line_number == 10
        assert finding.severity == FindingSeverity.HIGH
        assert finding.scanner == "trufflehog"
        assert finding.verified is False
        assert "****" in finding.secret_preview

    def test_parse_verified_finding(self, scanner: TrufflehogScanner, tmp_path: Path):
        """Test parsing a verified finding has CRITICAL severity."""
        item: dict[str, Any] = {
            "SourceMetadata": {
                "Data": {
                    "Filesystem": {
                        "file": "secrets.py",
                    }
                }
            },
            "Raw": "secret123",
            "DetectorName": "Generic",
            "Verified": True,
        }
        finding = scanner._parse_finding(item, tmp_path)

        assert finding is not None
        assert finding.severity == FindingSeverity.CRITICAL
        assert finding.verified is True
        assert "Verified" in finding.description

    def test_parse_git_finding(self, scanner: TrufflehogScanner, tmp_path: Path):
        """Test parsing a git history finding."""
        item: dict[str, Any] = {
            "SourceMetadata": {
                "Data": {
                    "Git": {
                        "file": "config.py",
                        "line": 5,
                        "commit": "abc123def456",
                        "email": "dev@example.com",
                        "timestamp": "2024-01-15T10:00:00Z",
                    }
                }
            },
            "Raw": "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "DetectorName": "GitHub",
            "Verified": False,
        }
        finding = scanner._parse_finding(item, tmp_path)

        assert finding is not None
        assert finding.commit_sha == "abc123def456"
        assert finding.commit_author == "dev@example.com"
        assert finding.commit_date == "2024-01-15T10:00:00Z"

    def test_parse_finding_with_relative_path(self, scanner: TrufflehogScanner, tmp_path: Path):
        """Test parsing finding with relative file path."""
        item: dict[str, Any] = {
            "SourceMetadata": {
                "Data": {
                    "Filesystem": {
                        "file": "src/config/secrets.py",
                    }
                }
            },
            "Raw": "secret123",
            "DetectorName": "Generic",
            "Verified": False,
        }
        finding = scanner._parse_finding(item, tmp_path)

        assert finding is not None
        assert finding.file_path == tmp_path / "src/config/secrets.py"

    def test_parse_finding_with_empty_source_data(self, scanner: TrufflehogScanner, tmp_path: Path):
        """Test parsing finding with minimal source data."""
        item: dict[str, Any] = {
            "SourceMetadata": {"Data": {}},
            "Raw": "secret",
            "DetectorName": "Test",
            "Verified": False,
        }
        finding = scanner._parse_finding(item, tmp_path)

        assert finding is not None
        assert finding.file_path == tmp_path

    def test_parse_finding_handles_empty_data(self, scanner: TrufflehogScanner, tmp_path: Path):
        """Test that empty data creates a finding with defaults instead of raising."""
        # Missing all fields
        item: dict[str, Any] = {}
        finding = scanner._parse_finding(item, tmp_path)
        # Based on implementation, empty dict still creates a finding with defaults
        assert finding is not None
        assert finding.file_path == tmp_path
        assert finding.rule_id == "trufflehog-unknown"


class TestTrufflehogScanExecution:
    """Tests for trufflehog scan execution with mocked subprocess."""

    @pytest.fixture
    def mock_scanner(self, tmp_path: Path) -> TrufflehogScanner:
        """Create a scanner with mocked binary."""
        scanner = TrufflehogScanner(auto_install=False)
        binary_path = tmp_path / "trufflehog"
        binary_path.touch()
        scanner._binary_path = binary_path
        return scanner

    def test_scan_parses_json_lines_output(self, mock_scanner: TrufflehogScanner, tmp_path: Path):
        """Test that scan correctly parses JSON lines output."""
        # Trufflehog outputs one JSON per line
        findings_output = (
            '{"SourceMetadata":{"Data":{"Filesystem":{"file":"test.py"}}},'
            '"Raw":"secret1","DetectorName":"AWS","Verified":false}\n'
            '{"SourceMetadata":{"Data":{"Filesystem":{"file":"test2.py"}}},'
            '"Raw":"secret2","DetectorName":"GitHub","Verified":false}\n'
        )

        with patch.object(mock_scanner, "_find_binary", return_value=mock_scanner._binary_path):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    stdout=findings_output,
                    stderr="",
                    returncode=0,
                )
                result = mock_scanner.scan([tmp_path])

        assert result.success is True
        assert len(result.findings) == 2

    def test_scan_handles_empty_output(self, mock_scanner: TrufflehogScanner, tmp_path: Path):
        """Test that scan handles empty output."""
        with patch.object(mock_scanner, "_find_binary", return_value=mock_scanner._binary_path):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
                result = mock_scanner.scan([tmp_path])

        assert result.success is True
        assert len(result.findings) == 0

    def test_scan_handles_invalid_json_lines(self, mock_scanner: TrufflehogScanner, tmp_path: Path):
        """Test that scan handles invalid JSON lines gracefully."""
        mixed_output = 'not json\n{"SourceMetadata":{"Data":{"Filesystem":{"file":"test.py"}}},"Raw":"secret","DetectorName":"Test","Verified":false}\nalso not json\n'

        with patch.object(mock_scanner, "_find_binary", return_value=mock_scanner._binary_path):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    stdout=mixed_output,
                    stderr="",
                    returncode=0,
                )
                result = mock_scanner.scan([tmp_path])

        assert result.success is True
        # Should have parsed the one valid JSON line
        assert len(result.findings) == 1

    def test_scan_handles_timeout(self, mock_scanner: TrufflehogScanner, tmp_path: Path):
        """Test that scan handles subprocess timeout."""
        with patch.object(mock_scanner, "_find_binary", return_value=mock_scanner._binary_path):
            with patch("subprocess.run") as mock_run:
                mock_run.side_effect = subprocess.TimeoutExpired(cmd="trufflehog", timeout=600)
                result = mock_scanner.scan([tmp_path])

        assert "timed out" in result.error.lower()
        assert result.success is False

    def test_scan_uses_filesystem_mode(self, mock_scanner: TrufflehogScanner, tmp_path: Path):
        """Test that scan uses filesystem mode by default."""
        with patch.object(mock_scanner, "_find_binary", return_value=mock_scanner._binary_path):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
                mock_scanner.scan([tmp_path], include_git_history=False)

        call_args = mock_run.call_args[0][0]
        assert "filesystem" in call_args

    def test_scan_uses_git_mode_for_history(self, mock_scanner: TrufflehogScanner, tmp_path: Path):
        """Test that scan uses git mode when scanning history."""
        # Create a fake .git directory
        (tmp_path / ".git").mkdir()

        with patch.object(mock_scanner, "_find_binary", return_value=mock_scanner._binary_path):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
                mock_scanner.scan([tmp_path], include_git_history=True)

        call_args = mock_run.call_args[0][0]
        assert "git" in call_args

    def test_scan_with_verification_disabled(self, mock_scanner: TrufflehogScanner, tmp_path: Path):
        """Test that scan passes --no-verification flag."""
        with patch.object(mock_scanner, "_find_binary", return_value=mock_scanner._binary_path):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
                mock_scanner.scan([tmp_path])

        call_args = mock_run.call_args[0][0]
        assert "--no-verification" in call_args

    def test_scan_with_verification_enabled(self, tmp_path: Path):
        """Test that scan does not pass --no-verification when verify=True."""
        scanner = TrufflehogScanner(auto_install=False, verify=True)
        scanner._binary_path = tmp_path / "trufflehog"
        scanner._binary_path.touch()

        with patch.object(scanner, "_find_binary", return_value=scanner._binary_path):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
                scanner.scan([tmp_path])

        call_args = mock_run.call_args[0][0]
        assert "--no-verification" not in call_args

    def test_scan_multiple_paths(self, mock_scanner: TrufflehogScanner, tmp_path: Path):
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
        assert mock_run.call_count == 2


class TestTrufflehogAutoInstall:
    """Tests for trufflehog auto-installation."""

    @patch("shutil.which", return_value=None)
    @patch("envdrift.scanner.trufflehog.get_trufflehog_path")
    @patch.object(TrufflehogInstaller, "install")
    def test_auto_install_when_not_found(
        self,
        mock_install: MagicMock,
        mock_path: MagicMock,
        mock_which: MagicMock,
        tmp_path: Path,
    ):
        """Test that scanner auto-installs when binary not found."""
        mock_path.return_value = Path("/nonexistent/trufflehog")
        installed_path = tmp_path / "trufflehog"
        installed_path.touch()
        mock_install.return_value = installed_path

        scanner = TrufflehogScanner(auto_install=True)
        binary = scanner._find_binary()

        assert binary == installed_path
        mock_install.assert_called_once()

    @patch("shutil.which", return_value=None)
    @patch("envdrift.scanner.trufflehog.get_trufflehog_path")
    @patch.object(TrufflehogInstaller, "install")
    def test_auto_install_failure_raises_error(
        self,
        mock_install: MagicMock,
        mock_path: MagicMock,
        mock_which: MagicMock,
    ):
        """Test that auto-install failure raises appropriate error."""
        mock_path.return_value = Path("/nonexistent/trufflehog")
        mock_install.side_effect = TrufflehogInstallError("Download failed")

        scanner = TrufflehogScanner(auto_install=True)
        with pytest.raises(TrufflehogNotFoundError, match="auto-install failed"):
            scanner._find_binary()


class TestTrufflehogVersion:
    """Tests for trufflehog version detection."""

    def test_get_version_when_not_installed(self):
        """Test get_version returns None when not installed."""
        scanner = TrufflehogScanner(auto_install=False)
        with patch.object(scanner, "_find_binary", side_effect=TrufflehogNotFoundError):
            version = scanner.get_version()
            assert version is None

    @patch("subprocess.run")
    def test_get_version_parses_output(self, mock_run: MagicMock, tmp_path: Path):
        """Test get_version correctly parses version output."""
        mock_run.return_value = MagicMock(
            stdout="trufflehog 3.88.3\n",
            returncode=0,
        )
        scanner = TrufflehogScanner(auto_install=False)
        binary = tmp_path / "trufflehog"
        binary.touch()
        scanner._binary_path = binary

        version = scanner.get_version()
        assert version == "3.88.3"


class TestGitRepoDetection:
    """Tests for git repository detection."""

    @pytest.fixture
    def scanner(self) -> TrufflehogScanner:
        """Create a scanner for testing."""
        return TrufflehogScanner(auto_install=False)

    def test_is_git_repo_with_git_dir(self, scanner: TrufflehogScanner, tmp_path: Path):
        """Test detection when .git directory exists."""
        (tmp_path / ".git").mkdir()
        assert scanner._is_git_repo(tmp_path) is True

    def test_is_git_repo_without_git_dir(self, scanner: TrufflehogScanner, tmp_path: Path):
        """Test detection when no .git directory."""
        assert scanner._is_git_repo(tmp_path) is False

    def test_is_git_repo_with_parent_git_dir(self, scanner: TrufflehogScanner, tmp_path: Path):
        """Test detection when .git exists in parent directory."""
        (tmp_path / ".git").mkdir()
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        assert scanner._is_git_repo(subdir) is True

    def test_is_git_repo_with_file_path(self, scanner: TrufflehogScanner, tmp_path: Path):
        """Test detection when given a file path."""
        (tmp_path / ".git").mkdir()
        file_path = tmp_path / "test.py"
        file_path.touch()
        assert scanner._is_git_repo(file_path) is True


class TestExceptionClasses:
    """Tests for exception classes."""

    def test_trufflehog_not_found_error(self):
        """Test TrufflehogNotFoundError."""
        error = TrufflehogNotFoundError("Binary not found")
        assert str(error) == "Binary not found"
        assert isinstance(error, Exception)

    def test_trufflehog_install_error(self):
        """Test TrufflehogInstallError."""
        error = TrufflehogInstallError("Download failed")
        assert str(error) == "Download failed"
        assert isinstance(error, Exception)

    def test_trufflehog_error(self):
        """Test TrufflehogError."""
        error = TrufflehogError("Command failed")
        assert str(error) == "Command failed"
        assert isinstance(error, Exception)


# Mark integration tests that require actual trufflehog installation
@pytest.mark.skipif(
    not TrufflehogScanner(auto_install=False).is_installed(),
    reason="trufflehog not installed",
)
class TestTrufflehogIntegration:
    """Integration tests that require trufflehog to be installed."""

    def test_scan_clean_directory(self, tmp_path: Path):
        """Test scanning a directory with no secrets."""
        # Create a clean file
        (tmp_path / "clean.py").write_text("# No secrets here\nx = 1 + 1\n")

        scanner = TrufflehogScanner(auto_install=False)
        result = scanner.scan([tmp_path])

        assert result.success is True

    def test_scan_file_with_test_secret(self, tmp_path: Path):
        """Test scanning a file with a fake secret pattern."""
        # Create a file with a fake AWS key
        secret_file = tmp_path / "secrets.py"
        secret_file.write_text('# Test file\nAWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')

        scanner = TrufflehogScanner(auto_install=False)
        result = scanner.scan([tmp_path])

        assert result.success is True
