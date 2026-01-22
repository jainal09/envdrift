"""Tests for platform utilities module."""

from __future__ import annotations

import os
import tarfile
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from envdrift.scanner.platform_utils import (
    get_platform_info,
    get_venv_bin_dir,
    safe_extract_tar,
    safe_extract_zip,
)


class TestGetPlatformInfo:
    """Tests for get_platform_info function."""

    def test_returns_tuple(self):
        """Test that get_platform_info returns a tuple of strings."""
        system, machine = get_platform_info()
        assert isinstance(system, str)
        assert isinstance(machine, str)
        assert system in ("Darwin", "Linux", "Windows")

    @patch("platform.system", return_value="Darwin")
    @patch("platform.machine", return_value="arm64")
    def test_darwin_arm64(self, mock_machine: MagicMock, mock_system: MagicMock):
        """Test platform detection for macOS ARM."""
        system, machine = get_platform_info()
        assert system == "Darwin"
        assert machine == "arm64"

    @patch("platform.system", return_value="Linux")
    @patch("platform.machine", return_value="x86_64")
    def test_linux_x86_64(self, mock_machine: MagicMock, mock_system: MagicMock):
        """Test platform detection for Linux x86_64."""
        system, machine = get_platform_info()
        assert system == "Linux"
        assert machine == "x86_64"

    @patch("platform.system", return_value="Windows")
    @patch("platform.machine", return_value="AMD64")
    def test_windows_normalizes_amd64(self, mock_machine: MagicMock, mock_system: MagicMock):
        """Test that AMD64 is normalized to x86_64 on Windows."""
        system, machine = get_platform_info()
        assert system == "Windows"
        assert machine == "x86_64"

    @patch("platform.system", return_value="Linux")
    @patch("platform.machine", return_value="amd64")
    def test_normalizes_lowercase_amd64(self, mock_machine: MagicMock, mock_system: MagicMock):
        """Test that lowercase amd64 is normalized to x86_64."""
        _system, machine = get_platform_info()
        assert machine == "x86_64"

    @patch("platform.system", return_value="Linux")
    @patch("platform.machine", return_value="aarch64")
    def test_normalizes_aarch64_to_arm64(self, mock_machine: MagicMock, mock_system: MagicMock):
        """Test that aarch64 is normalized to arm64."""
        _system, machine = get_platform_info()
        assert machine == "arm64"


class TestGetVenvBinDir:
    """Tests for get_venv_bin_dir function."""

    @patch.dict(os.environ, {"VIRTUAL_ENV": "/path/to/venv"}, clear=False)
    @patch("platform.system", return_value="Linux")
    def test_returns_venv_bin_on_linux(self, mock_system: MagicMock):
        """Test that function returns venv/bin on Linux."""
        result = get_venv_bin_dir()
        assert result == Path("/path/to/venv/bin")

    @patch.dict(os.environ, {"VIRTUAL_ENV": "/path/to/venv"}, clear=False)
    @patch("platform.system", return_value="Windows")
    def test_returns_venv_scripts_on_windows(self, mock_system: MagicMock):
        """Test that function returns venv/Scripts on Windows."""
        result = get_venv_bin_dir()
        assert result == Path("/path/to/venv/Scripts")

    @patch.dict(os.environ, {}, clear=True)
    @patch("platform.system", return_value="Linux")
    def test_finds_venv_in_sys_path(self, mock_system: MagicMock):
        """Test that function finds venv in sys.path."""
        with patch("sys.path", ["/home/user/project/.venv/lib/python3.10/site-packages"]):
            result = get_venv_bin_dir()
            assert result == Path("/home/user/project/.venv/bin")

    @patch.dict(os.environ, {}, clear=True)
    @patch("platform.system", return_value="Windows")
    def test_finds_venv_in_sys_path_windows(self, mock_system: MagicMock):
        """Test that function finds venv in sys.path on Windows."""
        with patch("sys.path", ["/home/user/project/venv/lib/python3.10/site-packages"]):
            result = get_venv_bin_dir()
            assert result == Path("/home/user/project/venv/Scripts")

    @patch.dict(os.environ, {}, clear=True)
    @patch("platform.system", return_value="Linux")
    def test_falls_back_to_cwd_venv(self, mock_system: MagicMock, tmp_path: Path):
        """Test that function falls back to .venv in cwd."""
        venv_dir = tmp_path / ".venv"
        venv_dir.mkdir()
        with patch("sys.path", []):
            with patch("pathlib.Path.cwd", return_value=tmp_path):
                result = get_venv_bin_dir()
                assert result == venv_dir / "bin"

    @patch.dict(os.environ, {}, clear=True)
    @patch("platform.system", return_value="Linux")
    def test_falls_back_to_user_bin(self, mock_system: MagicMock, tmp_path: Path):
        """Test that function falls back to ~/.local/bin on Linux."""
        with patch("sys.path", []):
            with patch("pathlib.Path.cwd", return_value=tmp_path):
                with patch("pathlib.Path.home", return_value=tmp_path):
                    result = get_venv_bin_dir()
                    assert result == tmp_path / ".local" / "bin"
                    assert result.exists()

    @patch("platform.system", return_value="Windows")
    def test_falls_back_to_appdata_on_windows(self, mock_system: MagicMock, tmp_path: Path):
        """Test that function falls back to APPDATA on Windows."""
        appdata_path = tmp_path / "AppData" / "Roaming"
        appdata_path.mkdir(parents=True)
        with patch.dict(os.environ, {"APPDATA": str(appdata_path)}, clear=True):
            with patch("sys.path", []):
                with patch("pathlib.Path.cwd", return_value=tmp_path):
                    result = get_venv_bin_dir()
                    assert "Python" in str(result) and "Scripts" in str(result)


class TestSafeExtractTar:
    """Tests for safe_extract_tar function."""

    def test_extracts_safe_archive(self, tmp_path: Path):
        """Test that safe archives are extracted correctly."""
        # Create a tar.gz with safe files
        archive_path = tmp_path / "test.tar.gz"
        extract_dir = tmp_path / "extract"
        extract_dir.mkdir()

        # Create archive
        with tarfile.open(archive_path, "w:gz") as tar:
            test_file = tmp_path / "test.txt"
            test_file.write_text("test content")
            tar.add(test_file, arcname="test.txt")

        # Extract using our safe function
        with tarfile.open(archive_path, "r:gz") as tar:
            safe_extract_tar(tar, extract_dir, ValueError)

        assert (extract_dir / "test.txt").exists()
        assert (extract_dir / "test.txt").read_text() == "test content"

    def test_raises_on_path_traversal(self, tmp_path: Path):
        """Test that path traversal attempts are blocked."""
        archive_path = tmp_path / "malicious.tar.gz"
        extract_dir = tmp_path / "extract"
        extract_dir.mkdir()

        # Create archive with path traversal
        with tarfile.open(archive_path, "w:gz") as tar:
            # Create a malicious member with path traversal
            info = tarfile.TarInfo(name="../../../etc/passwd")
            info.size = 4
            tar.addfile(info, fileobj=__import__("io").BytesIO(b"evil"))

        # Attempt extraction should raise
        with tarfile.open(archive_path, "r:gz") as tar:
            with pytest.raises(ValueError, match="Unsafe path"):
                safe_extract_tar(tar, extract_dir, ValueError)


class TestSafeExtractZip:
    """Tests for safe_extract_zip function."""

    def test_extracts_safe_archive(self, tmp_path: Path):
        """Test that safe zip archives are extracted correctly."""
        archive_path = tmp_path / "test.zip"
        extract_dir = tmp_path / "extract"
        extract_dir.mkdir()

        # Create zip archive
        with zipfile.ZipFile(archive_path, "w") as zf:
            zf.writestr("test.txt", "test content")

        # Extract using our safe function
        with zipfile.ZipFile(archive_path, "r") as zf:
            safe_extract_zip(zf, extract_dir, ValueError)

        assert (extract_dir / "test.txt").exists()
        assert (extract_dir / "test.txt").read_text() == "test content"

    def test_raises_on_path_traversal(self, tmp_path: Path):
        """Test that path traversal attempts are blocked in zip."""
        archive_path = tmp_path / "malicious.zip"
        extract_dir = tmp_path / "extract"
        extract_dir.mkdir()

        # Create zip with path traversal attempt
        with zipfile.ZipFile(archive_path, "w") as zf:
            # Add a file with path traversal in name
            zf.writestr("../../../etc/passwd", "evil content")

        # Attempt extraction should raise
        with zipfile.ZipFile(archive_path, "r") as zf:
            with pytest.raises(ValueError, match="Unsafe path"):
                safe_extract_zip(zf, extract_dir, ValueError)

    def test_extracts_nested_directories(self, tmp_path: Path):
        """Test that nested directories are extracted correctly."""
        archive_path = tmp_path / "nested.zip"
        extract_dir = tmp_path / "extract"
        extract_dir.mkdir()

        # Create zip with nested structure
        with zipfile.ZipFile(archive_path, "w") as zf:
            zf.writestr("dir1/dir2/file.txt", "nested content")

        # Extract using our safe function
        with zipfile.ZipFile(archive_path, "r") as zf:
            safe_extract_zip(zf, extract_dir, ValueError)

        assert (extract_dir / "dir1" / "dir2" / "file.txt").exists()
