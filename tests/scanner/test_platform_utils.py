"""Tests for platform utilities module."""

from __future__ import annotations

import os
import sys
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
    scan_argument,
    symlinked_file,
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


def _symlink(link: Path, target: Path) -> None:
    """Create ``link`` -> ``target``, skipping where symlinks need a privilege."""
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
    except OSError as exc:  # Windows without the symlink privilege
        pytest.skip(f"cannot create a symlink here: {exc}")


class TestScanArgument:
    """What gitleaks and Infisical are given for a path, run from our cwd (#843, #853, #854)."""

    @pytest.fixture
    def tree(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        """``tmp_path/proj/sub/app.env``, with the cwd set to ``tmp_path``."""
        (tmp_path / "proj" / "sub").mkdir(parents=True)
        (tmp_path / "proj" / "sub" / "app.env").write_text("X=1\n")
        monkeypatch.chdir(tmp_path)
        return tmp_path

    @pytest.mark.parametrize(
        ("cwd", "target"),
        [(".", "proj"), (".", "proj/sub"), ("proj/sub", "../../proj")],
    )
    def test_directory_is_given_as_is_with_a_trailing_separator(
        self, tree: Path, monkeypatch: pytest.MonkeyPatch, cwd: str, target: str
    ):
        """The binary runs in our cwd, so the path is not re-expressed (#854)."""
        monkeypatch.chdir(tree / cwd)

        argument = scan_argument(Path(target))

        assert argument == f"{Path(target)}{os.sep}"
        assert Path(argument).resolve() == (tree / cwd / target).resolve()

    def test_dot_keeps_its_form(self, tree: Path):
        """``guard .`` hands the binaries ``.``, exactly as before (#854)."""
        assert scan_argument(Path()) == "."

    def test_filesystem_root_keeps_its_form(self, tree: Path):
        anchor = Path(tree.anchor)

        assert scan_argument(anchor) == str(anchor)

    @pytest.mark.parametrize("target", ["proj/sub/app.env", "<abs>/proj/sub/app.env"])
    def test_file_is_given_as_is(self, tree: Path, target: str):
        path = Path(target.replace("<abs>", str(tree)))

        assert scan_argument(path) == str(path)

    def test_absolute_directory_keeps_its_form(self, tree: Path):
        assert scan_argument(tree / "proj") == f"{tree / 'proj'}{os.sep}"

    @pytest.mark.parametrize("absolute", [False, True], ids=["relative", "absolute"])
    def test_symlinked_directory_gets_the_separator_the_binaries_need(
        self, tree: Path, absolute: bool
    ):
        """Without it both binaries skip a symlinked root and report nothing (#853)."""
        _symlink(tree / "linkproj", tree / "proj")
        link = tree / "linkproj" if absolute else Path("linkproj")

        assert scan_argument(link) == f"{link}{os.sep}"

    def test_relative_symlinked_file_is_given_as_its_cwd_relative_target(self, tree: Path):
        """Both binaries skip a symlinked file even as the root, so it is given by target."""
        _symlink(tree / "link.env", tree / "proj" / "sub" / "app.env")

        assert scan_argument(Path("link.env")) == str(Path("proj/sub/app.env"))

    def test_absolute_symlinked_file_is_given_as_its_absolute_target(self, tree: Path):
        _symlink(tree / "link.env", tree / "proj" / "sub" / "app.env")

        argument = scan_argument(tree / "link.env")

        assert Path(argument) == (tree / "proj" / "sub" / "app.env").resolve()

    def test_symlinked_file_target_on_another_drive_stays_absolute(self, tree: Path):
        """On Windows a target on another drive than the cwd has no relative form."""
        _symlink(tree / "link.env", tree / "proj" / "sub" / "app.env")

        def other_drive(*_args: object) -> str:
            raise ValueError("path is on mount 'D:', start on mount 'C:'")

        with patch("envdrift.scanner.platform_utils.os.path.relpath", side_effect=other_drive):
            argument = scan_argument(Path("link.env"))

        assert Path(argument) == (tree / "proj" / "sub" / "app.env").resolve()

    @pytest.mark.parametrize(
        "target",
        [
            "linkrepo/..",
            # Windows resolves ``..`` lexically, so ``linkrepo/../proj`` names
            # ``./proj``, which this tree no longer has: not a directory to scan.
            pytest.param(
                "linkrepo/../proj",
                marks=pytest.mark.skipif(
                    sys.platform == "win32",
                    reason="Windows resolves '..' lexically: ./proj does not exist",
                ),
            ),
            "<abs>/linkrepo/..",
        ],
    )
    def test_parent_reference_after_a_symlink_names_the_same_directory_once_cleaned(
        self, tree: Path, target: str
    ):
        """Both binaries clean every walked path lexically, so ``link/..`` scanned nothing.

        On POSIX ``..`` after a symlink names the link target's parent. The
        binaries walked that directory, but joined and cleaned each entry
        lexically into a path below ``.`` that does not exist, and skipped it
        without an error. The argument must name, once cleaned, the directory
        the path names (on Windows, which cleans ``..`` lexically itself, the
        path as given already does).
        """
        (tree / "elsewhere" / "repo").mkdir(parents=True)
        (tree / "proj").rename(tree / "elsewhere" / "proj")
        _symlink(tree / "linkrepo", tree / "elsewhere" / "repo")
        path = Path(target.replace("<abs>", str(tree)))

        argument = scan_argument(path)

        assert Path(os.path.normpath(argument)).resolve() == path.resolve()
        assert Path(argument).is_absolute() == path.is_absolute()
        assert argument.endswith(os.sep)

    def test_parent_reference_without_a_symlink_keeps_its_form(self, tree: Path):
        assert scan_argument(Path("proj/sub/..")) == f"{Path('proj/sub/..')}{os.sep}"

    def test_unresolvable_parent_reference_keeps_its_form(self, tree: Path):
        """A path that cannot be resolved is passed as given, for the binary to report."""
        real_resolve = Path.resolve

        def resolve(self: Path, strict: bool = False) -> Path:
            if os.pardir in self.parts:
                raise OSError("permission denied")
            return real_resolve(self, strict)

        with patch.object(Path, "resolve", resolve):
            argument = scan_argument(Path("proj/sub/.."))

        assert argument == f"{Path('proj/sub/..')}{os.sep}"


class TestSymlinkedFile:
    """``symlinked_file``: the link gitleaks and Infisical are given as its target (#853)."""

    def test_symlink_to_a_file(self, tmp_path: Path):
        (tmp_path / "app.env").write_text("X=1\n")
        _symlink(tmp_path / "link.env", tmp_path / "app.env")

        assert symlinked_file(tmp_path / "link.env") == tmp_path / "link.env"

    def test_regular_file(self, tmp_path: Path):
        (tmp_path / "app.env").write_text("X=1\n")

        assert symlinked_file(tmp_path / "app.env") is None

    def test_symlink_to_a_directory(self, tmp_path: Path):
        (tmp_path / "proj").mkdir()
        _symlink(tmp_path / "linkproj", tmp_path / "proj")

        assert symlinked_file(tmp_path / "linkproj") is None
