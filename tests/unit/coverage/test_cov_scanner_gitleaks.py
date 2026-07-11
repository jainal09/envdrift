"""Coverage-focused tests for envdrift.scanner.gitleaks.

These tests target previously-uncovered error branches, platform guards,
and edge cases in the gitleaks scanner integration. All external processes,
network downloads, and binaries are mocked.
"""

from __future__ import annotations

import platform
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from envdrift.scanner.gitleaks import (
    GitleaksInstaller,
    GitleaksInstallError,
    GitleaksScanner,
    get_venv_bin_dir,
)
from tests.helpers import write_checksums_for


class TestGetVenvBinDirWindowsBranches:
    """Windows-specific branches of get_venv_bin_dir (lines 129, 136)."""

    def test_venv_from_sys_path_windows_returns_scripts(self, tmp_path: Path, monkeypatch):
        """sys.path discovery on Windows returns the Scripts dir (line 129)."""
        venv_site = tmp_path / ".venv" / "Lib" / "site-packages"
        venv_site.mkdir(parents=True)
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.setattr(sys, "path", [str(venv_site)])
        monkeypatch.setattr(platform, "system", lambda: "Windows")

        bin_dir = get_venv_bin_dir()
        assert bin_dir == tmp_path / ".venv" / "Scripts"

    def test_cwd_venv_windows_returns_scripts(self, tmp_path: Path, monkeypatch):
        """cwd .venv discovery on Windows returns Scripts dir (line 136)."""
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.setattr(sys, "path", [str(tmp_path / "site-packages")])
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".venv").mkdir()
        monkeypatch.setattr(platform, "system", lambda: "Windows")

        bin_dir = get_venv_bin_dir()
        assert bin_dir == tmp_path / ".venv" / "Scripts"

    def test_windows_no_appdata_raises_runtime_error(self, tmp_path: Path, monkeypatch):
        """Windows with no APPDATA and no venv raises RuntimeError (line 151)."""
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.delenv("APPDATA", raising=False)
        monkeypatch.setattr(sys, "path", [str(tmp_path / "site-packages")])
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(platform, "system", lambda: "Windows")

        with pytest.raises(RuntimeError, match="Cannot find suitable bin directory"):
            get_venv_bin_dir()


class TestGetDownloadUrlDefaultTemplate:
    """Default download URL template branch (line 222)."""

    @patch("envdrift.scanner.gitleaks._get_gitleaks_download_urls", return_value={})
    @patch("envdrift.scanner.gitleaks.get_platform_info")
    def test_default_template_used_when_no_custom_urls(
        self, mock_platform: MagicMock, _mock_urls: MagicMock
    ):
        """When no custom URLs in constants, the default template is built (line 222)."""
        mock_platform.return_value = ("Darwin", "arm64")
        installer = GitleaksInstaller(version="9.9.9")
        url = installer.get_download_url()
        assert url == (
            "https://github.com/gitleaks/gitleaks/releases/download/"
            "v9.9.9/gitleaks_9.9.9_darwin_arm64.tar.gz"
        )


class TestDownloadAndExtractErrors:
    """Error branches in download_and_extract (lines 249-250, 260, 272)."""

    def test_download_failure_wrapped_in_install_error(self, tmp_path: Path, monkeypatch):
        """A bounded-download failure is wrapped in GitleaksInstallError."""
        installer = GitleaksInstaller(version="8.30.0")
        monkeypatch.setattr(
            installer, "get_download_url", lambda: "https://example.com/gitleaks.tar.gz"
        )

        def boom(_url, _filename, **_kwargs):
            raise OSError("network down")

        monkeypatch.setattr("envdrift.scanner.gitleaks.download_file", boom)

        with pytest.raises(GitleaksInstallError, match="Download failed: network down"):
            installer.download_and_extract(tmp_path / "bin" / "gitleaks")

    def test_unknown_archive_format_raises(self, tmp_path: Path, monkeypatch):
        """An archive with an unsupported extension raises (line 260)."""
        installer = GitleaksInstaller(version="8.30.0")
        monkeypatch.setattr(
            installer, "get_download_url", lambda: "https://example.com/gitleaks.rar"
        )

        checksums_path = tmp_path / "stub-checksums.txt"

        def fake_download(_url, filename, **_kwargs):
            Path(filename).write_bytes(b"junk")
            write_checksums_for(Path(filename), checksums_path, "gitleaks.rar")

        monkeypatch.setattr("envdrift.scanner.gitleaks.download_file", fake_download)
        monkeypatch.setattr(
            installer, "get_checksums_url", lambda: checksums_path.resolve().as_uri()
        )

        with pytest.raises(GitleaksInstallError, match="Unknown archive format"):
            installer.download_and_extract(tmp_path / "bin" / "gitleaks")

    def test_binary_not_found_in_archive_raises(self, tmp_path: Path, monkeypatch):
        """A tarball lacking the gitleaks binary raises (line 272)."""
        # Build a tar.gz that contains a non-matching file.
        payload = tmp_path / "payload"
        payload.mkdir()
        other = payload / "README.txt"
        other.write_text("nothing here")
        archive = tmp_path / "archive.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            tar.add(other, arcname="README.txt")

        installer = GitleaksInstaller(version="8.30.0")
        monkeypatch.setattr(
            installer, "get_download_url", lambda: "https://example.com/gitleaks.tar.gz"
        )
        monkeypatch.setattr(platform, "system", lambda: "Linux")

        def fake_download(_url, filename, **_kwargs):
            Path(filename).write_bytes(archive.read_bytes())

        monkeypatch.setattr("envdrift.scanner.gitleaks.download_file", fake_download)
        checksums_url = write_checksums_for(
            archive, tmp_path / "stub-checksums.txt", "gitleaks.tar.gz"
        )
        monkeypatch.setattr(installer, "get_checksums_url", lambda: checksums_url)

        with pytest.raises(GitleaksInstallError, match="not found in archive"):
            installer.download_and_extract(tmp_path / "bin" / "gitleaks")


class TestExtractPathTraversal:
    """Path-traversal guards in tar/zip extraction (lines 295, 305)."""

    def test_tar_path_traversal_rejected(self, tmp_path: Path):
        """A tar member escaping the target dir raises (line 295)."""
        # Create a tar containing a member with a traversal path.
        evil = tmp_path / "evil.txt"
        evil.write_text("evil")
        archive = tmp_path / "evil.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            tar.add(evil, arcname="../escapee.txt")

        installer = GitleaksInstaller(version="8.30.0")
        target = tmp_path / "target"
        target.mkdir()
        with pytest.raises(GitleaksInstallError, match="Unsafe path in archive"):
            installer._extract_tar_gz(archive, target)

    def test_zip_path_traversal_rejected(self, tmp_path: Path):
        """A zip member escaping the target dir raises (line 305)."""
        archive = tmp_path / "evil.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("../escapee.txt", "evil")

        installer = GitleaksInstaller(version="8.30.0")
        target = tmp_path / "target"
        target.mkdir()
        with pytest.raises(GitleaksInstallError, match="Unsafe path in archive"):
            installer._extract_zip(archive, target)


class TestInstallerInstall:
    """GitleaksInstaller.install version-check branches (lines 317-335)."""

    def test_install_returns_existing_when_version_matches(self, tmp_path: Path, monkeypatch):
        """An existing binary reporting the right version is reused (lines 317-330)."""
        binary = tmp_path / "gitleaks"
        binary.touch()
        monkeypatch.setattr("envdrift.scanner.gitleaks.get_gitleaks_path", lambda: binary)
        messages: list[str] = []
        installer = GitleaksInstaller(version="8.30.0", progress_callback=messages.append)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="gitleaks version 8.30.0\n")
            result = installer.install()

        assert result == binary
        assert any("already installed" in m for m in messages)

    def test_install_reinstalls_when_version_check_raises(self, tmp_path: Path, monkeypatch):
        """A failing version check falls through to download (lines 331-335)."""
        binary = tmp_path / "gitleaks"
        binary.touch()
        monkeypatch.setattr("envdrift.scanner.gitleaks.get_gitleaks_path", lambda: binary)
        installer = GitleaksInstaller(version="8.30.0")

        download_calls: list[Path] = []
        monkeypatch.setattr(
            installer,
            "download_and_extract",
            lambda target: download_calls.append(target),
        )

        with patch("subprocess.run", side_effect=OSError("cannot exec")):
            result = installer.install()

        assert result == binary
        assert download_calls == [binary]

    def test_install_reinstalls_when_version_mismatch(self, tmp_path: Path, monkeypatch):
        """A version mismatch triggers download_and_extract (line 334)."""
        binary = tmp_path / "gitleaks"
        binary.touch()
        monkeypatch.setattr("envdrift.scanner.gitleaks.get_gitleaks_path", lambda: binary)
        installer = GitleaksInstaller(version="8.30.0")

        download_calls: list[Path] = []
        monkeypatch.setattr(
            installer,
            "download_and_extract",
            lambda target: download_calls.append(target),
        )

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="gitleaks version 1.0.0\n")
            result = installer.install()

        assert result == binary
        assert download_calls == [binary]


class TestFindBinarySystemPath:
    """_find_binary system-PATH branch (lines 422-423)."""

    def test_find_binary_uses_system_path(self, tmp_path: Path, monkeypatch):
        """When gitleaks is on PATH it is used and cached (lines 422-423)."""
        sys_binary = tmp_path / "system" / "gitleaks"
        sys_binary.parent.mkdir()
        sys_binary.touch()

        missing = tmp_path / "venv" / "gitleaks"
        monkeypatch.setattr("envdrift.scanner.gitleaks.get_gitleaks_path", lambda: missing)
        monkeypatch.setattr("shutil.which", lambda _name: str(sys_binary))

        scanner = GitleaksScanner(auto_install=False)
        found = scanner._find_binary()
        assert found == sys_binary
        # Cached on the instance.
        assert scanner._binary_path == sys_binary


class TestScannerInstallMethod:
    """GitleaksScanner.install delegates to the installer (lines 452-457)."""

    def test_install_delegates_to_installer(self, tmp_path: Path):
        """scanner.install builds an installer and stores the path (lines 452-457)."""
        installed = tmp_path / "gitleaks"
        installed.touch()
        scanner = GitleaksScanner(auto_install=False, version="8.30.0")

        with patch.object(GitleaksInstaller, "install", return_value=installed) as mock_inst:
            result = scanner.install(progress_callback=lambda _m: None)

        assert result == installed
        assert scanner._binary_path == installed
        mock_inst.assert_called_once()


class TestScanErrorBranches:
    """scan() returncode and generic-exception branches (lines 522-528, 560-561)."""

    @pytest.fixture
    def scanner_with_binary(self, tmp_path: Path) -> GitleaksScanner:
        scanner = GitleaksScanner(auto_install=False)
        binary = tmp_path / "gitleaks"
        binary.touch()
        scanner._binary_path = binary
        return scanner

    def test_scan_nonzero_returncode_returns_error(
        self, scanner_with_binary: GitleaksScanner, tmp_path: Path
    ):
        """A non-zero exit code produces an error ScanResult (lines 522-528)."""
        with patch.object(
            scanner_with_binary, "_find_binary", return_value=scanner_with_binary._binary_path
        ):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(stdout="", stderr="fatal: boom", returncode=2)
                result = scanner_with_binary.scan([tmp_path])

        assert result.success is False
        assert result.error == "fatal: boom"

    def test_scan_nonzero_returncode_synthesizes_message(
        self, scanner_with_binary: GitleaksScanner, tmp_path: Path
    ):
        """Empty stderr/stdout yields a synthesized error message (line 523/526)."""
        with patch.object(
            scanner_with_binary, "_find_binary", return_value=scanner_with_binary._binary_path
        ):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(stdout="", stderr="", returncode=7)
                result = scanner_with_binary.scan([tmp_path])

        assert result.success is False
        assert result.error is not None
        assert "exit code 7" in result.error

    def test_scan_generic_exception_returns_error(
        self, scanner_with_binary: GitleaksScanner, tmp_path: Path
    ):
        """An unexpected exception during scan yields an error result (lines 560-561)."""
        with patch.object(
            scanner_with_binary, "_find_binary", return_value=scanner_with_binary._binary_path
        ):
            with patch("subprocess.run", side_effect=RuntimeError("kaboom")):
                result = scanner_with_binary.scan([tmp_path])

        assert result.success is False
        assert result.error == "kaboom"


class TestParseFindingException:
    """_parse_finding returns None on parse failure (lines 627-628)."""

    def test_parse_finding_returns_none_on_exception(self, tmp_path: Path):
        """When ScanFinding construction fails, None is returned (lines 627-628)."""
        scanner = GitleaksScanner(auto_install=False)
        item: dict[str, Any] = {
            "Description": "Secret",
            "File": "x.py",
            "Secret": "abc",
            "RuleID": "r",
        }
        with patch("envdrift.scanner.gitleaks.ScanFinding", side_effect=ValueError("bad")):
            result = scanner._parse_finding(item, tmp_path)
        assert result is None
