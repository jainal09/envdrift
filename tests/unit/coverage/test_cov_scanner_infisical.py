"""Coverage-focused tests for envdrift.scanner.infisical.

These tests target previously-uncovered branches: the download-URL template
fallback, the zip / unknown-archive extraction branches, the installer's
already-installed version check, the scanner's get_version parsing, the cached
binary path, the scanner-level install wrapper, the generic scan exception
handler, and the _parse_finding failure path.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from envdrift.scanner.infisical import (
    InfisicalInstaller,
    InfisicalScanner,
)


class TestDownloadUrlTemplateFallback:
    """Cover the DOWNLOAD_URL_TEMPLATE fallback (line 162)."""

    @patch("envdrift.scanner.infisical._get_infisical_download_urls", return_value={})
    @patch("envdrift.scanner.infisical.get_platform_info")
    def test_falls_back_to_template_when_no_custom_url(
        self, mock_platform: MagicMock, mock_custom: MagicMock
    ):
        """When constants provide no custom URL, build from the template."""
        mock_platform.return_value = ("Linux", "x86_64")
        installer = InfisicalInstaller(version="9.9.9")
        url = installer.get_download_url()
        # Template uses os/arch/ext placeholders -> linux/amd64/tar.gz
        assert url == (
            "https://github.com/Infisical/infisical/releases/download/"
            "infisical-cli/v9.9.9/infisical_9.9.9_linux_amd64.tar.gz"
        )

    @patch(
        "envdrift.scanner.infisical._get_infisical_download_urls",
        return_value={"windows_amd64": "custom://{version}/win.zip"},
    )
    @patch("envdrift.scanner.infisical.get_platform_info")
    def test_template_fallback_for_unlisted_key(
        self, mock_platform: MagicMock, mock_custom: MagicMock
    ):
        """A custom map missing the current key still falls to the template."""
        mock_platform.return_value = ("Linux", "arm64")
        installer = InfisicalInstaller(version="1.2.3")
        url = installer.get_download_url()
        assert url.endswith("infisical_1.2.3_linux_arm64.tar.gz")
        assert "custom://" not in url


class TestDownloadAndExtractBranches:
    """Cover the zip and unknown-archive branches of download_and_extract."""

    @patch("envdrift.scanner.infisical.platform.system", return_value="Windows")
    @patch("urllib.request.urlretrieve")
    @patch.object(InfisicalInstaller, "get_download_url")
    def test_zip_archive_branch(
        self,
        mock_url: MagicMock,
        mock_urlretrieve: MagicMock,
        mock_system: MagicMock,
        tmp_path: Path,
    ):
        """A .zip URL exercises the _extract_zip branch (lines 197-198)."""
        import zipfile

        mock_url.return_value = "https://example.test/infisical_x_windows_amd64.zip"
        target = tmp_path / "out" / "infisical.exe"

        def fake_download(url: str, dest: str) -> None:
            with zipfile.ZipFile(dest, "w") as zf:
                zf.writestr("infisical.exe", "binary-bytes")

        mock_urlretrieve.side_effect = fake_download

        installer = InfisicalInstaller(version="x")
        installer.download_and_extract(target)

        assert target.exists()
        assert target.read_text() == "binary-bytes"

    @patch("urllib.request.urlretrieve")
    @patch.object(InfisicalInstaller, "get_download_url")
    def test_unknown_archive_format_raises(
        self,
        mock_url: MagicMock,
        mock_urlretrieve: MagicMock,
        tmp_path: Path,
    ):
        """An unrecognized archive extension raises (line 200)."""
        from envdrift.scanner.infisical import InfisicalInstallError

        mock_url.return_value = "https://example.test/infisical_x_linux.bz2"
        mock_urlretrieve.side_effect = lambda url, dest: Path(dest).write_bytes(b"x")

        installer = InfisicalInstaller(version="x")
        with pytest.raises(InfisicalInstallError, match="Unknown archive format"):
            installer.download_and_extract(tmp_path / "infisical")


class TestInstallerAlreadyInstalled:
    """Cover the version-check path of InfisicalInstaller.install (251-263)."""

    @patch("envdrift.scanner.infisical.get_infisical_path")
    def test_returns_existing_when_version_matches(self, mock_get_path: MagicMock, tmp_path: Path):
        """An installed binary whose --version matches is reused, not re-downloaded."""
        binary = tmp_path / "infisical"
        binary.touch()
        mock_get_path.return_value = binary

        messages: list[str] = []
        installer = InfisicalInstaller(version="0.31.1", progress_callback=messages.append)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="infisical version 0.31.1", returncode=0)
            with patch.object(installer, "download_and_extract") as mock_dl:
                result = installer.install()

        assert result == binary
        mock_dl.assert_not_called()
        assert any("already installed" in m for m in messages)

    @patch("envdrift.scanner.infisical.get_infisical_path")
    def test_reinstalls_when_version_mismatch(self, mock_get_path: MagicMock, tmp_path: Path):
        """A version mismatch triggers download_and_extract."""
        binary = tmp_path / "infisical"
        binary.touch()
        mock_get_path.return_value = binary

        installer = InfisicalInstaller(version="0.31.1")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="infisical version 0.20.0", returncode=0)
            with patch.object(installer, "download_and_extract") as mock_dl:
                result = installer.install()

        assert result == binary
        mock_dl.assert_called_once_with(binary)

    @patch("envdrift.scanner.infisical.get_infisical_path")
    def test_reinstalls_when_version_check_raises(self, mock_get_path: MagicMock, tmp_path: Path):
        """A corrupt binary (subprocess raises) falls through to reinstall (261-263)."""
        binary = tmp_path / "infisical"
        binary.touch()
        mock_get_path.return_value = binary

        installer = InfisicalInstaller(version="0.31.1")

        with patch("subprocess.run", side_effect=OSError("exec format error")):
            with patch.object(installer, "download_and_extract") as mock_dl:
                result = installer.install()

        assert result == binary
        mock_dl.assert_called_once_with(binary)


class TestScannerGetVersion:
    """Cover InfisicalScanner.get_version (319-336)."""

    def test_get_version_parses_numeric_token(self, tmp_path: Path):
        """get_version extracts the first digit-leading token from output."""
        scanner = InfisicalScanner(auto_install=False)
        binary = tmp_path / "infisical"
        binary.touch()

        with patch.object(scanner, "_find_binary", return_value=binary):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(stdout="infisical version 0.31.1\n")
                version = scanner.get_version()

        assert version == "0.31.1"

    def test_get_version_returns_none_for_non_numeric_output(self, tmp_path: Path):
        """Output with no digit-leading token yields None (line 334)."""
        scanner = InfisicalScanner(auto_install=False)
        binary = tmp_path / "infisical"
        binary.touch()

        with patch.object(scanner, "_find_binary", return_value=binary):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(stdout="infisical version unknown")
                version = scanner.get_version()

        assert version is None

    def test_get_version_returns_none_on_exception(self, tmp_path: Path):
        """An exception during version lookup is swallowed and returns None (335-336)."""
        scanner = InfisicalScanner(auto_install=False)
        binary = tmp_path / "infisical"
        binary.touch()

        with patch.object(scanner, "_find_binary", return_value=binary):
            with patch("subprocess.run", side_effect=subprocess.SubprocessError("boom")):
                version = scanner.get_version()

        assert version is None


class TestFindBinaryCached:
    """Cover the cached-binary fast path of _find_binary (347-348)."""

    def test_returns_cached_path_without_relookup(self, tmp_path: Path):
        """A cached, still-existing binary path is returned directly."""
        binary = tmp_path / "infisical"
        binary.touch()
        scanner = InfisicalScanner(auto_install=False)
        scanner._binary_path = binary

        # If the cached path were ignored, get_infisical_path/which would be hit.
        with patch("envdrift.scanner.infisical.get_infisical_path") as mock_get:
            with patch("shutil.which") as mock_which:
                result = scanner._find_binary()

        assert result == binary
        mock_get.assert_not_called()
        mock_which.assert_not_called()


class TestScannerInstallWrapper:
    """Cover the scanner-level install() wrapper (390-395)."""

    def test_install_delegates_to_installer_and_caches_path(self, tmp_path: Path):
        """scanner.install builds an installer, runs it, and caches the path."""
        installed = tmp_path / "infisical"
        installed.touch()
        messages: list[str] = []

        scanner = InfisicalScanner(auto_install=False, version="0.31.1")

        with patch.object(InfisicalInstaller, "install", return_value=installed) as mock_install:
            result = scanner.install(progress_callback=messages.append)

        assert result == installed
        assert scanner._binary_path == installed
        mock_install.assert_called_once()


class TestScanGenericException:
    """Cover the generic Exception handler inside scan (504-505)."""

    def test_unexpected_error_becomes_scan_error(self, tmp_path: Path):
        """A non-timeout exception from subprocess yields an error ScanResult."""
        scanner = InfisicalScanner(auto_install=False)
        binary = tmp_path / "infisical"
        binary.touch()
        scanner._binary_path = binary

        with patch.object(scanner, "_find_binary", return_value=binary):
            with patch("subprocess.run", side_effect=RuntimeError("kaboom")):
                result = scanner.scan([tmp_path])

        assert result.success is False
        assert result.error is not None
        assert "kaboom" in result.error


class TestParseFindingFailure:
    """Cover the _parse_finding exception path returning None (571-572)."""

    def test_returns_none_when_redaction_raises(self, tmp_path: Path):
        """If redact_secret raises, _parse_finding swallows it and returns None."""
        scanner = InfisicalScanner(auto_install=False)
        item: dict[str, Any] = {
            "File": "test.py",
            "Secret": "AKIAIOSFODNN7EXAMPLE",
            "RuleID": "aws-access-key-id",
        }

        with patch(
            "envdrift.scanner.infisical.redact_secret",
            side_effect=ValueError("bad secret"),
        ):
            result = scanner._parse_finding(item, tmp_path)

        assert result is None

    def test_returns_none_for_non_mapping_item(self, tmp_path: Path):
        """A non-dict item (no .get) triggers the exception path -> None."""
        scanner = InfisicalScanner(auto_install=False)
        # Passing a list triggers AttributeError on .get inside the try block.
        result = scanner._parse_finding(["not", "a", "dict"], tmp_path)  # type: ignore[arg-type]
        assert result is None
