"""Coverage-focused unit tests for envdrift.scanner.trivy.

These tests target previously-uncovered branches: the template-URL fallback,
the zip/unknown-archive paths in download_and_extract, install() version
verification, get_version(), the cached _find_binary path, the install()
instance method, scan() generic-exception handling, and _parse_secret edge
cases (relative path against a file base, and parse failure -> None).
"""

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
    TrivyScanner,
)


class TestDownloadUrlTemplateFallback:
    """Cover the DOWNLOAD_URL_TEMPLATE fallback (no custom URL in constants)."""

    @patch("envdrift.scanner.trivy._get_trivy_download_urls", return_value={})
    @patch("envdrift.scanner.trivy.get_platform_info")
    def test_template_used_when_no_custom_url(self, mock_platform: MagicMock, mock_urls: MagicMock):
        """When constants have no matching custom URL, the template is formatted."""
        mock_platform.return_value = ("Linux", "x86_64")
        installer = TrivyInstaller(version="0.59.9")
        url = installer.get_download_url()

        # Comes from DOWNLOAD_URL_TEMPLATE, not the custom constants mapping.
        assert url == (
            "https://github.com/aquasecurity/trivy/releases/download/"
            "v0.59.9/trivy_0.59.9_Linux-64bit.tar.gz"
        )
        mock_urls.assert_called_once()


class TestDownloadAndExtractArchiveTypes:
    """Cover the zip and unknown-archive branches in download_and_extract."""

    @patch("urllib.request.urlretrieve")
    def test_zip_archive_branch(self, mock_urlretrieve: MagicMock, tmp_path: Path):
        """A .zip download routes through _extract_zip and installs the binary."""
        target = tmp_path / "out" / "trivy.exe"

        def fake_download(url: str, dest: str) -> None:
            import zipfile

            with zipfile.ZipFile(dest, "w") as zf:
                zf.writestr("trivy.exe", "binary-bytes")

        mock_urlretrieve.side_effect = fake_download

        installer = TrivyInstaller(version="0.58.0")
        # Force a windows .zip URL regardless of host platform.
        with (
            patch.object(
                installer,
                "get_download_url",
                return_value="https://example.test/trivy_0.58.0_windows-64bit.zip",
            ),
            patch("envdrift.scanner.trivy.platform.system", return_value="Windows"),
        ):
            installer.download_and_extract(target)

        assert target.exists()
        assert target.read_text() == "binary-bytes"

    @patch("urllib.request.urlretrieve")
    def test_unknown_archive_format_raises(self, mock_urlretrieve: MagicMock, tmp_path: Path):
        """An archive with an unrecognized extension raises TrivyInstallError."""
        mock_urlretrieve.side_effect = lambda url, dest: Path(dest).write_bytes(b"x")
        installer = TrivyInstaller()
        with patch.object(
            installer,
            "get_download_url",
            return_value="https://example.test/trivy_0.58.0.rpm",
        ):
            with pytest.raises(TrivyInstallError, match="Unknown archive format"):
                installer.download_and_extract(tmp_path / "trivy")


class TestInstallVersionVerification:
    """Cover install() when an existing binary's version is verified."""

    @patch("envdrift.scanner.trivy.get_trivy_path")
    def test_existing_binary_matching_version_short_circuits(
        self, mock_get_path: MagicMock, tmp_path: Path
    ):
        """If the installed binary already reports the target version, skip download."""
        binary = tmp_path / "trivy"
        binary.touch()
        mock_get_path.return_value = binary

        messages: list[str] = []
        installer = TrivyInstaller(version="0.58.0", progress_callback=messages.append)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout='{"Version": "0.58.0"}', returncode=0)
            with patch.object(installer, "download_and_extract") as mock_dl:
                result = installer.install()

        assert result == binary
        mock_dl.assert_not_called()
        assert any("already installed" in m for m in messages)

    @patch("envdrift.scanner.trivy.get_trivy_path")
    def test_existing_binary_version_check_exception_reinstalls(
        self, mock_get_path: MagicMock, tmp_path: Path
    ):
        """A crashing version check falls through to a reinstall."""
        binary = tmp_path / "trivy"
        binary.touch()
        mock_get_path.return_value = binary

        installer = TrivyInstaller(version="0.58.0")
        with patch("subprocess.run", side_effect=OSError("boom")):
            with patch.object(installer, "download_and_extract") as mock_dl:
                result = installer.install()

        # Version verification raised -> we proceed to download_and_extract.
        mock_dl.assert_called_once_with(binary)
        assert result == binary

    @patch("envdrift.scanner.trivy.get_trivy_path")
    def test_existing_binary_version_mismatch_reinstalls(
        self, mock_get_path: MagicMock, tmp_path: Path
    ):
        """A version mismatch in output proceeds to reinstall."""
        binary = tmp_path / "trivy"
        binary.touch()
        mock_get_path.return_value = binary

        installer = TrivyInstaller(version="0.58.0")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout='{"Version": "0.40.0"}', returncode=0)
            with patch.object(installer, "download_and_extract") as mock_dl:
                installer.install()

        mock_dl.assert_called_once_with(binary)


class TestGetVersion:
    """Cover TrivyScanner.get_version()."""

    def test_get_version_parses_json(self, tmp_path: Path):
        """get_version returns the Version field from trivy JSON output."""
        binary = tmp_path / "trivy"
        binary.touch()
        scanner = TrivyScanner(auto_install=False)
        with patch.object(scanner, "_find_binary", return_value=binary):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(stdout='{"Version": "0.58.0"}', returncode=0)
                assert scanner.get_version() == "0.58.0"

    def test_get_version_invalid_json_returns_none(self, tmp_path: Path):
        """Non-JSON version output yields None (JSONDecodeError swallowed)."""
        binary = tmp_path / "trivy"
        binary.touch()
        scanner = TrivyScanner(auto_install=False)
        with patch.object(scanner, "_find_binary", return_value=binary):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(stdout="not json", returncode=0)
                assert scanner.get_version() is None

    def test_get_version_nonzero_returncode_returns_none(self, tmp_path: Path):
        """A non-zero return code yields None."""
        binary = tmp_path / "trivy"
        binary.touch()
        scanner = TrivyScanner(auto_install=False)
        with patch.object(scanner, "_find_binary", return_value=binary):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(stdout="", returncode=1)
                assert scanner.get_version() is None

    def test_get_version_exception_returns_none(self):
        """Any exception in the version path returns None."""
        scanner = TrivyScanner(auto_install=False)
        with patch.object(scanner, "_find_binary", side_effect=OSError("no binary")):
            assert scanner.get_version() is None


class TestFindBinaryCached:
    """Cover the cached-path early return in _find_binary."""

    def test_find_binary_returns_cached_existing_path(self, tmp_path: Path):
        """A previously resolved, still-existing binary path is returned directly."""
        binary = tmp_path / "trivy"
        binary.touch()
        scanner = TrivyScanner(auto_install=False)
        scanner._binary_path = binary

        # If the cache were ignored, get_trivy_path/which would be consulted;
        # patch them to fail loudly to prove the cache path is taken.
        with patch(
            "envdrift.scanner.trivy.get_trivy_path",
            side_effect=AssertionError("cache not used"),
        ):
            assert scanner._find_binary() == binary


class TestInstallInstanceMethod:
    """Cover the TrivyScanner.install() instance method."""

    def test_install_delegates_to_installer(self, tmp_path: Path):
        """Scanner.install builds a TrivyInstaller and caches the returned path."""
        installed = tmp_path / "trivy"
        installed.touch()
        scanner = TrivyScanner(auto_install=False, version="0.58.0")

        messages: list[str] = []
        with patch.object(TrivyInstaller, "install", return_value=installed) as mock_install:
            result = scanner.install(progress_callback=messages.append)

        assert result == installed
        assert scanner._binary_path == installed
        mock_install.assert_called_once()


class TestScanGenericException:
    """Cover the generic Exception handler inside scan()'s per-path loop."""

    def test_scan_generic_exception_returns_error_result(self, tmp_path: Path):
        """A non-timeout exception from subprocess becomes an error ScanResult."""
        binary = tmp_path / "trivy"
        binary.touch()
        scanner = TrivyScanner(auto_install=False)
        scanner._binary_path = binary

        with patch.object(scanner, "_find_binary", return_value=binary):
            with patch("subprocess.run", side_effect=ValueError("kaboom")):
                result = scanner.scan([tmp_path])

        assert result.success is False
        assert result.error is not None
        assert "kaboom" in result.error


class TestParseSecretEdgeCases:
    """Cover _parse_secret relative-against-file path and failure -> None."""

    def test_relative_target_against_file_base(self, tmp_path: Path):
        """When base_path is a file, the relative target resolves to its parent."""
        base_file = tmp_path / "sub" / "config.env"
        base_file.parent.mkdir(parents=True)
        base_file.write_text("x=1\n")

        scanner = TrivyScanner(auto_install=False)
        secret: dict[str, Any] = {
            "RuleID": "generic-api-key",
            "Category": "Generic",
            "Title": "Generic API Key",
            "Severity": "HIGH",
            "StartLine": 3,
            "Match": "SECRET_VALUE",
        }
        finding = scanner._parse_secret(secret, "config.env", base_file)

        assert finding is not None
        # Resolved against the parent directory of the file base_path.
        assert finding.file_path == base_file.parent / "config.env"

    def test_parse_secret_returns_none_on_error(self, tmp_path: Path):
        """An exception while building the finding yields None, not a raise."""
        scanner = TrivyScanner(auto_install=False)
        # secret.get("Severity") returns a non-str -> .upper() raises AttributeError,
        # which is caught and converted to None.
        secret: dict[str, Any] = {
            "RuleID": "x",
            "Category": "c",
            "Title": "t",
            "Severity": 123,
            "Match": "m",
        }
        assert scanner._parse_secret(secret, "t.py", tmp_path) is None

    def test_unknown_severity_maps_to_high(self, tmp_path: Path):
        """An unrecognized severity string falls back to HIGH."""
        scanner = TrivyScanner(auto_install=False)
        secret: dict[str, Any] = {
            "RuleID": "x",
            "Category": "c",
            "Title": "t",
            "Severity": "WEIRD",
            "Match": "m",
        }
        finding = scanner._parse_secret(secret, "t.py", tmp_path)
        assert finding is not None
        assert finding.severity == FindingSeverity.HIGH


class TestScanTimeoutAndErrorBranches:
    """Extra coverage for timeout vs generic error and JSON re-entry."""

    def test_scan_timeout_distinct_from_generic(self, tmp_path: Path):
        """TimeoutExpired is reported as a timeout, separate from generic errors."""
        binary = tmp_path / "trivy"
        binary.touch()
        scanner = TrivyScanner(auto_install=False)
        scanner._binary_path = binary
        with patch.object(scanner, "_find_binary", return_value=binary):
            with patch(
                "subprocess.run",
                side_effect=subprocess.TimeoutExpired(cmd="trivy", timeout=300),
            ):
                result = scanner.scan([tmp_path])
        assert result.success is False
        assert result.error is not None
        assert "timed out" in result.error.lower()

    def test_scan_valid_findings_via_json(self, tmp_path: Path):
        """A valid JSON payload produces parsed findings (happy path re-entry)."""
        binary = tmp_path / "trivy"
        binary.touch()
        scanner = TrivyScanner(auto_install=False)
        scanner._binary_path = binary
        payload = json.dumps(
            {
                "Results": [
                    {
                        "Target": "leak.env",
                        "Secrets": [
                            {
                                "RuleID": "aws-key",
                                "Category": "AWS",
                                "Title": "AWS Key",
                                "Severity": "CRITICAL",
                                "StartLine": 2,
                                "Match": "AKIAIOSFODNN7EXAMPLE",
                            }
                        ],
                    }
                ]
            }
        )
        with patch.object(scanner, "_find_binary", return_value=binary):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(stdout=payload, stderr="", returncode=0)
                result = scanner.scan([tmp_path])
        assert result.success is True
        assert len(result.findings) == 1
        assert result.findings[0].severity == FindingSeverity.CRITICAL
