"""Coverage-focused tests for envdrift.scanner.talisman.

These tests target previously-uncovered branches: the template-URL fallback,
version-check exception handling, get_version parsing, binary caching,
scanner.install, scan edge cases (file pattern, invalid JSON report, generic
exceptions), and report/failure parsing edge cases.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from envdrift.scanner.talisman import (
    TalismanInstaller,
    TalismanScanner,
)


class TestGetDownloadUrlTemplateFallback:
    """Exercise the DOWNLOAD_URL_TEMPLATE fallback (line 148)."""

    @patch("envdrift.scanner.talisman._get_talisman_download_urls", return_value={})
    @patch("envdrift.scanner.talisman.get_platform_info")
    def test_uses_template_when_no_custom_url(self, mock_platform: MagicMock, mock_urls: MagicMock):
        """When constants have no custom URL, the template is formatted."""
        mock_platform.return_value = ("Linux", "x86_64")
        installer = TalismanInstaller(version="9.9.9")
        url = installer.get_download_url()

        assert url == (
            "https://github.com/thoughtworks/talisman/releases/download/v9.9.9/talisman_linux_amd64"
        )

    @patch("envdrift.scanner.talisman._get_talisman_download_urls", return_value={})
    @patch("envdrift.scanner.talisman.get_platform_info")
    def test_template_includes_exe_for_windows(
        self, mock_platform: MagicMock, mock_urls: MagicMock
    ):
        """Windows template fallback carries the .exe extension."""
        mock_platform.return_value = ("Windows", "x86_64")
        installer = TalismanInstaller(version="1.2.3")
        url = installer.get_download_url()

        assert url.endswith("talisman_windows_amd64.exe")


class TestInstallerVersionCheckException:
    """Exercise install() version-check exception handling (lines 209-210)."""

    @patch("subprocess.run")
    def test_version_check_exception_triggers_reinstall(self, mock_run: MagicMock, tmp_path: Path):
        """If `--version` subprocess raises, install falls through to download."""
        target_path = tmp_path / "talisman"
        target_path.write_bytes(b"existing")

        # subprocess.run raises -> except branch (pass) -> download_binary called
        mock_run.side_effect = OSError("cannot exec")

        installer = TalismanInstaller(version="1.32.0")
        with (
            patch(
                "envdrift.scanner.talisman.get_talisman_path",
                return_value=target_path,
            ),
            patch.object(installer, "download_binary") as mock_download,
        ):
            result = installer.install()

        assert result == target_path
        mock_download.assert_called_once_with(target_path)


class TestGetVersion:
    """Exercise TalismanScanner.get_version (lines 268-285)."""

    def test_get_version_extracts_numeric_token(self, tmp_path: Path):
        """A version string with a numeric token is extracted."""
        binary = tmp_path / "talisman"
        binary.touch()
        scanner = TalismanScanner(auto_install=False)

        with (
            patch.object(scanner, "_find_binary", return_value=binary),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(stdout="talisman version 1.32.0", stderr="")
            version = scanner.get_version()

        assert version == "1.32.0"

    def test_get_version_falls_back_to_stderr(self, tmp_path: Path):
        """When stdout is empty, stderr is parsed for the version."""
        binary = tmp_path / "talisman"
        binary.touch()
        scanner = TalismanScanner(auto_install=False)

        with (
            patch.object(scanner, "_find_binary", return_value=binary),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(stdout="   ", stderr="talisman 2.0.1")
            version = scanner.get_version()

        # stdout is whitespace-only, so stderr is used; "2.0.1" is the first
        # numeric-leading token.
        assert version == "2.0.1"

    def test_get_version_returns_none_when_no_numeric_token(self, tmp_path: Path):
        """Output without any numeric-leading token yields None."""
        binary = tmp_path / "talisman"
        binary.touch()
        scanner = TalismanScanner(auto_install=False)

        with (
            patch.object(scanner, "_find_binary", return_value=binary),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(stdout="no version here", stderr="")
            version = scanner.get_version()

        assert version is None

    def test_get_version_returns_none_on_exception(self):
        """When _find_binary raises, get_version swallows it and returns None."""
        scanner = TalismanScanner(auto_install=False)
        with patch.object(scanner, "_find_binary", side_effect=RuntimeError("boom")):
            assert scanner.get_version() is None


class TestFindBinaryCache:
    """Exercise the cached binary fast-path (line 297)."""

    def test_find_binary_returns_cached_path(self, tmp_path: Path):
        """A cached, still-existing binary path is returned directly."""
        binary = tmp_path / "talisman"
        binary.touch()
        scanner = TalismanScanner(auto_install=False)
        scanner._binary_path = binary

        # If the cache short-circuit fires, get_talisman_path is never consulted.
        with patch("envdrift.scanner.talisman.get_talisman_path") as mock_path:
            result = scanner._find_binary()

        assert result == binary
        mock_path.assert_not_called()


class TestScannerInstall:
    """Exercise TalismanScanner.install (lines 338-343)."""

    def test_install_delegates_to_installer(self, tmp_path: Path):
        """Scanner.install builds an installer, runs it, and caches the path."""
        installed = tmp_path / "talisman"
        installed.touch()
        messages: list[str] = []
        scanner = TalismanScanner(auto_install=False, version="1.32.0")

        with patch.object(TalismanInstaller, "install", return_value=installed) as mock_install:
            result = scanner.install(progress_callback=messages.append)

        assert result == installed
        assert scanner._binary_path == installed
        mock_install.assert_called_once()


class TestScanFilePattern:
    """Exercise the path.is_file() --pattern branch in scan (line 397)."""

    def test_scan_single_file_adds_pattern_arg(self, tmp_path: Path):
        """Scanning a file passes --pattern <filename> and runs in parent dir."""
        target = tmp_path / "secrets.env"
        target.write_text("KEY=value\n")

        binary = tmp_path / "talisman"
        binary.touch()
        scanner = TalismanScanner(auto_install=False)
        scanner._binary_path = binary

        with (
            patch.object(scanner, "_find_binary", return_value=binary),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
            result = scanner.scan([target])

        assert result.success is True
        args = mock_run.call_args.args[0]
        assert "--pattern" in args
        assert args[args.index("--pattern") + 1] == "secrets.env"
        # Should run from the parent directory of the file.
        assert mock_run.call_args.kwargs["cwd"] == str(tmp_path)


class TestScanInvalidJsonReport:
    """Exercise the json.JSONDecodeError continue branch (lines 427-429)."""

    def test_scan_skips_invalid_json_report(self, tmp_path: Path):
        """An invalid JSON report is skipped; a later valid one is parsed."""
        binary = tmp_path / "talisman"
        binary.touch()
        scanner = TalismanScanner(auto_install=False)
        scanner._binary_path = binary

        report_dir = tmp_path / "report"
        report_dir.mkdir()
        # First candidate location: invalid JSON -> JSONDecodeError -> continue.
        bad_dir = report_dir / "talisman_reports" / "data"
        bad_dir.mkdir(parents=True)
        (bad_dir / "report.json").write_text("{ this is not json ")
        # Second candidate location: valid JSON with one finding.
        valid_report = {
            "results": [
                {
                    "filename": "x.py",
                    "failures": [{"type": "filecontent", "message": "secret", "severity": "high"}],
                }
            ]
        }
        (report_dir / "report.json").write_text(json.dumps(valid_report))

        with (
            patch.object(scanner, "_find_binary", return_value=binary),
            patch("tempfile.TemporaryDirectory") as mock_temp,
            patch("subprocess.run") as mock_run,
        ):
            mock_temp.return_value.__enter__.return_value = str(report_dir)
            mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
            result = scanner.scan([tmp_path])

        assert result.success is True
        assert len(result.findings) == 1
        assert result.findings[0].rule_id == "talisman-filecontent"


class TestScanGenericException:
    """Exercise the generic Exception handler in scan (lines 451-452)."""

    def test_scan_handles_generic_exception(self, tmp_path: Path):
        """A non-timeout exception from subprocess.run yields an error result."""
        binary = tmp_path / "talisman"
        binary.touch()
        scanner = TalismanScanner(auto_install=False)
        scanner._binary_path = binary

        with (
            patch.object(scanner, "_find_binary", return_value=binary),
            patch("subprocess.run", side_effect=ValueError("unexpected failure")),
        ):
            result = scanner.scan([tmp_path])

        assert result.success is False
        assert result.error == "unexpected failure"


class TestParseReportRelativeToFile:
    """Exercise base_path.is_file() relative-path resolution (line 495)."""

    def test_relative_paths_resolved_against_file_parent(self, tmp_path: Path):
        """When base_path is a file, relative finding paths use its parent dir."""
        base_file = tmp_path / "scanned.py"
        base_file.write_text("x = 1\n")
        scanner = TalismanScanner(auto_install=False)

        report_data: dict[str, Any] = {
            "results": [
                {
                    "filename": "nested/secret.txt",
                    "failures": [{"type": "filecontent", "message": "leak", "severity": "high"}],
                }
            ]
        }
        findings, _ = scanner._parse_report(report_data, base_file)

        assert len(findings) == 1
        assert findings[0].file_path == tmp_path / "nested" / "secret.txt"


class TestParseReportIgnores:
    """Exercise the ignores loop body (line 513)."""

    def test_ignores_are_iterated_without_findings(self, tmp_path: Path):
        """Entries under 'ignores' are iterated but produce no findings."""
        scanner = TalismanScanner(auto_install=False)
        report_data: dict[str, Any] = {
            "results": [
                {
                    "filename": "ignored.py",
                    "failures": [],
                    "warnings": [],
                    "ignores": [
                        {"type": "filecontent", "message": "acknowledged"},
                        {"type": "entropy", "message": "acknowledged 2"},
                    ],
                }
            ]
        }
        findings, files_scanned = scanner._parse_report(report_data, tmp_path)

        assert files_scanned == 1
        assert findings == []


class TestParseFailureException:
    """Exercise the _parse_failure exception guard (lines 568-569)."""

    def test_parse_failure_returns_none_on_bad_input(self, tmp_path: Path):
        """A failure object whose .get raises is swallowed, returning None."""
        scanner = TalismanScanner(auto_install=False)

        class ExplodingFailure(dict):
            def get(self, *args: object, **kwargs: object) -> object:
                raise RuntimeError("boom")

        result = scanner._parse_failure(ExplodingFailure(), tmp_path / "f.py")
        assert result is None

    def test_parse_failure_returns_none_when_severity_not_str(self, tmp_path: Path):
        """A non-string severity triggers .lower() AttributeError -> None."""
        scanner = TalismanScanner(auto_install=False)
        failure: dict[str, Any] = {
            "type": "filecontent",
            "message": "secret",
            "severity": 123,  # int has no .lower()
        }
        assert scanner._parse_failure(failure, tmp_path / "f.py") is None


@pytest.mark.parametrize(
    "side_effect",
    [
        subprocess.TimeoutExpired(cmd="talisman", timeout=10),
        OSError("cannot exec"),
    ],
)
def test_get_version_subprocess_errors_return_none(side_effect: Exception, tmp_path: Path):
    """get_version returns None for any subprocess error type."""
    binary = tmp_path / "talisman"
    binary.touch()
    scanner = TalismanScanner(auto_install=False)
    with (
        patch.object(scanner, "_find_binary", return_value=binary),
        patch("subprocess.run", side_effect=side_effect),
    ):
        assert scanner.get_version() is None
