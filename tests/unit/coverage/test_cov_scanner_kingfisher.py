"""Coverage-focused unit tests for envdrift.scanner.kingfisher.

These tests target previously-uncovered branches: error/exception handlers in
get_version, _find_binary, _install_via_homebrew, install, and scan, plus the
relative-path resolution branches of _parse_finding.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from envdrift.scanner.kingfisher import (
    KingfisherInstallError,
    KingfisherNotFoundError,
    KingfisherScanner,
)


class TestGetVersionExceptionBranch:
    """Cover the broad except in get_version (lines 193-194)."""

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_get_version_returns_none_on_subprocess_exception(self, mock_run, mock_which):
        """A raised subprocess error is swallowed and None is returned."""
        mock_which.return_value = "/opt/homebrew/bin/kingfisher"
        mock_run.side_effect = OSError("boom")

        scanner = KingfisherScanner(auto_install=False)
        assert scanner.get_version() is None

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_get_version_returns_none_when_stdout_empty(self, mock_run, mock_which):
        """Empty stdout with returncode 0 yields None (parts is falsy)."""
        mock_which.return_value = "/opt/homebrew/bin/kingfisher"
        mock_run.return_value = MagicMock(returncode=0, stdout="   \n")

        scanner = KingfisherScanner(auto_install=False)
        assert scanner.get_version() is None


class TestFindBinaryBranches:
    """Cover _find_binary cached + auto-install branches (lines 206, 216-222)."""

    def test_cached_binary_path_is_reused(self, tmp_path):
        """When a cached binary exists, it is returned without touching PATH."""
        fake_binary = tmp_path / "kingfisher"
        fake_binary.write_text("#!/bin/sh\n")
        scanner = KingfisherScanner(auto_install=False)
        scanner._binary_path = fake_binary

        with patch("shutil.which") as mock_which:
            assert scanner._find_binary() == fake_binary
            mock_which.assert_not_called()

    def test_auto_install_success_sets_binary_path(self, tmp_path):
        """A successful install populates and returns the binary path."""
        installed = tmp_path / "kingfisher"
        installed.write_text("#!/bin/sh\n")
        scanner = KingfisherScanner(auto_install=True)

        with (
            patch("shutil.which", return_value=None),
            patch.object(scanner, "_install_via_homebrew", return_value=installed),
        ):
            result = scanner._find_binary()

        assert result == installed
        assert scanner._binary_path == installed

    def test_auto_install_failure_raises_not_found(self):
        """KingfisherInstallError during install is swallowed; not-found is raised."""
        scanner = KingfisherScanner(auto_install=True)

        with (
            patch("shutil.which", return_value=None),
            patch.object(
                scanner,
                "_install_via_homebrew",
                side_effect=KingfisherInstallError("nope"),
            ),
            pytest.raises(KingfisherNotFoundError),
        ):
            scanner._find_binary()


class TestInstallViaHomebrewErrorBranches:
    """Cover _install_via_homebrew error paths (lines 258, 265, 267-270)."""

    @patch("platform.system", return_value="Darwin")
    @patch("shutil.which")
    @patch("subprocess.run")
    def test_install_failure_raises_with_stderr(self, mock_run, mock_which, _mock_sys):
        """Non-zero exit without 'already installed' raises with stderr text."""
        mock_which.return_value = "/opt/homebrew/bin/brew"
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="Error: download failed")

        scanner = KingfisherScanner(auto_install=False)
        with pytest.raises(KingfisherInstallError, match="download failed"):
            scanner._install_via_homebrew()

    @patch("platform.system", return_value="Linux")
    @patch("shutil.which")
    @patch("subprocess.run")
    def test_install_success_but_binary_missing(self, mock_run, mock_which, _mock_sys):
        """Successful brew run but no resolvable binary raises."""
        # first which -> brew found, second which -> kingfisher not found
        mock_which.side_effect = ["/usr/bin/brew", None]
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        scanner = KingfisherScanner(auto_install=False)
        with pytest.raises(KingfisherInstallError, match="binary not found"):
            scanner._install_via_homebrew()

    @patch("platform.system", return_value="Darwin")
    @patch("shutil.which")
    @patch("subprocess.run")
    def test_install_timeout_wrapped(self, mock_run, mock_which, _mock_sys):
        """subprocess timeout is wrapped into KingfisherInstallError."""
        mock_which.return_value = "/opt/homebrew/bin/brew"
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="brew", timeout=120)

        scanner = KingfisherScanner(auto_install=False)
        with pytest.raises(KingfisherInstallError, match="timed out"):
            scanner._install_via_homebrew()

    @patch("platform.system", return_value="Darwin")
    @patch("shutil.which")
    @patch("subprocess.run")
    def test_install_generic_exception_wrapped(self, mock_run, mock_which, _mock_sys):
        """A generic exception during install is wrapped."""
        mock_which.return_value = "/opt/homebrew/bin/brew"
        mock_run.side_effect = RuntimeError("kaboom")

        scanner = KingfisherScanner(auto_install=False)
        with pytest.raises(KingfisherInstallError, match="Installation failed"):
            scanner._install_via_homebrew()


class TestPublicInstall:
    """Cover the public install() method (lines 284-293)."""

    def test_install_invokes_progress_callback_on_success(self, tmp_path):
        """progress_callback is called before and after a successful install."""
        installed = tmp_path / "kingfisher"
        scanner = KingfisherScanner(auto_install=False)
        messages: list[str] = []

        with patch.object(scanner, "_install_via_homebrew", return_value=installed):
            result = scanner.install(progress_callback=messages.append)

        assert result == installed
        assert any("Installing Kingfisher" in m for m in messages)
        assert any(str(installed) in m for m in messages)

    def test_install_returns_none_on_install_error(self):
        """install() swallows KingfisherInstallError and returns None."""
        scanner = KingfisherScanner(auto_install=False)
        with patch.object(
            scanner, "_install_via_homebrew", side_effect=KingfisherInstallError("x")
        ):
            assert scanner.install() is None


class TestScanErrorBranches:
    """Cover scan() error/edge branches (lines 334-335, 416, 420, 437-440, 466-478)."""

    @patch("shutil.which")
    def test_temp_file_oserror_returns_error_result(self, mock_which, tmp_path):
        """An OSError creating the temp file produces an error ScanResult."""
        mock_which.return_value = "/opt/homebrew/bin/kingfisher"
        (tmp_path / "f.txt").write_text("data")

        scanner = KingfisherScanner(auto_install=False)
        with patch("tempfile.NamedTemporaryFile", side_effect=OSError("disk full")):
            result = scanner.scan([tmp_path])

        assert result.error is not None
        assert "Failed to create temp file" in result.error

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_no_binary_and_no_extract_flags(self, mock_run, mock_which, tmp_path):
        """Disabling binary scan and archive extraction adds the matching flags."""
        mock_which.return_value = "/opt/homebrew/bin/kingfisher"
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        (tmp_path / "f.txt").write_text("data")

        scanner = KingfisherScanner(
            auto_install=False,
            validate_secrets=False,
            scan_binary_files=False,
            extract_archives=False,
        )
        scanner.scan([tmp_path])

        call_args = mock_run.call_args[0][0]
        assert "--no-binary" in call_args
        assert "--no-extract-archives" in call_args

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_jobs_flag_added(self, mock_run, mock_which, tmp_path):
        """Setting jobs adds the --jobs argument (line 370)."""
        mock_which.return_value = "/opt/homebrew/bin/kingfisher"
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        (tmp_path / "f.txt").write_text("data")

        scanner = KingfisherScanner(auto_install=False, jobs=2)
        scanner.scan([tmp_path])

        call_args = mock_run.call_args[0][0]
        assert "--jobs" in call_args
        assert call_args[call_args.index("--jobs") + 1] == "2"

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_error_exit_code_returns_error_result(self, mock_run, mock_which, tmp_path):
        """A non-(0,200) exit code yields an error ScanResult (lines 437-440)."""
        mock_which.return_value = "/opt/homebrew/bin/kingfisher"
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="fatal: bad rule")
        (tmp_path / "f.txt").write_text("data")

        scanner = KingfisherScanner(auto_install=False)
        result = scanner.scan([tmp_path])

        assert result.error is not None
        assert "Kingfisher error" in result.error
        assert "bad rule" in result.error

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_invalid_json_report_is_ignored(self, mock_run, mock_which, tmp_path):
        """An invalid JSON report is swallowed, yielding no findings (466-468)."""
        mock_which.return_value = "/opt/homebrew/bin/kingfisher"
        mock_run.return_value = MagicMock(returncode=200, stdout="", stderr="")

        report_file = tmp_path / "report.json"
        report_file.write_text("this is not json {{{")
        (tmp_path / "f.txt").write_text("data")

        scanner = KingfisherScanner(auto_install=False, validate_secrets=False)
        with patch("tempfile.NamedTemporaryFile") as mock_temp:
            instance = MagicMock()
            instance.name = str(report_file)
            mock_temp.return_value.__enter__ = MagicMock(return_value=instance)
            mock_temp.return_value.__exit__ = MagicMock(return_value=False)
            result = scanner.scan([tmp_path])

        assert result.error is None
        assert result.findings == []

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_generic_exception_during_scan(self, mock_run, mock_which, tmp_path):
        """A generic exception from subprocess.run yields an error result (477-478)."""
        mock_which.return_value = "/opt/homebrew/bin/kingfisher"
        mock_run.side_effect = RuntimeError("unexpected")
        (tmp_path / "f.txt").write_text("data")

        scanner = KingfisherScanner(auto_install=False)
        result = scanner.scan([tmp_path])

        assert result.error is not None
        assert "RuntimeError" in result.error
        assert "unexpected" in result.error


class TestParseFindingPathBranches:
    """Cover _parse_finding path resolution + failure (lines 515, 517, 564-565)."""

    def test_relative_path_is_resolved_against_base(self, tmp_path):
        """A relative finding path is resolved against the base path (line 515)."""
        scanner = KingfisherScanner(auto_install=False)
        item = {
            "rule": {"id": "kingfisher.generic.1", "name": "Generic"},
            "finding": {"path": "sub/secret.env", "line": 3, "snippet": "abc"},
        }

        result = scanner._parse_finding(item, tmp_path)

        assert result is not None
        assert result.file_path == (tmp_path / "sub/secret.env").resolve()
        assert result.line_number == 3

    def test_missing_path_falls_back_to_base(self, tmp_path):
        """An empty finding path falls back to the base path (line 517)."""
        scanner = KingfisherScanner(auto_install=False)
        item = {
            "rule": {"id": "kingfisher.generic.1", "name": "Generic"},
            "finding": {"path": "", "snippet": "abc"},
        }

        result = scanner._parse_finding(item, tmp_path)

        assert result is not None
        assert result.file_path == tmp_path

    def test_parse_finding_returns_none_on_bad_input(self):
        """A non-dict item triggers the except branch returning None (564-565)."""
        scanner = KingfisherScanner(auto_install=False)
        # item.get(...) on a non-dict raises AttributeError -> caught -> None
        assert scanner._parse_finding("not-a-dict", Path("/base")) is None  # type: ignore[arg-type]

    def test_parse_finding_handles_bad_entropy(self, tmp_path):
        """A non-numeric entropy string raises inside try and returns None."""
        scanner = KingfisherScanner(auto_install=False)
        item = {
            "rule": {"id": "kingfisher.generic.1", "name": "Generic"},
            "finding": {"path": "x.env", "entropy": "not-a-number", "snippet": "abc"},
        }

        assert scanner._parse_finding(item, tmp_path) is None
