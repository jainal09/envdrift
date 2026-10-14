"""Tests for the detect-secrets version check and the warning it adds to a scan."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from envdrift.scanner import detect_secrets as detect_secrets_module
from envdrift.scanner.detect_secrets import (
    DetectSecretsNotFoundError,
    DetectSecretsScanner,
    _installed_version,
    _versions_match,
)
from tests.scanner.detect_secrets_helpers import (
    PINNED,
    REAL_VERSION_WARNINGS,
    no_version_probe,  # noqa: F401  (autouse)
    version_run,
)


class TestVersionsMatch:
    """Comparing the installed version with the pin."""

    @pytest.mark.parametrize(
        ("installed", "pinned"),
        [
            ("1.5.0", "1.5.0"),
            ("1.5", "1.5.0"),
            ("1.5.0", "1.5"),
            ("1.5.0.0", "1.5.0"),
            ("2", "2.0.0"),
        ],
    )
    def test_the_same_release_matches(self, installed: str, pinned: str):
        assert _versions_match(installed, pinned)

    @pytest.mark.parametrize(
        ("installed", "pinned"),
        [
            ("1.4.0", "1.5.0"),
            ("1.5.1", "1.5.0"),
            ("1.6.0", "1.5.0"),
            ("1.10.0", "1.1.0"),
            ("2.0", "1.5.0"),
        ],
    )
    def test_another_release_does_not_match(self, installed: str, pinned: str):
        assert not _versions_match(installed, pinned)

    @pytest.mark.parametrize("installed", ["1.5.0.dev1", "1.5.0+local", "1.5.0rc1", "garbage", ""])
    def test_a_version_that_is_not_a_plain_release_does_not_match_the_release(self, installed: str):
        """It may carry other detector names than the release it is named after."""
        assert not _versions_match(installed, "1.5.0")

    def test_a_version_that_is_not_a_plain_release_matches_itself(self):
        assert _versions_match("1.5.0.dev1", "1.5.0.dev1")


class TestVersionWarnings:
    """What the check says, and that it never touches the environment."""

    def test_the_pinned_version_is_silent(self):
        with patch("subprocess.run", return_value=version_run(f"{PINNED}\n")) as run:
            assert REAL_VERSION_WARNINGS() == []
        assert run.call_count == 1

    def test_the_pinned_version_in_the_older_output_format_is_silent(self):
        with patch("subprocess.run", return_value=version_run(f"detect-secrets {PINNED}\n")):
            assert REAL_VERSION_WARNINGS() == []

    def test_another_version_warns_with_both_versions_the_consequence_and_the_fix(self):
        with patch("subprocess.run", return_value=version_run("1.4.0\n")):
            (warning,) = REAL_VERSION_WARNINGS()

        assert "installed version is 1.4.0" in warning
        assert f"version {PINNED}" in warning
        assert "severities may be inaccurate" in warning
        assert f"pip install detect-secrets=={PINNED}" in warning

    def test_the_warning_does_not_repeat_the_scanner_name_the_output_adds(self):
        """Every output prefixes the scanner name (``detect-secrets: ...``), so it is not here."""
        with patch("subprocess.run", return_value=version_run("1.4.0\n")):
            (warning,) = REAL_VERSION_WARNINGS()

        assert not warning.lower().startswith("detect-secrets")

    def test_the_probe_runs_the_interpreters_detect_secrets_and_nothing_else(self):
        """Never reinstall or otherwise modify the environment: the only call is ``--version``."""
        with patch("subprocess.run", return_value=version_run("1.4.0\n")) as run:
            REAL_VERSION_WARNINGS()

        (call,) = run.call_args_list
        assert call.args[0] == [sys.executable, "-m", "detect_secrets", "--version"]

    @pytest.mark.parametrize(
        "run",
        [
            pytest.param(version_run("", returncode=1, stderr="boom"), id="exit-code"),
            pytest.param(version_run("", returncode=0), id="no-output"),
            pytest.param(version_run("  \n", returncode=0), id="blank-output"),
        ],
    )
    def test_a_probe_that_reports_no_version_is_a_warning_not_an_error(self, run: Any):
        with patch("subprocess.run", return_value=run):
            (warning,) = REAL_VERSION_WARNINGS()

        assert "Could not read the installed version" in warning
        assert PINNED in warning
        assert "severities may be inaccurate" in warning
        assert f"pip install detect-secrets=={PINNED}" in warning

    @pytest.mark.parametrize(
        "error",
        [
            subprocess.TimeoutExpired(cmd="detect_secrets", timeout=10),
            OSError("exec format error"),
            subprocess.SubprocessError("odd"),
            # What subprocess raises for an interpreter path it cannot use (``sys.executable``
            # is None or empty in some embedded builds, or holds a null byte).
            TypeError("expected str, bytes or os.PathLike object, not NoneType"),
            ValueError("embedded null byte"),
        ],
        ids=["timeout", "oserror", "subprocess-error", "typeerror", "valueerror"],
    )
    def test_a_probe_that_fails_to_run_is_a_warning_not_an_error(self, error: Exception):
        with patch("subprocess.run", side_effect=error):
            (warning,) = REAL_VERSION_WARNINGS()

        assert "Could not read the installed version" in warning
        assert type(error).__name__ in warning

    def test_the_probe_is_cached_for_the_process(self):
        with patch("subprocess.run", return_value=version_run("1.4.0\n")) as run:
            first = REAL_VERSION_WARNINGS()
            second = REAL_VERSION_WARNINGS()
            assert _installed_version() == "1.4.0"

        assert first == second
        assert run.call_count == 1

    def test_a_failed_probe_is_not_cached(self):
        """A package installed after a failed probe is seen by the next scan."""
        with patch("subprocess.run", return_value=version_run("", returncode=1)):
            assert REAL_VERSION_WARNINGS()
        with patch("subprocess.run", return_value=version_run(f"{PINNED}\n")):
            assert REAL_VERSION_WARNINGS() == []

    def test_the_probe_is_cached_per_interpreter(self):
        with patch("subprocess.run", return_value=version_run("1.4.0\n")) as run:
            _installed_version()
            with patch.object(sys, "executable", "/another/python"):
                _installed_version()
        assert run.call_count == 2

    def test_is_installed_and_the_version_check_share_one_probe(self):
        """A scan asks whether the package is there and which version, with one subprocess."""
        scanner = DetectSecretsScanner(auto_install=False)
        with patch("subprocess.run", return_value=version_run("1.4.0\n")) as run:
            assert scanner.is_installed()
            (warning,) = REAL_VERSION_WARNINGS()

        assert "1.4.0" in warning
        assert run.call_count == 1

    def test_get_version_shares_the_probe_too(self):
        scanner = DetectSecretsScanner(auto_install=False)
        with patch("subprocess.run", return_value=version_run("detect-secrets 1.4.0\n")) as run:
            assert scanner.get_version() == "1.4.0"
            assert _installed_version() == "1.4.0"

        assert run.call_count == 1

    def test_a_probe_result_that_is_not_text_is_not_remembered(self):
        """Only a real version string is cached for the process, never a stray object."""
        scanner = DetectSecretsScanner(auto_install=False)
        odd = SimpleNamespace(returncode=0, stdout=MagicMock(), stderr="")
        with patch("subprocess.run", return_value=odd):
            assert scanner.is_installed()

        assert detect_secrets_module._installed_versions == {}


class TestScanCarriesTheVersionWarning:
    """``scan`` returns the warning with every result, and the findings are unaffected."""

    @pytest.fixture
    def scanner(self) -> DetectSecretsScanner:
        return DetectSecretsScanner(auto_install=False)

    @staticmethod
    def _scan(scanner: DetectSecretsScanner, tmp_path: Path, run: Any):
        warning = "detect-secrets 1.4.0 is installed, but ..."
        with (
            patch.object(scanner, "_ensure_installed", return_value=None),
            patch.object(detect_secrets_module, "_version_warnings", lambda: [warning]),
            patch("subprocess.run", **run),
        ):
            return scanner.scan([tmp_path]), warning

    def test_a_clean_scan_carries_the_warning(self, scanner: DetectSecretsScanner, tmp_path: Path):
        baseline = json.dumps({"results": {}})
        result, warning = self._scan(scanner, tmp_path, {"return_value": version_run(baseline)})

        assert result.error is None
        assert result.warnings == [warning]

    def test_a_scan_with_findings_carries_the_warning(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        entry = {"type": "Slack Token", "line_number": 1, "hashed_secret": "ab"}
        baseline = json.dumps({"results": {"a.cfg": [entry]}})
        result, warning = self._scan(scanner, tmp_path, {"return_value": version_run(baseline)})

        assert len(result.findings) == 1
        assert result.warnings == [warning]
        assert result.success

    def test_a_failed_scan_carries_the_warning(self, scanner: DetectSecretsScanner, tmp_path: Path):
        failed = version_run("", returncode=2, stderr="boom")
        result, warning = self._scan(scanner, tmp_path, {"return_value": failed})

        assert result.error == "boom"
        assert result.warnings == [warning]

    def test_a_timed_out_scan_carries_the_warning(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        timeout = subprocess.TimeoutExpired(cmd="detect_secrets", timeout=1)
        result, warning = self._scan(scanner, tmp_path, {"side_effect": timeout})

        assert result.error == f"Scan timed out for {tmp_path}"
        assert result.warnings == [warning]

    def test_a_crashed_scan_carries_the_warning(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        result, warning = self._scan(scanner, tmp_path, {"side_effect": RuntimeError("kaput")})

        assert result.error == "kaput"
        assert result.warnings == [warning]

    def test_scan_without_the_package_has_no_version_to_check(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        missing = DetectSecretsNotFoundError("missing")
        with (
            patch.object(scanner, "_ensure_installed", side_effect=missing),
            patch.object(
                detect_secrets_module, "_version_warnings", side_effect=AssertionError("probed")
            ),
        ):
            result = scanner.scan([tmp_path])

        assert result.error == "missing"
        assert result.warnings == []

    def test_scan_never_reinstalls_a_different_version(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """With auto-install on, an installed but different package is left alone and warned about."""
        scanner = DetectSecretsScanner(auto_install=True)
        monkeypatch.setattr(detect_secrets_module, "_version_warnings", REAL_VERSION_WARNINGS)
        calls: list[list[str]] = []

        def fake_run(args: list[str], **_kwargs: Any):
            calls.append(args)
            if args[-1] == "--version":
                return version_run("1.4.0\n")
            return version_run(json.dumps({"results": {}}))

        with patch("subprocess.run", side_effect=fake_run):
            result = scanner.scan([tmp_path])

        assert result.error is None
        assert [w for w in result.warnings if "1.4.0" in w and PINNED in w]
        # Only detect-secrets itself ran (its --version probe and the scan), and the git calls
        # that say where the directory's files are: no pip, no uv, nothing that changes the
        # install.
        for args in calls:
            assert "detect_secrets" in args or args[0] == "git", args
        assert not any("install" in args for args in calls)
