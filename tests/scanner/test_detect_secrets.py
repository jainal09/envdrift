"""Tests for detect-secrets scanner integration."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path, PurePath
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from envdrift.scanner import detect_secrets as detect_secrets_module
from envdrift.scanner.base import FindingSeverity
from envdrift.scanner.detect_secrets import (
    _EXCLUDED_DIRECTORIES,
    DETECTOR_SEVERITY,
    DetectSecretsInstaller,
    DetectSecretsInstallError,
    DetectSecretsNotFoundError,
    DetectSecretsScanner,
    _check_git_file_list,
    _exclude_files_regex,
    _get_detect_secrets_version,
    _git_quotes,
    _installed_version,
    _is_undecodable,
    _plan_scan,
    _scannable_tracked_names,
    _version_warnings,
    _versions_match,
)

# The real probe and warning builder, bound before the fixture below replaces the module's.
REAL_VERSION_WARNINGS = _version_warnings
PINNED = _get_detect_secrets_version()


@pytest.fixture(autouse=True)
def _no_version_probe(monkeypatch: pytest.MonkeyPatch):
    """Keep the scan tests off the real ``--version`` probe, which would eat a mocked run.

    Tests of the version check itself call the real ``_version_warnings`` directly.
    """
    monkeypatch.setattr(detect_secrets_module, "_version_warnings", lambda: [])
    detect_secrets_module._installed_versions.clear()
    yield
    detect_secrets_module._installed_versions.clear()


class TestDetectSecretsInstaller:
    """Tests for DetectSecretsInstaller."""

    def test_default_version_from_constants(self):
        """Installer uses pinned version by default."""
        installer = DetectSecretsInstaller()
        assert installer.version == _get_detect_secrets_version()

    def test_custom_version(self):
        """Custom version can be specified."""
        installer = DetectSecretsInstaller(version="1.4.0")
        assert installer.version == "1.4.0"

    def test_progress_callback(self):
        """Progress callback is invoked."""
        messages: list[str] = []
        installer = DetectSecretsInstaller(progress_callback=messages.append)
        installer.progress("hello")
        assert messages == ["hello"]

    @patch.object(DetectSecretsInstaller, "_is_installed", return_value=True)
    @patch("subprocess.run")
    def test_install_short_circuits_when_installed(
        self,
        mock_run: MagicMock,
        _mock_is_installed: MagicMock,
    ):
        """Installer returns early when already installed."""
        installer = DetectSecretsInstaller(version="1.5.0")
        assert installer.install() is True
        mock_run.assert_not_called()

    @patch("subprocess.run")
    def test_is_installed_returns_true(self, mock_run: MagicMock):
        """_is_installed returns True on version success."""
        mock_run.return_value = SimpleNamespace(returncode=0, stderr="", stdout="")
        installer = DetectSecretsInstaller(version="1.5.0")
        assert installer._is_installed() is True

    @patch("subprocess.run", side_effect=RuntimeError("boom"))
    def test_is_installed_handles_exception(self, _mock_run: MagicMock):
        """_is_installed returns False on errors."""
        installer = DetectSecretsInstaller(version="1.5.0")
        assert installer._is_installed() is False

    @patch.object(DetectSecretsInstaller, "_is_installed", return_value=False)
    @patch("shutil.which", return_value="/usr/bin/uv")
    @patch("subprocess.run")
    def test_install_uses_uv_when_available(
        self,
        mock_run: MagicMock,
        _mock_which: MagicMock,
        _mock_is_installed: MagicMock,
    ):
        """Installer prefers uv when available."""
        mock_run.return_value = SimpleNamespace(returncode=0, stderr="", stdout="")
        installer = DetectSecretsInstaller(version="1.5.0")
        assert installer.install() is True

        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "/usr/bin/uv"
        assert cmd[1:4] == ["pip", "install", "--quiet"]
        assert cmd[-1] == "detect-secrets==1.5.0"

    @patch.object(DetectSecretsInstaller, "_is_installed", return_value=False)
    @patch("shutil.which", return_value=None)
    @patch("subprocess.run")
    def test_install_uses_pip_when_uv_missing(
        self,
        mock_run: MagicMock,
        _mock_which: MagicMock,
        _mock_is_installed: MagicMock,
    ):
        """Installer falls back to pip when uv is missing."""
        mock_run.return_value = SimpleNamespace(returncode=0, stderr="", stdout="")
        installer = DetectSecretsInstaller(version="1.5.0")
        assert installer.install() is True

        cmd = mock_run.call_args[0][0]
        assert cmd[:3] == [sys.executable, "-m", "pip"]
        assert cmd[-1] == "detect-secrets==1.5.0"

    @patch("shutil.which", return_value=None)
    @patch("subprocess.run")
    def test_a_reinstall_forgets_the_version_probed_before_it(
        self, mock_run: MagicMock, _mock_which: MagicMock
    ):
        """The version check reads the package that is there after an install, not before it."""
        detect_secrets_module._installed_versions[sys.executable] = "1.4.0"
        mock_run.return_value = SimpleNamespace(returncode=0, stderr="", stdout="")

        assert DetectSecretsInstaller(version="1.5.0").install(force=True) is True

        assert detect_secrets_module._installed_versions == {}

    @patch("shutil.which", return_value=None)
    @patch("subprocess.run")
    def test_a_failed_install_keeps_the_version_probed_before_it(
        self, mock_run: MagicMock, _mock_which: MagicMock
    ):
        """Nothing changed, so what was probed still holds."""
        detect_secrets_module._installed_versions[sys.executable] = "1.4.0"
        mock_run.return_value = SimpleNamespace(returncode=1, stderr="boom", stdout="")

        with pytest.raises(DetectSecretsInstallError):
            DetectSecretsInstaller(version="1.5.0").install(force=True)

        assert detect_secrets_module._installed_versions == {sys.executable: "1.4.0"}

    @patch.object(DetectSecretsInstaller, "_is_installed", return_value=False)
    @patch("shutil.which", return_value=None)
    @patch("subprocess.run")
    def test_install_raises_on_failure(
        self,
        mock_run: MagicMock,
        _mock_which: MagicMock,
        _mock_is_installed: MagicMock,
    ):
        """Installer raises when pip fails."""
        mock_run.return_value = SimpleNamespace(returncode=1, stderr="boom", stdout="")
        installer = DetectSecretsInstaller(version="1.5.0")
        with pytest.raises(DetectSecretsInstallError, match="Install failed"):
            installer.install()

    @patch.object(DetectSecretsInstaller, "_is_installed", return_value=False)
    @patch("shutil.which", return_value=None)
    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="pip", timeout=1))
    def test_install_timeout_raises(
        self,
        _mock_run: MagicMock,
        _mock_which: MagicMock,
        _mock_is_installed: MagicMock,
    ):
        """Installer surfaces timeout errors."""
        installer = DetectSecretsInstaller(version="1.5.0")
        with pytest.raises(DetectSecretsInstallError, match="timed out"):
            installer.install()


class TestDetectSecretsScanner:
    """Tests for DetectSecretsScanner."""

    def test_scanner_name(self):
        """Scanner name is detect-secrets."""
        scanner = DetectSecretsScanner(auto_install=False)
        assert scanner.name == "detect-secrets"

    def test_scanner_description(self):
        """Scanner description includes detect-secrets."""
        scanner = DetectSecretsScanner(auto_install=False)
        assert "detect-secrets" in scanner.description.lower()

    def test_is_installed_returns_cached_value(self):
        """is_installed returns cached result when available."""
        scanner = DetectSecretsScanner(auto_install=False)
        scanner._installed = True
        with patch("subprocess.run") as mock_run:
            assert scanner.is_installed() is True
            mock_run.assert_not_called()

    @patch("subprocess.run")
    def test_is_installed_handles_exception(self, mock_run: MagicMock):
        """is_installed returns False on exceptions."""
        mock_run.side_effect = RuntimeError("boom")
        scanner = DetectSecretsScanner(auto_install=False)
        assert scanner.is_installed() is False

    @patch("subprocess.run")
    def test_is_installed_sets_cache_true(self, mock_run: MagicMock):
        """is_installed caches True when detect-secrets is available."""
        mock_run.return_value = SimpleNamespace(returncode=0, stderr="", stdout="")
        scanner = DetectSecretsScanner(auto_install=False)
        assert scanner.is_installed() is True
        assert scanner._installed is True

    @patch("subprocess.run")
    def test_is_installed_sets_cache_false(self, mock_run: MagicMock):
        """is_installed caches False when command fails."""
        mock_run.return_value = SimpleNamespace(returncode=1, stderr="", stdout="")
        scanner = DetectSecretsScanner(auto_install=False)
        assert scanner.is_installed() is False
        assert scanner._installed is False

    @patch("subprocess.run")
    def test_get_version_parses_output(self, mock_run: MagicMock):
        """get_version returns parsed version string."""
        mock_run.return_value = SimpleNamespace(
            returncode=0, stdout="detect-secrets 1.6.1\n", stderr=""
        )
        scanner = DetectSecretsScanner(auto_install=False)
        assert scanner.get_version() == "1.6.1"

    @patch("subprocess.run")
    def test_get_version_returns_none_on_failure(self, mock_run: MagicMock):
        """get_version returns None on failure."""
        mock_run.return_value = SimpleNamespace(returncode=1, stdout="", stderr="err")
        scanner = DetectSecretsScanner(auto_install=False)
        assert scanner.get_version() is None

    @patch("subprocess.run", side_effect=OSError("no interpreter"))
    def test_get_version_returns_none_when_the_probe_cannot_run(self, _mock_run: MagicMock):
        """The probe is a subprocess: when it cannot start there is no version, not a crash."""
        scanner = DetectSecretsScanner(auto_install=False)
        assert scanner.get_version() is None
        assert detect_secrets_module._installed_versions == {}

    def test_ensure_installed_when_disabled_raises(self):
        """_ensure_installed raises when auto-install disabled."""
        scanner = DetectSecretsScanner(auto_install=False)
        with patch.object(scanner, "is_installed", return_value=False):
            with pytest.raises(DetectSecretsNotFoundError):
                scanner._ensure_installed()

    def test_ensure_installed_when_auto_install_succeeds(self):
        """_ensure_installed returns True after successful install."""
        scanner = DetectSecretsScanner(auto_install=True)
        with patch.object(scanner, "is_installed", return_value=False):
            with patch.object(DetectSecretsInstaller, "install", return_value=None):
                assert scanner._ensure_installed() is True
                assert scanner._installed is True

    def test_ensure_installed_when_auto_install_fails(self):
        """_ensure_installed raises when install fails."""
        scanner = DetectSecretsScanner(auto_install=True)
        with (
            patch.object(scanner, "is_installed", return_value=False),
            patch.object(
                DetectSecretsInstaller,
                "install",
                side_effect=DetectSecretsInstallError("nope"),
            ),
            pytest.raises(DetectSecretsNotFoundError, match="auto-install failed"),
        ):
            scanner._ensure_installed()

    def test_install_updates_installed_flag(self):
        """install updates cached installed state."""
        scanner = DetectSecretsScanner(auto_install=True)
        with patch.object(DetectSecretsInstaller, "install", return_value=None):
            # scanner.install() returns None for pip packages (no binary path)
            # installer.install() returning without exception still marks installed
            assert scanner.install() is None
            assert scanner._installed is True

    def test_parse_secret_sets_severity_and_preview(self):
        """_parse_secret maps detector type to severity and preview."""
        scanner = DetectSecretsScanner(auto_install=False)
        secret = {
            "type": "Slack Token",
            "line_number": 12,
            "hashed_secret": "abcdef123456",
        }
        finding = scanner._parse_secret(secret, Path("config.py"))
        assert finding is not None
        assert finding.severity == FindingSeverity.CRITICAL
        assert finding.secret_preview == "[hash:abcdef12...]"
        assert finding.rule_id == "detect-secrets-slack-token"

    def test_parse_secret_false_positive_sets_info(self):
        """False positives are downgraded to INFO."""
        scanner = DetectSecretsScanner(auto_install=False)
        secret = {
            "type": "Slack Token",
            "line_number": 3,
            "hashed_secret": "abcd1234",
            "is_secret": False,
        }
        finding = scanner._parse_secret(secret, Path("secrets.txt"))
        assert finding is not None
        assert finding.severity == FindingSeverity.INFO

    def test_parse_secret_unknown_type_defaults_high(self):
        """Unknown detector types default to HIGH severity."""
        scanner = DetectSecretsScanner(auto_install=False)
        secret = {"type": "Unknown Detector", "line_number": 1, "hashed_secret": "abc"}
        finding = scanner._parse_secret(secret, Path("misc.txt"))
        assert finding is not None
        assert finding.severity == FindingSeverity.HIGH


class TestDetectSecretsScan:
    """Tests for detect-secrets scan behavior."""

    def test_scan_returns_error_when_not_installed(self, tmp_path: Path):
        """Scan returns error when detect-secrets is unavailable."""
        scanner = DetectSecretsScanner(auto_install=False)
        with patch.object(
            scanner,
            "_ensure_installed",
            side_effect=DetectSecretsNotFoundError("missing"),
        ):
            result = scanner.scan([tmp_path])
        assert result.error == "missing"
        assert result.scanner_name == "detect-secrets"

    def test_scan_parses_baseline(self, tmp_path: Path):
        """Scan parses JSON baseline output into findings."""
        scanner = DetectSecretsScanner(auto_install=False)
        baseline = {
            "results": {
                "config.py": [
                    {
                        "type": "Slack Token",
                        "line_number": 12,
                        "hashed_secret": "abcd1234",
                    }
                ],
                "secrets.txt": [
                    {
                        "type": "Unknown Detector",
                        "line_number": 4,
                        "hashed_secret": "beef1234",
                    }
                ],
            }
        }
        with patch.object(scanner, "_ensure_installed", return_value=None):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = SimpleNamespace(
                    returncode=0, stdout=json.dumps(baseline), stderr=""
                )
                result = scanner.scan([tmp_path])

        assert result.error is None
        assert result.files_scanned == 2
        assert len(result.findings) == 2
        assert result.findings[0].file_path == tmp_path / "config.py"

    def test_scan_reports_output_it_cannot_read_as_an_error(self, tmp_path: Path):
        """A report that cannot be read is not a clean run (#851).

        Unreadable output with nothing on stderr used to pass as "no findings".
        """
        scanner = DetectSecretsScanner(auto_install=False)
        with patch.object(scanner, "_ensure_installed", return_value=None):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = SimpleNamespace(returncode=0, stdout="not-json", stderr="")
                result = scanner.scan([tmp_path])

        assert result.error is not None
        assert "detect-secrets output error" in result.error
        assert "not-json" in result.error
        assert result.findings == []

    def test_scan_prefers_stderr_in_the_unreadable_output_error(self, tmp_path: Path):
        scanner = DetectSecretsScanner(auto_install=False)
        with patch.object(scanner, "_ensure_installed", return_value=None):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = SimpleNamespace(
                    returncode=0, stdout="not-json", stderr="Traceback: boom"
                )
                result = scanner.scan([tmp_path])

        assert result.error == "detect-secrets output error: Traceback: boom"

    @pytest.mark.parametrize(
        "stdout",
        ["[]", "null", '"done"', "42", "{}", '{"version": "1.5.0"}', '{"results": []}'],
    )
    def test_scan_reports_json_that_is_not_a_report_as_an_error(self, tmp_path: Path, stdout: str):
        """A report is an object with a ``results`` mapping, empty when nothing was found.

        Anything else cannot be told from a scan that looked at nothing, so it is not a clean run.
        """
        scanner = DetectSecretsScanner(auto_install=False)
        with patch.object(scanner, "_ensure_installed", return_value=None):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = SimpleNamespace(returncode=0, stdout=stdout, stderr="")
                result = scanner.scan([tmp_path])

        assert result.error is not None
        assert result.error.startswith("detect-secrets output error: ")
        assert result.findings == []

    def test_scan_accepts_an_empty_report(self, tmp_path: Path):
        scanner = DetectSecretsScanner(auto_install=False)
        with patch.object(scanner, "_ensure_installed", return_value=None):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = SimpleNamespace(
                    returncode=0, stdout='{"results": {}}', stderr=""
                )
                result = scanner.scan([tmp_path])

        assert result.error is None
        assert result.findings == []
        assert result.files_scanned == 0

    def test_scan_reports_a_missing_report_as_an_error(self, tmp_path: Path):
        """detect-secrets always prints a baseline; none at all means nothing was scanned."""
        scanner = DetectSecretsScanner(auto_install=False)
        with patch.object(scanner, "_ensure_installed", return_value=None):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = SimpleNamespace(returncode=0, stdout="  \n", stderr="")
                result = scanner.scan([tmp_path])

        assert result.error == f"detect-secrets printed no report for {tmp_path}"
        assert result.findings == []

    def test_scan_timeout_returns_error(self, tmp_path: Path):
        """Timeouts return a ScanResult with error."""
        scanner = DetectSecretsScanner(auto_install=False)
        with (
            patch.object(scanner, "_ensure_installed", return_value=None),
            patch(
                "subprocess.run",
                side_effect=subprocess.TimeoutExpired(cmd="detect_secrets", timeout=1),
            ),
        ):
            result = scanner.scan([tmp_path])

        assert result.error == f"Scan timed out for {tmp_path}"


def test_detector_severity_mapping_contains_slack_token():
    """Detector severity map includes Slack Token as critical."""
    assert DETECTOR_SEVERITY["Slack Token"] == FindingSeverity.CRITICAL


# The ``type`` strings detect-secrets 1.5.0 actually emits for these plugins, taken
# from a real ``detect_secrets scan --force-use-all-plugins`` run. DETECTOR_SEVERITY
# used to key them as "Cloudant", "npm credentials", "OpenAI API Key" and "PyPI
# upload token", names no plugin emits, so all four fell back to HIGH.
@pytest.mark.parametrize(
    "emitted_type",
    ["Cloudant Credentials", "NPM tokens", "OpenAI Token", "PyPI Token"],
)
def test_emitted_detector_types_get_their_intended_severity(emitted_type: str):
    """Credential detectors graded CRITICAL are keyed on the name the tool emits."""
    scanner = DetectSecretsScanner(auto_install=False)
    secret = {"type": emitted_type, "line_number": 1, "hashed_secret": "0123abcd"}
    finding = scanner._parse_secret(secret, Path("app.cfg"))
    assert finding is not None
    assert finding.severity == FindingSeverity.CRITICAL


# detect-secrets graded these by a table that disagreed with the other scanners (#850).
# The ``type`` strings are those detect-secrets 1.5.0 emits.
@pytest.mark.parametrize(
    ("emitted_type", "expected"),
    [
        ("Private Key", FindingSeverity.CRITICAL),
        ("Secret Keyword", FindingSeverity.HIGH),
        ("Artifactory Credentials", FindingSeverity.HIGH),
        ("Twilio API Key", FindingSeverity.HIGH),
        # Never lowered below the HIGH it always was: a JWT can be a bearer token.
        ("JSON Web Token", FindingSeverity.HIGH),
        ("Base64 High Entropy String", FindingSeverity.MEDIUM),
    ],
)
def test_detector_grades_follow_the_cross_scanner_policy(
    emitted_type: str, expected: FindingSeverity
):
    """The full table is held to tests/severity_policy.py by test_severity_policy.py."""
    scanner = DetectSecretsScanner(auto_install=False)
    secret = {"type": emitted_type, "line_number": 1, "hashed_secret": "0123abcd"}
    finding = scanner._parse_secret(secret, Path("app.cfg"))
    assert finding is not None
    assert finding.severity == expected


# --- The installed version is checked against the pin (the severity table is keyed on it) ---


def _version_run(stdout: str = f"{PINNED}\n", returncode: int = 0, stderr: str = ""):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


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
        with patch("subprocess.run", return_value=_version_run(f"{PINNED}\n")) as run:
            assert REAL_VERSION_WARNINGS() == []
        assert run.call_count == 1

    def test_the_pinned_version_in_the_older_output_format_is_silent(self):
        with patch("subprocess.run", return_value=_version_run(f"detect-secrets {PINNED}\n")):
            assert REAL_VERSION_WARNINGS() == []

    def test_another_version_warns_with_both_versions_the_consequence_and_the_fix(self):
        with patch("subprocess.run", return_value=_version_run("1.4.0\n")):
            (warning,) = REAL_VERSION_WARNINGS()

        assert "installed version is 1.4.0" in warning
        assert f"version {PINNED}" in warning
        assert "severities may be inaccurate" in warning
        assert f"pip install detect-secrets=={PINNED}" in warning

    def test_the_warning_does_not_repeat_the_scanner_name_the_output_adds(self):
        """Every output prefixes the scanner name (``detect-secrets: ...``), so it is not here."""
        with patch("subprocess.run", return_value=_version_run("1.4.0\n")):
            (warning,) = REAL_VERSION_WARNINGS()

        assert not warning.lower().startswith("detect-secrets")

    def test_the_probe_runs_the_interpreters_detect_secrets_and_nothing_else(self):
        """Never reinstall or otherwise modify the environment: the only call is ``--version``."""
        with patch("subprocess.run", return_value=_version_run("1.4.0\n")) as run:
            REAL_VERSION_WARNINGS()

        (call,) = run.call_args_list
        assert call.args[0] == [sys.executable, "-m", "detect_secrets", "--version"]

    @pytest.mark.parametrize(
        "run",
        [
            pytest.param(_version_run("", returncode=1, stderr="boom"), id="exit-code"),
            pytest.param(_version_run("", returncode=0), id="no-output"),
            pytest.param(_version_run("  \n", returncode=0), id="blank-output"),
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
        with patch("subprocess.run", return_value=_version_run("1.4.0\n")) as run:
            first = REAL_VERSION_WARNINGS()
            second = REAL_VERSION_WARNINGS()
            assert _installed_version() == "1.4.0"

        assert first == second
        assert run.call_count == 1

    def test_a_failed_probe_is_not_cached(self):
        """A package installed after a failed probe is seen by the next scan."""
        with patch("subprocess.run", return_value=_version_run("", returncode=1)):
            assert REAL_VERSION_WARNINGS()
        with patch("subprocess.run", return_value=_version_run(f"{PINNED}\n")):
            assert REAL_VERSION_WARNINGS() == []

    def test_the_probe_is_cached_per_interpreter(self):
        with patch("subprocess.run", return_value=_version_run("1.4.0\n")) as run:
            _installed_version()
            with patch.object(sys, "executable", "/another/python"):
                _installed_version()
        assert run.call_count == 2

    def test_is_installed_and_the_version_check_share_one_probe(self):
        """A scan asks whether the package is there and which version, with one subprocess."""
        scanner = DetectSecretsScanner(auto_install=False)
        with patch("subprocess.run", return_value=_version_run("1.4.0\n")) as run:
            assert scanner.is_installed()
            (warning,) = REAL_VERSION_WARNINGS()

        assert "1.4.0" in warning
        assert run.call_count == 1

    def test_get_version_shares_the_probe_too(self):
        scanner = DetectSecretsScanner(auto_install=False)
        with patch("subprocess.run", return_value=_version_run("detect-secrets 1.4.0\n")) as run:
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
        result, warning = self._scan(scanner, tmp_path, {"return_value": _version_run(baseline)})

        assert result.error is None
        assert result.warnings == [warning]

    def test_a_scan_with_findings_carries_the_warning(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        entry = {"type": "Slack Token", "line_number": 1, "hashed_secret": "ab"}
        baseline = json.dumps({"results": {"a.cfg": [entry]}})
        result, warning = self._scan(scanner, tmp_path, {"return_value": _version_run(baseline)})

        assert len(result.findings) == 1
        assert result.warnings == [warning]
        assert result.success

    def test_a_failed_scan_carries_the_warning(self, scanner: DetectSecretsScanner, tmp_path: Path):
        failed = _version_run("", returncode=2, stderr="boom")
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
                return _version_run("1.4.0\n")
            return _version_run(json.dumps({"results": {}}))

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


# --- Where and how detect-secrets runs over a path (#851) ---


def _init_repo(path: Path) -> Path:
    """Make ``path`` a git repository and return it."""
    if shutil.which("git") is None:
        pytest.skip("git not available")
    subprocess.run(["git", "init", "-q"], cwd=path, check=True, capture_output=True)
    return path


def _add(repo: Path, *names: str) -> None:
    """Create each file (a one-line placeholder) and ``git add`` it."""
    for name in names:
        file = repo / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text("x = 1\n")
    subprocess.run(["git", "add", "--", *names], cwd=repo, check=True, capture_output=True)


class TestExcludePattern:
    """The ``--exclude-files`` pattern skips directories by name, never files or look-alikes."""

    @staticmethod
    def _path(separator: str, *parts: str) -> str:
        return separator.join(parts)

    @pytest.mark.parametrize("separator", ["/", "\\"])
    def test_a_directory_with_an_excluded_name_excludes_everything_below_it(self, separator: str):
        """git lists ``a/b``; a scan of all files builds ``a\\b`` on Windows (the OS separator)."""
        pattern = re.compile(_exclude_files_regex())

        for skipped in _EXCLUDED_DIRECTORIES:
            assert pattern.search(self._path(separator, skipped, "x.js")), skipped
            assert pattern.search(self._path(separator, "pkg", skipped, "deep", "x.js")), skipped

    @pytest.mark.parametrize("separator", ["/", "\\"])
    def test_look_alike_names_are_scanned(self, separator: str):
        pattern = re.compile(_exclude_files_regex())

        for scanned in (
            "app.py",
            "distance.py",
            "rebuild",
            "gitops",
            "node_modules_backup",
            "venv2",
        ):
            assert not pattern.search(self._path(separator, "src", scanned, "x.js")), scanned
            assert not pattern.search(self._path(separator, scanned, "x.js")), scanned

    @pytest.mark.parametrize("separator", ["/", "\\"])
    def test_a_file_named_like_an_excluded_directory_is_scanned(self, separator: str):
        """A script called ``build`` is a file, not a directory of build output."""
        pattern = re.compile(_exclude_files_regex())

        for name in _EXCLUDED_DIRECTORIES:
            assert not pattern.search(name), name
            assert not pattern.search(self._path(separator, "bin", name)), name

    def test_the_leading_components_are_never_looked_at(self):
        """They lead to the directory that was asked for, whatever it is called."""
        pattern = re.compile(_exclude_files_regex(2))

        assert not pattern.search("vendor/build/app.cfg")
        assert not pattern.search("build/dist/sub/app.cfg")
        assert not pattern.search("build/dist/build")
        assert pattern.search("vendor/app/node_modules/x.cfg")
        assert pattern.search("vendor\\app\\dist\\x.cfg")

    def test_no_leading_components_are_skipped_by_default(self):
        assert re.compile(_exclude_files_regex()).search("build/app.cfg")
        assert re.compile(_exclude_files_regex(0)).search("build/app.cfg")


class TestScanPlan:
    """``_plan_scan`` picks the directory detect-secrets runs in and the path it is given."""

    def test_a_file_is_scanned_from_its_own_directory(self, tmp_path: Path):
        target = tmp_path / "app.cfg"
        target.write_text("x = 1\n")

        plan = _plan_scan(target)

        assert plan.cwd == tmp_path
        assert plan.scan_path == "app.cfg"
        assert not plan.all_files
        assert plan.git_root is None

    def test_a_file_in_a_repository_is_scanned_the_same_way(self, tmp_path: Path):
        repo = _init_repo(tmp_path)
        _add(repo, "sub/app.cfg")

        plan = _plan_scan(repo / "sub" / "app.cfg")

        assert (plan.cwd, plan.scan_path, plan.all_files) == (repo / "sub", "app.cfg", False)

    def test_a_directory_outside_git_is_scanned_for_all_files(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setattr(detect_secrets_module, "get_git_root", lambda _path: None)

        plan = _plan_scan(tmp_path)

        assert (plan.cwd, plan.scan_path, plan.all_files) == (tmp_path, ".", True)
        assert plan.prefix == PurePath()
        assert plan.git_root is None
        assert plan.exclude == _exclude_files_regex()

    def test_the_top_level_of_a_repository_keeps_scanning_tracked_files(self, tmp_path: Path):
        repo = _init_repo(tmp_path)

        plan = _plan_scan(repo)

        assert (plan.cwd, plan.scan_path, plan.all_files) == (repo, ".", False)
        assert plan.prefix == PurePath()
        assert plan.git_root is not None
        assert plan.git_root.samefile(repo)
        assert plan.exclude == _exclude_files_regex()

    def test_a_subdirectory_is_scanned_from_the_top_level_with_its_own_path(self, tmp_path: Path):
        """Run from the subdirectory, detect-secrets matches no file git lists (#851)."""
        repo = _init_repo(tmp_path)
        (repo / "sub" / "deep").mkdir(parents=True)

        plan = _plan_scan(repo / "sub" / "deep")

        assert plan.cwd.samefile(repo)
        assert plan.scan_path == "sub/deep"
        assert not plan.all_files
        assert plan.prefix == PurePath("sub", "deep")
        assert plan.git_root is not None
        assert plan.git_root.samefile(repo)
        assert plan.exclude == _exclude_files_regex(2)

    def test_a_subdirectory_reached_through_a_symlink_is_planned_by_where_it_really_is(
        self, tmp_path: Path
    ):
        repo = tmp_path / "repo"
        repo.mkdir()
        _init_repo(repo)
        (repo / "sub").mkdir()
        link = tmp_path / "link"
        try:
            link.symlink_to(repo, target_is_directory=True)
        except (OSError, NotImplementedError):
            pytest.skip("cannot create symlinks here")

        plan = _plan_scan(link / "sub")

        assert plan.prefix == PurePath("sub")
        assert plan.scan_path == "sub"

    def test_a_directory_whose_way_to_the_top_level_cannot_be_named_is_scanned_for_all_files(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """Scanning every file beats scanning none."""
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        target = tmp_path / "target"
        target.mkdir()
        monkeypatch.setattr(detect_secrets_module, "get_git_root", lambda _path: elsewhere)

        plan = _plan_scan(target)

        assert (plan.cwd, plan.scan_path, plan.all_files) == (target, ".", True)
        assert plan.git_root is None


class TestFileNamesBelowTheScanPath:
    """The report names files from the directory detect-secrets ran in; findings are shown
    below the path the caller gave."""

    @staticmethod
    def _report(*names: str) -> dict[str, Any]:
        entry = {"type": "Slack Token", "line_number": 1, "hashed_secret": "ab"}
        return {"results": {name: [entry] for name in names}}

    def test_a_report_relative_to_the_scanned_directory_is_joined_to_it(self, tmp_path: Path):
        scanner = DetectSecretsScanner(auto_install=False)

        findings = scanner._parse_baseline(self._report("a.cfg", "deep/b.cfg"), tmp_path)

        assert [f.file_path for f in findings] == [tmp_path / "a.cfg", tmp_path / "deep" / "b.cfg"]

    def test_the_way_from_the_top_level_to_the_scanned_directory_is_dropped(self, tmp_path: Path):
        scanner = DetectSecretsScanner(auto_install=False)
        report = self._report("sub/deep/a.cfg", "sub/deep/more/b.cfg")

        findings = scanner._parse_baseline(report, tmp_path / "sub" / "deep", PurePath("sub/deep"))

        assert [f.file_path for f in findings] == [
            tmp_path / "sub" / "deep" / "a.cfg",
            tmp_path / "sub" / "deep" / "more" / "b.cfg",
        ]

    def test_a_name_that_does_not_start_with_the_prefix_is_kept_whole(self, tmp_path: Path):
        scanner = DetectSecretsScanner(auto_install=False)

        findings = scanner._parse_baseline(self._report("other/a.cfg"), tmp_path, PurePath("sub"))

        assert [f.file_path for f in findings] == [tmp_path / "other" / "a.cfg"]

    def test_a_prefix_that_is_only_part_of_a_name_is_not_dropped(self, tmp_path: Path):
        scanner = DetectSecretsScanner(auto_install=False)

        findings = scanner._parse_baseline(self._report("subway/a.cfg"), tmp_path, PurePath("sub"))

        assert [f.file_path for f in findings] == [tmp_path / "subway" / "a.cfg"]


def _fake_detect_secrets(report: dict[str, Any] | None = None, stderr: str = ""):
    """A ``subprocess.run`` that answers detect-secrets with ``report`` and runs git for real."""
    real_run = subprocess.run
    calls: list[tuple[list[str], dict[str, Any]]] = []

    def run(args: list[str], **kwargs: Any):
        if "detect_secrets" in args:
            calls.append((args, kwargs))
            return _version_run(json.dumps(report or {"results": {}}), stderr=stderr)
        return real_run(args, **kwargs)

    return run, calls


class TestNonGitDirectories:
    """detect-secrets lists a directory's files with ``git ls-files``: nothing outside git."""

    @pytest.fixture
    def scanner(self) -> DetectSecretsScanner:
        return DetectSecretsScanner(auto_install=False)

    def _scan(self, scanner: DetectSecretsScanner, target: Path, **fake: Any):
        run, calls = _fake_detect_secrets(**fake)
        with (
            patch.object(scanner, "_ensure_installed", return_value=None),
            patch("subprocess.run", side_effect=run),
        ):
            result = scanner.scan([target])
        (call,) = calls
        return result, call[0], call[1]

    def test_a_directory_outside_git_is_scanned_for_all_files(
        self, scanner: DetectSecretsScanner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setattr(detect_secrets_module, "get_git_root", lambda _path: None)

        _result, args, kwargs = self._scan(scanner, tmp_path)

        assert args[args.index("scan") + 1] == "--all-files"
        # The exclude pattern and the plugins are unchanged.
        assert args[args.index("--exclude-files") + 1] == _exclude_files_regex()
        assert "--force-use-all-plugins" in args
        assert args[-1] == "."
        assert Path(kwargs["cwd"]) == tmp_path

    def test_the_top_level_of_a_repository_keeps_scanning_tracked_files(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        repo = _init_repo(tmp_path)
        _add(repo, "app.cfg")

        _result, args, kwargs = self._scan(scanner, repo)

        assert "--all-files" not in args
        assert args[-1] == "."
        assert Path(kwargs["cwd"]) == repo

    def test_a_subdirectory_of_a_repository_is_scanned_from_the_top_level(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        """From the subdirectory itself detect-secrets matched none of the files git lists."""
        repo = _init_repo(tmp_path)
        _add(repo, "sub/a.cfg")
        report = {
            "results": {
                "sub/a.cfg": [{"type": "Slack Token", "line_number": 1, "hashed_secret": "ab"}]
            }
        }

        result, args, kwargs = self._scan(scanner, repo / "sub", report=report)

        assert "--all-files" not in args
        assert args[-1] == "sub"
        assert Path(kwargs["cwd"]).samefile(repo)
        assert args[args.index("--exclude-files") + 1] == _exclude_files_regex(1)
        # The finding is shown below the path that was asked for.
        assert [f.file_path for f in result.findings] == [repo / "sub" / "a.cfg"]
        assert result.warnings == []

    def test_a_file_is_scanned_the_same_in_or_out_of_git(
        self, scanner: DetectSecretsScanner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        target = tmp_path / "app.cfg"
        target.write_text("x = 1\n")

        for in_git in (False, True):
            monkeypatch.setattr(
                detect_secrets_module,
                "get_git_root",
                lambda _path, in_git=in_git: tmp_path if in_git else None,
            )
            _result, args, kwargs = self._scan(scanner, target)
            assert "--all-files" not in args
            assert args[-1] == "app.cfg"
            assert Path(kwargs["cwd"]) == tmp_path

    def test_the_check_is_made_on_the_scanned_directory(
        self, scanner: DetectSecretsScanner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        sub = tmp_path / "sub"
        sub.mkdir()
        asked: list[Path] = []

        def get_git_root(path: Path) -> None:
            asked.append(path)

        monkeypatch.setattr(detect_secrets_module, "get_git_root", get_git_root)

        self._scan(scanner, sub)

        assert asked == [sub]

    def test_a_scan_that_listed_no_git_files_is_an_error_not_a_clean_run(
        self, scanner: DetectSecretsScanner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """Belt and braces: if detect-secrets still finds no git work tree, nothing was scanned."""
        monkeypatch.setattr(detect_secrets_module, "get_git_root", lambda _path: None)
        notice = "Did not detect git repository. Try scanning all files instead."

        result, _args, _kwargs = self._scan(scanner, tmp_path, stderr=notice)

        assert result.error is not None
        assert "scanned nothing" in result.error
        assert str(tmp_path) in result.error
        assert result.findings == []


def _create_tracked(repo: Path, *names: str) -> None:
    """Like ``_add``, but skips the test where the file system cannot hold such a name."""
    try:
        _add(repo, *names)
    except OSError as exc:
        pytest.skip(f"this file system cannot hold the name: {exc}")


# Latin-1 "café": the byte 0xe9 that is not UTF-8, as Python reads it from a POSIX file name.
NOT_UTF8 = "caf\udce9.cfg"
NOT_UTF8_PLATFORM = pytest.mark.skipif(
    sys.platform == "win32", reason="Windows file names are UTF-16, never bytes that are not UTF-8"
)


class TestUnquotedGitPaths:
    """detect-secrets lists tracked files with ``git ls-files``, which quotes a name it escapes.

    Under git's default ``core.quotepath`` the list holds ``"caf\\303\\251.env"`` for ``café.env``.
    That names no file, so detect-secrets skipped the file in silence and the scan read as clean.
    The scan runs with the setting off instead, and says so for a name git quotes regardless.
    """

    @pytest.fixture
    def scanner(self) -> DetectSecretsScanner:
        return DetectSecretsScanner(auto_install=False)

    @pytest.fixture(autouse=True)
    def _no_git_settings_in_the_environment(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("GIT_CONFIG_COUNT", raising=False)

    @staticmethod
    def _scan(scanner: DetectSecretsScanner, target: Path):
        run, calls = _fake_detect_secrets()
        with (
            patch.object(scanner, "_ensure_installed", return_value=None),
            patch("subprocess.run", side_effect=run),
        ):
            result = scanner.scan([target])
        (call,) = calls
        return result, call[1]["env"]

    @staticmethod
    def _quotepath_setting(env: dict[str, str]) -> tuple[str, str, str] | None:
        if "GIT_CONFIG_COUNT" not in env:
            return None
        return (env["GIT_CONFIG_COUNT"], env["GIT_CONFIG_KEY_0"], env["GIT_CONFIG_VALUE_0"])

    def test_the_scan_of_tracked_files_runs_with_core_quotepath_off(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        repo = _init_repo(tmp_path)
        _add(repo, "app.cfg")

        result, env = self._scan(scanner, repo)

        assert self._quotepath_setting(env) == ("1", "core.quotepath", "false")
        assert result.warnings == []

    def test_the_rest_of_the_environment_is_passed_on(
        self, scanner: DetectSecretsScanner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setenv("ENVDRIFT_TEST_MARKER", "kept")
        repo = _init_repo(tmp_path)
        _add(repo, "app.cfg")

        _result, env = self._scan(scanner, repo)

        assert env["ENVDRIFT_TEST_MARKER"] == "kept"

    def test_a_scan_that_does_not_use_gits_list_gets_the_environment_as_it_is(
        self, scanner: DetectSecretsScanner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setattr(detect_secrets_module, "get_git_root", lambda _path: None)

        _result, env = self._scan(scanner, tmp_path)

        assert self._quotepath_setting(env) is None

    def test_git_settings_the_user_already_exports_are_kept(self):
        environ = {
            "PATH": "/usr/bin",
            "GIT_CONFIG_COUNT": "2",
            "GIT_CONFIG_KEY_0": "user.name",
            "GIT_CONFIG_VALUE_0": "someone",
            "GIT_CONFIG_KEY_1": "core.autocrlf",
            "GIT_CONFIG_VALUE_1": "input",
        }

        env = detect_secrets_module._with_unquoted_git_paths(environ)

        assert env == {
            **environ,
            "GIT_CONFIG_COUNT": "3",
            "GIT_CONFIG_KEY_2": "core.quotepath",
            "GIT_CONFIG_VALUE_2": "false",
        }
        # The mapping that was passed in is left alone.
        assert environ["GIT_CONFIG_COUNT"] == "2"
        assert "GIT_CONFIG_KEY_2" not in environ

    @pytest.mark.parametrize("count", ["", "junk", "-3", "1.5"])
    def test_a_count_git_cannot_use_is_replaced(self, count: str):
        env = detect_secrets_module._with_unquoted_git_paths({"GIT_CONFIG_COUNT": count})

        assert (env["GIT_CONFIG_COUNT"], env["GIT_CONFIG_KEY_0"], env["GIT_CONFIG_VALUE_0"]) == (
            "1",
            "core.quotepath",
            "false",
        )

    def test_a_non_ascii_name_is_scanned_not_reported(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        repo = _init_repo(tmp_path)
        _create_tracked(repo, "café.cfg", "sub/naïve.cfg")

        result, env = self._scan(scanner, repo)

        assert self._quotepath_setting(env) == ("1", "core.quotepath", "false")
        assert result.warnings == []

    @pytest.mark.skipif(sys.platform == "win32", reason="Windows file names cannot hold these")
    def test_names_git_quotes_whatever_the_setting_are_reported(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        repo = _init_repo(tmp_path)
        _create_tracked(repo, 'say "hi".cfg', "back\\slash.cfg", "new\nline.cfg", "plain.cfg")

        result, env = self._scan(scanner, repo)

        assert self._quotepath_setting(env) == ("1", "core.quotepath", "false")
        (warning,) = result.warnings
        assert warning.startswith(f"Not scanned in {repo}: git writes the name of 3 tracked ")
        for shown in (repr('say "hi".cfg'), repr("back\\slash.cfg"), repr("new\nline.cfg")):
            assert shown in warning
        assert "plain.cfg" not in warning
        # The message is one line of printable text, whatever the names hold.
        assert "\n" not in warning

    @pytest.mark.skipif(sys.platform == "win32", reason="Windows file names cannot hold these")
    def test_only_the_first_names_are_listed(self, scanner: DetectSecretsScanner, tmp_path: Path):
        repo = _init_repo(tmp_path)
        _create_tracked(repo, *(f'q"{number}.cfg' for number in range(5)))

        (warning,) = self._scan(scanner, repo)[0].warnings

        assert "5 tracked file(s)" in warning
        assert warning.count('q"') == 3
        assert " and 2 more)" in warning

    @NOT_UTF8_PLATFORM
    def test_a_name_that_is_not_utf8_leaves_the_setting_alone_and_reports_every_quoted_name(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        """With the setting off detect-secrets cannot decode the list and fails the whole scan.

        The default is kept for such a repository, which skips every non-ASCII name, and each
        of them is reported.
        """
        repo = _init_repo(tmp_path)
        _create_tracked(repo, NOT_UTF8, "café.cfg", "plain.cfg")

        result, env = self._scan(scanner, repo)

        assert self._quotepath_setting(env) is None
        (warning,) = result.warnings
        assert "the name of 2 tracked file(s)" in warning
        assert repr(NOT_UTF8) in warning
        assert repr("café.cfg") in warning
        assert "plain.cfg" not in warning

    @NOT_UTF8_PLATFORM
    def test_the_names_of_a_scan_below_a_subdirectory_are_those_below_it(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        repo = _init_repo(tmp_path)
        _create_tracked(repo, NOT_UTF8, "sub/plain.cfg")

        assert self._scan(scanner, repo / "sub")[0].warnings == []
        assert self._quotepath_setting(self._scan(scanner, repo / "sub")[1]) == (
            "1",
            "core.quotepath",
            "false",
        )

    def test_a_directory_that_tracks_nothing_gets_the_environment_as_it_is(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        repo = _init_repo(tmp_path)

        result, env = self._scan(scanner, repo)

        assert self._quotepath_setting(env) is None
        (warning,) = result.warnings
        assert warning.startswith("Scanned nothing in ")

    def test_a_git_that_cannot_list_files_leaves_the_environment_alone(self, tmp_path: Path):
        env, warnings = _check_git_file_list(tmp_path, None)

        assert warnings == []
        assert self._quotepath_setting(env) is None

    @pytest.mark.parametrize(
        ("name", "quotepath_off", "quoted"),
        [
            ("plain.cfg", False, False),
            ("with space/and-dash_1.cfg", False, False),
            ("café.cfg", False, True),
            ("café.cfg", True, False),
            ("文档/配置.cfg", False, True),
            ("文档/配置.cfg", True, False),
            ('say "hi".cfg', True, True),
            ("back\\slash.cfg", True, True),
            ("new\nline.cfg", True, True),
            ("tab\there.cfg", True, True),
            ("bell\x07.cfg", True, True),
            ("del\x7f.cfg", True, True),
            ("it's.cfg", True, False),
        ],
    )
    def test_which_names_git_quotes(self, name: str, quotepath_off: bool, quoted: bool):
        assert _git_quotes(name, quotepath_off=quotepath_off) is quoted

    def test_a_lone_surrogate_is_a_name_that_is_not_utf8(self):
        assert _is_undecodable(NOT_UTF8)
        assert not _is_undecodable("café.cfg")
        assert not _is_undecodable("plain.cfg")


class TestNothingToScan:
    """In a repository detect-secrets scans what git tracks, and says nothing when that is
    nothing. The scanner must not let that pass for a clean run."""

    @pytest.fixture
    def scanner(self) -> DetectSecretsScanner:
        return DetectSecretsScanner(auto_install=False)

    @staticmethod
    def _scan(scanner: DetectSecretsScanner, target: Path):
        run, _calls = _fake_detect_secrets()
        with (
            patch.object(scanner, "_ensure_installed", return_value=None),
            patch("subprocess.run", side_effect=run),
        ):
            return scanner.scan([target])

    def test_a_repository_that_tracks_nothing_warns(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        repo = _init_repo(tmp_path)
        (repo / "new.cfg").write_text("x = 1\n")

        result = self._scan(scanner, repo)

        assert result.error is None
        (warning,) = result.warnings
        assert warning.startswith("Scanned nothing in ")
        assert str(repo) in warning
        assert "git add" in warning

    def test_a_repository_that_tracks_a_file_does_not(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        repo = _init_repo(tmp_path)
        _add(repo, "app.cfg")

        assert self._scan(scanner, repo).warnings == []

    def test_files_tracked_only_below_an_excluded_directory_count_as_nothing(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        repo = _init_repo(tmp_path)
        _add(repo, "vendor/lib.cfg", "build/out.cfg")

        (warning,) = self._scan(scanner, repo).warnings

        assert warning.startswith("Scanned nothing in ")

    def test_a_subdirectory_that_tracks_nothing_warns_though_the_repository_does_not(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        repo = _init_repo(tmp_path)
        _add(repo, "tracked/app.cfg")
        (repo / "untracked").mkdir()
        (repo / "untracked" / "new.cfg").write_text("x = 1\n")

        assert self._scan(scanner, repo / "tracked").warnings == []
        (warning,) = self._scan(scanner, repo / "untracked").warnings
        assert str(repo / "untracked") in warning

    def test_a_directory_named_like_an_excluded_one_is_not_nothing(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        """The directory that was asked for is scanned whatever it is called."""
        repo = _init_repo(tmp_path)
        _add(repo, "build/app.cfg")

        assert self._scan(scanner, repo / "build").warnings == []

    def test_a_directory_outside_git_is_never_warned_about(
        self, scanner: DetectSecretsScanner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setattr(detect_secrets_module, "get_git_root", lambda _path: None)

        assert self._scan(scanner, tmp_path).warnings == []

    def test_a_git_that_cannot_list_files_is_not_taken_for_an_empty_repository(
        self, scanner: DetectSecretsScanner, tmp_path: Path
    ):
        repo = _init_repo(tmp_path)
        plan = _plan_scan(repo)
        real_run = subprocess.run

        def failing(args: list[str], **kwargs: Any):
            if args[:2] == ["git", "ls-files"]:
                return SimpleNamespace(returncode=128, stdout="", stderr="fatal")
            return real_run(args, **kwargs)

        with patch("subprocess.run", side_effect=failing):
            assert _scannable_tracked_names(plan) is None

        with patch("subprocess.run", side_effect=OSError("no git")):
            assert _scannable_tracked_names(plan) is None
