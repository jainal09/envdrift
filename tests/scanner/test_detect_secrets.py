"""Tests for the detect-secrets scanner: installer, scan and report parsing, severities."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from envdrift.scanner import detect_secrets as detect_secrets_module
from envdrift.scanner.base import FindingSeverity
from envdrift.scanner.detect_secrets import (
    DETECTOR_SEVERITY,
    DetectSecretsInstaller,
    DetectSecretsInstallError,
    DetectSecretsNotFoundError,
    DetectSecretsScanner,
    _get_detect_secrets_version,
)
from tests.scanner.detect_secrets_helpers import no_version_probe  # noqa: F401  (autouse)


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
