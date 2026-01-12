"""Tests for detect-secrets scanner integration."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from envdrift.scanner.base import FindingSeverity
from envdrift.scanner.detect_secrets import (
    DETECTOR_SEVERITY,
    DetectSecretsInstaller,
    DetectSecretsInstallError,
    DetectSecretsNotFoundError,
    DetectSecretsScanner,
)


class TestDetectSecretsInstaller:
    """Tests for DetectSecretsInstaller."""

    def test_default_version_from_constants(self):
        """Installer uses pinned version by default."""
        installer = DetectSecretsInstaller()
        assert installer.version == "1.5.0"

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

    def test_scan_handles_invalid_json(self, tmp_path: Path):
        """Scan ignores invalid JSON output."""
        scanner = DetectSecretsScanner(auto_install=False)
        with patch.object(scanner, "_ensure_installed", return_value=None):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = SimpleNamespace(returncode=0, stdout="not-json", stderr="")
                result = scanner.scan([tmp_path])

        assert result.error is None
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
