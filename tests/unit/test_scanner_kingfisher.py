"""Unit tests for Kingfisher scanner integration."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from envdrift.scanner.base import FindingSeverity
from envdrift.scanner.kingfisher import (
    KingfisherInstallError,
    KingfisherScanner,
    _map_severity,
)


class TestMapSeverity:
    """Tests for severity mapping function."""

    def test_bcrypt_is_critical(self):
        """bcrypt password hashes should be CRITICAL."""
        assert (
            _map_severity("kingfisher.bcrypt.1", "Password Hash (bcrypt)")
            == FindingSeverity.CRITICAL
        )

    def test_sha512crypt_is_critical(self):
        """sha512crypt hashes should be CRITICAL."""
        assert (
            _map_severity("kingfisher.shadow.1", "Password Hash (sha512crypt)")
            == FindingSeverity.CRITICAL
        )

    def test_netrc_is_critical(self):
        """netrc credentials should be CRITICAL."""
        assert _map_severity("kingfisher.netrc.1", "netrc Credentials") == FindingSeverity.CRITICAL

    def test_github_token_is_high(self):
        """GitHub tokens should be HIGH."""
        assert _map_severity("kingfisher.github.1", "GitHub Token") == FindingSeverity.HIGH

    def test_slack_token_is_high(self):
        """Slack tokens should be HIGH."""
        assert _map_severity("kingfisher.slack.1", "Slack Token") == FindingSeverity.HIGH

    def test_api_key_pattern_is_high(self):
        """Rules containing api_key/api-key pattern should be HIGH."""
        assert _map_severity("kingfisher.api-key.1", "AWS API Key") == FindingSeverity.HIGH
        assert _map_severity("kingfisher.api_key.1", "Generic API_KEY") == FindingSeverity.HIGH

    def test_password_is_high(self):
        """Password patterns should be HIGH."""
        assert _map_severity("kingfisher.weak.1", "Weak Password Pattern") == FindingSeverity.HIGH

    def test_unknown_is_medium(self):
        """Unknown rules should default to MEDIUM."""
        assert _map_severity("kingfisher.unknown.1", "Unknown Rule") == FindingSeverity.MEDIUM


class TestKingfisherScanner:
    """Tests for KingfisherScanner class."""

    def test_scanner_name(self):
        """Scanner should have correct name."""
        scanner = KingfisherScanner(auto_install=False)
        assert scanner.name == "kingfisher"

    def test_scanner_description(self):
        """Scanner should have informative description."""
        scanner = KingfisherScanner(auto_install=False)
        assert "700+" in scanner.description
        assert "password" in scanner.description.lower()

    def test_default_options(self):
        """Default options should be set for maximum detection."""
        scanner = KingfisherScanner()
        assert scanner._auto_install is True
        assert scanner._validate_secrets is True
        assert scanner._confidence == "low"
        assert scanner._scan_binary_files is True
        assert scanner._extract_archives is True

    def test_custom_options(self):
        """Custom options should be respected."""
        scanner = KingfisherScanner(
            auto_install=False,
            validate_secrets=False,
            confidence="high",
            scan_binary_files=False,
            extract_archives=False,
            min_entropy=3.5,
            max_file_size_mb=100,
        )
        assert scanner._auto_install is False
        assert scanner._validate_secrets is False
        assert scanner._confidence == "high"
        assert scanner._scan_binary_files is False
        assert scanner._extract_archives is False
        assert scanner._min_entropy == 3.5
        assert scanner._max_file_size_mb == 100

    @patch("shutil.which")
    def test_is_installed_true(self, mock_which):
        """is_installed returns True when binary is found."""
        mock_which.return_value = "/opt/homebrew/bin/kingfisher"
        scanner = KingfisherScanner(auto_install=False)
        assert scanner.is_installed() is True

    @patch("shutil.which")
    def test_is_installed_false(self, mock_which):
        """is_installed returns False when binary not found."""
        mock_which.return_value = None
        scanner = KingfisherScanner(auto_install=False)
        assert scanner.is_installed() is False

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_get_version(self, mock_run, mock_which):
        """get_version returns correct version string."""
        mock_which.return_value = "/opt/homebrew/bin/kingfisher"
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="kingfisher 1.73.0\n",
        )
        scanner = KingfisherScanner(auto_install=False)
        assert scanner.get_version() == "1.73.0"

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_get_version_failure(self, mock_run, mock_which):
        """get_version returns None on error."""
        mock_which.return_value = "/opt/homebrew/bin/kingfisher"
        mock_run.return_value = MagicMock(returncode=1, stdout="")
        scanner = KingfisherScanner(auto_install=False)
        assert scanner.get_version() is None

    @patch("shutil.which")
    def test_scan_binary_not_found(self, mock_which):
        """Scan returns error when binary not found."""
        mock_which.return_value = None
        scanner = KingfisherScanner(auto_install=False)
        result = scanner.scan([Path()])
        assert result.error is not None
        assert "not found" in result.error.lower()

    @patch("shutil.which")
    @patch("subprocess.run")
    @patch("tempfile.NamedTemporaryFile")
    def test_scan_no_findings(self, mock_temp, mock_run, mock_which):
        """Scan returns empty results when no secrets found."""
        mock_which.return_value = "/opt/homebrew/bin/kingfisher"
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        # Mock temp file
        mock_temp_file = MagicMock()
        mock_temp_file.name = "/tmp/test_report.json"
        mock_temp.return_value.__enter__ = MagicMock(return_value=mock_temp_file)
        mock_temp.return_value.__exit__ = MagicMock(return_value=False)

        with patch.object(Path, "exists", return_value=False):
            scanner = KingfisherScanner(auto_install=False)
            result = scanner.scan([Path("/nonexistent")])
            assert result.error is None
            assert len(result.findings) == 0

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_scan_with_findings(self, mock_run, mock_which, tmp_path):
        """Scan correctly parses findings from Kingfisher output."""
        mock_which.return_value = "/opt/homebrew/bin/kingfisher"

        # Create test directory
        test_file = tmp_path / "test.env"
        test_file.write_text("SECRET_KEY=abc123")

        # Kingfisher JSON output format
        kingfisher_output = {
            "findings": [
                {
                    "rule": {"name": "Generic API Key", "id": "kingfisher.generic.1"},
                    "finding": {
                        "snippet": "abc123",
                        "path": str(test_file),
                        "line": 1,
                        "column_start": 12,
                        "confidence": "medium",
                        "entropy": "3.5",
                        "validation": {"status": "Not Attempted"},
                    },
                }
            ]
        }

        # Create temp report file
        report_file = tmp_path / "report.json"
        report_file.write_text(json.dumps(kingfisher_output))

        mock_run.return_value = MagicMock(returncode=200, stdout="", stderr="")

        with patch("tempfile.NamedTemporaryFile") as mock_temp:
            mock_temp_instance = MagicMock()
            mock_temp_instance.name = str(report_file)
            mock_temp.return_value.__enter__ = MagicMock(return_value=mock_temp_instance)
            mock_temp.return_value.__exit__ = MagicMock(return_value=False)

            scanner = KingfisherScanner(auto_install=False, validate_secrets=False)
            result = scanner.scan([tmp_path])

            assert result.error is None
            assert len(result.findings) == 1
            assert result.findings[0].rule_id == "kingfisher-kingfisher.generic.1"
            assert result.findings[0].rule_description == "Generic API Key"
            # "Generic API Key" doesn't match HIGH patterns, so it's MEDIUM
            assert result.findings[0].severity == FindingSeverity.MEDIUM

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_scan_timeout(self, mock_run, mock_which):
        """Scan handles timeout gracefully."""
        mock_which.return_value = "/opt/homebrew/bin/kingfisher"
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="kingfisher", timeout=600)

        scanner = KingfisherScanner(auto_install=False)
        result = scanner.scan([Path()])

        assert result.error is not None
        assert "timed out" in result.error.lower()

    def test_parse_finding_with_bcrypt_hash(self):
        """Parse finding correctly identifies bcrypt as CRITICAL."""
        scanner = KingfisherScanner(auto_install=False)

        finding_data = {
            "rule": {"name": "Password Hash (bcrypt)", "id": "kingfisher.bcrypt.1"},
            "finding": {
                "snippet": "$2y$10$abcdefghijklmnop",
                "path": "/test/db/dump.sql",
                "line": 42,
                "column_start": 10,
                "confidence": "high",
                "entropy": "4.2",
                "validation": {"status": "Not Attempted"},
            },
        }

        result = scanner._parse_finding(finding_data, Path("/test"))

        assert result is not None
        assert result.severity == FindingSeverity.CRITICAL
        assert "bcrypt" in result.rule_description.lower()
        assert result.line_number == 42


class TestKingfisherInstallation:
    """Tests for Kingfisher installation functionality."""

    @patch("platform.system")
    @patch("shutil.which")
    def test_install_not_supported_on_windows(self, mock_which, mock_system):
        """Installation raises error on Windows."""
        mock_system.return_value = "Windows"
        mock_which.side_effect = [None, None]  # kingfisher not found, brew not found

        scanner = KingfisherScanner(auto_install=False)
        with pytest.raises(KingfisherInstallError):
            scanner._install_via_homebrew()

    @patch("platform.system")
    @patch("shutil.which")
    def test_install_fails_without_homebrew(self, mock_which, mock_system):
        """Installation raises error when Homebrew is not available."""
        mock_system.return_value = "Darwin"
        mock_which.return_value = None  # brew not found

        scanner = KingfisherScanner(auto_install=False)
        with pytest.raises(KingfisherInstallError, match="Homebrew not found"):
            scanner._install_via_homebrew()

    @patch("platform.system")
    @patch("shutil.which")
    @patch("subprocess.run")
    def test_install_via_homebrew_success(self, mock_run, mock_which, mock_system):
        """Successful Homebrew installation."""
        mock_system.return_value = "Darwin"
        mock_which.side_effect = [
            "/opt/homebrew/bin/brew",  # brew found
            "/opt/homebrew/bin/kingfisher",  # kingfisher found after install
        ]
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        scanner = KingfisherScanner(auto_install=False)
        result = scanner._install_via_homebrew()

        assert result == Path("/opt/homebrew/bin/kingfisher")

    @patch("platform.system")
    @patch("shutil.which")
    @patch("subprocess.run")
    def test_install_already_installed(self, mock_run, mock_which, mock_system):
        """Installation handles 'already installed' gracefully."""
        mock_system.return_value = "Darwin"
        mock_which.side_effect = [
            "/opt/homebrew/bin/brew",
            "/opt/homebrew/bin/kingfisher",
        ]
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="Warning: kingfisher 1.73.0 is already installed",
        )

        scanner = KingfisherScanner(auto_install=False)
        result = scanner._install_via_homebrew()

        assert result == Path("/opt/homebrew/bin/kingfisher")


class TestKingfisherCommandBuilding:
    """Tests for command-line argument building."""

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_command_includes_all_rules(self, mock_run, mock_which, tmp_path):
        """Command includes --rule all for maximum detection."""
        mock_which.return_value = "/opt/homebrew/bin/kingfisher"
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        # Create empty test path
        (tmp_path / "test.txt").write_text("test")

        scanner = KingfisherScanner(auto_install=False, validate_secrets=False)
        scanner.scan([tmp_path])

        # Check the command that was called
        call_args = mock_run.call_args[0][0]
        assert "--rule" in call_args
        assert "all" in call_args

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_command_includes_confidence_low(self, mock_run, mock_which, tmp_path):
        """Command includes --confidence low for maximum detection."""
        mock_which.return_value = "/opt/homebrew/bin/kingfisher"
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        (tmp_path / "test.txt").write_text("test")

        scanner = KingfisherScanner(auto_install=False, confidence="low")
        scanner.scan([tmp_path])

        call_args = mock_run.call_args[0][0]
        assert "--confidence" in call_args
        idx = call_args.index("--confidence")
        assert call_args[idx + 1] == "low"

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_command_includes_no_validate_when_disabled(self, mock_run, mock_which, tmp_path):
        """Command includes --no-validate when validation is disabled."""
        mock_which.return_value = "/opt/homebrew/bin/kingfisher"
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        (tmp_path / "test.txt").write_text("test")

        scanner = KingfisherScanner(auto_install=False, validate_secrets=False)
        scanner.scan([tmp_path])

        call_args = mock_run.call_args[0][0]
        assert "--no-validate" in call_args

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_command_includes_git_history_full_when_enabled(self, mock_run, mock_which, tmp_path):
        """Command includes --git-history full when history scanning is enabled."""
        mock_which.return_value = "/opt/homebrew/bin/kingfisher"
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        (tmp_path / "test.txt").write_text("test")

        scanner = KingfisherScanner(auto_install=False, validate_secrets=False)
        scanner.scan([tmp_path], include_git_history=True)

        call_args = mock_run.call_args[0][0]
        assert "--git-history" in call_args
        idx = call_args.index("--git-history")
        assert call_args[idx + 1] == "full"

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_command_includes_entropy_threshold(self, mock_run, mock_which, tmp_path):
        """Command includes --min-entropy when threshold is set."""
        mock_which.return_value = "/opt/homebrew/bin/kingfisher"
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        (tmp_path / "test.txt").write_text("test")

        scanner = KingfisherScanner(auto_install=False, min_entropy=3.0)
        scanner.scan([tmp_path])

        call_args = mock_run.call_args[0][0]
        assert "--min-entropy" in call_args
        idx = call_args.index("--min-entropy")
        assert call_args[idx + 1] == "3.0"
