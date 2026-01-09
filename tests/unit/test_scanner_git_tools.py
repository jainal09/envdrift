"""Unit tests for GitHound and git-secrets scanner integration."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from envdrift.scanner.git_hound import (
    GitHoundScanner,
    get_platform_info,
)
from envdrift.scanner.git_secrets import (
    GitSecretsScanner,
)


class TestGitHoundScanner:
    """Tests for GitHoundScanner."""

    def test_scanner_name(self) -> None:
        """Test scanner name property."""
        scanner = GitHoundScanner(auto_install=False)
        assert scanner.name == "git-hound"

    def test_scanner_description(self) -> None:
        """Test scanner description property."""
        scanner = GitHoundScanner(auto_install=False)
        assert "GitHound" in scanner.description
        assert "dorks" in scanner.description.lower() or "pattern" in scanner.description.lower()

    def test_is_installed_returns_false_when_not_found(self) -> None:
        """Test is_installed returns False when binary not found."""
        with patch("shutil.which", return_value=None):
            scanner = GitHoundScanner(auto_install=False)
            assert scanner.is_installed() is False

    def test_is_installed_returns_true_when_found(self) -> None:
        """Test is_installed returns True when binary is in PATH."""
        with patch("shutil.which", return_value="/usr/local/bin/git-hound"):
            scanner = GitHoundScanner(auto_install=False)
            assert scanner.is_installed() is True

    def test_scan_returns_error_when_not_installed(self) -> None:
        """Test scan returns error result when scanner not installed."""
        with patch("shutil.which", return_value=None):
            with patch.object(
                GitHoundScanner, "is_installed", return_value=False
            ):
                scanner = GitHoundScanner(auto_install=False)
                # Directly call scan without mocking _find_binary
                result = scanner.scan([Path(".")])
                assert result.error is not None
                assert "not found" in result.error.lower()

    def test_get_platform_info_returns_tuple(self) -> None:
        """Test get_platform_info returns system and machine tuple."""
        system, machine = get_platform_info()
        assert isinstance(system, str)
        assert isinstance(machine, str)
        assert system in ("Darwin", "Linux", "Windows")


class TestGitSecretsScanner:
    """Tests for GitSecretsScanner."""

    def test_scanner_name(self) -> None:
        """Test scanner name property."""
        scanner = GitSecretsScanner(auto_install=False)
        assert scanner.name == "git-secrets"

    def test_scanner_description(self) -> None:
        """Test scanner description property."""
        scanner = GitSecretsScanner(auto_install=False)
        assert "AWS" in scanner.description or "git-secrets" in scanner.description

    def test_is_installed_returns_false_when_not_found(self) -> None:
        """Test is_installed returns False when binary not found."""
        with patch("shutil.which", return_value=None):
            with patch("subprocess.run") as mock_run:
                mock_run.side_effect = FileNotFoundError()
                scanner = GitSecretsScanner(auto_install=False)
                assert scanner.is_installed() is False

    def test_is_installed_returns_true_when_found(self) -> None:
        """Test is_installed returns True when binary is in PATH."""
        with patch("shutil.which", return_value="/usr/local/bin/git-secrets"):
            scanner = GitSecretsScanner(auto_install=False)
            assert scanner.is_installed() is True

    def test_scan_returns_error_when_not_installed(self) -> None:
        """Test scan returns error result when scanner not installed."""
        with patch("shutil.which", return_value=None):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value.returncode = 1
                mock_run.return_value.stdout = ""
                scanner = GitSecretsScanner(auto_install=False)
                result = scanner.scan([Path(".")])
                assert result.error is not None
                assert "not found" in result.error.lower()

    def test_get_version_returns_none(self) -> None:
        """Test get_version returns None (git-secrets has no version flag)."""
        scanner = GitSecretsScanner(auto_install=False)
        assert scanner.get_version() is None

    def test_detect_rule_type_aws_access_key(self) -> None:
        """Test _detect_rule_type correctly identifies AWS access keys."""
        scanner = GitSecretsScanner(auto_install=False)
        assert scanner._detect_rule_type("AKIAIOSFODNN7EXAMPLE") == "aws-access-key"
        assert scanner._detect_rule_type("ASIAIOSFODNN7EXAMPLE") == "aws-access-key"

    def test_detect_rule_type_password(self) -> None:
        """Test _detect_rule_type correctly identifies passwords."""
        scanner = GitSecretsScanner(auto_install=False)
        assert scanner._detect_rule_type("password=secret123") == "password"
        assert scanner._detect_rule_type("PASSWD=mypass") == "password"

    def test_detect_rule_type_token(self) -> None:
        """Test _detect_rule_type correctly identifies tokens."""
        scanner = GitSecretsScanner(auto_install=False)
        assert scanner._detect_rule_type("api_token=abc123") == "token"

    def test_detect_rule_type_generic(self) -> None:
        """Test _detect_rule_type returns generic for unknown patterns."""
        scanner = GitSecretsScanner(auto_install=False)
        assert scanner._detect_rule_type("some_value=xyz") == "generic-secret"

    def test_get_rule_description(self) -> None:
        """Test _get_rule_description returns correct descriptions."""
        scanner = GitSecretsScanner(auto_install=False)
        assert scanner._get_rule_description("aws-access-key") == "AWS Access Key ID"
        assert scanner._get_rule_description("password") == "Password or Credential"
        assert scanner._get_rule_description("unknown") == "Secret Pattern Match"


class TestScanEngineIntegration:
    """Tests for scanner integration with ScanEngine."""

    def test_engine_can_use_git_hound(self) -> None:
        """Test ScanEngine can be configured to use git-hound."""
        from envdrift.scanner.engine import GuardConfig

        config = GuardConfig(
            use_native=False,
            use_gitleaks=False,
            use_git_hound=True,
        )
        assert config.use_git_hound is True

    def test_engine_can_use_git_secrets(self) -> None:
        """Test ScanEngine can be configured to use git-secrets."""
        from envdrift.scanner.engine import GuardConfig

        config = GuardConfig(
            use_native=False,
            use_gitleaks=False,
            use_git_secrets=True,
        )
        assert config.use_git_secrets is True

    def test_config_from_dict_parses_git_hound(self) -> None:
        """Test GuardConfig.from_dict correctly parses git-hound."""
        from envdrift.scanner.engine import GuardConfig

        config_dict = {
            "guard": {
                "scanners": ["native", "git-hound"],
            }
        }
        config = GuardConfig.from_dict(config_dict)
        assert config.use_native is True
        assert config.use_git_hound is True
        assert config.use_gitleaks is False

    def test_config_from_dict_parses_git_secrets(self) -> None:
        """Test GuardConfig.from_dict correctly parses git-secrets."""
        from envdrift.scanner.engine import GuardConfig

        config_dict = {
            "guard": {
                "scanners": ["native", "git-secrets"],
            }
        }
        config = GuardConfig.from_dict(config_dict)
        assert config.use_native is True
        assert config.use_git_secrets is True
        assert config.use_gitleaks is False
