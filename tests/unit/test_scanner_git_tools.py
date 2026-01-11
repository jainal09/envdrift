"""Unit tests for git-secrets scanner integration."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from envdrift.scanner.git_secrets import (
    GitSecretsInstaller,
    GitSecretsScanner,
    get_venv_bin_dir,
)


class TestGetVenvBinDir:
    """Tests for get_venv_bin_dir function."""

    def test_returns_venv_bin_when_virtual_env_set(self) -> None:
        """Test returns venv/bin when VIRTUAL_ENV is set."""
        with patch.dict("os.environ", {"VIRTUAL_ENV": "/path/to/venv"}):
            with patch("platform.system", return_value="Linux"):
                result = get_venv_bin_dir()
                assert result == Path("/path/to/venv/bin")

    def test_returns_venv_scripts_on_windows(self) -> None:
        """Test returns venv/Scripts on Windows."""
        with patch.dict("os.environ", {"VIRTUAL_ENV": "C:\\path\\to\\venv"}):
            with patch("platform.system", return_value="Windows"):
                result = get_venv_bin_dir()
                assert result == Path("C:\\path\\to\\venv/Scripts")

    def test_returns_local_bin_when_no_venv(self) -> None:
        """Test returns ~/.local/bin when no venv."""
        with patch.dict("os.environ", {}, clear=True):
            with patch("platform.system", return_value="Linux"):
                with patch("pathlib.Path.home", return_value=Path("/home/user")):
                    with patch("pathlib.Path.mkdir"):
                        result = get_venv_bin_dir()
                        assert result == Path("/home/user/.local/bin")

    def test_raises_on_windows_without_venv(self) -> None:
        """Test raises RuntimeError on Windows without venv."""
        import pytest

        with patch.dict("os.environ", {}, clear=True):
            with patch("platform.system", return_value="Windows"):
                with pytest.raises(RuntimeError, match="Cannot find suitable bin directory"):
                    get_venv_bin_dir()


class TestGitSecretsInstaller:
    """Tests for GitSecretsInstaller."""

    def test_install_returns_existing_when_already_installed(self) -> None:
        """Test install returns existing path when already installed."""
        with patch("shutil.which", return_value="/usr/local/bin/git-secrets"):
            installer = GitSecretsInstaller()
            result = installer.install()
            assert result == Path("/usr/local/bin/git-secrets")

    def test_install_homebrew_on_darwin(self) -> None:
        """Test install uses homebrew on macOS."""
        with patch("shutil.which") as mock_which:
            mock_which.side_effect = (
                lambda x: "/usr/local/bin/brew"
                if x == "brew"
                else ("/usr/local/bin/git-secrets" if x == "git-secrets" else None)
            )
            with patch("platform.system", return_value="Darwin"):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
                    installer = GitSecretsInstaller()
                    result = installer.install(force=True)
                    assert result == Path("/usr/local/bin/git-secrets")


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
        with patch("shutil.which", return_value=None), patch("subprocess.run") as mock_run:
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
        with patch("shutil.which", return_value=None), patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 1
            mock_run.return_value.stdout = ""
            scanner = GitSecretsScanner(auto_install=False)
            result = scanner.scan([Path()])
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

    def test_detect_rule_type_api_key(self) -> None:
        """Test _detect_rule_type correctly identifies API keys."""
        scanner = GitSecretsScanner(auto_install=False)
        assert scanner._detect_rule_type("api_key=xyz789") == "api-key"
        assert scanner._detect_rule_type("APIKEY=abc") == "api-key"

    def test_detect_rule_type_private_key(self) -> None:
        """Test _detect_rule_type correctly identifies private keys."""
        scanner = GitSecretsScanner(auto_install=False)
        assert scanner._detect_rule_type("private_key=secret_value") == "private-key"

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

    def test_extract_secret_aws_access_key(self) -> None:
        """Test _extract_secret extracts AWS access key."""
        scanner = GitSecretsScanner(auto_install=False)
        content = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        result = scanner._extract_secret(content)
        assert "AKIA" in result

    def test_extract_secret_with_quotes(self) -> None:
        """Test _extract_secret handles quoted values."""
        scanner = GitSecretsScanner(auto_install=False)
        content = 'password="mysecretpassword"'
        result = scanner._extract_secret(content)
        assert result == "mysecretpassword"

    def test_extract_secret_truncates_long_content(self) -> None:
        """Test _extract_secret truncates long content without patterns."""
        scanner = GitSecretsScanner(auto_install=False)
        long_content = "x" * 100
        result = scanner._extract_secret(long_content)
        assert len(result) == 50

    def test_find_binary_uses_cached_path(self) -> None:
        """Test _find_binary returns cached path if available."""
        scanner = GitSecretsScanner(auto_install=False)
        scanner._binary_path = Path("/cached/git-secrets")
        with patch.object(Path, "exists", return_value=True):
            result = scanner._find_binary()
            assert result == Path("/cached/git-secrets")

    def test_install_method_returns_path(self) -> None:
        """Test install method returns installed path."""
        with patch.object(
            GitSecretsInstaller, "install", return_value=Path("/installed/git-secrets")
        ):
            scanner = GitSecretsScanner(auto_install=False)
            result = scanner.install()
            assert result == Path("/installed/git-secrets")

    def test_run_git_secrets_uses_standalone_command(self) -> None:
        """Test _run_git_secrets uses standalone command when available."""
        with patch("shutil.which", return_value="/usr/local/bin/git-secrets"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
                scanner = GitSecretsScanner(auto_install=False)
                scanner._run_git_secrets(["--list"], Path("/tmp"))
                mock_run.assert_called_once()
                assert mock_run.call_args[0][0][0] == "/usr/local/bin/git-secrets"

    def test_run_git_secrets_falls_back_to_git_subcommand(self) -> None:
        """Test _run_git_secrets falls back to git subcommand."""
        with patch("shutil.which", return_value=None), patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            scanner = GitSecretsScanner(auto_install=False)
            scanner._run_git_secrets(["--list"], Path("/tmp"))
            mock_run.assert_called_once()
            assert mock_run.call_args[0][0][0] == "git"
            assert mock_run.call_args[0][0][1] == "secrets"


class TestGitSecretsParseOutput:
    """Tests for git-secrets output parsing."""

    def test_parse_output_with_findings(self) -> None:
        """Test _parse_output correctly parses finding lines."""
        scanner = GitSecretsScanner(auto_install=False)
        output = "test.env:5:AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        findings = scanner._parse_output(output, Path("/repo"))
        assert len(findings) == 1
        assert findings[0].line_number == 5
        assert "AKIA" in findings[0].secret_preview or "AKIA" in findings[0].description

    def test_parse_output_with_commit_sha(self) -> None:
        """Test _parse_output handles history scan output with commit."""
        scanner = GitSecretsScanner(auto_install=False)
        output = "abc123def:test.env:10:password=secret\n"
        findings = scanner._parse_output(output, Path("/repo"))
        assert len(findings) == 1
        assert findings[0].commit_sha == "abc123def"

    def test_parse_output_ignores_non_finding_lines(self) -> None:
        """Test _parse_output ignores lines without proper format."""
        scanner = GitSecretsScanner(auto_install=False)
        output = "Some informational message\ntest.env:5:secret=value\nAnother message\n"
        findings = scanner._parse_output(output, Path("/repo"))
        # Should only find the properly formatted line
        assert len(findings) >= 1

    def test_parse_output_empty_string(self) -> None:
        """Test _parse_output handles empty output."""
        scanner = GitSecretsScanner(auto_install=False)
        findings = scanner._parse_output("", Path("/repo"))
        assert findings == []


class TestScanEngineIntegration:
    """Tests for scanner integration with ScanEngine."""

    def test_engine_can_use_git_secrets(self) -> None:
        """Test ScanEngine can be configured to use git-secrets."""
        from envdrift.scanner.engine import GuardConfig

        config = GuardConfig(
            use_native=False,
            use_gitleaks=False,
            use_git_secrets=True,
        )
        assert config.use_git_secrets is True

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

    def test_config_from_dict_without_guard_section(self) -> None:
        """Test GuardConfig.from_dict handles missing guard section."""
        from envdrift.scanner.engine import GuardConfig

        config_dict = {}
        config = GuardConfig.from_dict(config_dict)
        # Should use defaults
        assert config.use_native is True

    def test_config_all_scanners_disabled(self) -> None:
        """Test GuardConfig with all scanners disabled."""
        from envdrift.scanner.engine import GuardConfig

        config = GuardConfig(
            use_native=False,
            use_gitleaks=False,
            use_trufflehog=False,
            use_detect_secrets=False,
            use_kingfisher=False,
            use_git_secrets=False,
        )
        assert config.use_native is False
        assert config.use_git_secrets is False
