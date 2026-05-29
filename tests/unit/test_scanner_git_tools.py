"""Unit tests for git-secrets scanner integration."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from envdrift.scanner.git_secrets import (
    GitSecretsInstaller,
    GitSecretsInstallError,
    GitSecretsNotFoundError,
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


# ---------------------------------------------------------------------------
# Installer path coverage (lines 134-238)
# ---------------------------------------------------------------------------


class TestGitSecretsInstallerPaths:
    """Tests for GitSecretsInstaller installation paths."""

    def test_install_linux_uses_from_source(self) -> None:
        """Test install delegates to _install_from_source on Linux."""
        with (
            patch("shutil.which", return_value=None),
            patch("platform.system", return_value="Linux"),
            patch.object(
                GitSecretsInstaller,
                "_install_from_source",
                return_value=Path("/usr/local/bin/git-secrets"),
            ) as mock_src,
        ):
            installer = GitSecretsInstaller()
            result = installer.install(force=True)
            mock_src.assert_called_once()
            assert result == Path("/usr/local/bin/git-secrets")

    def test_install_unsupported_platform_raises(self) -> None:
        """Test install raises GitSecretsInstallError on unsupported platforms."""
        with (
            patch("shutil.which", return_value=None),
            patch("platform.system", return_value="FreeBSD"),
        ):
            installer = GitSecretsInstaller()
            with pytest.raises(GitSecretsInstallError, match="not supported"):
                installer.install(force=True)

    def test_install_homebrew_no_brew_raises(self) -> None:
        """Test _install_homebrew raises when brew is not in PATH."""
        with patch("shutil.which", return_value=None):
            installer = GitSecretsInstaller()
            with pytest.raises(GitSecretsInstallError, match="Homebrew not found"):
                installer._install_homebrew()

    def test_install_homebrew_already_installed_in_stderr(self) -> None:
        """Test _install_homebrew handles 'already installed' message in stderr."""
        with patch("shutil.which") as mock_which, patch("subprocess.run") as mock_run:
            mock_which.side_effect = lambda x: (
                "/usr/local/bin/brew"
                if x == "brew"
                else ("/usr/local/bin/git-secrets" if x == "git-secrets" else None)
            )
            mock_run.return_value = MagicMock(
                returncode=1, stdout="", stderr="Warning: git-secrets already installed"
            )
            installer = GitSecretsInstaller()
            result = installer._install_homebrew()
            assert result == Path("/usr/local/bin/git-secrets")

    def test_install_homebrew_already_installed_in_stdout(self) -> None:
        """Test _install_homebrew handles 'already installed' message in stdout."""
        with patch("shutil.which") as mock_which, patch("subprocess.run") as mock_run:
            mock_which.side_effect = lambda x: (
                "/usr/local/bin/brew"
                if x == "brew"
                else ("/usr/local/bin/git-secrets" if x == "git-secrets" else None)
            )
            mock_run.return_value = MagicMock(
                returncode=1, stdout="git-secrets already installed", stderr=""
            )
            installer = GitSecretsInstaller()
            result = installer._install_homebrew()
            assert result == Path("/usr/local/bin/git-secrets")

    def test_install_homebrew_nonzero_no_already_installed_raises(self) -> None:
        """Test _install_homebrew raises when brew fails without 'already installed'."""
        with patch("shutil.which") as mock_which, patch("subprocess.run") as mock_run:
            mock_which.side_effect = lambda x: ("/usr/local/bin/brew" if x == "brew" else None)
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="Some brew error")
            installer = GitSecretsInstaller()
            with pytest.raises(GitSecretsInstallError, match="Homebrew installation failed"):
                installer._install_homebrew()

    def test_install_homebrew_binary_not_found_after_install_raises(self) -> None:
        """Test _install_homebrew raises when git-secrets is absent after install."""
        with patch("shutil.which") as mock_which, patch("subprocess.run") as mock_run:
            mock_which.side_effect = lambda x: ("/usr/local/bin/brew" if x == "brew" else None)
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            installer = GitSecretsInstaller()
            with pytest.raises(GitSecretsInstallError, match="not found after installation"):
                installer._install_homebrew()

    def test_install_homebrew_timeout_raises(self) -> None:
        """Test _install_homebrew raises GitSecretsInstallError on timeout."""
        with patch("shutil.which") as mock_which, patch("subprocess.run") as mock_run:
            mock_which.side_effect = lambda x: ("/usr/local/bin/brew" if x == "brew" else None)
            mock_run.side_effect = subprocess.TimeoutExpired(cmd=["brew"], timeout=300)
            installer = GitSecretsInstaller()
            with pytest.raises(GitSecretsInstallError, match="timed out"):
                installer._install_homebrew()

    def test_install_homebrew_subprocess_error_raises(self) -> None:
        """Test _install_homebrew raises GitSecretsInstallError on SubprocessError."""
        with patch("shutil.which") as mock_which, patch("subprocess.run") as mock_run:
            mock_which.side_effect = lambda x: ("/usr/local/bin/brew" if x == "brew" else None)
            mock_run.side_effect = subprocess.SubprocessError("pipe broken")
            installer = GitSecretsInstaller()
            with pytest.raises(GitSecretsInstallError, match="Homebrew installation failed"):
                installer._install_homebrew()

    def test_install_from_source_no_git_raises(self) -> None:
        """Test _install_from_source raises when git is not installed."""
        with patch("shutil.which", return_value=None):
            installer = GitSecretsInstaller()
            with pytest.raises(GitSecretsInstallError, match="git not found"):
                installer._install_from_source()

    def test_install_from_source_no_make_raises(self) -> None:
        """Test _install_from_source raises when make is not installed."""
        with patch("shutil.which") as mock_which:
            mock_which.side_effect = lambda x: "/usr/bin/git" if x == "git" else None
            installer = GitSecretsInstaller()
            with pytest.raises(GitSecretsInstallError, match="make not found"):
                installer._install_from_source()

    def test_install_from_source_success(self, tmp_path: Path) -> None:
        """Test _install_from_source returns the installed binary path."""
        fake_bin = tmp_path / "bin" / "git-secrets"
        fake_bin.parent.mkdir()
        fake_bin.touch()
        with (
            patch("shutil.which") as mock_which,
            patch("subprocess.run") as mock_run,
            patch(
                "envdrift.scanner.git_secrets.get_venv_bin_dir",
                return_value=tmp_path / "bin",
            ),
        ):
            mock_which.side_effect = lambda x: (
                "/usr/bin/git" if x == "git" else ("/usr/bin/make" if x == "make" else None)
            )
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            installer = GitSecretsInstaller()
            result = installer._install_from_source()
            assert result == fake_bin

    def test_install_from_source_found_in_system_path(self, tmp_path: Path) -> None:
        """Test _install_from_source falls back to shutil.which when binary missing from target dir."""
        with (
            patch("shutil.which") as mock_which,
            patch("subprocess.run") as mock_run,
            patch(
                "envdrift.scanner.git_secrets.get_venv_bin_dir",
                return_value=tmp_path / "bin",
            ),
        ):
            mock_which.side_effect = lambda x: (
                "/usr/bin/git"
                if x == "git"
                else (
                    "/usr/bin/make"
                    if x == "make"
                    else ("/usr/local/bin/git-secrets" if x == "git-secrets" else None)
                )
            )
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            installer = GitSecretsInstaller()
            result = installer._install_from_source()
            assert result == Path("/usr/local/bin/git-secrets")

    def test_install_from_source_binary_not_found_raises(self, tmp_path: Path) -> None:
        """Test _install_from_source raises when binary cannot be located after build."""
        with (
            patch("shutil.which") as mock_which,
            patch("subprocess.run") as mock_run,
            patch(
                "envdrift.scanner.git_secrets.get_venv_bin_dir",
                return_value=tmp_path / "bin",
            ),
        ):
            mock_which.side_effect = lambda x: (
                "/usr/bin/git" if x == "git" else ("/usr/bin/make" if x == "make" else None)
            )
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            installer = GitSecretsInstaller()
            with pytest.raises(GitSecretsInstallError, match="not found after installation"):
                installer._install_from_source()

    def test_install_from_source_called_process_error_raises(self) -> None:
        """Test _install_from_source raises on CalledProcessError from git/make."""
        with patch("shutil.which") as mock_which, patch("subprocess.run") as mock_run:
            mock_which.side_effect = lambda x: (
                "/usr/bin/git" if x == "git" else ("/usr/bin/make" if x == "make" else None)
            )
            mock_run.side_effect = subprocess.CalledProcessError(1, "git", stderr="clone failed")
            installer = GitSecretsInstaller()
            with pytest.raises(GitSecretsInstallError, match="Installation failed"):
                installer._install_from_source()

    def test_install_from_source_timeout_raises(self) -> None:
        """Test _install_from_source raises on TimeoutExpired from git/make."""
        with patch("shutil.which") as mock_which, patch("subprocess.run") as mock_run:
            mock_which.side_effect = lambda x: (
                "/usr/bin/git" if x == "git" else ("/usr/bin/make" if x == "make" else None)
            )
            mock_run.side_effect = subprocess.TimeoutExpired(cmd=["git"], timeout=120)
            installer = GitSecretsInstaller()
            with pytest.raises(GitSecretsInstallError, match="timed out"):
                installer._install_from_source()


# ---------------------------------------------------------------------------
# _find_binary extra paths (lines 328-329, 338-343)
# ---------------------------------------------------------------------------


class TestGitSecretsScannerFindBinaryExtra:
    """Extra _find_binary paths not covered by the basic tests."""

    def test_find_binary_via_git_subcommand(self) -> None:
        """Test _find_binary marks binary as available via git subcommand."""
        with patch("shutil.which", return_value=None), patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            scanner = GitSecretsScanner(auto_install=False)
            result = scanner._find_binary()
            assert result == Path("git-secrets-subcommand")

    def test_find_binary_auto_install_success(self) -> None:
        """Test _find_binary auto-installs when binary is not found in PATH."""
        with (
            patch("shutil.which", return_value=None),
            patch("subprocess.run") as mock_run,
            patch.object(
                GitSecretsInstaller,
                "install",
                return_value=Path("/installed/git-secrets"),
            ),
        ):
            mock_run.return_value = MagicMock(returncode=1)
            scanner = GitSecretsScanner(auto_install=True)
            result = scanner._find_binary()
            assert result == Path("/installed/git-secrets")

    def test_find_binary_auto_install_fails_raises(self) -> None:
        """Test _find_binary raises GitSecretsNotFoundError when auto-install fails."""
        with (
            patch("shutil.which", return_value=None),
            patch("subprocess.run") as mock_run,
            patch.object(
                GitSecretsInstaller,
                "install",
                side_effect=GitSecretsInstallError("install failed"),
            ),
        ):
            mock_run.return_value = MagicMock(returncode=1)
            scanner = GitSecretsScanner(auto_install=True)
            with pytest.raises(GitSecretsNotFoundError, match="auto-install failed"):
                scanner._find_binary()


# ---------------------------------------------------------------------------
# scan() body (lines 422-534)
# ---------------------------------------------------------------------------


class TestGitSecretsScan:
    """Tests for GitSecretsScanner.scan() covering previously uncovered branches."""

    def test_scan_skips_nonexistent_path(self, tmp_path: Path) -> None:
        """Test scan silently skips paths that do not exist on disk."""
        nonexistent = tmp_path / "does_not_exist.env"
        with (
            patch("shutil.which", return_value="/usr/bin/git-secrets"),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            scanner = GitSecretsScanner(auto_install=False)
            result = scanner.scan([nonexistent])
        assert result.error is None
        assert len(result.findings) == 0

    def test_scan_file_with_findings_in_stdout(self, tmp_path: Path) -> None:
        """Test scan parses findings from stdout when returncode is non-zero."""
        (tmp_path / ".git").mkdir()
        secret_file = tmp_path / "secrets.env"
        secret_file.write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
        with (
            patch("shutil.which", return_value="/usr/bin/git-secrets"),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="", stderr=""),  # --list
                MagicMock(returncode=0, stdout="", stderr=""),  # --register-aws
                MagicMock(
                    returncode=1,
                    stdout="secrets.env:1:AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
                    stderr="",
                ),  # --scan
            ]
            scanner = GitSecretsScanner(auto_install=False, register_aws=True)
            result = scanner.scan([secret_file])
        assert len(result.findings) == 1
        assert result.findings[0].line_number == 1
        assert result.files_scanned == 1

    def test_scan_directory_path(self, tmp_path: Path) -> None:
        """Test scan accepts a directory as the scan target."""
        (tmp_path / ".git").mkdir()
        with (
            patch("shutil.which", return_value="/usr/bin/git-secrets"),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            scanner = GitSecretsScanner(auto_install=False, register_aws=False)
            result = scanner.scan([tmp_path])
        assert result.error is None
        assert result.files_scanned == 0  # directories are not individually counted

    def test_scan_include_git_history_calls_scan_history(self, tmp_path: Path) -> None:
        """Test scan uses --scan-history flag when include_git_history=True."""
        (tmp_path / ".git").mkdir()
        with (
            patch("shutil.which", return_value="/usr/bin/git-secrets"),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            scanner = GitSecretsScanner(auto_install=False, register_aws=False)
            scanner.scan([tmp_path], include_git_history=True)
        all_calls = [str(c) for c in mock_run.call_args_list]
        assert any("--scan-history" in c for c in all_calls)

    def test_scan_timeout_returns_error_result(self, tmp_path: Path) -> None:
        """Test scan returns ScanResult with error message when subprocess times out."""
        (tmp_path / ".git").mkdir()
        with (
            patch("shutil.which", return_value="/usr/bin/git-secrets"),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="", stderr=""),  # --list
                MagicMock(returncode=0, stdout="", stderr=""),  # --register-aws
                subprocess.TimeoutExpired(cmd=["git-secrets"], timeout=300),  # --scan
            ]
            scanner = GitSecretsScanner(auto_install=False)
            result = scanner.scan([tmp_path])
        assert result.error is not None
        assert "timed out" in result.error.lower()

    def test_scan_non_fatal_exception_continues_to_next_path(self, tmp_path: Path) -> None:
        """Test scan continues scanning subsequent paths after a non-fatal exception."""
        (tmp_path / ".git").mkdir()
        path1 = tmp_path / "file1.env"
        path1.write_text("x=1")
        path2 = tmp_path / "file2.env"
        path2.write_text("y=2")
        with (
            patch("shutil.which", return_value="/usr/bin/git-secrets"),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="", stderr=""),  # --list (path1)
                MagicMock(returncode=0, stdout="", stderr=""),  # --register-aws (path1)
                RuntimeError("unexpected"),  # --scan (path1) — skipped
                MagicMock(returncode=0, stdout="", stderr=""),  # --list (path2)
                MagicMock(returncode=0, stdout="", stderr=""),  # --register-aws (path2)
                MagicMock(returncode=0, stdout="", stderr=""),  # --scan (path2)
            ]
            scanner = GitSecretsScanner(auto_install=False)
            result = scanner.scan([path1, path2])
        assert result.error is None
        assert mock_run.call_count == 6  # confirms path2 was actually scanned
        assert result.files_scanned == 2  # both files counted; proves the loop continued past path1

    def test_scan_finds_parent_git_root(self, tmp_path: Path) -> None:
        """Test scan walks parent directories to locate the git root."""
        (tmp_path / ".git").mkdir()
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        secret_file = subdir / "secrets.env"
        secret_file.write_text("token=abc123")
        with (
            patch("shutil.which", return_value="/usr/bin/git-secrets"),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            scanner = GitSecretsScanner(auto_install=False, register_aws=False)
            result = scanner.scan([secret_file])
        assert result.error is None
        # The scan command must include the subdir-relative path (e.g. "subdir/secrets.env")
        scan_cmd = mock_run.call_args_list[-1][0][0]
        assert any("subdir" in str(arg) for arg in scan_cmd)

    def test_scan_no_git_repo_still_scans(self, tmp_path: Path) -> None:
        """Test scan proceeds with --scan even when no .git directory is found.

        tmp_path lives under /private/var/... (pytest's temp root), which is
        outside the project tree, so the parent-walk never finds a .git.
        """
        secret_file = tmp_path / "secrets.env"
        secret_file.write_text("password=topsecret")
        with (
            patch("shutil.which", return_value="/usr/bin/git-secrets"),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout="secrets.env:1:password=topsecret",
                stderr="",
            )
            scanner = GitSecretsScanner(auto_install=False)
            result = scanner.scan([secret_file])
        assert result.error is None
        assert len(result.findings) == 1

    def test_scan_aws_patterns_already_installed_skips_registration(self, tmp_path: Path) -> None:
        """Test scan does not call --register-aws when AWS patterns are already present."""
        (tmp_path / ".git").mkdir()
        with (
            patch("shutil.which", return_value="/usr/bin/git-secrets"),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.side_effect = [
                MagicMock(
                    returncode=0,
                    stdout="secrets.patterns=A3T[A-Z0-9]AKIA...",
                    stderr="",
                ),  # --list — AWS pattern already present
                MagicMock(returncode=0, stdout="", stderr=""),  # --scan
            ]
            scanner = GitSecretsScanner(auto_install=False, register_aws=True)
            result = scanner.scan([tmp_path])
        assert result.error is None
        assert mock_run.call_count == 2  # --list + --scan only

    def test_scan_register_aws_disabled_skips_registration(self, tmp_path: Path) -> None:
        """Test scan never calls --register-aws when register_aws=False."""
        (tmp_path / ".git").mkdir()
        with (
            patch("shutil.which", return_value="/usr/bin/git-secrets"),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="", stderr=""),  # --list
                MagicMock(returncode=0, stdout="", stderr=""),  # --scan
            ]
            scanner = GitSecretsScanner(auto_install=False, register_aws=False)
            result = scanner.scan([tmp_path])
        assert result.error is None
        assert mock_run.call_count == 2  # --list + --scan, no --register-aws

    def test_scan_stderr_findings_are_deduped(self, tmp_path: Path) -> None:
        """Test scan does not duplicate findings that appear in both stdout and stderr."""
        (tmp_path / ".git").mkdir()
        finding_line = "test.env:5:AWS_SECRET_ACCESS_KEY=abc123defghijklmnop"
        with (
            patch("shutil.which", return_value="/usr/bin/git-secrets"),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="", stderr=""),  # --list
                MagicMock(returncode=0, stdout="", stderr=""),  # --register-aws
                MagicMock(
                    returncode=1, stdout=finding_line, stderr=finding_line
                ),  # --scan (same finding in both streams)
            ]
            scanner = GitSecretsScanner(auto_install=False, register_aws=True)
            result = scanner.scan([tmp_path])
        assert len(result.findings) == 1


# ---------------------------------------------------------------------------
# _parse_output branch coverage (line 570, 631->635)
# ---------------------------------------------------------------------------


class TestGitSecretsParseOutputBranches:
    """Extra _parse_output branch tests."""

    def test_parse_output_skips_error_bracket_lines(self) -> None:
        """Test _parse_output skips lines starting with [ERROR]."""
        scanner = GitSecretsScanner(auto_install=False)
        output = "[ERROR] something went wrong\ntest.env:1:secret=value\n"
        findings = scanner._parse_output(output, Path("/repo"))
        assert len(findings) == 1  # only the valid line survives

    def test_parse_output_skips_error_colon_lines(self) -> None:
        """Test _parse_output skips lines starting with 'error:'."""
        scanner = GitSecretsScanner(auto_install=False)
        output = "error: fatal git problem\ntest.env:2:api_key=xyz\n"
        findings = scanner._parse_output(output, Path("/repo"))
        assert len(findings) == 1

    def test_parse_output_absolute_file_path_used_directly(self) -> None:
        """Test _create_finding uses an absolute path as-is without prepending base_path."""
        scanner = GitSecretsScanner(auto_install=False)
        output = "/absolute/path/secrets.env:3:token=abcdef\n"
        findings = scanner._parse_output(output, Path("/repo"))
        assert len(findings) == 1
        assert findings[0].file_path == Path("/absolute/path/secrets.env")

    def test_parse_output_unmatched_line_produces_no_finding(self) -> None:
        """Test _parse_output produces no finding for lines that match no pattern."""
        scanner = GitSecretsScanner(auto_install=False)
        output = "this is a plain log message with no colon-number pattern\n"
        findings = scanner._parse_output(output, Path("/repo"))
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# _detect_rule_type aws-secret-key (line 702)
# ---------------------------------------------------------------------------


class TestDetectRuleTypeAWSSecretKey:
    """Tests for the aws-secret-key detection branch."""

    def test_detect_rule_type_aws_secret_content(self) -> None:
        """Test _detect_rule_type returns aws-secret-key for aws_secret content."""
        scanner = GitSecretsScanner(auto_install=False)
        assert scanner._detect_rule_type("aws_secret=XXXX") == "aws-secret-key"

    def test_detect_rule_type_secret_access_key_content(self) -> None:
        """Test _detect_rule_type returns aws-secret-key for secret_access_key content."""
        scanner = GitSecretsScanner(auto_install=False)
        assert scanner._detect_rule_type("secret_access_key=abcdefgh") == "aws-secret-key"


# ---------------------------------------------------------------------------
# install_hooks (lines 747-755)
# ---------------------------------------------------------------------------


class TestInstallHooks:
    """Tests for GitSecretsScanner.install_hooks."""

    def test_install_hooks_no_git_dir_returns_false(self, tmp_path: Path) -> None:
        """Test install_hooks returns False when repo has no .git directory."""
        scanner = GitSecretsScanner(auto_install=False)
        assert scanner.install_hooks(tmp_path) is False

    def test_install_hooks_success_returns_true(self, tmp_path: Path) -> None:
        """Test install_hooks returns True when --install succeeds."""
        (tmp_path / ".git").mkdir()
        with (
            patch("shutil.which", return_value="/usr/bin/git-secrets"),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=0)
            scanner = GitSecretsScanner(auto_install=False)
            assert scanner.install_hooks(tmp_path) is True

    def test_install_hooks_nonzero_returncode_returns_false(self, tmp_path: Path) -> None:
        """Test install_hooks returns False when --install command fails."""
        (tmp_path / ".git").mkdir()
        with (
            patch("shutil.which", return_value="/usr/bin/git-secrets"),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=1)
            scanner = GitSecretsScanner(auto_install=False)
            assert scanner.install_hooks(tmp_path) is False

    def test_install_hooks_exception_returns_false(self, tmp_path: Path) -> None:
        """Test install_hooks returns False when an exception is raised."""
        (tmp_path / ".git").mkdir()
        with (
            patch("shutil.which", return_value="/usr/bin/git-secrets"),
            patch("subprocess.run", side_effect=RuntimeError("oops")),
        ):
            scanner = GitSecretsScanner(auto_install=False)
            assert scanner.install_hooks(tmp_path) is False


# ---------------------------------------------------------------------------
# add_pattern (lines 768-778)
# ---------------------------------------------------------------------------


class TestAddPattern:
    """Tests for GitSecretsScanner.add_pattern."""

    def test_add_prohibited_pattern_success(self, tmp_path: Path) -> None:
        """Test add_pattern adds a prohibited pattern without --allowed flag."""
        with (
            patch("shutil.which", return_value="/usr/bin/git-secrets"),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=0)
            scanner = GitSecretsScanner(auto_install=False)
            assert scanner.add_pattern("my-secret-regex", tmp_path, allowed=False) is True
            call_args = mock_run.call_args[0][0]
            assert "--add" in call_args
            assert "my-secret-regex" in call_args
            assert "--allowed" not in call_args

    def test_add_allowed_pattern_includes_allowed_flag(self, tmp_path: Path) -> None:
        """Test add_pattern includes --allowed flag for false-positive patterns."""
        with (
            patch("shutil.which", return_value="/usr/bin/git-secrets"),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=0)
            scanner = GitSecretsScanner(auto_install=False)
            assert scanner.add_pattern("safe-regex", tmp_path, allowed=True) is True
            call_args = mock_run.call_args[0][0]
            assert "--allowed" in call_args

    def test_add_pattern_nonzero_returncode_returns_false(self) -> None:
        """Test add_pattern returns False when the command exits non-zero."""
        with (
            patch("shutil.which", return_value="/usr/bin/git-secrets"),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=1)
            scanner = GitSecretsScanner(auto_install=False)
            assert scanner.add_pattern("pattern", Path()) is False

    def test_add_pattern_exception_returns_false(self) -> None:
        """Test add_pattern returns False when an exception is raised."""
        with (
            patch("shutil.which", return_value="/usr/bin/git-secrets"),
            patch("subprocess.run", side_effect=RuntimeError("boom")),
        ):
            scanner = GitSecretsScanner(auto_install=False)
            assert scanner.add_pattern("pattern", Path()) is False


# ---------------------------------------------------------------------------
# list_patterns (lines 789-819)
# ---------------------------------------------------------------------------


class TestListPatterns:
    """Tests for GitSecretsScanner.list_patterns."""

    def test_list_patterns_returns_all_three_categories(self, tmp_path: Path) -> None:
        """Test list_patterns correctly parses patterns, allowed, and providers."""
        list_output = (
            "secrets.patterns=AKIA[0-9A-Z]{16}\n"
            "secrets.allowed=test_.*\n"
            "secrets.providers=git secrets --aws-provider\n"
        )
        with (
            patch("shutil.which", return_value="/usr/bin/git-secrets"),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=0, stdout=list_output, stderr="")
            scanner = GitSecretsScanner(auto_install=False)
            result = scanner.list_patterns(tmp_path)
        assert "AKIA[0-9A-Z]{16}" in result["patterns"]
        assert "test_.*" in result["allowed"]
        assert "git secrets --aws-provider" in result["providers"]

    def test_list_patterns_empty_output_returns_empty_lists(self) -> None:
        """Test list_patterns returns empty lists when command output is blank."""
        with (
            patch("shutil.which", return_value="/usr/bin/git-secrets"),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            scanner = GitSecretsScanner(auto_install=False)
            result = scanner.list_patterns(Path())
        assert result == {"patterns": [], "allowed": [], "providers": []}

    def test_list_patterns_nonzero_returncode_returns_empty(self) -> None:
        """Test list_patterns returns empty lists when command exits non-zero."""
        with (
            patch("shutil.which", return_value="/usr/bin/git-secrets"),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error")
            scanner = GitSecretsScanner(auto_install=False)
            result = scanner.list_patterns(Path())
        assert result == {"patterns": [], "allowed": [], "providers": []}

    def test_list_patterns_exception_returns_empty(self) -> None:
        """Test list_patterns returns empty lists when an exception is raised."""
        with (
            patch("shutil.which", return_value="/usr/bin/git-secrets"),
            patch("subprocess.run", side_effect=RuntimeError("fail")),
        ):
            scanner = GitSecretsScanner(auto_install=False)
            result = scanner.list_patterns(Path())
        assert result == {"patterns": [], "allowed": [], "providers": []}

    def test_list_patterns_lines_without_value_are_skipped(self) -> None:
        """Test list_patterns skips lines that have no '=' (len(parts) <= 1)."""
        # Each git-config key with no value — split("=", 1) yields a single-element list
        list_output = "secrets.patterns\nsecrets.allowed\nsecrets.providers\n"
        with (
            patch("shutil.which", return_value="/usr/bin/git-secrets"),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=0, stdout=list_output, stderr="")
            scanner = GitSecretsScanner(auto_install=False)
            result = scanner.list_patterns(Path())
        assert result == {"patterns": [], "allowed": [], "providers": []}


# ---------------------------------------------------------------------------
# Remaining scan() branches
# ---------------------------------------------------------------------------


class TestGitSecretsScanExtra:
    """Extra scan() branch tests for near-complete coverage."""

    def test_scan_directory_with_parent_git_root(self, tmp_path: Path) -> None:
        """Test scan handles a directory whose .git is in a parent directory."""
        (tmp_path / ".git").mkdir()
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        with (
            patch("shutil.which", return_value="/usr/bin/git-secrets"),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            scanner = GitSecretsScanner(auto_install=False, register_aws=False)
            # Scanning a sub-directory — not a file, so path.is_file() is False
            result = scanner.scan([subdir])
        assert result.error is None
        assert mock_run.call_count == 2  # --list + --scan (git root in parent)

    def test_scan_unique_stderr_finding_is_appended(self, tmp_path: Path) -> None:
        """Test scan appends a stderr finding that is not already in all_findings."""
        (tmp_path / ".git").mkdir()
        with (
            patch("shutil.which", return_value="/usr/bin/git-secrets"),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="", stderr=""),  # --list
                MagicMock(returncode=0, stdout="", stderr=""),  # --register-aws
                # returncode=0 → stdout not parsed; stderr has a new finding
                MagicMock(
                    returncode=0,
                    stdout="",
                    stderr="test.env:7:password=topsecret",
                ),
            ]
            scanner = GitSecretsScanner(auto_install=False, register_aws=True)
            result = scanner.scan([tmp_path])
        assert len(result.findings) == 1

    def test_scan_register_aws_exception_is_silently_ignored(self, tmp_path: Path) -> None:
        """Test scan continues normally when --register-aws raises an exception."""
        (tmp_path / ".git").mkdir()
        with (
            patch("shutil.which", return_value="/usr/bin/git-secrets"),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="", stderr=""),  # --list (no AWS)
                RuntimeError("register-aws exploded"),  # --register-aws fails
                MagicMock(returncode=0, stdout="", stderr=""),  # --scan proceeds
            ]
            scanner = GitSecretsScanner(auto_install=False, register_aws=True)
            result = scanner.scan([tmp_path])
        assert result.error is None
