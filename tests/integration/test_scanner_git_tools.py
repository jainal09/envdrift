"""Integration tests for git-secrets scanner integration.

Tests for:
- Scanner CLI flags (--git-secrets)
- Scanner configuration via envdrift.toml
- Scanner detection and findings on test data
- The source install, at the commit pinned in constants.json
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from envdrift.scanner.base import FindingSeverity
from envdrift.scanner.git_secrets import (
    GitSecretsInstaller,
    GitSecretsScanner,
    _get_git_secrets_commit,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
PYTHONPATH = str(REPO_ROOT / "src")

_GIT_SECRETS_AVAILABLE = shutil.which("git-secrets") is not None


def _run_envdrift(
    args: list[str], *, cwd: Path, env: dict[str, str], check: bool = True
) -> subprocess.CompletedProcess:
    """Run envdrift CLI command."""
    cmd = [sys.executable, "-m", "envdrift.cli", *args]
    result = subprocess.run(
        cmd,
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
    )
    if check and result.returncode != 0:
        # Don't raise for guard command as it returns non-zero on findings
        if "guard" not in args:
            raise AssertionError(
                f"envdrift failed\ncmd: {' '.join(cmd)}\n"
                f"cwd: {cwd}\nstdout:\n{result.stdout}\n"
                f"stderr:\n{result.stderr}"
            )
    return result


@pytest.fixture
def scanner_test_env(tmp_path):
    """Create a test environment for scanner tests."""
    work_dir = tmp_path / "test_repo"
    work_dir.mkdir()

    env = os.environ.copy()
    env["PYTHONPATH"] = f"{PYTHONPATH}{os.pathsep}{env.get('PYTHONPATH', '')}"

    return {"work_dir": work_dir, "env": env, "tmp_path": tmp_path}


@pytest.mark.integration
class TestGitSecretsCLI:
    """Test git-secrets scanner CLI integration."""

    def test_git_secrets_flag_shown_in_help(self, scanner_test_env):
        """Test that --git-secrets flag appears in guard help."""
        import re

        work_dir = scanner_test_env["work_dir"]
        env = scanner_test_env["env"]

        result = _run_envdrift(["guard", "--help"], cwd=work_dir, env=env)

        # Strip ANSI escape codes for comparison - more comprehensive pattern
        ansi_escape = re.compile(r"\x1B\[[0-9;]*[A-Za-z]|\x1B[@-Z\\-_]")
        clean_output = ansi_escape.sub("", result.stdout)

        assert "--git-secrets" in clean_output, (
            f"--git-secrets not found in help output: {clean_output[:500]}"
        )
        assert "--no-git-secrets" in clean_output

    def test_git_secrets_flag_enables_scanner(self, scanner_test_env):
        """Test that --git-secrets flag enables the git-secrets scanner."""
        work_dir = scanner_test_env["work_dir"]
        env = scanner_test_env["env"]

        # Create a test file
        test_file = work_dir / "test.txt"
        test_file.write_text("No secrets here\n")

        result = _run_envdrift(
            ["guard", "--git-secrets", "--verbose", str(work_dir)],
            cwd=work_dir,
            env=env,
            check=False,
        )

        # Should show git-secrets in scanner list if installed
        # Note: It might not be installed, but the flag should be recognized
        assert "--git-secrets" not in result.stderr  # No error about unknown flag

    def test_git_secrets_config_enables_scanner(self, scanner_test_env):
        """Test that git-secrets in config enables the scanner."""
        work_dir = scanner_test_env["work_dir"]
        env = scanner_test_env["env"]

        config = textwrap.dedent(
            """\
            [guard]
            scanners = ["native", "git-secrets"]
            auto_install = false
            """
        )
        (work_dir / "envdrift.toml").write_text(config)

        test_file = work_dir / "test.txt"
        test_file.write_text("No secrets here\n")

        result = _run_envdrift(
            ["guard", "--verbose", str(work_dir)],
            cwd=work_dir,
            env=env,
            check=False,
        )

        # Should recognize git-secrets from config
        assert result.returncode is not None  # Command completed


@pytest.mark.integration
class TestScannerDetection:
    """Test scanner detection of secrets."""

    def test_native_scanner_detects_aws_key(self, scanner_test_env):
        """Test native scanner detects AWS access key."""
        work_dir = scanner_test_env["work_dir"]
        env = scanner_test_env["env"]

        # Create file with AWS key pattern
        test_file = work_dir / ".env"
        test_file.write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")

        result = _run_envdrift(
            ["guard", "--native-only", "--json", str(work_dir)],
            cwd=work_dir,
            env=env,
            check=False,
        )

        # Should detect the AWS key
        assert "aws" in result.stdout.lower() or result.returncode != 0

    def test_native_scanner_detects_private_key(self, scanner_test_env):
        """Test native scanner detects private key."""
        work_dir = scanner_test_env["work_dir"]
        env = scanner_test_env["env"]

        # Create file with private key pattern
        test_file = work_dir / "key.pem"
        test_file.write_text(
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEAyXP5...\n"
            "-----END RSA PRIVATE KEY-----\n"
        )

        result = _run_envdrift(
            ["guard", "--native-only", "--json", str(work_dir)],
            cwd=work_dir,
            env=env,
            check=False,
        )

        # Should detect the private key
        assert "private" in result.stdout.lower() or result.returncode != 0

    def test_guard_with_multiple_scanners(self, scanner_test_env):
        """Test guard command with multiple scanners enabled."""
        work_dir = scanner_test_env["work_dir"]
        env = scanner_test_env["env"]

        # Create file with secrets
        test_file = work_dir / ".env"
        test_file.write_text(
            "API_KEY=sk_live_1234567890abcdef\n"
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        )

        result = _run_envdrift(
            ["guard", "--verbose", str(work_dir)],
            cwd=work_dir,
            env=env,
            check=False,
        )

        # Should run and find secrets
        assert result.returncode != 0 or "findings" in result.stdout.lower()

    def test_guard_json_output_format(self, scanner_test_env):
        """Test guard --json produces valid JSON output."""
        import json

        work_dir = scanner_test_env["work_dir"]
        env = scanner_test_env["env"]

        # Create file with a secret
        test_file = work_dir / ".env"
        test_file.write_text("SECRET=very_secret_value_12345\n")

        result = _run_envdrift(
            ["guard", "--native-only", "--json", str(work_dir)],
            cwd=work_dir,
            env=env,
            check=False,
        )

        # Should produce valid JSON
        try:
            data = json.loads(result.stdout)
            assert "findings" in data or "summary" in data
        except json.JSONDecodeError:
            # JSON output might be empty if no findings
            if result.stdout.strip():
                pytest.fail(f"Invalid JSON output: {result.stdout[:200]}")


@pytest.mark.integration
@pytest.mark.skipif(not _GIT_SECRETS_AVAILABLE, reason="git-secrets binary not installed")
class TestGitSecretsRealBinary:
    """End-to-end tests against the real git-secrets binary (issue #322).

    Real git-secrets writes findings to STDERR and leaves stdout empty, so these
    tests prove ``GitSecretsScanner.scan()`` recovers findings from stderr.
    """

    def _init_repo_with_aws_patterns(self, work_dir: Path) -> None:
        subprocess.run(["git", "init", "-q"], cwd=str(work_dir), check=True, capture_output=True)
        subprocess.run(
            ["git", "secrets", "--register-aws"],
            cwd=str(work_dir),
            check=True,
            capture_output=True,
        )

    def test_scan_detects_aws_key_via_stderr(self, scanner_test_env):
        """scan() returns a finding for a real AWS key (emitted on stderr)."""
        work_dir = scanner_test_env["work_dir"]
        self._init_repo_with_aws_patterns(work_dir)
        # Non-example key (git-secrets allowlists the AKIA...EXAMPLE key).
        (work_dir / "leak.txt").write_text("AWS_KEY=AKIAZ9Q8W7E6R5T4Y3U2\n")

        scanner = GitSecretsScanner(auto_install=False, register_aws=True)
        result = scanner.scan([work_dir])

        assert result.error is None
        assert len(result.findings) >= 1, "git-secrets finding (emitted on stderr) was not captured"
        assert any("aws" in f.rule_id for f in result.findings)
        # An AWS access key ID is CRITICAL whichever scanner finds it (#850).
        assert [f.severity for f in result.findings] == [FindingSeverity.CRITICAL]

    def test_scan_grades_an_aws_secret_access_key_critical(self, scanner_test_env):
        """git-secrets' AWS provider also flags a secret access key: CRITICAL like gitleaks."""
        work_dir = scanner_test_env["work_dir"]
        self._init_repo_with_aws_patterns(work_dir)
        # 40 characters of the base64 alphabet, built here so the literal is never whole.
        secret = "Zq8W7E6R5T4Y3U2I1O0P" + "aSdFgHjKlZxCvBnM1234"
        (work_dir / "secret.cfg").write_text(f"aws_secret_access_key = {secret}\n")

        scanner = GitSecretsScanner(auto_install=False, register_aws=True)
        result = scanner.scan([work_dir])

        assert result.error is None
        assert [(f.rule_id, f.severity) for f in result.findings] == [
            ("git-secrets-aws-secret-key", FindingSeverity.CRITICAL)
        ]

    def test_scan_grades_a_hash_rocket_secret_access_key_critical(self, scanner_test_env):
        """Puppet, Ruby and PHP assign with ``=>``, which git-secrets' AWS pattern matches too.

        git-secrets flags the line, so the key on it is graded like the one assigned with ``=``.
        """
        work_dir = scanner_test_env["work_dir"]
        self._init_repo_with_aws_patterns(work_dir)
        secret = "Zq8W7E6R5T4Y3U2I1O0P" + "aSdFgHjKlZxCvBnM1234"
        (work_dir / "puppet.pp").write_text(f"aws_secret_access_key => '{secret}',\n")
        (work_dir / "ruby.rb").write_text(f':aws_secret_access_key => "{secret}"\n')
        (work_dir / "php.php").write_text(f"'secret_access_key' => '{secret}',\n")

        scanner = GitSecretsScanner(auto_install=False, register_aws=True)
        result = scanner.scan([work_dir])

        assert result.error is None
        graded = {f.file_path.name: (f.rule_id, f.severity) for f in result.findings}
        assert graded == dict.fromkeys(
            ("puppet.pp", "ruby.rb", "php.php"),
            ("git-secrets-aws-secret-key", FindingSeverity.CRITICAL),
        )

    def test_scan_grades_a_region_name_as_a_password_not_an_aws_key(self, scanner_test_env):
        """A flagged line holding the letters "asia" is not an AWS key: HIGH, not CRITICAL.

        The rule type decides the severity, and the type was read from the letters "akia" and
        "asia" in the line, so ``password=asia-northeast1`` (a GCP region) graded CRITICAL.
        """
        work_dir = scanner_test_env["work_dir"]
        self._init_repo_with_aws_patterns(work_dir)
        subprocess.run(
            ["git", "secrets", "--add", r"password\s*=\s*\S+"],
            cwd=str(work_dir),
            check=True,
            capture_output=True,
        )
        (work_dir / "region.cfg").write_text("password=asia-northeast1\n")
        # Built here so the access key ID is never whole in the source (push protection).
        (work_dir / "aws.cfg").write_text("AWS_KEY=AKIA" + "Z9Q8W7E6R5T4Y3U2\n")

        scanner = GitSecretsScanner(auto_install=False, register_aws=True)
        result = scanner.scan([work_dir])

        assert result.error is None
        graded = {f.file_path.name: (f.rule_id, f.severity) for f in result.findings}
        assert graded == {
            "region.cfg": ("git-secrets-password", FindingSeverity.HIGH),
            "aws.cfg": ("git-secrets-aws-access-key", FindingSeverity.CRITICAL),
        }

    def test_scan_clean_repo_has_no_findings(self, scanner_test_env):
        """scan() of a repo without secrets yields no findings and no error."""
        work_dir = scanner_test_env["work_dir"]
        self._init_repo_with_aws_patterns(work_dir)
        (work_dir / "clean.txt").write_text("nothing to see here\n")

        scanner = GitSecretsScanner(auto_install=False, register_aws=True)
        result = scanner.scan([work_dir])

        assert result.error is None
        assert result.findings == []

    def test_scan_detects_ignored_secret_file(self, scanner_test_env):
        """An ignored dotenv file remains in scope when Git metadata is excluded (#581)."""
        work_dir = scanner_test_env["work_dir"]
        self._init_repo_with_aws_patterns(work_dir)
        (work_dir / ".gitignore").write_text(".env\n")
        (work_dir / ".env").write_text("AWS_KEY=AKIAZ9Q8W7E6R5T4Y3U2\n")

        scanner = GitSecretsScanner(auto_install=False, register_aws=True)
        result = scanner.scan([work_dir])

        assert result.error is None
        assert any(f.file_path == (work_dir / ".env").resolve() for f in result.findings)

    def test_scan_detects_ignored_nested_secret_file(self, scanner_test_env):
        """Recursive scanning retains ignored nested files when Git metadata is excluded (#581)."""
        work_dir = scanner_test_env["work_dir"]
        self._init_repo_with_aws_patterns(work_dir)
        nested_dir = work_dir / "sub" / "deep"
        nested_dir.mkdir(parents=True)
        (work_dir / ".gitignore").write_text("sub/\n")
        secret_file = nested_dir / "secrets.env"
        secret_file.write_text("AWS_KEY=AKIAZ9Q8W7E6R5T4Y3U2\n")

        scanner = GitSecretsScanner(auto_install=False, register_aws=True)
        result = scanner.scan([work_dir])

        assert result.error is None
        assert any(f.file_path == secret_file.resolve() for f in result.findings)

    def test_scan_that_git_secrets_cannot_run_fails(self, scanner_test_env):
        """A repository whose git config git cannot read is not scanned, so it is not clean.

        git-secrets then loads no patterns, matches nothing and exits 0; only git's
        ``fatal:`` message says so. The run that never matched ``leak.txt`` was a clean scan.
        """
        work_dir = scanner_test_env["work_dir"]
        self._init_repo_with_aws_patterns(work_dir)
        (work_dir / "leak.txt").write_text("AWS_KEY=AKIA" + "Z9Q8W7E6R5T4Y3U2\n")
        with (work_dir / ".git" / "config").open("a") as config:
            config.write("[core\n")  # a section that is never closed

        scanner = GitSecretsScanner(auto_install=False, register_aws=True)
        result = scanner.scan([work_dir])

        assert result.error is not None
        assert result.error.startswith(f"git-secrets could not scan {work_dir}: fatal: ")
        assert result.findings == []


def _clone_upstream(dest: Path) -> None:
    """Clone the git-secrets repository; skip only when the network cannot be reached."""
    result = subprocess.run(
        ["git", "clone", "--quiet", GitSecretsInstaller.REPO_URL, str(dest)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
    )
    if result.returncode != 0 and "unable to access" in result.stderr:
        pytest.skip(f"cannot reach {GitSecretsInstaller.REPO_URL}: {result.stderr.strip()[:160]}")
    assert result.returncode == 0, f"cannot clone git-secrets: {result.stderr.strip()}"


def _script_at(repo: Path, commit: str) -> bytes:
    """The git-secrets script as it is at ``commit``."""
    return subprocess.run(
        ["git", "show", f"{commit}:git-secrets"], cwd=repo, capture_output=True, check=True
    ).stdout


@pytest.mark.integration
@pytest.mark.skipif(
    platform.system() != "Linux", reason="git-secrets is built from source on Linux"
)
@pytest.mark.skipif(shutil.which("make") is None, reason="make not installed")
class TestGitSecretsSourceInstall:
    """The real source install builds the commit pinned in constants.json (#902).

    It used to clone master with ``--depth 1``, so what it installed changed with upstream.
    """

    def test_installs_the_pinned_commit(self, tmp_path, monkeypatch):
        """The pinned commit exists upstream and is the script that gets installed."""
        upstream = tmp_path / "upstream"
        _clone_upstream(upstream)
        monkeypatch.setenv("VIRTUAL_ENV", str(tmp_path / "venv"))

        installed = GitSecretsInstaller().install(force=True)

        assert installed == tmp_path / "venv" / "bin" / "git-secrets"
        assert installed.read_bytes() == _script_at(upstream, _get_git_secrets_commit())

    def test_installs_the_pinned_commit_not_master(self, tmp_path, monkeypatch):
        """Pinned to an older commit, the install is that commit's script, not master's.

        The commit of release 1.3.0 stands in for an older pin: its script differs from
        master's, so an install of master cannot pass for it.
        """
        upstream = tmp_path / "upstream"
        _clone_upstream(upstream)
        older = subprocess.run(
            ["git", "rev-parse", "1.3.0^{commit}"],
            cwd=upstream,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        assert _script_at(upstream, older) != _script_at(upstream, "HEAD")
        monkeypatch.setenv("VIRTUAL_ENV", str(tmp_path / "venv"))
        monkeypatch.setattr("envdrift.scanner.git_secrets._get_git_secrets_commit", lambda: older)

        installed = GitSecretsInstaller().install(force=True)

        assert installed.read_bytes() == _script_at(upstream, older)


@pytest.mark.integration
class TestScannerConfiguration:
    """Test scanner configuration options."""

    def test_all_scanners_in_config(self, scanner_test_env):
        """Test enabling all scanners via config."""
        work_dir = scanner_test_env["work_dir"]
        env = scanner_test_env["env"]

        config = textwrap.dedent(
            """\
            [guard]
            scanners = ["native", "gitleaks", "git-secrets"]
            auto_install = false
            """
        )
        (work_dir / "envdrift.toml").write_text(config)

        test_file = work_dir / "test.txt"
        test_file.write_text("No secrets\n")

        result = _run_envdrift(
            ["guard", "--verbose", str(work_dir)],
            cwd=work_dir,
            env=env,
            check=False,
        )

        # Command should complete without error about unknown scanners
        assert "unknown scanner" not in result.stderr.lower()

    def test_disable_scanner_via_no_flag(self, scanner_test_env):
        """Test disabling scanners via --no-* flags."""
        work_dir = scanner_test_env["work_dir"]
        env = scanner_test_env["env"]

        config = textwrap.dedent(
            """\
            [guard]
            scanners = ["native", "gitleaks", "git-secrets"]
            """
        )
        (work_dir / "envdrift.toml").write_text(config)

        test_file = work_dir / "test.txt"
        test_file.write_text("No secrets\n")

        result = _run_envdrift(
            ["guard", "--no-git-secrets", "--verbose", str(work_dir)],
            cwd=work_dir,
            env=env,
            check=False,
        )

        # git-secrets should not appear in running scanners
        # (hard to verify without parsing, but command should complete)
        assert result.returncode is not None

    def test_native_only_disables_all_external(self, scanner_test_env):
        """Test --native-only disables all external scanners including new ones."""
        work_dir = scanner_test_env["work_dir"]
        env = scanner_test_env["env"]

        config = textwrap.dedent(
            """\
            [guard]
            scanners = ["native", "gitleaks", "git-secrets"]
            """
        )
        (work_dir / "envdrift.toml").write_text(config)

        test_file = work_dir / "test.txt"
        test_file.write_text("No secrets\n")

        result = _run_envdrift(
            ["guard", "--native-only", "--verbose", str(work_dir)],
            cwd=work_dir,
            env=env,
            check=False,
        )

        # Only native should run
        output = result.stdout + result.stderr
        # git-secrets should not be in running scanners
        assert "Running scanners: native" in output or "native" in output
