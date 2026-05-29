"""Tests for native scanner module."""

from __future__ import annotations

from pathlib import Path

import pytest

from envdrift.scanner.base import FindingSeverity
from envdrift.scanner.native import NativeScanner


class TestNativeScanner:
    """Tests for NativeScanner class."""

    @pytest.fixture
    def scanner(self) -> NativeScanner:
        """Create a native scanner instance."""
        return NativeScanner()

    @pytest.fixture
    def scanner_with_entropy(self) -> NativeScanner:
        """Create a scanner with entropy checking enabled."""
        return NativeScanner(check_entropy=True, entropy_threshold=4.0)

    def test_scanner_properties(self, scanner: NativeScanner):
        """Test scanner name and description."""
        assert scanner.name == "native"
        assert "Built-in" in scanner.description
        assert scanner.is_installed() is True

    def test_scan_empty_directory(self, scanner: NativeScanner, tmp_path: Path):
        """Test scanning an empty directory."""
        result = scanner.scan([tmp_path])

        assert result.scanner_name == "native"
        assert result.findings == []
        assert result.files_scanned == 0
        assert result.error is None

    def test_scan_nonexistent_path(self, scanner: NativeScanner):
        """Test scanning a nonexistent path."""
        result = scanner.scan([Path("/nonexistent/path/12345")])

        assert result.findings == []
        assert result.files_scanned == 0


class TestNativeScannerInternals:
    """Tests for internal native scanner behaviors."""

    def test_collect_files_handles_permission_error(self, tmp_path: Path, monkeypatch):
        """Permission errors during rglob return empty results."""
        scanner = NativeScanner()

        def raise_permission(self, _pattern: str):
            raise PermissionError("nope")

        monkeypatch.setattr(Path, "rglob", raise_permission)
        assert scanner._collect_files(tmp_path) == []

    def test_collect_files_sorts_git_results(self, tmp_path: Path, monkeypatch):
        """Git-based collection returns deterministically sorted results."""
        import subprocess

        scanner = NativeScanner()

        (tmp_path / "a.txt").touch()
        (tmp_path / "b.txt").touch()
        (tmp_path / ".env.a").touch()
        (tmp_path / ".env.z").touch()

        def mock_run(cmd, **kwargs):
            if cmd[:2] == ["git", "ls-files"] and "--others" not in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout="b.txt\na.txt\n", stderr="")
            if cmd[:2] == ["git", "ls-files"] and "--others" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=".env.z\n.env.a\n", stderr="")
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", mock_run)

        files = scanner._collect_files(tmp_path)
        expected = sorted(
            {tmp_path / "a.txt", tmp_path / "b.txt", tmp_path / ".env.a", tmp_path / ".env.z"},
            key=lambda p: str(p),
        )

        assert files == expected

    def test_collect_files_includes_gitignored_env_secret(self, tmp_path: Path):
        """A gitignored, untracked, plaintext .env secret must still be collected.

        Partial-encryption secret files are typically gitignored and left as
        plaintext on disk after `pull-partial`. They must never slip through the
        secret scan just because git is told to ignore them.
        """
        import shutil
        import subprocess

        if shutil.which("git") is None:
            pytest.skip("git not available")

        def git(*args: str) -> None:
            subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)

        git("init")
        git("config", "user.email", "test@example.com")
        git("config", "user.name", "Test")

        # .env.production.secret is gitignored and never committed; on disk it is
        # plaintext (as it would be right after `envdrift pull-partial`).
        (tmp_path / ".gitignore").write_text(".env.production.secret\n")
        (tmp_path / ".env.production.secret").write_text("API_KEY=plaintext-leak\n")
        (tmp_path / "tracked.txt").write_text("hello\n")
        git("add", ".gitignore", "tracked.txt")
        git("commit", "-m", "init")

        scanner = NativeScanner()
        collected = scanner._collect_files(tmp_path)

        assert (tmp_path / ".env.production.secret").resolve() in {p.resolve() for p in collected}

    def test_collect_files_excludes_gitignored_env_keys(self, tmp_path: Path):
        """A gitignored .env.keys must NOT be collected — that is its correct state.

        .env.keys is dotenvx's private-key file: always plaintext, meant to stay
        local-only. Now that `push` gitignores it, scanning it would wrongly flag a
        properly-configured project. A gitignored secret file is still collected.
        """
        import shutil
        import subprocess

        if shutil.which("git") is None:
            pytest.skip("git not available")

        def git(*args: str) -> None:
            subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)

        git("init")
        git("config", "user.email", "test@example.com")
        git("config", "user.name", "Test")

        (tmp_path / ".gitignore").write_text(".env.keys\n.env.production.secret\n")
        (tmp_path / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=abc123\n")
        (tmp_path / ".env.production.secret").write_text("API_KEY=plaintext-leak\n")
        (tmp_path / "tracked.txt").write_text("hello\n")
        git("add", ".gitignore", "tracked.txt")
        git("commit", "-m", "init")

        scanner = NativeScanner()
        collected = {p.resolve() for p in scanner._collect_files(tmp_path)}

        # Gitignored private-key file is excluded...
        assert (tmp_path / ".env.keys").resolve() not in collected
        # ...but a gitignored secret file is still scanned.
        assert (tmp_path / ".env.production.secret").resolve() in collected

    def test_collect_files_includes_tracked_env_keys(self, tmp_path: Path):
        """A *tracked* (committed) .env.keys IS still collected — it is a real leak."""
        import shutil
        import subprocess

        if shutil.which("git") is None:
            pytest.skip("git not available")

        def git(*args: str) -> None:
            subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)

        git("init")
        git("config", "user.email", "test@example.com")
        git("config", "user.name", "Test")

        # .env.keys committed to the repo — a private key leak that must be scanned.
        (tmp_path / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=abc123\n")
        git("add", ".env.keys")
        git("commit", "-m", "oops committed keys")

        scanner = NativeScanner()
        collected = {p.resolve() for p in scanner._collect_files(tmp_path)}

        assert (tmp_path / ".env.keys").resolve() in collected

    def test_collect_files_includes_staged_env_keys(self, tmp_path: Path):
        """A staged (git add'd, not yet committed) .env.keys IS collected — still a leak.

        The ignored-pass exclusion must not hide a key that is on its way into a
        commit. `git ls-files` reports the index, so a staged .env.keys — even one
        force-added past .gitignore — is picked up via Method 1.
        """
        import shutil
        import subprocess

        if shutil.which("git") is None:
            pytest.skip("git not available")

        def git(*args: str) -> None:
            subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)

        git("init")
        git("config", "user.email", "test@example.com")
        git("config", "user.name", "Test")

        # .env.keys is gitignored but force-staged — about to be committed.
        (tmp_path / ".gitignore").write_text(".env.keys\n")
        (tmp_path / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=abc123\n")
        git("add", "-f", ".env.keys")

        scanner = NativeScanner()
        collected = {p.resolve() for p in scanner._collect_files(tmp_path)}

        assert (tmp_path / ".env.keys").resolve() in collected

    def test_collect_files_fallback_sorts_results(self, tmp_path: Path):
        """Fallback file collection returns deterministically ordered results."""
        scanner = NativeScanner()

        (tmp_path / "z").mkdir()
        (tmp_path / "a").mkdir()
        (tmp_path / "z" / "b.txt").write_text("x")
        (tmp_path / "a" / "c.txt").write_text("x")

        files = scanner._collect_files_fallback(tmp_path)
        expected = sorted(files, key=lambda p: str(p))

        assert files == expected

    def test_should_ignore_handles_outside_base(self):
        """Relative path failures fall back to full path matching."""
        scanner = NativeScanner(ignore_patterns=["secret.txt"])
        assert scanner._should_ignore(Path("/outside/secret.txt"), Path("/base")) is True

    def test_should_ignore_matches_path_parts(self, tmp_path: Path):
        """Ignore patterns match individual path parts."""
        scanner = NativeScanner(ignore_patterns=["secrets"])
        file_path = tmp_path / "nested" / "secrets" / "file.txt"
        assert scanner._should_ignore(file_path, tmp_path) is True

    def test_scan_file_handles_read_errors(self, tmp_path: Path, monkeypatch):
        """Read failures return no findings."""
        scanner = NativeScanner()
        file_path = tmp_path / "config.py"
        file_path.write_text("SECRET=VALUE")
        original_read_text = Path.read_text

        def raise_error(self, *args, **kwargs):
            if self == file_path:
                raise OSError("boom")
            return original_read_text(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", raise_error)
        assert scanner._scan_file(file_path) == []

    def test_scan_file_skips_empty_content(self, tmp_path: Path):
        """Empty files return no findings."""
        scanner = NativeScanner()
        file_path = tmp_path / "empty.txt"
        file_path.write_text("")
        assert scanner._scan_file(file_path) == []


class TestUnencryptedEnvDetection:
    """Tests for unencrypted .env file detection."""

    @pytest.fixture
    def scanner(self) -> NativeScanner:
        """Create a native scanner instance."""
        return NativeScanner()

    def test_detects_unencrypted_env_file(self, scanner: NativeScanner, tmp_path: Path):
        """Test detection of unencrypted .env file."""
        env_file = tmp_path / ".env"
        env_file.write_text("DATABASE_URL=postgres://localhost/db\n")

        result = scanner.scan([tmp_path])

        assert len(result.findings) >= 1
        unencrypted_findings = [f for f in result.findings if f.rule_id == "unencrypted-env-file"]
        assert len(unencrypted_findings) == 1
        assert unencrypted_findings[0].severity == FindingSeverity.HIGH

    def test_detects_unencrypted_env_production(self, scanner: NativeScanner, tmp_path: Path):
        """Test detection of unencrypted .env.production file."""
        env_file = tmp_path / ".env.production"
        env_file.write_text("SECRET_KEY=mysecret\n")

        result = scanner.scan([tmp_path])

        unencrypted_findings = [f for f in result.findings if f.rule_id == "unencrypted-env-file"]
        assert len(unencrypted_findings) == 1

    def test_ignores_encrypted_dotenvx_file(self, scanner: NativeScanner, tmp_path: Path):
        """Test that encrypted dotenvx files are not flagged."""
        env_file = tmp_path / ".env"
        env_file.write_text(
            """#/---[DOTENV_PUBLIC_KEY]---/
DOTENV_PUBLIC_KEY="abc123"
DATABASE_URL="encrypted:xyz789"
"""
        )

        result = scanner.scan([tmp_path])

        unencrypted_findings = [f for f in result.findings if f.rule_id == "unencrypted-env-file"]
        assert len(unencrypted_findings) == 0

    def test_ignores_encrypted_sops_file(self, scanner: NativeScanner, tmp_path: Path):
        """Test that encrypted SOPS files are not flagged."""
        env_file = tmp_path / ".env"
        env_file.write_text(
            """DATABASE_URL=ENC[AES256_GCM,data:xyz789]
sops:
    version: 3.7.0
"""
        )

        result = scanner.scan([tmp_path])

        unencrypted_findings = [f for f in result.findings if f.rule_id == "unencrypted-env-file"]
        assert len(unencrypted_findings) == 0

    def test_ignores_env_example(self, scanner: NativeScanner, tmp_path: Path):
        """Test that .env.example files are ignored."""
        env_example = tmp_path / ".env.example"
        env_example.write_text("DATABASE_URL=\n")

        result = scanner.scan([tmp_path])

        assert len(result.findings) == 0


class TestUnencryptedSecretFile:
    """Tests for the dedicated plaintext .secret rule (Severity 2 hard block).

    A partial-encryption ``.secret`` file is sensitive by definition. A plaintext
    one is flagged with a dedicated CRITICAL ``unencrypted-secret-file`` rule (not
    the generic HIGH ``unencrypted-env-file``) so ``guard --staged`` blocks the
    commit and the remediation points at ``envdrift push``.
    """

    @pytest.fixture
    def scanner(self) -> NativeScanner:
        """Create a native scanner instance."""
        return NativeScanner()

    def test_plaintext_secret_file_flagged_critical(self, scanner: NativeScanner, tmp_path: Path):
        """A plaintext .secret is flagged unencrypted-secret-file (CRITICAL)."""
        secret = tmp_path / ".env.production.secret"
        secret.write_text("API_KEY=plaintext-leak\nDB_PASSWORD=hunter2\n")

        result = scanner.scan([tmp_path])

        secret_findings = [f for f in result.findings if f.rule_id == "unencrypted-secret-file"]
        assert len(secret_findings) == 1
        assert secret_findings[0].severity == FindingSeverity.CRITICAL
        assert "push" in secret_findings[0].description.lower()
        # Must NOT also be flagged with the generic env-file rule.
        assert not [f for f in result.findings if f.rule_id == "unencrypted-env-file"]

    def test_encrypted_secret_file_not_flagged(self, scanner: NativeScanner, tmp_path: Path):
        """An already-encrypted .secret produces no unencrypted finding."""
        secret = tmp_path / ".env.production.secret"
        secret.write_text(
            '#/---[DOTENV_PUBLIC_KEY]---/\nDOTENV_PUBLIC_KEY="abc"\n'
            'API_KEY="encrypted:vault1AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"\n'
        )

        result = scanner.scan([tmp_path])

        assert not [
            f
            for f in result.findings
            if f.rule_id in ("unencrypted-secret-file", "unencrypted-env-file")
        ]

    def test_regular_env_file_still_flagged_high(self, scanner: NativeScanner, tmp_path: Path):
        """A plaintext non-secret .env file keeps the HIGH unencrypted-env-file rule."""
        env = tmp_path / ".env.production"
        env.write_text("SECRET_KEY=mysecret\n")

        result = scanner.scan([tmp_path])

        env_findings = [f for f in result.findings if f.rule_id == "unencrypted-env-file"]
        assert len(env_findings) == 1
        assert env_findings[0].severity == FindingSeverity.HIGH
        assert not [f for f in result.findings if f.rule_id == "unencrypted-secret-file"]


class TestMixedContentScanning:
    """Tests for partial-encryption combined files (Severity 4).

    Combined files interleave dotenvx-encrypted secret lines with cleartext
    config lines. A whole-file skip (triggered by a single ``encrypted:`` marker)
    used to leave the cleartext portion unscanned, hiding plaintext secrets that
    were pasted into the clear half. Pattern scanning now runs per-line.
    """

    @pytest.fixture
    def scanner(self) -> NativeScanner:
        """Create a native scanner instance."""
        return NativeScanner()

    def test_scans_cleartext_secret_in_combined_file(self, scanner: NativeScanner, tmp_path: Path):
        """A plaintext secret in the cleartext half of a combined file is flagged."""
        env_file = tmp_path / ".env.production"
        env_file.write_text(
            """#/---[DOTENV_PUBLIC_KEY]---/
DOTENV_PUBLIC_KEY="abc123"
# clear (non-sensitive) config
LOG_LEVEL=info
AWS_KEY="AKIAIOSFODNN7EXAMPLE"
# secrets (encrypted)
DATABASE_URL="encrypted:xyz789"
"""
        )

        result = scanner.scan([tmp_path])

        aws_findings = [f for f in result.findings if "aws" in f.rule_id.lower()]
        assert len(aws_findings) >= 1, (
            "plaintext secret in the cleartext half of a combined file must be scanned"
        )

    def test_combined_file_ignores_encrypted_and_public_key(
        self, scanner: NativeScanner, tmp_path: Path
    ):
        """Encrypted values and the dotenvx public key produce no pattern findings."""
        env_file = tmp_path / ".env.production"
        env_file.write_text(
            """#/---[DOTENV_PUBLIC_KEY]---/
DOTENV_PUBLIC_KEY_PRODUCTION="0339d2eef5d3a3a4f8c1d2b3a4958e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4"
LOG_LEVEL=info
DATABASE_URL="encrypted:vault1AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
API_KEY="encrypted:vault2ZyXwVuTsRqPoNmLkJiHgFeDcBa9876543210"
"""
        )

        result = scanner.scan([tmp_path])

        assert result.findings == [], (
            f"encrypted values / public key should not be flagged, got: "
            f"{[f.rule_id for f in result.findings]}"
        )


class TestPrivateKeyFileScanResult:
    """Tests for the dedicated .env.keys (committed-private-key) rule.

    Collection of .env.keys is covered in TestNativeScannerInternals; these tests
    cover the *finding* produced. A tracked/staged key file is flagged
    committed-private-key (CRITICAL) with accurate remediation — never the awkward
    unencrypted-env-file rule, whose "encrypt it" advice is wrong for a key file.
    A local/untracked key file is left alone.
    """

    @pytest.fixture
    def scanner(self) -> NativeScanner:
        """Create a native scanner instance."""
        return NativeScanner()

    @staticmethod
    def _git_repo(tmp_path: Path):
        """Initialise a git repo in tmp_path, returning a git() runner."""
        import shutil
        import subprocess

        if shutil.which("git") is None:
            pytest.skip("git not available")

        def git(*args: str) -> None:
            subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)

        git("init")
        git("config", "user.email", "test@example.com")
        git("config", "user.name", "Test")
        return git

    _KEY_CONTENT = (
        'DOTENV_PRIVATE_KEY_PRODUCTION="a1b2c3d4e5f6a7b8c9d0e1f2'
        'a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"\n'
    )

    def test_local_untracked_key_file_is_not_flagged(self, scanner: NativeScanner, tmp_path: Path):
        """A local, untracked .env.keys (the expected state) produces no findings."""
        self._git_repo(tmp_path)
        (tmp_path / ".env.keys").write_text(self._KEY_CONTENT)

        result = scanner.scan([tmp_path])

        assert result.findings == [], (
            f"local key file should not be flagged, got: {[f.rule_id for f in result.findings]}"
        )

    def test_gitignored_key_file_is_not_flagged(self, scanner: NativeScanner, tmp_path: Path):
        """A gitignored .env.keys (normal safe state) produces no findings."""
        self._git_repo(tmp_path)
        (tmp_path / ".gitignore").write_text(".env.keys\n")
        (tmp_path / ".env.keys").write_text(self._KEY_CONTENT)

        result = scanner.scan([tmp_path])

        assert result.findings == []

    def test_staged_key_file_flagged_as_committed_private_key(
        self, scanner: NativeScanner, tmp_path: Path
    ):
        """A staged .env.keys is flagged as committed-private-key (CRITICAL)."""
        git = self._git_repo(tmp_path)
        (tmp_path / ".env.keys").write_text(self._KEY_CONTENT)
        git("add", "-f", ".env.keys")

        result = scanner.scan([tmp_path])

        key_findings = [f for f in result.findings if f.rule_id == "committed-private-key"]
        assert len(key_findings) == 1
        assert key_findings[0].severity == FindingSeverity.CRITICAL
        # Remediation must NOT tell the user to encrypt the key file.
        assert "encrypt" not in key_findings[0].description.lower().replace("do not encrypt", "")
        assert "rotate" in key_findings[0].description.lower()
        # The key file must not also be flagged with the wrong rule.
        assert not [f for f in result.findings if f.rule_id == "unencrypted-env-file"]

    def test_committed_key_file_flagged_as_committed_private_key(
        self, scanner: NativeScanner, tmp_path: Path
    ):
        """A committed .env.keys is flagged as committed-private-key (CRITICAL)."""
        git = self._git_repo(tmp_path)
        (tmp_path / ".env.keys").write_text(self._KEY_CONTENT)
        git("add", "-f", ".env.keys")
        git("commit", "-m", "oops")

        result = scanner.scan([tmp_path])

        key_findings = [f for f in result.findings if f.rule_id == "committed-private-key"]
        assert len(key_findings) == 1
        assert key_findings[0].severity == FindingSeverity.CRITICAL


class TestSecretPatternDetection:
    """Tests for secret pattern detection."""

    @pytest.fixture
    def scanner(self) -> NativeScanner:
        """Create a native scanner instance."""
        return NativeScanner()

    def test_detects_aws_access_key(self, scanner: NativeScanner, tmp_path: Path):
        """Test detection of AWS access key."""
        config_file = tmp_path / "config.py"
        config_file.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')

        result = scanner.scan([tmp_path])

        aws_findings = [f for f in result.findings if "aws" in f.rule_id.lower()]
        assert len(aws_findings) >= 1
        assert aws_findings[0].severity == FindingSeverity.CRITICAL

    def test_detects_github_token(self, scanner: NativeScanner, tmp_path: Path):
        """Test detection of GitHub personal access token."""
        config_file = tmp_path / "config.py"
        config_file.write_text('GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"\n')

        result = scanner.scan([tmp_path])

        github_findings = [f for f in result.findings if "github" in f.rule_id.lower()]
        assert len(github_findings) >= 1

    def test_detects_private_key(self, scanner: NativeScanner, tmp_path: Path):
        """Test detection of private key."""
        key_file = tmp_path / "key.pem"
        key_file.write_text(
            """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----
"""
        )

        result = scanner.scan([tmp_path])

        key_findings = [f for f in result.findings if "private-key" in f.rule_id]
        assert len(key_findings) >= 1
        assert key_findings[0].severity == FindingSeverity.CRITICAL

    def test_detects_stripe_key(self, scanner: NativeScanner, tmp_path: Path):
        """Test detection of Stripe secret key."""
        config_file = tmp_path / "config.py"
        config_file.write_text('STRIPE_KEY = "sk_live_TESTKEY00000000000000000"\n')

        result = scanner.scan([tmp_path])

        stripe_findings = [f for f in result.findings if "stripe" in f.rule_id.lower()]
        assert len(stripe_findings) >= 1

    def test_skips_comments(self, scanner: NativeScanner, tmp_path: Path):
        """Test that commented lines are skipped."""
        config_file = tmp_path / "config.py"
        config_file.write_text('# AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')

        result = scanner.scan([tmp_path])

        aws_findings = [f for f in result.findings if "aws" in f.rule_id.lower()]
        assert len(aws_findings) == 0

    def test_finding_has_line_number(self, scanner: NativeScanner, tmp_path: Path):
        """Test that findings include line numbers."""
        config_file = tmp_path / "config.py"
        config_file.write_text(
            """# Configuration
import os

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
"""
        )

        result = scanner.scan([tmp_path])

        aws_findings = [f for f in result.findings if "aws" in f.rule_id.lower()]
        assert len(aws_findings) >= 1
        assert aws_findings[0].line_number == 4

    def test_finding_has_redacted_preview(self, scanner: NativeScanner, tmp_path: Path):
        """Test that findings have redacted secret preview."""
        config_file = tmp_path / "config.py"
        config_file.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')

        result = scanner.scan([tmp_path])

        aws_findings = [f for f in result.findings if "aws" in f.rule_id.lower()]
        assert len(aws_findings) >= 1
        preview = aws_findings[0].secret_preview
        assert "AKIA" in preview
        assert "*" in preview


class TestEntropyDetection:
    """Tests for entropy-based secret detection."""

    @pytest.fixture
    def scanner(self) -> NativeScanner:
        """Create a scanner with entropy checking enabled."""
        return NativeScanner(check_entropy=True, entropy_threshold=4.0)

    def test_detects_high_entropy_string(self, scanner: NativeScanner, tmp_path: Path):
        """Test detection of high-entropy strings."""
        config_file = tmp_path / "config.py"
        # High entropy random string
        config_file.write_text('SECRET = "aB3xK9mN2pQ5vR8tY1wZ4cF7hJ0kL6"\n')

        result = scanner.scan([tmp_path])

        entropy_findings = [f for f in result.findings if f.rule_id == "high-entropy-string"]
        assert len(entropy_findings) >= 1
        assert entropy_findings[0].severity == FindingSeverity.MEDIUM
        assert entropy_findings[0].entropy is not None
        assert entropy_findings[0].entropy >= 4.0

    def test_ignores_low_entropy_string(self, scanner: NativeScanner, tmp_path: Path):
        """Test that low-entropy strings are not flagged."""
        config_file = tmp_path / "config.py"
        config_file.write_text('VALUE = "aaaaaaaaaaaaaaaa"\n')

        result = scanner.scan([tmp_path])

        entropy_findings = [f for f in result.findings if f.rule_id == "high-entropy-string"]
        assert len(entropy_findings) == 0

    def test_ignores_urls(self, scanner: NativeScanner, tmp_path: Path):
        """Test that URLs are not flagged as high entropy."""
        config_file = tmp_path / "config.py"
        config_file.write_text('URL = "https://example.com/path/to/resource"\n')

        result = scanner.scan([tmp_path])

        entropy_findings = [f for f in result.findings if f.rule_id == "high-entropy-string"]
        assert len(entropy_findings) == 0

    def test_skips_comments_and_paths(self, scanner: NativeScanner, tmp_path: Path):
        """Comment lines and path-like values are skipped."""
        content = (
            "# SECRET = ABCDEFGHIJKLMNOP\n"
            "PATH = /var/tmp/abcdefghijklmnop\n"
            "REL = ./abcdefghijklmnop\n"
        )
        findings = scanner._scan_entropy(tmp_path / "config.py", content)
        assert findings == []

    def test_skips_alpha_only_values(self, scanner: NativeScanner, tmp_path: Path):
        """Alpha-only uppercase or lowercase values are skipped."""
        content = "LOWER = abcdefghijklmnop\nUPPER = ABCDEFGHIJKLMNOP\n"
        findings = scanner._scan_entropy(tmp_path / "config.py", content)
        assert findings == []

    def test_disabled_by_default(self, tmp_path: Path):
        """Test that entropy detection is disabled by default."""
        scanner = NativeScanner()  # Default: check_entropy=False
        config_file = tmp_path / "config.py"
        config_file.write_text('SECRET = "aB3xK9mN2pQ5vR8tY1wZ4cF7hJ0kL6"\n')

        result = scanner.scan([tmp_path])

        entropy_findings = [f for f in result.findings if f.rule_id == "high-entropy-string"]
        assert len(entropy_findings) == 0


class TestIgnorePatterns:
    """Tests for file ignore patterns."""

    def test_ignores_node_modules(self, tmp_path: Path):
        """Test that node_modules is ignored."""
        scanner = NativeScanner()
        node_modules = tmp_path / "node_modules" / "package"
        node_modules.mkdir(parents=True)
        secret_file = node_modules / "config.js"
        secret_file.write_text('const KEY = "AKIAIOSFODNN7EXAMPLE";\n')

        result = scanner.scan([tmp_path])

        assert result.files_scanned == 0

    def test_ignores_git_directory(self, tmp_path: Path):
        """Test that .git directory is ignored."""
        scanner = NativeScanner()
        git_dir = tmp_path / ".git" / "config"
        git_dir.parent.mkdir(parents=True)
        git_dir.write_text('token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"\n')

        result = scanner.scan([tmp_path])

        github_findings = [f for f in result.findings if "github" in f.rule_id.lower()]
        assert len(github_findings) == 0

    def test_ignores_venv(self, tmp_path: Path):
        """Test that virtual environment directories are ignored."""
        scanner = NativeScanner()
        venv_dir = tmp_path / ".venv" / "lib"
        venv_dir.mkdir(parents=True)
        secret_file = venv_dir / "config.py"
        secret_file.write_text('KEY = "AKIAIOSFODNN7EXAMPLE"\n')

        result = scanner.scan([tmp_path])

        assert result.files_scanned == 0

    def test_custom_ignore_patterns(self, tmp_path: Path):
        """Test custom ignore patterns."""
        scanner = NativeScanner(ignore_patterns=["*.test.py"])
        test_file = tmp_path / "config.test.py"
        test_file.write_text('KEY = "AKIAIOSFODNN7EXAMPLE"\n')

        result = scanner.scan([tmp_path])

        assert result.files_scanned == 0

    def test_additional_ignore_patterns(self, tmp_path: Path):
        """Test additional ignore patterns (added to defaults)."""
        scanner = NativeScanner(additional_ignore_patterns=["*.custom"])
        custom_file = tmp_path / "secrets.custom"
        custom_file.write_text('KEY = "AKIAIOSFODNN7EXAMPLE"\n')

        result = scanner.scan([tmp_path])

        assert result.files_scanned == 0


class TestScanSingleFile:
    """Tests for scanning individual files."""

    @pytest.fixture
    def scanner(self) -> NativeScanner:
        """Create a native scanner instance."""
        return NativeScanner()

    def test_scan_single_file(self, scanner: NativeScanner, tmp_path: Path):
        """Test scanning a single file directly."""
        config_file = tmp_path / "config.py"
        config_file.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')

        result = scanner.scan([config_file])

        assert result.files_scanned == 1
        assert len(result.findings) >= 1

    def test_scan_multiple_files(self, scanner: NativeScanner, tmp_path: Path):
        """Test scanning multiple specific files."""
        file1 = tmp_path / "config1.py"
        file1.write_text('KEY1 = "AKIAIOSFODNN7EXAMPLE"\n')
        file2 = tmp_path / "config2.py"
        file2.write_text('KEY2 = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"\n')

        result = scanner.scan([file1, file2])

        assert result.files_scanned == 2
        assert len(result.findings) >= 2

    def test_scan_binary_file_skipped(self, scanner: NativeScanner, tmp_path: Path):
        """Test that binary files are skipped."""
        binary_file = tmp_path / "binary.dat"
        binary_file.write_bytes(b"\x00\x01\x02\x03" + b"AKIAIOSFODNN7EXAMPLE")

        result = scanner.scan([binary_file])

        # Binary file should be scanned but no findings from pattern matching
        # because we skip files with null bytes
        assert len(result.findings) == 0


class TestSkipClearFiles:
    """Tests for skip_clear_files feature."""

    def test_clear_files_scanned_by_default(self, tmp_path: Path):
        """Test that .clear files ARE scanned by default."""
        scanner = NativeScanner()
        clear_file = tmp_path / ".env.production.clear"
        clear_file.write_text('AWS_KEY="AKIAIOSFODNN7EXAMPLE"\n')

        result = scanner.scan([tmp_path])

        assert result.files_scanned == 1
        aws_findings = [f for f in result.findings if "aws" in f.rule_id.lower()]
        assert len(aws_findings) >= 1
        # .clear files should not be flagged as unencrypted even if not in allowed list
        unencrypted_findings = [f for f in result.findings if f.rule_id == "unencrypted-env-file"]
        assert len(unencrypted_findings) == 0

    def test_clear_files_skipped_when_enabled(self, tmp_path: Path):
        """Test that .clear files produce no findings when skip_clear_files=True."""
        scanner = NativeScanner(skip_clear_files=True)
        clear_file = tmp_path / ".env.production.clear"
        clear_file.write_text('AWS_KEY="AKIAIOSFODNN7EXAMPLE"\n')

        result = scanner.scan([tmp_path])

        # File is processed but should produce no findings
        assert len(result.findings) == 0

    def test_skip_clear_does_not_affect_regular_env_files(self, tmp_path: Path):
        """Test that skip_clear_files doesn't affect regular .env files."""
        scanner = NativeScanner(skip_clear_files=True)
        env_file = tmp_path / ".env"
        env_file.write_text("DATABASE_URL=postgres://localhost/db\n")

        result = scanner.scan([tmp_path])

        # Regular .env file should still be scanned
        assert result.files_scanned == 1
        unencrypted_findings = [f for f in result.findings if f.rule_id == "unencrypted-env-file"]
        assert len(unencrypted_findings) == 1

    def test_skip_clear_with_multiple_clear_extensions(self, tmp_path: Path):
        """Test that various .clear file patterns produce no findings."""
        scanner = NativeScanner(skip_clear_files=True)

        # Create various .clear file patterns with secrets
        (tmp_path / ".env.clear").write_text('AWS_KEY="AKIAIOSFODNN7EXAMPLE"\n')
        (tmp_path / ".env.localenv.clear").write_text('AWS_KEY="AKIAIOSFODNN7EXAMPLE"\n')
        (tmp_path / ".env.production.clear").write_text('AWS_KEY="AKIAIOSFODNN7EXAMPLE"\n')
        (tmp_path / "config.clear").write_text('AWS_KEY="AKIAIOSFODNN7EXAMPLE"\n')

        result = scanner.scan([tmp_path])

        # All .clear files should produce no findings
        assert len(result.findings) == 0

    def test_skip_clear_false_scans_all_clear_files(self, tmp_path: Path):
        """Test that skip_clear_files=False scans all .clear files."""
        scanner = NativeScanner(skip_clear_files=False)

        # Create .clear files with secrets
        (tmp_path / ".env.production.clear").write_text('AWS_KEY="AKIAIOSFODNN7EXAMPLE"\n')

        result = scanner.scan([tmp_path])

        # .clear file should be scanned
        assert result.files_scanned == 1

    def test_is_clear_file_detection(self, tmp_path: Path):
        """Test the _is_clear_file method."""
        scanner = NativeScanner()

        # Should be detected as .clear files
        assert scanner._is_clear_file(Path(".env.clear")) is True
        assert scanner._is_clear_file(Path(".env.production.clear")) is True
        assert scanner._is_clear_file(Path("config.clear")) is True
        assert scanner._is_clear_file(Path("path/to/.env.localenv.clear")) is True

        # Should NOT be detected as .clear files
        assert scanner._is_clear_file(Path(".env")) is False
        assert scanner._is_clear_file(Path(".env.production")) is False
        assert scanner._is_clear_file(Path("config.py")) is False
        assert scanner._is_clear_file(Path(".env.secret")) is False

    def test_clear_files_not_flagged_as_unencrypted_when_in_allowed_list(self, tmp_path: Path):
        """Test that allowed .clear files are not flagged as unencrypted."""
        clear_file = tmp_path / ".env.production.clear"
        clear_file.write_text("DATABASE_URL=postgres://localhost/db\n")

        scanner = NativeScanner(allowed_clear_files=[str(clear_file)])

        result = scanner.scan([tmp_path])

        # Should be scanned but not flagged as unencrypted
        unencrypted_findings = [f for f in result.findings if f.rule_id == "unencrypted-env-file"]
        assert len(unencrypted_findings) == 0
