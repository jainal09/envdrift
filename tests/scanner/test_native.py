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
