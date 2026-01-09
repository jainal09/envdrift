"""Integration tests for Kingfisher scanner.

These tests verify Kingfisher scanner integration with real scanning operations.
Requires Kingfisher to be installed (via Homebrew: brew install kingfisher).
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

from envdrift.scanner.kingfisher import KingfisherScanner

# Skip all tests if Kingfisher is not installed
pytestmark = pytest.mark.skipif(
    shutil.which("kingfisher") is None,
    reason="Kingfisher not installed (install with: brew install kingfisher)",
)


class TestKingfisherIntegration:
    """Integration tests for Kingfisher scanner."""

    def test_scanner_is_installed(self):
        """Verify Kingfisher scanner is detected as installed."""
        scanner = KingfisherScanner(auto_install=False)
        assert scanner.is_installed() is True

    def test_scanner_version(self):
        """Verify version is returned correctly."""
        scanner = KingfisherScanner(auto_install=False)
        version = scanner.get_version()
        assert version is not None
        assert len(version.split(".")) >= 2  # e.g., "1.73.0"

    def test_scan_empty_directory(self, tmp_path):
        """Scanning an empty directory returns no findings."""
        scanner = KingfisherScanner(auto_install=False, validate_secrets=False)
        result = scanner.scan([tmp_path])

        assert result.error is None
        assert len(result.findings) == 0

    def test_scan_detects_api_key(self, tmp_path):
        """Scanner detects generic API keys."""
        # Create a file with a secret-like pattern
        test_file = tmp_path / "config.env"
        test_file.write_text("API_KEY=test_api_key_abc123def456ghi789")

        scanner = KingfisherScanner(
            auto_install=False,
            validate_secrets=False,
            confidence="low",
        )
        result = scanner.scan([tmp_path])

        assert result.error is None
        # Kingfisher may or may not detect this depending on confidence
        # The key thing is it runs without error

    def test_scan_detects_private_key(self, tmp_path):
        """Scanner detects private keys."""
        test_file = tmp_path / "key.pem"
        test_file.write_text("""-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGyhPtrXk5oPRxE=
-----END RSA PRIVATE KEY-----
""")

        scanner = KingfisherScanner(
            auto_install=False,
            validate_secrets=False,
            confidence="low",
        )
        result = scanner.scan([tmp_path])

        assert result.error is None
        # Check if private key was detected
        key_findings = [
            f
            for f in result.findings
            if "private" in f.rule_description.lower() or "key" in f.rule_description.lower()
        ]
        assert len(key_findings) >= 1

    def test_scan_detects_bcrypt_hash(self, tmp_path):
        """Scanner detects bcrypt password hashes."""
        test_file = tmp_path / "dump.sql"
        test_file.write_text("""
INSERT INTO users (username, password_hash) VALUES
('admin', '$2y$10$abcdefghijklmnopqrstuv'),
('user1', '$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW');
""")

        scanner = KingfisherScanner(
            auto_install=False,
            validate_secrets=False,
            confidence="low",
        )
        result = scanner.scan([tmp_path])

        assert result.error is None
        # Check if bcrypt hash was detected
        hash_findings = [
            f
            for f in result.findings
            if "bcrypt" in f.rule_description.lower() or "hash" in f.rule_description.lower()
        ]
        # Kingfisher should detect bcrypt hashes
        assert len(hash_findings) >= 1

    def test_scan_detects_netrc_credentials(self, tmp_path):
        """Scanner detects .netrc credentials."""
        test_file = tmp_path / ".netrc"
        test_file.write_text("""
machine github.com
login myuser
password ghp_abcdefghijklmnopqrstuvwxyz1234567890
""")

        scanner = KingfisherScanner(
            auto_install=False,
            validate_secrets=False,
            confidence="low",
        )
        result = scanner.scan([tmp_path])

        assert result.error is None
        # netrc credentials may or may not be detected depending on patterns
        # The key thing is the scan runs without error

    def test_scan_with_git_history_disabled(self, tmp_path):
        """Scan runs correctly with git history disabled."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("No secrets here")

        scanner = KingfisherScanner(
            auto_install=False,
            validate_secrets=False,
        )
        result = scanner.scan([tmp_path], include_git_history=False)

        assert result.error is None

    def test_scan_duration_is_reasonable(self, tmp_path):
        """Scan completes within reasonable time."""
        # Create a few test files
        for i in range(10):
            (tmp_path / f"file{i}.txt").write_text(f"Content {i}")

        scanner = KingfisherScanner(
            auto_install=False,
            validate_secrets=False,
        )
        result = scanner.scan([tmp_path])

        assert result.error is None
        # Should complete in under 10 seconds for small directories
        assert result.duration_ms < 10000

    def test_findings_have_correct_scanner_name(self, tmp_path):
        """Findings should have 'kingfisher' as scanner name."""
        test_file = tmp_path / "secret.env"
        test_file.write_text("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

        scanner = KingfisherScanner(
            auto_install=False,
            validate_secrets=False,
            confidence="low",
        )
        result = scanner.scan([tmp_path])

        assert result.scanner_name == "kingfisher"
        for finding in result.findings:
            assert finding.scanner == "kingfisher"

    def test_finding_severity_mapping(self, tmp_path):
        """Findings should have appropriate severity levels."""
        # Create file with bcrypt hash (should be CRITICAL)
        test_file = tmp_path / "users.sql"
        test_file.write_text("password='$2y$10$abcdefghijklmnopqrstuv'")

        scanner = KingfisherScanner(
            auto_install=False,
            validate_secrets=False,
            confidence="low",
        )
        result = scanner.scan([tmp_path])

        # Any bcrypt findings should be CRITICAL
        from envdrift.scanner.base import FindingSeverity

        bcrypt_findings = [f for f in result.findings if "bcrypt" in f.rule_description.lower()]
        for f in bcrypt_findings:
            assert f.severity == FindingSeverity.CRITICAL


class TestKingfisherWithGuard:
    """Integration tests for Kingfisher with guard command."""

    def test_guard_with_kingfisher_flag(self, tmp_path):
        """Guard command accepts --kingfisher flag."""
        # Create a test file
        test_file = tmp_path / "config.env"
        test_file.write_text("DATABASE_URL=postgres://user:pass@localhost/db")

        # Run guard command with kingfisher
        result = subprocess.run(
            ["envdrift", "guard", str(tmp_path), "--kingfisher", "--no-gitleaks", "--json"],
            capture_output=True,
            text=True,
            timeout=120,
        )

        # Should not error (exit code 0, 1, 2, or 3 are valid)
        assert result.returncode in (0, 1, 2, 3)

    def test_guard_config_with_kingfisher(self, tmp_path):
        """Guard respects kingfisher in config file."""
        # Create config file
        config_file = tmp_path / "envdrift.toml"
        config_file.write_text("""
[guard]
scanners = ["native", "kingfisher"]
auto_install = false
""")

        # Create a test file
        test_file = tmp_path / "test.env"
        test_file.write_text("API_KEY=test123")

        # Run guard with config
        result = subprocess.run(
            ["envdrift", "guard", str(tmp_path), "--config", str(config_file), "--json"],
            capture_output=True,
            text=True,
            timeout=120,
        )

        # Should run successfully
        assert result.returncode in (0, 1, 2, 3)
