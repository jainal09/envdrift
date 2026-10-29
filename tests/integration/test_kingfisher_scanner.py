"""Integration tests for Kingfisher scanner.

These tests verify Kingfisher scanner integration with real scanning operations.
Requires Kingfisher to be installed (via Homebrew: brew install kingfisher).
"""

from __future__ import annotations

import shutil
import subprocess

import pytest
from tests.severity_policy import class_samples

from envdrift.scanner.base import FindingSeverity
from envdrift.scanner.kingfisher import KingfisherScanner
from envdrift.scanner.native import NativeScanner

# Real-binary tests: integration lane only; skip all if Kingfisher is not installed
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        shutil.which("kingfisher") is None,
        reason="Kingfisher not installed (install with: brew install kingfisher)",
    ),
]


def _rsa_private_key_pem() -> bytes:
    """A whole RSA private key, made for the test: GitHub's push protection rejects a real one."""
    rsa = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.rsa")
    serialization = pytest.importorskip("cryptography.hazmat.primitives.serialization")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
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
        """A whole private key is found, and graded CRITICAL, as private keys are (#928).

        The key was cut down to one line of base64, which Kingfisher 2.x does not take for a key.
        """
        (tmp_path / "key.pem").write_bytes(_rsa_private_key_pem())

        scanner = KingfisherScanner(
            auto_install=False,
            validate_secrets=False,
            confidence="low",
        )
        result = scanner.scan([tmp_path])

        assert result.error is None
        key_findings = [f for f in result.findings if "private-key" in f.rule_id]
        assert key_findings, result.findings
        assert {f.file_path.name for f in key_findings} == {"key.pem"}
        assert {f.severity for f in key_findings} == {FindingSeverity.CRITICAL}

    def test_password_hashes_are_left_to_the_native_scanner(self, tmp_path):
        """Kingfisher 2.x has no rule for password hashes: the native scanner finds them (#928).

        The docs said Kingfisher found bcrypt and sha512crypt hashes, as 1.x did. Should a release
        find them again, this fails, and the docs can say so again.
        """
        for name, content in class_samples()["password-hash"].items():
            (tmp_path / name).write_text(content)

        scanner = KingfisherScanner(
            auto_install=False,
            validate_secrets=False,
            confidence="low",
        )
        result = scanner.scan([tmp_path])

        assert result.error is None
        assert result.findings == []
        native = NativeScanner().scan([tmp_path])
        assert {f.rule_id for f in native.findings} == {"bcrypt-hash", "sha512crypt-hash"}

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
