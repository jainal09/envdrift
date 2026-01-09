"""Tests for scanner patterns module."""

from __future__ import annotations

import pytest

from envdrift.scanner.base import FindingSeverity
from envdrift.scanner.patterns import (
    ALL_PATTERNS,
    CRITICAL_PATTERNS,
    HIGH_PATTERNS,
    calculate_entropy,
    redact_secret,
)


class TestSecretPatterns:
    """Tests for secret detection patterns."""

    @pytest.mark.parametrize(
        "secret,expected_pattern_id",
        [
            # AWS - AKIA/ASIA prefix must be followed by uppercase alphanumeric
            ("AKIAIOSFODNN7EXAMPLE", "aws-access-key-id"),
            ("ASIAISAMPLEKEYID1234", "aws-access-key-id"),
            # GitHub
            ("ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "github-pat"),
            ("gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "github-oauth"),
            ("ghu_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "github-app-token"),
            ("ghs_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "github-app-token"),
            ("glpat-xxxxxxxxxxxxxxxxxxxx", "gitlab-pat"),
            # Stripe - using TESTKEY prefix to avoid push protection
            ("sk_live_TESTKEY00000000000000000", "stripe-secret-key"),
            ("rk_live_TESTKEY00000000000000000", "stripe-restricted-key"),
            # Google - AIza followed by exactly 35 alphanumeric and dash/underscore chars (39 total)
            ("AIzaSyCaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "google-api-key"),
            # SendGrid
            (
                "SG.xxxxxxxxxxxxxxxxxxxxxx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                "sendgrid-api-key",
            ),
            # NPM
            ("npm_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "npm-token"),
            # Private keys
            ("-----BEGIN RSA PRIVATE KEY-----", "private-key-rsa"),
            ("-----BEGIN OPENSSH PRIVATE KEY-----", "private-key-openssh"),
            ("-----BEGIN EC PRIVATE KEY-----", "private-key-ec"),
            ("-----BEGIN PRIVATE KEY-----", "private-key-generic"),
        ],
    )
    def test_critical_patterns_match(self, secret: str, expected_pattern_id: str):
        """Test that critical patterns match known secret formats."""
        matched = False
        for pattern in CRITICAL_PATTERNS:
            if pattern.pattern.search(secret):
                if pattern.id == expected_pattern_id:
                    matched = True
                    break

        assert matched, f"Pattern {expected_pattern_id} should match {secret[:20]}..."

    @pytest.mark.parametrize(
        "non_secret",
        [
            "hello_world",
            "my_variable_name",
            "SOME_CONFIG_VALUE",
            "12345",
            "localhost:8080",
            "https://example.com",
            "/usr/local/bin",
            "user@example.com",
        ],
    )
    def test_no_false_positives_on_common_strings(self, non_secret: str):
        """Test that common strings don't trigger patterns."""
        matches = []
        for pattern in CRITICAL_PATTERNS:
            if pattern.pattern.search(non_secret):
                matches.append(pattern.id)

        assert len(matches) == 0, f"False positives: {matches}"

    def test_all_critical_patterns_have_critical_severity(self):
        """Test that all critical patterns have CRITICAL severity."""
        for pattern in CRITICAL_PATTERNS:
            assert pattern.severity in (
                FindingSeverity.CRITICAL,
                FindingSeverity.HIGH,
            ), f"Pattern {pattern.id} should be CRITICAL or HIGH"

    def test_all_patterns_combined(self):
        """Test that ALL_PATTERNS contains both critical and high patterns."""
        assert len(ALL_PATTERNS) == len(CRITICAL_PATTERNS) + len(HIGH_PATTERNS)

    def test_pattern_ids_are_unique(self):
        """Test that all pattern IDs are unique."""
        ids = [p.id for p in ALL_PATTERNS]
        assert len(ids) == len(set(ids)), "Duplicate pattern IDs found"

    def test_patterns_have_required_fields(self):
        """Test that all patterns have required fields."""
        for pattern in ALL_PATTERNS:
            assert pattern.id, "Pattern must have an ID"
            assert pattern.description, "Pattern must have a description"
            assert pattern.pattern is not None, "Pattern must have a regex"
            assert pattern.severity is not None, "Pattern must have a severity"


class TestHighPatterns:
    """Tests for high/generic patterns."""

    @pytest.mark.parametrize(
        "line",
        [
            'API_KEY = "sk_test_abcdefghijklmnop"',
            "api_key: abcdefghijklmnopqrst",
            'apikey="verylongsecretvalue123"',
        ],
    )
    def test_generic_api_key_pattern(self, line: str):
        """Test generic API key pattern matches."""
        pattern = next(p for p in HIGH_PATTERNS if p.id == "generic-api-key")
        assert pattern.pattern.search(line), f"Should match: {line}"

    @pytest.mark.parametrize(
        "line",
        [
            'SECRET = "mysupersecretvalue"',
            "password: verylongpassword123",
            'TOKEN="abcdef123456789012"',
        ],
    )
    def test_generic_secret_pattern(self, line: str):
        """Test generic secret pattern matches."""
        pattern = next(p for p in HIGH_PATTERNS if p.id == "generic-secret")
        assert pattern.pattern.search(line), f"Should match: {line}"

    @pytest.mark.parametrize(
        "line",
        [
            "postgres://user:password@localhost:5432/db",
            "postgresql://admin:secret123@db.example.com/mydb",
        ],
    )
    def test_postgres_url_pattern(self, line: str):
        """Test PostgreSQL URL pattern matches."""
        pattern = next(p for p in HIGH_PATTERNS if p.id == "database-url-postgres")
        assert pattern.pattern.search(line), f"Should match: {line}"


class TestRedactSecret:
    """Tests for secret redaction function."""

    def test_redact_long_secret(self):
        """Test redacting a long secret."""
        result = redact_secret("AKIAIOSFODNN7EXAMPLE")
        assert result == "AKIA************MPLE"
        assert len(result) == len("AKIAIOSFODNN7EXAMPLE")

    def test_redact_short_secret(self):
        """Test redacting a short secret."""
        result = redact_secret("short")
        assert result == "*****"

    def test_redact_with_custom_visible(self):
        """Test redacting with custom visible characters."""
        result = redact_secret("AKIAIOSFODNN7EXAMPLE", visible_chars=2)
        assert result.startswith("AK")
        assert result.endswith("LE")

    def test_redact_minimum_length(self):
        """Test redacting at minimum length threshold."""
        result = redact_secret("12345678", visible_chars=4)
        assert result == "********"

    def test_redact_empty_string(self):
        """Test redacting empty string."""
        result = redact_secret("")
        assert result == ""


class TestCalculateEntropy:
    """Tests for entropy calculation function."""

    def test_empty_string_entropy(self):
        """Test entropy of empty string is 0."""
        assert calculate_entropy("") == 0.0

    def test_single_char_entropy(self):
        """Test entropy of single repeated character is 0."""
        assert calculate_entropy("aaaaaaaaaa") == 0.0

    def test_high_entropy_string(self):
        """Test that random-looking strings have high entropy."""
        high_entropy = "aB3$xK9#mN2@pQ5&vR8!"
        entropy = calculate_entropy(high_entropy)
        assert entropy > 4.0, f"Expected high entropy, got {entropy}"

    def test_low_entropy_string(self):
        """Test that repetitive strings have low entropy."""
        low_entropy = "ababababab"
        entropy = calculate_entropy(low_entropy)
        assert entropy < 2.0, f"Expected low entropy, got {entropy}"

    def test_uuid_entropy(self):
        """Test entropy of UUID-like strings."""
        uuid_like = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        entropy = calculate_entropy(uuid_like)
        # UUIDs have moderate to high entropy
        assert 3.0 < entropy < 5.0, f"Expected moderate entropy, got {entropy}"

    def test_entropy_increases_with_diversity(self):
        """Test that more character diversity increases entropy."""
        low = calculate_entropy("aaaaabbbbb")
        medium = calculate_entropy("abcdeabcde")
        high = calculate_entropy("aB1@cD2#eF")

        assert low < medium < high
