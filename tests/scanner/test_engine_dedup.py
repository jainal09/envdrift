"""Tests for scan engine deduplication.

Split out of ``test_engine.py`` to keep each test module focused and within a
reasonable size. Covers ``ScanEngine._deduplicate`` and its helpers across the
default and ``--skip-duplicate`` paths.
"""

from __future__ import annotations

from pathlib import Path

from envdrift.scanner.base import FindingSeverity, ScanFinding
from envdrift.scanner.engine import GuardConfig, ScanEngine


class TestDeduplication:
    """Tests for finding deduplication."""

    def test_deduplicate_identical_findings(self):
        """Test that identical findings are deduplicated."""
        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)

        findings = [
            ScanFinding(
                file_path=Path("config.py"),
                line_number=10,
                rule_id="aws-key",
                rule_description="AWS Key",
                description="AWS key",
                severity=FindingSeverity.CRITICAL,
                scanner="scanner1",
            ),
            ScanFinding(
                file_path=Path("config.py"),
                line_number=10,
                rule_id="aws-key",
                rule_description="AWS Key",
                description="AWS key",
                severity=FindingSeverity.CRITICAL,
                scanner="scanner2",
            ),
        ]

        unique = engine._deduplicate(findings)

        assert len(unique) == 1

    def test_deduplicate_keeps_higher_severity(self):
        """Test that deduplication keeps higher severity."""
        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)

        findings = [
            ScanFinding(
                file_path=Path("config.py"),
                line_number=10,
                rule_id="secret",
                rule_description="Secret",
                description="Secret",
                severity=FindingSeverity.MEDIUM,
                scanner="scanner1",
            ),
            ScanFinding(
                file_path=Path("config.py"),
                line_number=10,
                rule_id="secret",
                rule_description="Secret",
                description="Secret",
                severity=FindingSeverity.CRITICAL,
                scanner="scanner2",
            ),
        ]

        unique = engine._deduplicate(findings)

        assert len(unique) == 1
        assert unique[0].severity == FindingSeverity.CRITICAL

    def test_deduplicate_prefers_verified(self):
        """Test that deduplication prefers verified findings."""
        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)

        findings = [
            ScanFinding(
                file_path=Path("config.py"),
                line_number=10,
                rule_id="secret",
                rule_description="Secret",
                description="Secret",
                severity=FindingSeverity.HIGH,
                scanner="scanner1",
                verified=False,
            ),
            ScanFinding(
                file_path=Path("config.py"),
                line_number=10,
                rule_id="secret",
                rule_description="Secret",
                description="Secret",
                severity=FindingSeverity.HIGH,
                scanner="scanner2",
                verified=True,
            ),
        ]

        unique = engine._deduplicate(findings)

        assert len(unique) == 1
        assert unique[0].verified is True

    def test_deduplicate_prefers_secret_hash(self):
        """Test that deduplication prefers findings with secret_hash when tied."""
        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)

        findings = [
            ScanFinding(
                file_path=Path("config.py"),
                line_number=10,
                rule_id="secret",
                rule_description="Secret",
                description="Secret",
                severity=FindingSeverity.HIGH,
                scanner="scanner1",
                verified=False,
            ),
            ScanFinding(
                file_path=Path("config.py"),
                line_number=10,
                rule_id="secret",
                rule_description="Secret",
                description="Secret",
                severity=FindingSeverity.HIGH,
                scanner="scanner2",
                verified=False,
                secret_hash="hash-123",
            ),
        ]

        unique = engine._deduplicate(findings)

        assert len(unique) == 1
        assert unique[0].secret_hash == "hash-123"

    def test_deduplicate_distinct_secrets_same_line_both_kept(self):
        """Two distinct secrets on the same line, same rule, are both kept (#348).

        The default dedup key now includes the secret hash, so two genuinely
        different secrets matching the same rule on the same line do not collapse
        into a single finding. Without this, the ``finditer`` per-line fix in the
        native scanner would be silently undone by the engine for real
        ``envdrift guard`` / ``scan`` invocations.
        """
        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)

        findings = [
            ScanFinding(
                file_path=Path("config.py"),
                line_number=1,
                column_number=7,
                rule_id="aws-access-key-id",
                rule_description="AWS Key",
                description="AWS key",
                severity=FindingSeverity.HIGH,
                scanner="native",
                secret_hash="hash-aaa",
            ),
            ScanFinding(
                file_path=Path("config.py"),
                line_number=1,
                column_number=29,
                rule_id="aws-access-key-id",
                rule_description="AWS Key",
                description="AWS key",
                severity=FindingSeverity.HIGH,
                scanner="native",
                secret_hash="hash-bbb",
            ),
        ]

        unique = engine._deduplicate(findings)

        assert len(unique) == 2
        assert {f.secret_hash for f in unique} == {"hash-aaa", "hash-bbb"}

    def test_deduplicate_same_secret_two_scanners_not_collapsed_on_default_path(self):
        """The same secret from two scanners stays as two findings by default.

        Rule IDs are scanner-namespaced (native uses bare ids, gitleaks prefixes
        ``gitleaks-``), so even when two scanners report the *same* secret hash at
        the same location their default keys differ and both survive. Cross-scanner
        same-secret collapse only happens under ``skip_duplicate`` (hash-only key).
        This locks the documented behavior so the docs/comments cannot drift back
        to the (false) claim that the default path merges across scanners.
        """
        findings = [
            ScanFinding(
                file_path=Path("config.py"),
                line_number=1,
                rule_id="aws-access-key-id",  # native: bare id
                rule_description="AWS Key",
                description="AWS key",
                severity=FindingSeverity.HIGH,
                scanner="native",
                secret_hash="same-hash",
            ),
            ScanFinding(
                file_path=Path("config.py"),
                line_number=1,
                rule_id="gitleaks-aws-access-token",  # gitleaks: namespaced id
                rule_description="AWS Key",
                description="AWS key",
                severity=FindingSeverity.HIGH,
                scanner="gitleaks",
                secret_hash="same-hash",
            ),
        ]

        default_engine = ScanEngine(GuardConfig(use_native=True, use_gitleaks=False))
        default_unique = default_engine._deduplicate(findings)
        # Default path: different rule IDs -> different keys -> both survive.
        assert len(default_unique) == 2

        skip_engine = ScanEngine(
            GuardConfig(use_native=True, use_gitleaks=False, skip_duplicate=True)
        )
        skip_unique = skip_engine._deduplicate(findings)
        # skip_duplicate keys on the secret hash alone -> collapses across scanners.
        assert len(skip_unique) == 1

    def test_deduplicate_hashless_collapses_into_hashed_same_location(self):
        """A hashless finding collapses into a co-located hashed one (same secret).

        When one scanner extracts the secret value (hash present) and another
        reports the same finding at the same location without one, the hashless
        finding is the less precise duplicate and is dropped in favour of the
        hashed finding -- it must not survive alongside it.
        """
        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)

        findings = [
            ScanFinding(
                file_path=Path("config.py"),
                line_number=5,
                rule_id="secret",
                rule_description="Secret",
                description="Secret",
                severity=FindingSeverity.HIGH,
                scanner="scanner-no-hash",
                secret_hash="",
            ),
            ScanFinding(
                file_path=Path("config.py"),
                line_number=5,
                rule_id="secret",
                rule_description="Secret",
                description="Secret",
                severity=FindingSeverity.HIGH,
                scanner="scanner-with-hash",
                secret_hash="hash-123",
            ),
        ]

        unique = engine._deduplicate(findings)

        assert len(unique) == 1
        assert unique[0].secret_hash == "hash-123"

    def test_deduplicate_keeps_higher_severity_hashless_over_hashed(self):
        """A hashless finding more severe than the co-located hashed one survives.

        Pruning the hashless duplicate must never lower the severity reported at
        a location: if the hashless finding carries higher severity than every
        co-located hashed finding, it is not merely the less-precise duplicate --
        dropping it would hide a more serious signal, so it is kept alongside.
        """
        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)

        findings = [
            ScanFinding(
                file_path=Path("config.py"),
                line_number=5,
                rule_id="secret",
                rule_description="Secret",
                description="Secret",
                severity=FindingSeverity.CRITICAL,
                scanner="scanner-no-hash",
                secret_hash="",
            ),
            ScanFinding(
                file_path=Path("config.py"),
                line_number=5,
                rule_id="secret",
                rule_description="Secret",
                description="Secret",
                severity=FindingSeverity.MEDIUM,
                scanner="scanner-with-hash",
                secret_hash="hash-123",
            ),
        ]

        unique = engine._deduplicate(findings)

        # Both survive: the highest severity present is still reported.
        assert len(unique) == 2
        assert max(f.severity for f in unique) == FindingSeverity.CRITICAL

    def test_deduplicate_deterministic_tie_breaker(self):
        """Test deterministic tie-breaker for equal findings."""
        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)

        finding_a = ScanFinding(
            file_path=Path("config.py"),
            line_number=10,
            rule_id="secret",
            rule_description="Secret",
            description="Secret",
            severity=FindingSeverity.HIGH,
            scanner="a-scanner",
            verified=False,
            secret_hash="hash-123",
        )
        finding_b = ScanFinding(
            file_path=Path("config.py"),
            line_number=10,
            rule_id="secret",
            rule_description="Secret",
            description="Secret",
            severity=FindingSeverity.HIGH,
            scanner="b-scanner",
            verified=False,
            secret_hash="hash-123",
        )

        unique_first = engine._deduplicate([finding_b, finding_a])
        unique_second = engine._deduplicate([finding_a, finding_b])

        assert len(unique_first) == 1
        assert len(unique_second) == 1
        assert unique_first[0].scanner == unique_second[0].scanner == "a-scanner"

    def test_deduplicate_different_locations(self):
        """Test that findings at different locations are kept."""
        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)

        findings = [
            ScanFinding(
                file_path=Path("config1.py"),
                line_number=10,
                rule_id="secret",
                rule_description="Secret",
                description="Secret",
                severity=FindingSeverity.HIGH,
                scanner="native",
            ),
            ScanFinding(
                file_path=Path("config2.py"),
                line_number=10,
                rule_id="secret",
                rule_description="Secret",
                description="Secret",
                severity=FindingSeverity.HIGH,
                scanner="native",
            ),
        ]

        unique = engine._deduplicate(findings)

        assert len(unique) == 2

    def test_deduplicate_sorted_by_severity(self):
        """Test that results are sorted by severity."""
        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)

        findings = [
            ScanFinding(
                file_path=Path("a.py"),
                rule_id="low",
                rule_description="Low",
                description="Low",
                severity=FindingSeverity.LOW,
                scanner="native",
            ),
            ScanFinding(
                file_path=Path("b.py"),
                rule_id="critical",
                rule_description="Critical",
                description="Critical",
                severity=FindingSeverity.CRITICAL,
                scanner="native",
            ),
            ScanFinding(
                file_path=Path("c.py"),
                rule_id="medium",
                rule_description="Medium",
                description="Medium",
                severity=FindingSeverity.MEDIUM,
                scanner="native",
            ),
        ]

        unique = engine._deduplicate(findings)

        # Should be sorted: CRITICAL, MEDIUM, LOW
        assert unique[0].severity == FindingSeverity.CRITICAL
        assert unique[1].severity == FindingSeverity.MEDIUM
        assert unique[2].severity == FindingSeverity.LOW

    def test_deduplicate_skip_duplicate_by_secret_value(self):
        """Test skip_duplicate deduplicates by secret value only."""
        config = GuardConfig(use_native=True, use_gitleaks=False, skip_duplicate=True)
        engine = ScanEngine(config)

        # Same secret appearing in different files
        findings = [
            ScanFinding(
                file_path=Path("config1.py"),
                line_number=10,
                rule_id="aws-key",
                rule_description="AWS Key",
                description="AWS Key found",
                severity=FindingSeverity.HIGH,
                scanner="native",
                secret_preview="AKIA****XXXX",
            ),
            ScanFinding(
                file_path=Path("config2.py"),
                line_number=20,
                rule_id="aws-key",
                rule_description="AWS Key",
                description="AWS Key found",
                severity=FindingSeverity.HIGH,
                scanner="gitleaks",
                secret_preview="AKIA****XXXX",  # Same secret value
            ),
        ]

        unique = engine._deduplicate(findings)

        # Should be deduplicated to 1 since same secret_preview
        assert len(unique) == 1

    def test_deduplicate_skip_duplicate_prefers_secret_hash_key(self):
        """Test skip_duplicate uses secret_hash as key when available."""
        config = GuardConfig(use_native=True, use_gitleaks=False, skip_duplicate=True)
        engine = ScanEngine(config)

        findings = [
            ScanFinding(
                file_path=Path("config1.py"),
                line_number=10,
                rule_id="secret",
                rule_description="Secret",
                description="Secret",
                severity=FindingSeverity.HIGH,
                scanner="native",
                secret_preview="PREVIEW-1",
                secret_hash="hash-xyz",
            ),
            ScanFinding(
                file_path=Path("config2.py"),
                line_number=20,
                rule_id="secret",
                rule_description="Secret",
                description="Secret",
                severity=FindingSeverity.HIGH,
                scanner="gitleaks",
                secret_preview="PREVIEW-2",
                secret_hash="hash-xyz",
            ),
        ]

        unique = engine._deduplicate(findings)

        # Should deduplicate to 1 since secret_hash matches
        assert len(unique) == 1

    def test_deduplicate_skip_duplicate_fallback_location(self):
        """Test skip_duplicate falls back to location when no secret value is present."""
        config = GuardConfig(use_native=True, use_gitleaks=False, skip_duplicate=True)
        engine = ScanEngine(config)

        findings = [
            ScanFinding(
                file_path=Path("policy.json"),
                line_number=5,
                rule_id="policy-violation",
                rule_description="Policy",
                description="Policy finding",
                severity=FindingSeverity.MEDIUM,
                scanner="scanner1",
            ),
            ScanFinding(
                file_path=Path("policy.json"),
                line_number=5,
                rule_id="policy-violation",
                rule_description="Policy",
                description="Policy finding",
                severity=FindingSeverity.MEDIUM,
                scanner="scanner2",
            ),
        ]

        unique = engine._deduplicate(findings)

        # Should be deduplicated by location since no secret_hash/preview
        assert len(unique) == 1

    def test_deduplicate_skip_duplicate_keeps_different_secrets(self):
        """Test skip_duplicate keeps findings with different secret values."""
        config = GuardConfig(use_native=True, use_gitleaks=False, skip_duplicate=True)
        engine = ScanEngine(config)

        findings = [
            ScanFinding(
                file_path=Path("config.py"),
                line_number=10,
                rule_id="aws-key",
                rule_description="AWS Key",
                description="AWS Key found",
                severity=FindingSeverity.HIGH,
                scanner="native",
                secret_preview="AKIA****XXXX",
            ),
            ScanFinding(
                file_path=Path("config.py"),
                line_number=20,
                rule_id="aws-key",
                rule_description="AWS Key",
                description="AWS Key found",
                severity=FindingSeverity.HIGH,
                scanner="native",
                secret_preview="AKIA****YYYY",  # Different secret value
            ),
        ]

        unique = engine._deduplicate(findings)

        # Should keep both since different secret values
        assert len(unique) == 2

    def test_deduplicate_skip_duplicate_disabled_keeps_all_locations(self):
        """Test that with skip_duplicate=False, same secret in different locations is kept."""
        config = GuardConfig(use_native=True, use_gitleaks=False, skip_duplicate=False)
        engine = ScanEngine(config)

        # Same secret appearing in different files
        findings = [
            ScanFinding(
                file_path=Path("config1.py"),
                line_number=10,
                rule_id="aws-key",
                rule_description="AWS Key",
                description="AWS Key found",
                severity=FindingSeverity.HIGH,
                scanner="native",
                secret_preview="AKIA****XXXX",
            ),
            ScanFinding(
                file_path=Path("config2.py"),
                line_number=20,
                rule_id="aws-key",
                rule_description="AWS Key",
                description="AWS Key found",
                severity=FindingSeverity.HIGH,
                scanner="native",
                secret_preview="AKIA****XXXX",  # Same secret value
            ),
        ]

        unique = engine._deduplicate(findings)

        # Should keep both since they're in different files
        assert len(unique) == 2
