"""Tests for scan engine deduplication.

Split out of ``test_engine.py`` to keep each test module focused and within a
reasonable size. Covers ``ScanEngine._deduplicate`` and its helpers across the
default and ``--skip-duplicate`` paths.
"""

from __future__ import annotations

from pathlib import Path

from envdrift.scanner.base import FindingSeverity, ScanFinding
from envdrift.scanner.engine import GuardConfig, ScanEngine


def _finding(
    scanner: str,
    *,
    file_path: str = "config.py",
    rule_id: str = "secret",
    rule_description: str = "Secret",
    description: str = "Secret",
    severity: FindingSeverity = FindingSeverity.HIGH,
    line_number: int | None = 10,
    column_number: int | None = None,
    secret_preview: str = "",
    secret_hash: str = "",
    verified: bool = False,
) -> ScanFinding:
    """Build a ``ScanFinding`` with test defaults; pass only the fields that matter.

    Defaults describe one finding at ``config.py:10``, rule ``secret``, ``HIGH``
    severity, no secret value. Dedup keys depend on
    ``file_path`` / ``line_number`` / ``rule_id`` / ``secret_hash``, so each test
    overrides exactly the fields that define its scenario and leaves the rest at
    these (cosmetic) defaults. ``file_path`` may be passed as a ``str``.
    """
    return ScanFinding(
        scanner=scanner,
        file_path=Path(file_path),
        rule_id=rule_id,
        rule_description=rule_description,
        description=description,
        severity=severity,
        line_number=line_number,
        column_number=column_number,
        secret_preview=secret_preview,
        secret_hash=secret_hash,
        verified=verified,
    )


def _dedup(findings: list[ScanFinding], **config_overrides) -> list[ScanFinding]:
    """Run findings through ``_deduplicate`` with a native-only engine."""
    config = GuardConfig(use_native=True, use_gitleaks=False, **config_overrides)
    return ScanEngine(config)._deduplicate(findings)


class TestDeduplication:
    """Tests for finding deduplication."""

    def test_deduplicate_identical_findings(self):
        """Identical findings (same key) collapse to one."""
        findings = [
            _finding("scanner1", rule_id="aws-key", severity=FindingSeverity.CRITICAL),
            _finding("scanner2", rule_id="aws-key", severity=FindingSeverity.CRITICAL),
        ]

        assert len(_dedup(findings)) == 1

    def test_deduplicate_keeps_higher_severity(self):
        """The higher-severity finding wins when keys match."""
        findings = [
            _finding("scanner1", severity=FindingSeverity.MEDIUM),
            _finding("scanner2", severity=FindingSeverity.CRITICAL),
        ]

        unique = _dedup(findings)

        assert len(unique) == 1
        assert unique[0].severity == FindingSeverity.CRITICAL

    def test_deduplicate_prefers_verified(self):
        """A verified finding is preferred over an unverified one at the same key."""
        findings = [
            _finding("scanner1", verified=False),
            _finding("scanner2", verified=True),
        ]

        unique = _dedup(findings)

        assert len(unique) == 1
        assert unique[0].verified is True

    def test_deduplicate_prefers_secret_hash(self):
        """A finding with a secret_hash is preferred when otherwise tied."""
        findings = [
            _finding("scanner1", verified=False),
            _finding("scanner2", verified=False, secret_hash="hash-123"),
        ]

        unique = _dedup(findings)

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
        findings = [
            _finding(
                "native",
                line_number=1,
                column_number=7,
                rule_id="aws-access-key-id",
                secret_hash="hash-aaa",
            ),
            _finding(
                "native",
                line_number=1,
                column_number=29,
                rule_id="aws-access-key-id",
                secret_hash="hash-bbb",
            ),
        ]

        unique = _dedup(findings)

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
            _finding(
                "native",  # native: bare id
                line_number=1,
                rule_id="aws-access-key-id",
                secret_hash="same-hash",
            ),
            _finding(
                "gitleaks",  # gitleaks: namespaced id
                line_number=1,
                rule_id="gitleaks-aws-access-token",
                secret_hash="same-hash",
            ),
        ]

        # Default path: different rule IDs -> different keys -> both survive.
        assert len(_dedup(findings)) == 2
        # skip_duplicate keys on the secret hash alone -> collapses across scanners.
        assert len(_dedup(findings, skip_duplicate=True)) == 1

    def test_deduplicate_hashless_collapses_into_hashed_same_location(self):
        """A hashless finding collapses into a co-located hashed one (same secret).

        When one scanner extracts the secret value (hash present) and another
        reports the same finding at the same location without one, the hashless
        finding is the less precise duplicate and is dropped in favour of the
        hashed finding -- it must not survive alongside it.
        """
        findings = [
            _finding("scanner-no-hash", line_number=5, secret_hash=""),
            _finding("scanner-with-hash", line_number=5, secret_hash="hash-123"),
        ]

        unique = _dedup(findings)

        assert len(unique) == 1
        assert unique[0].secret_hash == "hash-123"

    def test_deduplicate_keeps_higher_severity_hashless_over_hashed(self):
        """A hashless finding more severe than the co-located hashed one survives.

        Pruning the hashless duplicate must never lower the severity reported at
        a location: if the hashless finding carries higher severity than every
        co-located hashed finding, it is not merely the less-precise duplicate --
        dropping it would hide a more serious signal, so it is kept alongside.
        """
        findings = [
            _finding(
                "scanner-no-hash",
                line_number=5,
                severity=FindingSeverity.CRITICAL,
                secret_hash="",
            ),
            _finding(
                "scanner-with-hash",
                line_number=5,
                severity=FindingSeverity.MEDIUM,
                secret_hash="hash-123",
            ),
        ]

        unique = _dedup(findings)

        # Both survive: the highest severity present is still reported.
        assert len(unique) == 2
        assert max(f.severity for f in unique) == FindingSeverity.CRITICAL

    def test_deduplicate_deterministic_tie_breaker(self):
        """Equal findings resolve to a stable winner regardless of input order."""
        finding_a = _finding("a-scanner", verified=False, secret_hash="hash-123")
        finding_b = _finding("b-scanner", verified=False, secret_hash="hash-123")

        unique_first = _dedup([finding_b, finding_a])
        unique_second = _dedup([finding_a, finding_b])

        assert len(unique_first) == 1
        assert len(unique_second) == 1
        assert unique_first[0].scanner == unique_second[0].scanner == "a-scanner"

    def test_deduplicate_different_locations(self):
        """Findings at different locations are both kept."""
        findings = [
            _finding("native", file_path="config1.py"),
            _finding("native", file_path="config2.py"),
        ]

        assert len(_dedup(findings)) == 2

    def test_deduplicate_sorted_by_severity(self):
        """Results are sorted by severity, highest first."""
        findings = [
            _finding("native", file_path="a.py", rule_id="low", severity=FindingSeverity.LOW),
            _finding(
                "native", file_path="b.py", rule_id="critical", severity=FindingSeverity.CRITICAL
            ),
            _finding("native", file_path="c.py", rule_id="medium", severity=FindingSeverity.MEDIUM),
        ]

        unique = _dedup(findings)

        # Should be sorted: CRITICAL, MEDIUM, LOW
        assert unique[0].severity == FindingSeverity.CRITICAL
        assert unique[1].severity == FindingSeverity.MEDIUM
        assert unique[2].severity == FindingSeverity.LOW

    def test_deduplicate_skip_duplicate_by_secret_value(self):
        """skip_duplicate deduplicates by secret value only (same preview collapses)."""
        # Same secret value appearing in different files.
        findings = [
            _finding(
                "native",
                file_path="config1.py",
                rule_id="aws-key",
                secret_preview="AKIA****XXXX",
            ),
            _finding(
                "gitleaks",
                file_path="config2.py",
                line_number=20,
                rule_id="aws-key",
                secret_preview="AKIA****XXXX",  # Same secret value
            ),
        ]

        assert len(_dedup(findings, skip_duplicate=True)) == 1

    def test_deduplicate_skip_duplicate_prefers_secret_hash_key(self):
        """skip_duplicate keys on secret_hash when available (matching hash collapses)."""
        findings = [
            _finding(
                "native",
                file_path="config1.py",
                secret_preview="PREVIEW-1",
                secret_hash="hash-xyz",
            ),
            _finding(
                "gitleaks",
                file_path="config2.py",
                line_number=20,
                secret_preview="PREVIEW-2",
                secret_hash="hash-xyz",
            ),
        ]

        # secret_hash matches -> deduplicated to one.
        assert len(_dedup(findings, skip_duplicate=True)) == 1

    def test_deduplicate_skip_duplicate_fallback_location(self):
        """skip_duplicate falls back to location when no secret value is present."""
        findings = [
            _finding(
                "scanner1",
                file_path="policy.json",
                line_number=5,
                rule_id="policy-violation",
                severity=FindingSeverity.MEDIUM,
            ),
            _finding(
                "scanner2",
                file_path="policy.json",
                line_number=5,
                rule_id="policy-violation",
                severity=FindingSeverity.MEDIUM,
            ),
        ]

        # No secret_hash/preview -> dedup by location -> one survivor.
        assert len(_dedup(findings, skip_duplicate=True)) == 1

    def test_deduplicate_skip_duplicate_keeps_different_secrets(self):
        """skip_duplicate keeps findings with different secret values."""
        findings = [
            _finding("native", rule_id="aws-key", secret_preview="AKIA****XXXX"),
            _finding(
                "native",
                line_number=20,
                rule_id="aws-key",
                secret_preview="AKIA****YYYY",  # Different secret value
            ),
        ]

        assert len(_dedup(findings, skip_duplicate=True)) == 2

    def test_deduplicate_skip_duplicate_disabled_keeps_all_locations(self):
        """With skip_duplicate=False, the same secret in different files is kept."""
        # Same secret value appearing in different files.
        findings = [
            _finding(
                "native",
                file_path="config1.py",
                rule_id="aws-key",
                secret_preview="AKIA****XXXX",
            ),
            _finding(
                "native",
                file_path="config2.py",
                line_number=20,
                rule_id="aws-key",
                secret_preview="AKIA****XXXX",  # Same secret value
            ),
        ]

        # Different locations -> both kept on the default path.
        assert len(_dedup(findings)) == 2
