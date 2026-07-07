"""Regression tests for #479 — trivy redacted-``Match`` hashing and dedup.

Split out of ``test_trivy.py`` (which covers install/scan plumbing) so each
module keeps a single responsibility: this one owns the secret-hash recovery
and ``--skip-duplicate`` collapse behavior of the trivy adapter.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from envdrift.scanner.patterns import hash_secret, redact_secret
from envdrift.scanner.trivy import TrivyScanner

# Distinct same-shape GitHub PATs (same variable name, same length) so their
# trivy-redacted Match lines are byte-identical. Assembled from fragments so the
# full secret pattern never appears as a contiguous literal in source (GitHub
# push protection).
_TOKEN_A = "ghp_" + "016C7eX9bQ2vYwN3" + "kLmZpRtUaScDfGhJkL01"
_TOKEN_B = "ghp_" + "92RkXwQ7tBn4MvCs" + "1LhJd8PfYg5WzEuA63To"


class TestRedactedMatchHashing:
    """Regression tests for #479 — trivy emits ``Match`` pre-redacted.

    Real trivy output never contains the raw secret: ``Secret`` is null and the
    matched span inside ``Match`` is replaced by a same-length run of ``*``.
    Hashing that redacted line as if it were the secret makes two distinct
    secrets of the same shape collide, and the engine's ``--skip-duplicate``
    dedup (keyed on ``secret_hash``) silently drops one. The adapter must
    recover the raw value from the scanned file when possible, and otherwise
    fall back to a location-qualified hash that can never collapse distinct
    findings.
    """

    @pytest.fixture
    def scanner(self) -> TrivyScanner:
        """TrivyScanner with auto-install disabled (parsing-only tests)."""
        return TrivyScanner(auto_install=False)

    @staticmethod
    def _trivy_secret(
        match: str,
        start_line: int = 1,
        end_line: int | None = None,
        rule: str = "github-pat",
    ) -> dict[str, Any]:
        """Build a secret dict shaped exactly like real ``trivy fs`` JSON output."""
        return {
            "RuleID": rule,
            "Category": "GitHub",
            "Severity": "CRITICAL",
            "Title": "GitHub Personal Access Token",
            "StartLine": start_line,
            "EndLine": end_line if end_line is not None else start_line,
            "Match": match,
        }

    @staticmethod
    def _masked_line(token: str, prefix: str = "TOKEN=") -> str:
        """The Match line trivy emits: raw line with the secret as ``*`` run."""
        return prefix + "*" * len(token)

    def test_distinct_secrets_with_identical_redacted_match_hash_differently(
        self, scanner: TrivyScanner, tmp_path: Path
    ):
        """#479: identical Match lines for distinct secrets must NOT share a hash."""
        assert len(_TOKEN_A) == len(_TOKEN_B)
        (tmp_path / "a.txt").write_text(f"TOKEN={_TOKEN_A}\n", encoding="utf-8")
        (tmp_path / "b.txt").write_text(f"TOKEN={_TOKEN_B}\n", encoding="utf-8")
        masked = self._masked_line(_TOKEN_A)

        finding_a = scanner._parse_secret(self._trivy_secret(masked), "a.txt", tmp_path)
        finding_b = scanner._parse_secret(self._trivy_secret(masked), "b.txt", tmp_path)

        assert finding_a is not None and finding_b is not None
        assert finding_a.secret_hash and finding_b.secret_hash
        assert finding_a.secret_hash != finding_b.secret_hash, (
            "distinct secrets sharing a redacted Match collapsed to one hash (#479)"
        )

    def test_two_distinct_same_rule_secrets_on_one_line_keep_distinct_hashes(
        self, scanner: TrivyScanner, tmp_path: Path
    ):
        """Two distinct same-rule secrets on ONE line must not share a hash.

        Trivy censors ALL secret spans in a line before building each
        finding's ``Match``, so the two findings' dicts are byte-identical
        (same ``StartLine``/``EndLine``/``RuleID`` and the same fully-censored
        ``Match`` — verified against real trivy output). Recovery is rejected
        for both (the differing span contains the unmasked separator), so the
        fallback hash must carry an occurrence index to keep them distinct.
        """
        line = f"T1={_TOKEN_A} T2={_TOKEN_B}"
        (tmp_path / "creds.env").write_text(line + "\n", encoding="utf-8")
        censored = f"T1={'*' * len(_TOKEN_A)} T2={'*' * len(_TOKEN_B)}"
        scan_data = {
            "Results": [
                {
                    "Target": "creds.env",
                    "Class": "secret",
                    "Secrets": [self._trivy_secret(censored), self._trivy_secret(censored)],
                }
            ]
        }

        findings, _ = scanner._parse_output(scan_data, tmp_path)
        findings_again, _ = scanner._parse_output(scan_data, tmp_path)

        assert len(findings) == 2
        hashes = [f.secret_hash for f in findings]
        assert all(hashes), "fallback findings must still carry a non-empty hash"
        assert hashes[0] != hashes[1], (
            "two distinct same-line secrets collapsed to one hash (#479 same-line case)"
        )
        # The censored span (which includes the unmasked ' T2=' separator)
        # must never be mistaken for the recovered secret.
        assert all(h != hash_secret(line) for h in hashes)
        # Re-parses stay stable: trivy reports findings in deterministic
        # order, so each occurrence keeps its index (and hence its hash).
        assert [f.secret_hash for f in findings_again] == hashes

    def test_recovered_hash_and_preview_use_raw_secret_value(
        self, scanner: TrivyScanner, tmp_path: Path
    ):
        """The raw value is recovered from the file for hash + preview."""
        (tmp_path / "creds.txt").write_text(
            f"# header\nexport TOKEN={_TOKEN_A}  # prod\n", encoding="utf-8"
        )
        masked = f"export TOKEN={'*' * len(_TOKEN_A)}  # prod"

        finding = scanner._parse_secret(
            self._trivy_secret(masked, start_line=2), "creds.txt", tmp_path
        )

        assert finding is not None
        assert finding.secret_hash == hash_secret(_TOKEN_A)
        assert finding.secret_preview == redact_secret(_TOKEN_A)
        assert _TOKEN_A not in finding.secret_preview

    def test_redacted_match_line_is_never_hashed_as_the_secret(
        self, scanner: TrivyScanner, tmp_path: Path
    ):
        """Neither recovery nor fallback may equal hash_secret(redacted Match)."""
        (tmp_path / "a.txt").write_text(f"TOKEN={_TOKEN_A}\n", encoding="utf-8")
        masked = self._masked_line(_TOKEN_A)

        recovered = scanner._parse_secret(self._trivy_secret(masked), "a.txt", tmp_path)
        fallback = scanner._parse_secret(self._trivy_secret(masked), "missing.txt", tmp_path)

        assert recovered is not None and fallback is not None
        assert recovered.secret_hash != hash_secret(masked)
        assert fallback.secret_hash != hash_secret(masked)

    def test_fallback_hash_is_location_qualified_when_file_is_missing(
        self, scanner: TrivyScanner, tmp_path: Path
    ):
        """Unrecoverable findings at different locations keep distinct hashes."""
        masked = self._masked_line(_TOKEN_A)

        finding_a = scanner._parse_secret(self._trivy_secret(masked), "gone-a.txt", tmp_path)
        finding_b = scanner._parse_secret(self._trivy_secret(masked), "gone-b.txt", tmp_path)
        finding_a_line9 = scanner._parse_secret(
            self._trivy_secret(masked, start_line=9), "gone-a.txt", tmp_path
        )

        assert finding_a is not None and finding_b is not None and finding_a_line9 is not None
        hashes = {finding_a.secret_hash, finding_b.secret_hash, finding_a_line9.secret_hash}
        assert all(hashes), "fallback findings must still carry a non-empty hash"
        assert len(hashes) == 3, "file and line must qualify the fallback hash"

    def test_fallback_hash_is_stable_for_the_same_finding(
        self, scanner: TrivyScanner, tmp_path: Path
    ):
        """Re-parsing the same unrecoverable finding yields the same hash."""
        masked = self._masked_line(_TOKEN_A)
        secret = self._trivy_secret(masked, start_line=3)

        first = scanner._parse_secret(secret, "gone.txt", tmp_path)
        second = scanner._parse_secret(secret, "gone.txt", tmp_path)

        assert first is not None and second is not None
        assert first.secret_hash == second.secret_hash

    def test_fallback_when_file_line_no_longer_aligns_with_match(
        self, scanner: TrivyScanner, tmp_path: Path
    ):
        """A changed/shorter line must not be mistaken for the secret."""
        (tmp_path / "a.txt").write_text("TOKEN=rotated\n", encoding="utf-8")
        masked = self._masked_line(_TOKEN_A)

        finding = scanner._parse_secret(self._trivy_secret(masked), "a.txt", tmp_path)

        assert finding is not None
        assert finding.secret_hash
        assert finding.secret_hash != hash_secret("rotated")
        assert finding.secret_hash != hash_secret(masked)

    def test_recovery_rejects_diff_span_that_is_not_all_asterisks(
        self, scanner: TrivyScanner, tmp_path: Path
    ):
        """Same-length but non-masked divergence must not be 'recovered'."""
        (tmp_path / "a.txt").write_text("TOKEN=abcdef\n", encoding="utf-8")
        # No * at all in the Match -> recovery is not even attempted.
        finding = scanner._parse_secret(self._trivy_secret("TOKEN=zzzzzz"), "a.txt", tmp_path)
        # * present but the differing span is not a pure * run -> rejected.
        finding_mixed = scanner._parse_secret(self._trivy_secret("TOKEN=*zzzz*"), "a.txt", tmp_path)

        assert finding is not None and finding_mixed is not None
        assert finding.secret_hash and finding_mixed.secret_hash
        assert finding.secret_hash != hash_secret("abcdef")
        assert finding_mixed.secret_hash != hash_secret("abcdef")

    def test_secret_with_literal_edge_asterisks_is_not_silently_truncated(
        self, scanner: TrivyScanner, tmp_path: Path
    ):
        """A ``*``-bracketed secret must not be recovered with its edges stripped.

        The prefix/suffix alignment walks INTO the masked span when the raw
        secret itself starts/ends with literal ``*``: the candidate would be
        the secret minus its edge characters, silently hashing as a value no
        other scanner computes. The mask boundary is ambiguous there, so the
        adapter must fall back to the location-qualified hash instead.
        """
        secret_value = "*abc-secret-xyz*"
        (tmp_path / "f.txt").write_text(f"PASSWORD={secret_value}\n", encoding="utf-8")
        masked = "PASSWORD=" + "*" * len(secret_value)

        finding = scanner._parse_secret(
            self._trivy_secret(masked, rule="generic-api-key"), "f.txt", tmp_path
        )

        assert finding is not None
        assert finding.secret_hash
        assert finding.secret_hash != hash_secret("abc-secret-xyz"), (
            "recovery truncated the secret's literal edge '*' characters"
        )
        assert finding.secret_hash != hash_secret(masked)

    def test_explicit_endline_null_is_treated_as_multi_line_and_falls_back(
        self, scanner: TrivyScanner, tmp_path: Path
    ):
        """``"EndLine": null`` must not bypass the multi-line recovery guard.

        ``secret.get("EndLine", start_line)`` only applies the default when
        the key is absent; an explicit ``null`` leaves the span unknown, so
        recovery must be rejected rather than assumed single-line.
        """
        (tmp_path / "a.txt").write_text(f"TOKEN={_TOKEN_A}\n", encoding="utf-8")
        secret = self._trivy_secret(self._masked_line(_TOKEN_A))
        secret["EndLine"] = None

        finding = scanner._parse_secret(secret, "a.txt", tmp_path)

        assert finding is not None
        assert finding.secret_hash
        assert finding.secret_hash != hash_secret(_TOKEN_A), (
            "EndLine: null must reject recovery (span unknown), not assume single-line"
        )

    def test_fallback_when_start_line_is_beyond_end_of_file(
        self, scanner: TrivyScanner, tmp_path: Path
    ):
        """A StartLine past EOF (file truncated since the scan) falls back."""
        (tmp_path / "a.txt").write_text("only one line\n", encoding="utf-8")
        masked = self._masked_line(_TOKEN_A)

        finding = scanner._parse_secret(self._trivy_secret(masked, start_line=5), "a.txt", tmp_path)

        assert finding is not None
        assert finding.secret_hash
        assert finding.secret_hash != hash_secret(masked)

    def test_multi_line_secret_falls_back_to_location_hash(
        self, scanner: TrivyScanner, tmp_path: Path
    ):
        """Multi-line findings (StartLine != EndLine) never hash a partial span."""
        # Markers built by concatenation so no key-shaped literal appears
        # whole in source (GitHub push protection).
        begin = "-----BEGIN " + "PRIVATE KEY-----"
        end = "-----END " + "PRIVATE KEY-----"
        (tmp_path / "key.pem").write_text(f"{begin}\nabc\n{end}\n", encoding="utf-8")
        masked = begin
        finding_a = scanner._parse_secret(
            self._trivy_secret(masked, start_line=1, end_line=3, rule="private-key"),
            "key.pem",
            tmp_path,
        )
        finding_b = scanner._parse_secret(
            self._trivy_secret(masked, start_line=1, end_line=3, rule="private-key"),
            "other.pem",
            tmp_path,
        )

        assert finding_a is not None and finding_b is not None
        assert finding_a.secret_hash and finding_b.secret_hash
        assert finding_a.secret_hash != finding_b.secret_hash

    def test_recovery_works_with_crlf_line_endings(self, scanner: TrivyScanner, tmp_path: Path):
        """CRLF files (Windows) still recover the raw value at the right line."""
        crlf = f"# header\r\nTOKEN={_TOKEN_A}\r\n"
        (tmp_path / "win.txt").write_bytes(crlf.encode("utf-8"))
        masked = self._masked_line(_TOKEN_A)

        finding = scanner._parse_secret(
            self._trivy_secret(masked, start_line=2), "win.txt", tmp_path
        )

        assert finding is not None
        assert finding.secret_hash == hash_secret(_TOKEN_A)

    def test_empty_match_still_yields_empty_hash_and_preview(
        self, scanner: TrivyScanner, tmp_path: Path
    ):
        """No Match at all keeps the historical empty hash/preview behavior."""
        secret = self._trivy_secret("", start_line=1)
        finding = scanner._parse_secret(secret, "a.txt", tmp_path)

        assert finding is not None
        assert finding.secret_hash == ""
        assert finding.secret_preview == ""
