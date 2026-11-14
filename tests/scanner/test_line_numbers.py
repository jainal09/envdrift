"""The scanner counts lines as git does (#937).

``str.splitlines()`` also breaks a line at a vertical tab, a form feed, ``\\x1c`` to ``\\x1e``,
``\\x85``, ``U+2028`` and ``U+2029``. git, grep and the external scanners do not. So after one of
them the native scanner put a finding a line lower than theirs, and every lookup by line number
read another line than the one an external scanner named: the inline ignore comment, the check
for a ciphertext line, and the recovery of the value trivy redacts.

Secret-shaped values are built by concatenation, so no realistic literal is in the repository.
"""

from __future__ import annotations

import random
import re
import time
import tracemalloc
from pathlib import Path

import pytest

from envdrift.scanner._native_filters import (
    _assignments,
    _line_values,
    _outside_encrypted_values,
    _skipped_value_spans,
    _sops_value_spans,
    _Spans,
)
from envdrift.scanner.base import FindingSeverity, ScanFinding
from envdrift.scanner.engine import GuardConfig, ScanEngine
from envdrift.scanner.gitleaks import GitleaksScanner
from envdrift.scanner.ignores import IgnoreFilter
from envdrift.scanner.native import NativeScanner
from envdrift.scanner.patterns import hash_secret
from envdrift.scanner.trivy import TrivyScanner
from envdrift.utils.text import LINE_CACHE_SIZE, line_and_column, split_lines

AWS_KEY = "AKIA" + "IOSFODNN7" + "EXAMPLX"
DOTENVX_CIPHERTEXT = "encrypted:BEj2" + "Zq9yKxw0Lr3VtP8sN1mD5cH7aG4fU6eB2oI9kJ3lQ0wR5tY8uA1sD4f=="
SOPS_VALUE = "API_TOKEN=ENC[AES256_GCM,data:" + "Zm9vYmFy" * 4 + ",iv:YWJj,tag:ZGVm,type:str]"
PUBLIC_KEY = 'DOTENV_PUBLIC_KEY="03' + "ab" * 32 + '"'
ENTROPY_TOKEN = "Zx9Kq2Wm7" + "Lp4Rt8Nv6" + "Bs3Yd1Hf5Gj0Qc"

# Where str.splitlines() breaks a line and git does not.
NOT_LINE_BREAKS = {
    "vertical-tab": "\v",
    "form-feed": "\f",
    "file-separator": "\x1c",
    "group-separator": "\x1d",
    "record-separator": "\x1e",
    "next-line": "\x85",
    "line-separator": "\u2028",
    "paragraph-separator": "\u2029",
}

separators = pytest.mark.parametrize(
    "separator", NOT_LINE_BREAKS.values(), ids=NOT_LINE_BREAKS.keys()
)


def _write(path: Path, text: str) -> Path:
    path.write_bytes(text.encode("utf-8"))
    return path


def _key_after(tmp_path: Path, separator: str, trailer: str = "") -> Path:
    """A file whose line 3, as git counts, holds the key; line 2 holds ``separator``."""
    return _write(
        tmp_path / "app.py", f'import os\n{separator}\nAWS_ACCESS_KEY_ID = "{AWS_KEY}"{trailer}\n'
    )


def _many_assignments(count: int) -> str:
    """A line of a SOPS value, then ``count`` high-entropy assignments."""
    values = " ".join(f"K{index}={ENTROPY_TOKEN}{index:06d}" for index in range(count))
    return f"{SOPS_VALUE} {values}"


def _byte_column(line: str, text: str) -> int:
    """The 1-based column of ``text`` in ``line`` as gitleaks reports it, which counts bytes."""
    return len(line[: line.index(text)].encode("utf-8")) + 1


def _external_finding(
    path: Path, line_number: int, scanner: str = "gitleaks", column: int | None = None
) -> ScanFinding:
    """A finding as an external scanner reports it, on the line git counts."""
    return ScanFinding(
        file_path=path,
        rule_id=f"{scanner}-aws-access-token",
        rule_description="AWS Access Key",
        description="AWS access key",
        severity=FindingSeverity.CRITICAL,
        scanner=scanner,
        line_number=line_number,
        column_number=column,
    )


class TestSplitLines:
    """``split_lines`` breaks lines where git does, and nowhere else."""

    def test_it_breaks_at_a_newline_a_crlf_and_a_carriage_return(self):
        assert split_lines("a\nb\r\nc\rd") == ["a", "b", "c", "d"]

    @separators
    def test_it_keeps_a_line_whole_where_splitlines_would_break_it(self, separator: str):
        text = f"a{separator}b\nc"

        assert split_lines(text) == [f"a{separator}b", "c"]
        assert text.splitlines() == ["a", "b", "c"]

    @pytest.mark.parametrize(
        ("text", "lines"),
        [("", []), ("a", ["a"]), ("a\n", ["a"]), ("a\n\n", ["a", ""]), ("\n", [""])],
    )
    def test_a_line_break_at_the_end_starts_no_line(self, text: str, lines: list[str]):
        assert split_lines(text) == lines == text.splitlines()


class TestLineAndColumn:
    """``line_and_column`` counts the lines ``split_lines`` splits, to a position in the text."""

    @pytest.mark.parametrize(
        ("text", "index", "expected"),
        [
            ("abc", 0, (1, 1)),
            ("abc", 2, (1, 3)),
            ("a\nbc", 3, (2, 2)),
            ("a\r\nbc", 4, (2, 2)),
            ("a\rbc", 2, (2, 1)),
            ("a\fb\nc", 4, (2, 1)),  # the form feed is no line break
        ],
    )
    def test_it_finds_the_line_and_the_column(self, text: str, index: int, expected):
        assert line_and_column(text, index) == expected


class TestNativeLineNumbers:
    """The native scanner puts a finding on the line git, grep and gitleaks name."""

    @separators
    def test_a_pattern_finding_after_a_separator(self, tmp_path: Path, separator: str):
        result = NativeScanner().scan([_key_after(tmp_path, separator)])

        assert [(f.rule_id, f.line_number) for f in result.findings] == [("aws-access-key-id", 3)]

    @separators
    def test_an_entropy_finding_after_a_separator(self, tmp_path: Path, separator: str):
        token = "Zx9Kq2Wm7" + "Lp4Rt8Nv6" + "Bs3Yd1Hf5Gj0Qc"
        path = _write(tmp_path / "app.py", f"import os\n{separator}\nSESSION_TOKEN={token}\n")

        result = NativeScanner(check_entropy=True).scan([path])

        assert [(f.rule_id, f.line_number) for f in result.findings] == [("high-entropy-string", 3)]

    def test_a_multiline_finding_is_counted_as_the_per_line_ones_are(self, tmp_path: Path):
        """A file with bare \\r line endings puts a multiline finding on its line too."""
        token = "Zx9Kq2Wm7" + "Lp4Rt8Nv6" + "Bs3Yd1Hf5Gj0Qc"
        account = (
            f"SESSION_TOKEN={token}\r"
            '{"type": "service_account",\r'
            '  "private_key": "-----BEGIN PRIVATE KEY-----\\nabc\\n-----END PRIVATE KEY-----"}\r'
        )
        path = _write(tmp_path / "service-account.json", account)

        result = NativeScanner(check_entropy=True).scan([path])

        located = {(f.rule_id, f.line_number, f.column_number) for f in result.findings}
        assert ("gcp-service-account", 2, 2) in located  # at "type", after the {
        assert ("private-key-generic", 3, 19) in located
        assert ("high-entropy-string", 1, 15) in located  # at the value


class TestInlineIgnore:
    """An ignore comment on a finding's line suppresses it, whichever scanner found it."""

    @separators
    def test_an_external_scanners_finding_is_ignored(self, tmp_path: Path, separator: str):
        path = _key_after(tmp_path, separator, trailer="  # envdrift:ignore")

        assert IgnoreFilter().filter([_external_finding(path, 3)]) == []

    @separators
    def test_a_native_finding_is_ignored(self, tmp_path: Path, separator: str):
        path = _key_after(tmp_path, separator, trailer="  # envdrift:ignore")

        assert IgnoreFilter().filter(NativeScanner().scan([path]).findings) == []


class TestEncryptedLineCheck:
    """In an encrypted .env file, a finding on a plaintext line is kept (#937).

    The check drops a finding on a ciphertext line. Reading another line than the finding's,
    it dropped a plaintext secret that only an external scanner had found.
    """

    @separators
    def test_a_finding_on_the_plaintext_line_is_kept(self, tmp_path: Path, separator: str):
        path = _write(
            tmp_path / ".env",
            f'{separator}\nAPI_TOKEN="{DOTENVX_CIPHERTEXT}"\nAWS_ACCESS_KEY_ID={AWS_KEY}\n',
        )
        engine = ScanEngine(GuardConfig(use_native=True, use_gitleaks=False))
        on_plaintext, on_ciphertext = _external_finding(path, 3), _external_finding(path, 2)

        assert engine._filter_encrypted_files([on_plaintext, on_ciphertext]) == [on_plaintext]


class TestPlaintextAfterAnEncryptedValue:
    """A plaintext secret on the line of an encrypted value is found (#937).

    The native scanner skipped the whole line of an encrypted value or of dotenvx's public key,
    and the engine dropped every finding on the line of an encrypted value. A form feed no longer
    starts a line, so a key after one shares the line of the value before it, as a key after a
    space always did. Only the value itself is skipped now (reported by CodeRabbit on #936).
    """

    @pytest.mark.parametrize("separator", ["\f", " "], ids=["form-feed", "space"])
    @pytest.mark.parametrize(
        "value", [f'API_TOKEN="{DOTENVX_CIPHERTEXT}"', PUBLIC_KEY], ids=["dotenvx", "public-key"]
    )
    def test_the_native_scanner_reports_the_key(self, tmp_path: Path, value: str, separator: str):
        path = _write(tmp_path / ".env", f"# app\n{value}{separator}AWS_ACCESS_KEY_ID={AWS_KEY}\n")

        located = [(f.rule_id, f.line_number) for f in NativeScanner().scan([path]).findings]

        assert ("aws-access-key-id", 2) in located

    @pytest.mark.parametrize("separator", ["\f", " "], ids=["form-feed", "space"])
    def test_a_high_entropy_value_after_a_sops_value_is_reported(
        self, tmp_path: Path, separator: str
    ):
        path = _write(tmp_path / ".env", f"{SOPS_VALUE}{separator}SESSION_TOKEN={ENTROPY_TOKEN}\n")

        findings = NativeScanner(check_entropy=True).scan([path]).findings

        assert [(f.rule_id, f.line_number, f.secret_hash) for f in findings] == [
            ("high-entropy-string", 1, hash_secret(ENTROPY_TOKEN))
        ]

    @pytest.mark.parametrize(
        "content",
        [
            f'{PUBLIC_KEY}  # public\nAPI_TOKEN="{DOTENVX_CIPHERTEXT}"  # rotated\n',
            f"{SOPS_VALUE} # x\n",
        ],
        ids=["dotenvx", "sops"],
    )
    def test_the_values_themselves_are_still_skipped(self, tmp_path: Path, content: str):
        path = _write(tmp_path / ".env", content)

        assert NativeScanner(check_entropy=True).scan([path]).findings == []

    def test_a_key_inside_the_ciphertext_is_not_reported(self, tmp_path: Path):
        """The skipped span runs to the end of the encrypted value, whatever it holds."""
        path = _write(
            tmp_path / ".env", f'API_TOKEN="encrypted:{AWS_KEY}/{DOTENVX_CIPHERTEXT[10:]}"\n'
        )

        assert NativeScanner(check_entropy=True).scan([path]).findings == []

    @pytest.mark.parametrize(
        "value", [f'API_TOKEN="{DOTENVX_CIPHERTEXT}"', SOPS_VALUE], ids=["dotenvx", "sops"]
    )
    def test_the_engine_keeps_an_external_finding_past_the_value(self, tmp_path: Path, value: str):
        line = f"{value}\fAWS_ACCESS_KEY_ID={AWS_KEY}"
        path = _write(tmp_path / ".env", f"{line}\n")
        engine = ScanEngine(GuardConfig(use_native=True, use_gitleaks=False))
        past_the_value = _external_finding(path, 1, column=line.index(AWS_KEY) + 1)
        in_the_value = _external_finding(path, 1, column=line.index("=") + 2)
        without_a_column = _external_finding(path, 1)

        kept = engine._filter_encrypted_files([past_the_value, in_the_value, without_a_column])

        assert kept == [past_the_value]

    def test_the_engine_keeps_a_native_entropy_finding_past_a_sops_value(self, tmp_path: Path):
        """A native entropy finding had no column, so the engine dropped it on an encrypted line.

        Reported by CodeRabbit on #936.
        """
        line = f"{SOPS_VALUE} SESSION_TOKEN={ENTROPY_TOKEN}"
        path = _write(tmp_path / ".env", f"{line}\n")
        engine = ScanEngine(GuardConfig(use_native=True, use_gitleaks=False, check_entropy=True))

        found = [(f.rule_id, f.column_number) for f in engine.scan([path]).unique_findings]

        assert found == [("high-entropy-string", line.index(ENTROPY_TOKEN) + 1)]

    @pytest.mark.parametrize("quote", ['"', "'"], ids=["double", "single"])
    def test_a_key_right_after_a_closing_quote_is_reported(self, tmp_path: Path, quote: str):
        """The aws pattern reads the character before a key, here the value's closing quote.

        That made its match start in the encrypted value, so the native scanner skipped the key,
        and its column put the engine in the value too. Reported by CodeRabbit on #936.
        """
        line = f"API_TOKEN={quote}{DOTENVX_CIPHERTEXT}{quote}{AWS_KEY}"
        path = _write(tmp_path / ".env", f"{line}\n")
        engine = ScanEngine(GuardConfig(use_native=True, use_gitleaks=False))
        column = line.index(AWS_KEY) + 1

        native = [(f.rule_id, f.column_number) for f in NativeScanner().scan([path]).findings]
        found = [(f.rule_id, f.column_number) for f in engine.scan([path]).unique_findings]

        assert ("aws-access-key-id", column) in native
        assert ("aws-access-key-id", column) in found


class TestAnEncryptedValueAfterASeparator:
    """An encrypted value after a form feed or the like is still recognized (#937).

    str.splitlines() started a line there, so the value started one too. Counted to its line
    break, the line holds it after other text, and the anchored check missed it: the native
    scanner reported the ciphertext as a high-entropy string, and the engine kept an external
    finding in it (reported by CodeRabbit on #936).
    """

    @separators
    def test_the_native_scanner_leaves_the_ciphertext_out(self, tmp_path: Path, separator: str):
        path = _write(tmp_path / ".env", f'CLEAR=ok{separator}API_TOKEN="{DOTENVX_CIPHERTEXT}"\n')

        assert NativeScanner(check_entropy=True).scan([path]).findings == []

    @separators
    def test_the_engine_drops_an_external_finding_in_it(self, tmp_path: Path, separator: str):
        line = f'CLEAR=ok{separator}API_TOKEN="{DOTENVX_CIPHERTEXT}"'
        path = _write(tmp_path / ".env", f"{line}\n")
        engine = ScanEngine(GuardConfig(use_native=True, use_gitleaks=False))
        in_the_value = _external_finding(path, 1, column=_byte_column(line, "encrypted:"))
        before_it = _external_finding(path, 1, column=1)

        assert engine._filter_encrypted_files([in_the_value, before_it]) == [before_it]


class TestSopsValueSpans:
    """A SOPS value's span is found in time linear in the line's length.

    The regex the spans came from takes an optional assignment before the envelope. On a long
    run of name characters it retried that run at every position: 10,000 characters took about
    3 seconds, and a 40,000-character line took guard 49 seconds (reported by CodeRabbit on #936).
    """

    # The pattern the spans followed. The new code must give exactly its matches.
    PATTERN = re.compile(
        r"(?:[\"']?[A-Za-z_][\w.-]*[\"']?\s*[=:]\s*[\"']?)?ENC\[AES256_GCM,[^\]]*\]?"
    )
    PIECES = ("a", "Z", "_", "9", ".", "-", '"', "'", " ", "\t", "\f", "\x1c", "=", ":", "]")
    PIECES += ("é", "²", "x", "ENC[AES256_GCM,")

    def test_the_spans_are_the_patterns_matches(self):
        rng = random.Random(936)  # noqa: S311 - a fixed sample of lines, not a secret
        for _ in range(20_000):
            line = "".join(rng.choice(self.PIECES) for _ in range(rng.randint(0, 24)))
            expected = [match.span() for match in self.PATTERN.finditer(line)]
            assert _sops_value_spans(line) == expected, repr(line)

    @pytest.mark.parametrize(
        ("line", "start"),
        [
            (SOPS_VALUE, 0),
            ('  "api_token": "ENC[AES256_GCM,data:x]",', 2),
            ("9=ENC[AES256_GCM,data:x]", 2),
            ("a b=ENC[AES256_GCM,data:x]", 2),
            ("-.key-1 = 'ENC[AES256_GCM,data:x]'", 2),
        ],
        ids=["dotenv", "json", "no-name", "space", "punctuation"],
    )
    def test_the_span_starts_at_the_assignment(self, line: str, start: int):
        assert _sops_value_spans(line) == [(start, line.index("]") + 1)]

    @pytest.mark.parametrize(
        "line",
        [
            "a" * 30_000,
            "a" * 30_000 + " ENC[AES256_GCM,data:x]",
            "a" * 30_000 + "=ENC[AES256_GCM,data:x]",
            "a=ENC[AES256_GCM,x] " * 2_000,
        ],
        ids=["name-characters", "a-value-after-them", "a-long-name", "many-values"],
    )
    def test_a_long_line_is_quick(self, line: str):
        started = time.perf_counter()

        _skipped_value_spans(line)

        assert time.perf_counter() - started < 1.0

    def test_the_native_scanner_reads_a_minified_line_quickly(self, tmp_path: Path):
        # Not *.min.js, which the default ignore patterns leave out before the file is read.
        path = _write(tmp_path / "bundle.js", "a" * 200_000 + "\n")
        started = time.perf_counter()

        result = NativeScanner(check_entropy=True).scan([path])

        assert time.perf_counter() - started < 10.0
        assert result.files_scanned == 1
        assert result.findings == []


class TestEntropyAssignments:
    """The entropy check finds its assignments in time linear in the line's length (#995).

    Its regex had an unanchored name before ``=`` or ``:``: on a long run of name characters it
    started at every position of the run, so 8,000 characters took half a second and each
    doubling four times as long.
    """

    # The pattern the entropy check used. The new code must give exactly its matches.
    PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\s*[=:]\s*[\"']?([^\"'\s=]{16,})[\"']?")
    PIECES = ("a", "Z", "_", "9", "-", ".", "/", '"', "'", " ", "\t", "\f", "=", ":", "é")
    PIECES += ("API_KEY", "Zx9Kq2Wm7Lp4Rt8N", "Zx9Kq2Wm")

    def test_the_assignments_are_the_patterns_matches(self):
        rng = random.Random(995)  # noqa: S311 - a fixed sample of lines, not a secret
        for _ in range(20_000):
            line = "".join(rng.choice(self.PIECES) for _ in range(rng.randint(0, 16)))
            expected = [
                (m.start(), m.end(), m.start(1), m.group(1)) for m in self.PATTERN.finditer(line)
            ]
            assert list(_assignments(line)) == expected, repr(line)

    @pytest.mark.parametrize(
        "line",
        ["a" * 30_000, "aZ9_" * 7_500, "a" * 30_000 + "=x", "a=" * 15_000],
        ids=["name-characters", "mixed-name-characters", "a-short-value", "many-separators"],
    )
    def test_a_long_line_is_quick(self, line: str):
        started = time.perf_counter()

        list(_assignments(line))

        assert time.perf_counter() - started < 1.0

    def test_the_entropy_check_still_reports_a_value_after_a_long_name(self):
        line = "a" * 30_000 + "_TOKEN=" + ENTROPY_TOKEN

        assert [value for *_, value in _assignments(line)] == [ENTROPY_TOKEN]


class TestALongLineOfFindings:
    """A line of many values and findings is read in time linear in its length.

    Each candidate secret was tested against every encrypted value on its line. Each finding made
    the engine find its line's encrypted values again, and the ignore filter look for its line's
    comment again. On one long line each of these took time quadratic in its length, and the
    filters run after the scanners' deadlines (reported by CodeRabbit on #936).
    """

    @staticmethod
    def _random_span(rng: random.Random) -> tuple[int, int]:
        start = rng.randint(0, 30)
        return start, rng.randint(start, 30)

    def test_an_overlap_is_found_as_by_testing_every_span(self):
        rng = random.Random(1936)  # noqa: S311 - a fixed sample of spans, not a secret
        for _ in range(20_000):
            spans = [self._random_span(rng) for _ in range(rng.randint(0, 6))]
            start, end = self._random_span(rng)
            expected = any(start < span_end and span_start < end for span_start, span_end in spans)
            assert _Spans(spans).overlaps(start, end) == expected, (spans, start, end)
        assert not _Spans([])
        assert _Spans([(3, 4)])

    @pytest.mark.parametrize(
        "case",
        [
            # A SOPS file is not pattern-scanned, so its values reach the entropy check only
            ("a=ENC[AES256_GCM,x] ", 50_000, True, 0),
            # A dotenvx value is looked for at the start of each piece split at a form feed
            (f'A="{DOTENVX_CIPHERTEXT}" {AWS_KEY}\f', 20_000, False, 20_000),
        ],
        ids=["sops-values-entropy-check", "dotenvx-values-patterns"],
    )
    def test_the_native_scanner_reads_many_encrypted_values_quickly(
        self, tmp_path: Path, case: tuple[str, int, bool, int]
    ):
        piece, repeat, check_entropy, count = case
        path = _write(tmp_path / ".env", piece * repeat + "\n")
        started = time.perf_counter()

        result = NativeScanner(check_entropy=check_entropy).scan([path])

        assert time.perf_counter() - started < 5.0
        assert result.files_scanned == 1
        assert len(result.findings) == count

    def test_the_engine_filters_many_findings_on_a_line_quickly(self, tmp_path: Path):
        path = _write(tmp_path / ".env", _many_assignments(10_000) + "\n")
        findings = NativeScanner(check_entropy=True).scan([path]).findings
        engine = ScanEngine(GuardConfig(use_native=True, use_gitleaks=False))
        started = time.perf_counter()

        kept = engine._filter_encrypted_files(findings)

        assert time.perf_counter() - started < 3.0
        assert len(findings) == 10_000
        assert kept == findings

    def test_the_engine_finds_the_values_of_each_files_line(self, tmp_path: Path):
        """The values found for a line are not used for the same line of another file."""
        column = SOPS_VALUE.index("data:") + 1
        encrypted = _write(tmp_path / "a.env", f"{SOPS_VALUE}\n")
        plaintext = _write(tmp_path / "b.env", f"{'K' * column}={ENTROPY_TOKEN}\n{SOPS_VALUE}\n")
        engine = ScanEngine(GuardConfig(use_native=True, use_gitleaks=False))
        in_the_value = _external_finding(encrypted, 1, column=column)
        past_it = _external_finding(plaintext, 1, column=column)

        kept = engine._filter_encrypted_files([in_the_value, past_it, in_the_value, past_it])

        assert kept == [past_it, past_it]

    def test_the_engine_keeps_the_values_of_a_few_lines_only(self, tmp_path: Path):
        """The values of every line with a finding were kept until the filter ended.

        With a finding on each of 100,000 lines, that held 28 MiB more than the findings' own
        22.9 MiB (reported by cubic on #936).
        """
        count = 50_000
        plaintext = "".join(f"K{index}=plain\n" for index in range(count))
        path = _write(tmp_path / ".env", f"{SOPS_VALUE}\n{plaintext}")
        engine = ScanEngine(GuardConfig(use_native=True, use_gitleaks=False))
        tracemalloc.start()
        try:
            started = tracemalloc.get_traced_memory()[0]
            findings = [_external_finding(path, line, column=1) for line in range(2, count + 2)]
            held = tracemalloc.get_traced_memory()[0]
            tracemalloc.reset_peak()

            kept = engine._filter_encrypted_files(findings)

            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        assert kept == findings
        assert peak - held < held - started

    def test_the_ignore_filter_keeps_the_comments_of_a_few_lines_only(self, tmp_path: Path):
        """Each line's comment was kept for as long as the filter lived (reported by cubic on #936).

        Every second line ignores its findings, and each line is looked up twice, the second
        time after its comment has been let go.
        """
        lines = [
            f"K{index} = 1" + ("  # envdrift:ignore" if index % 2 else "") for index in range(1_000)
        ]
        path = _write(tmp_path / "app.py", "\n".join(lines) + "\n")
        ignore_filter = IgnoreFilter()
        findings = [_external_finding(path, line) for line in range(1, 1_001)] * 2

        kept = ignore_filter.filter(findings)

        assert [finding.line_number for finding in kept] == list(range(1, 1_001, 2)) * 2
        assert len(ignore_filter._ignore_comments) == LINE_CACHE_SIZE

    def test_the_ignore_filter_reads_many_findings_on_a_line_quickly(self, tmp_path: Path):
        path = _write(tmp_path / ".env", _many_assignments(10_000) + "\n")
        findings = NativeScanner(check_entropy=True).scan([path]).findings
        started = time.perf_counter()

        kept = IgnoreFilter().filter(findings)

        assert time.perf_counter() - started < 3.0
        assert kept == findings

    def test_each_finding_is_matched_against_the_rule_its_line_ignores(self, tmp_path: Path):
        """The comment is looked for once per line, and still ignores only the rule it names."""
        path = _key_after(tmp_path, "", trailer="  # envdrift:ignore:gitleaks-aws-access-token")
        ignored, other_rule = _external_finding(path, 3), _external_finding(path, 3, "trufflehog")

        assert IgnoreFilter().filter([ignored, other_rule, ignored]) == [other_rule]


class TestColumnsPastAPlainStart:
    """A column after a NUL or a non-ASCII character is not compared with the encrypted values.

    Scanners count such a column differently. The native scanner drops NULs before it counts, and
    gitleaks counts bytes, but the values are found in the line as the engine reads it. So the
    column of a plaintext key named a place inside an encrypted value, and the engine dropped the
    key (reported by CodeRabbit on #936).
    """

    @pytest.mark.parametrize(
        ("line", "plain"),
        [("A=1", 3), ("A=\x00", 2), ("é", 0), ("A\udcffB", 1), ("A\tB\fC", 5), ("", 0)],
        ids=["ascii", "nul", "non-ascii", "byte-that-is-not-utf8", "tab-and-form-feed", "empty"],
    )
    def test_the_plain_start_ends_at_a_nul_or_a_non_ascii_character(self, line: str, plain: int):
        assert _line_values(line).plain == plain

    def test_a_column_up_to_the_plain_start_is_checked_and_one_past_it_is_not(self):
        line = 'API_TOKEN="encrypted:abc"é'
        values = _line_values(line)
        in_the_value = line.index("abc") + 1

        assert values.plain == line.index("é")
        assert not _outside_encrypted_values(values, in_the_value)
        assert _outside_encrypted_values(values, values.plain + 2)

    def test_a_byte_column_is_turned_into_the_character_it_starts(self):
        line = 'é="x" API_TOKEN=ENC[AES256_GCM,data:abc]'
        values = _line_values(line)

        assert values.byte_starts is not None
        assert values.byte_starts[:3] == [0, 2, 3]
        assert not _outside_encrypted_values(values, _byte_column(line, "abc"), in_bytes=True)
        assert _outside_encrypted_values(values, _byte_column(line, '"x"'), in_bytes=True)

    def test_the_engine_keeps_a_native_key_after_a_nul_in_an_encrypted_value(self, tmp_path: Path):
        """The native scanner drops the NUL, so its column of the key named the closing quote."""
        value = DOTENVX_CIPHERTEXT[:20] + "\x00" + DOTENVX_CIPHERTEXT[20:]
        path = _write(tmp_path / ".env", f'API_TOKEN="{value}"{AWS_KEY}\n')
        engine = ScanEngine(GuardConfig(use_native=True, use_gitleaks=False))
        native = NativeScanner().scan([path]).findings

        kept = [f.rule_id for f in engine._filter_encrypted_files(native)]

        assert [f.rule_id for f in native] == ["aws-access-key-id"]
        assert kept == ["aws-access-key-id"]

    def test_the_engine_keeps_a_gitleaks_key_after_non_ascii_text(self, tmp_path: Path):
        """gitleaks' byte column of the key fell in the SOPS value after it on the line."""
        line = "NOTE=" + "é" * 80 + f" {AWS_KEY} API_TOKEN=ENC[AES256_GCM,data:" + "A" * 200 + "]"
        path = _write(tmp_path / "app.env", f"{line}\n")
        byte_column = len(line[: line.index(AWS_KEY)].encode("utf-8")) + 1
        # The finding as gitleaks reports it and its adapter reads it
        report = {"File": str(path), "RuleID": "aws-access-token", "Secret": AWS_KEY}
        report |= {"StartLine": 1, "StartColumn": byte_column}
        finding = GitleaksScanner(auto_install=False)._parse_finding(report, tmp_path)
        engine = ScanEngine(GuardConfig(use_native=True, use_gitleaks=False))

        assert finding is not None
        assert engine._filter_encrypted_files([finding]) == [finding]

    def test_a_gitleaks_finding_in_an_encrypted_value_after_non_ascii_text_is_dropped(
        self, tmp_path: Path
    ):
        line = f"NOTE=é {SOPS_VALUE}"
        path = _write(tmp_path / ".env", f"{line}\n")
        engine = ScanEngine(GuardConfig(use_native=True, use_gitleaks=False))
        in_the_value = _external_finding(path, 1, column=_byte_column(line, "data:"))

        assert engine._filter_encrypted_files([in_the_value]) == []

    def test_a_gitleaks_column_after_bytes_that_are_not_utf8_is_placed(self, tmp_path: Path):
        """Each byte that is not UTF-8 keeps its place, so the key is not put in the SOPS value."""
        prefix = b"NOTE=" + b"\xff" * 30 + b" "
        sops = b" API_TOKEN=ENC[AES256_GCM,data:" + b"A" * 200 + b"]"
        path = tmp_path / "app.env"
        path.write_bytes(prefix + AWS_KEY.encode() + sops + b"\n")
        engine = ScanEngine(GuardConfig(use_native=True, use_gitleaks=False))
        key = _external_finding(path, 1, column=len(prefix) + 1)

        assert engine._filter_encrypted_files([key]) == [key]

    def test_a_column_in_an_unknown_unit_after_non_ascii_text_is_kept(self, tmp_path: Path):
        """The cost of the rule: a column that cannot be placed is reported, not dropped."""
        line = f"NOTE=é {SOPS_VALUE}"
        path = _write(tmp_path / ".env", f"{line}\n")
        engine = ScanEngine(GuardConfig(use_native=True, use_gitleaks=False))
        column = line.index("data:") + 1
        in_the_value = _external_finding(path, 1, scanner="kingfisher", column=column)

        assert engine._filter_encrypted_files([in_the_value]) == [in_the_value]


class TestTrivyValueRecovery:
    """The value trivy redacts is read back from the line trivy names."""

    @separators
    def test_the_value_is_recovered(self, tmp_path: Path, separator: str):
        path = _key_after(tmp_path, separator)
        # trivy's report for that file: the line git counts, the value masked.
        secret = {
            "StartLine": 3,
            "EndLine": 3,
            "Match": 'AWS_ACCESS_KEY_ID = "' + "*" * len(AWS_KEY) + '"',
        }

        assert TrivyScanner._recover_secret_value(path, secret) == AWS_KEY
