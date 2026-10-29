"""The scanner counts lines as git does (#937).

``str.splitlines()`` also breaks a line at a vertical tab, a form feed, ``\\x1c`` to ``\\x1e``,
``\\x85``, ``U+2028`` and ``U+2029``. git, grep and the external scanners do not. So after one of
them the native scanner put a finding a line lower than theirs, and every lookup by line number
read another line than the one an external scanner named: the inline ignore comment, the check
for a ciphertext line, and the recovery of the value trivy redacts.

Secret-shaped values are built by concatenation, so no realistic literal is in the repository.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from envdrift.scanner.base import FindingSeverity, ScanFinding
from envdrift.scanner.engine import GuardConfig, ScanEngine
from envdrift.scanner.ignores import IgnoreFilter
from envdrift.scanner.native import NativeScanner
from envdrift.scanner.trivy import TrivyScanner
from envdrift.utils.text import line_and_column, split_lines

AWS_KEY = "AKIA" + "IOSFODNN7" + "EXAMPLX"
DOTENVX_CIPHERTEXT = "encrypted:BEj2" + "Zq9yKxw0Lr3VtP8sN1mD5cH7aG4fU6eB2oI9kJ3lQ0wR5tY8uA1sD4f=="

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


def _external_finding(path: Path, line_number: int, scanner: str = "gitleaks") -> ScanFinding:
    """A finding as an external scanner reports it, on the line git counts."""
    return ScanFinding(
        file_path=path,
        rule_id=f"{scanner}-aws-access-token",
        rule_description="AWS Access Key",
        description="AWS access key",
        severity=FindingSeverity.CRITICAL,
        scanner=scanner,
        line_number=line_number,
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
        assert ("high-entropy-string", 1, None) in located


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
