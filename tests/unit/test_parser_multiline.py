"""Regression tests for #458: quoted multiline values parse like python-dotenv.

``EnvParser`` used to split content per physical line, truncating a quoted
multiline value at its first line (keeping the stray opening quote) and
re-parsing the interior lines as phantom assignments. python-dotenv — and
therefore pydantic-settings, the ground truth for ``validate`` — treats a
value opened with ``"``/``'`` as continuing across physical lines until the
matching close quote. These tests pin the parser to those semantics, including
byte-for-byte parity checks against the real python-dotenv and a real
pydantic-settings class loading the same file in-process.
"""

from __future__ import annotations

import pytest
from dotenv import dotenv_values

from envdrift.core.parser import EncryptionStatus, EnvParser

# PEM-style fixture material, built by concatenation so the literals never look
# like real key material (GitHub push protection).
PEM_HEADER = "-----BEGIN " + "TEST CERT-----"
PEM_FOOTER = "-----END " + "TEST CERT-----"
PEM_BODY_1 = "QUJDREVGMDEyMzQ1Njc4OQ" + "=="
PEM_BODY_2 = "MDEyMzQ1Njc4OWFiY2RlZg" + "=="
PEM_VALUE = "\n".join([PEM_HEADER, PEM_BODY_1, PEM_BODY_2, PEM_FOOTER])


def _values(env_file) -> dict[str, str]:
    """Plain ``{name: value}`` view of a parsed EnvFile."""
    return {name: var.value for name, var in env_file.variables.items()}


class TestMultilineQuotedValues:
    """#458: a quoted value continues across lines until the close quote."""

    def test_double_quoted_multiline_value_parsed_fully(self):
        """The full multiline value is kept — no truncation, no phantom vars."""
        content = f'CERT="{PEM_VALUE}"\nAFTER=ok\n'

        result = EnvParser().parse_string(content)

        assert set(result.variables) == {"CERT", "AFTER"}
        assert result.variables["CERT"].value == PEM_VALUE
        assert result.variables["AFTER"].value == "ok"

    def test_interior_assignment_is_value_not_phantom_var(self):
        """Issue #458 evidence: an interior ``KEY=...`` line is part of the
        value, not a fabricated variable the user never wrote."""
        inner = "DB_PASSWORD=oops_interpreted_as_assignment"
        cert_value = f"-----BEGIN CERT-----\n{inner}\n-----END CERT-----"
        content = f'CERT="{cert_value}"\n'

        result = EnvParser().parse_string(content)

        assert set(result.variables) == {"CERT"}
        assert "DB_PASSWORD" not in result
        assert result.variables["CERT"].value == cert_value

    def test_single_quoted_multiline_value(self):
        content = "NOTE='line one\nline two'\nX=1\n"

        result = EnvParser().parse_string(content)

        assert set(result.variables) == {"NOTE", "X"}
        assert result.variables["NOTE"].value == "line one\nline two"

    def test_escaped_double_quote_inside_multiline_does_not_close(self):
        """A ``\\"`` inside the value neither closes the quote nor survives
        verbatim — python-dotenv decodes it to ``"``."""
        content = 'MSG="say \\"hi\\"\nsecond line"\n'

        result = EnvParser().parse_string(content)

        assert set(result.variables) == {"MSG"}
        assert result.variables["MSG"].value == 'say "hi"\nsecond line'

    def test_escaped_single_quote_inside_multiline_does_not_close(self):
        content = "S='it\\'s\nfine'\n"

        result = EnvParser().parse_string(content)

        assert set(result.variables) == {"S"}
        assert result.variables["S"].value == "it's\nfine"

    def test_interior_comment_and_blank_lines_stay_in_value(self):
        """``#``/blank interior lines belong to the value — they are neither
        comments nor line separators."""
        block = "first\n# not a comment\n\nlast"
        content = f'BLOCK="{block}"\nX=1\n'

        result = EnvParser().parse_string(content)

        assert result.variables["BLOCK"].value == block
        assert result.comments == []

    def test_inline_comment_after_closing_quote_is_stripped(self):
        content = 'CERT="a\nb"  # trailing comment\n'

        result = EnvParser().parse_string(content)

        assert result.variables["CERT"].value == "a\nb"

    def test_line_numbers_resume_after_multiline_value(self):
        content = f'CERT="{PEM_VALUE}"\nAFTER=ok\n'

        result = EnvParser().parse_string(content)

        assert result.variables["CERT"].line_number == 1
        # CERT spans physical lines 1-4 (the 4-line PEM), so AFTER sits on 5.
        assert result.variables["AFTER"].line_number == 5

    def test_multiline_raw_line_preserves_physical_lines(self):
        content = f'CERT="{PEM_VALUE}"\n'

        result = EnvParser().parse_string(content)

        assert result.variables["CERT"].raw_line == f'CERT="{PEM_VALUE}"'

    def test_multiline_value_is_plaintext_status(self):
        content = f'CERT="{PEM_VALUE}"\n'

        result = EnvParser().parse_string(content)

        var = result.variables["CERT"]
        assert var.encryption_status == EncryptionStatus.PLAINTEXT
        assert var.encryption_backend is None

    def test_escaped_quote_on_continuation_line_does_not_close(self):
        """A continuation line containing only an escaped quote keeps the
        value open until the real close quote."""
        content = 'M="start\nmid \\" still\nend"\n'

        result = EnvParser().parse_string(content)

        assert set(result.variables) == {"M"}
        assert result.variables["M"].value == 'start\nmid " still\nend'

    def test_close_quote_with_trailing_junk_drops_binding_like_dotenv(self):
        """A close quote followed by non-comment content is a malformed
        binding: python-dotenv consumes the input through the close-quote
        line and registers nothing (``dotenv_values`` on this content is
        ``{'NEXT': '1'}``), so no truncated ``B`` and no phantom variables."""
        content = 'B="start\nend" garbage\nNEXT=1\n'

        result = EnvParser().parse_string(content)

        assert set(result.variables) == {"NEXT"}
        assert result.variables["NEXT"].value == "1"

    def test_trailing_junk_interior_assignment_is_not_a_phantom_var(self):
        """Review regression (#458 bug class): even when the close quote is
        junk-trailed, the interior ``DB_PASSWORD=...`` line belongs to the
        consumed (dropped) binding — python-dotenv's ``dotenv_values`` yields
        ``{'NEXT': '1'}``, never a ``DB_PASSWORD`` variable."""
        content = 'CERT="-----BEGIN-----\nDB_PASSWORD=oops\n-----END-----" junk\nNEXT=1\n'

        result = EnvParser().parse_string(content)

        assert set(result.variables) == {"NEXT"}
        assert "DB_PASSWORD" not in result
        assert "CERT" not in result

    def test_unterminated_quote_drops_binding_and_resumes_next_line(self):
        """No quote anywhere after the opener: python-dotenv's value regex
        fails, its error path consumes only the rest of the opening line, and
        the binding is dropped (``dotenv_values`` gives ``{'NEXT': 'ok'}`` —
        no truncated ``BROKEN``). Later lines still parse."""
        content = 'BROKEN="no closing quote\nNEXT=ok\n'

        result = EnvParser().parse_string(content)

        assert set(result.variables) == {"NEXT"}
        assert result.variables["NEXT"].value == "ok"

    def test_unterminated_quote_following_lines_parse_like_dotenv(self):
        """After an unterminated opener, python-dotenv re-parses the FOLLOWING
        lines as ordinary bindings (``dotenv_values`` gives
        ``{'DB_PASSWORD': 'leak', 'NEXT': 'ok'}``) — only the opening line is
        consumed by the error recovery."""
        content = 'BROKEN="no close\nDB_PASSWORD=leak\nNEXT=ok\n'

        result = EnvParser().parse_string(content)

        assert set(result.variables) == {"DB_PASSWORD", "NEXT"}
        assert result.variables["DB_PASSWORD"].value == "leak"

    def test_all_escaped_quotes_close_at_last_quote_like_dotenv(self):
        """python-dotenv's greedy ``(?:\\\\"|[^"])*`` lexing backtracks: when
        every quote is backslash-preceded, the LAST ``\\"`` is re-read as
        backslash + close quote (``dotenv_values`` on ``K="a\\"`` is
        ``{'K': 'a\\\\'}``)."""
        content = 'K="a\\"\n'

        result = EnvParser().parse_string(content)

        assert result.variables["K"].value == "a\\"

    def test_definitive_close_spans_lines_past_escaped_quotes(self):
        """A backslash-preceded quote stays interior when an unescaped quote
        exists later — even on a later line with junk after it, where the
        whole binding is dropped through that line (``dotenv_values`` on this
        content is ``{}``)."""
        content = 'M="a\\"\nB=2\nC="x"\n'

        result = EnvParser().parse_string(content)

        assert result.variables == {}

    def test_lenient_parse_honors_multiline_values(self):
        """``validate`` parses with ``lenient=True``; the continuation must
        apply there too (base64 ``==`` padding lines used to become phantom
        vars under the lenient pattern)."""
        content = f'X-API-KEY="{PEM_VALUE}"\nOK_KEY=1\n'

        result = EnvParser().parse_string(content, lenient=True)

        assert set(result.variables) == {"X-API-KEY", "OK_KEY"}
        assert result.variables["X-API-KEY"].value == PEM_VALUE

    def test_crlf_multiline_value_normalizes_to_lf(self, tmp_path):
        """A CRLF (Windows) file yields LF-joined values, exactly like
        python-dotenv reading the same file."""
        raw = f'CERT="{PEM_HEADER}\r\n{PEM_BODY_1}\r\n{PEM_FOOTER}"\r\nAFTER=ok\r\n'
        env_path = tmp_path / ".env"
        env_path.write_bytes(raw.encode("utf-8"))

        result = EnvParser().parse(env_path)

        assert set(result.variables) == {"CERT", "AFTER"}
        expected = f"{PEM_HEADER}\n{PEM_BODY_1}\n{PEM_FOOTER}"
        assert result.variables["CERT"].value == expected


class TestSingleLineQuotedEscapes:
    """Quoted single-line values follow python-dotenv's escape decoding."""

    def test_double_quoted_escape_sequences_are_decoded(self):
        content = 'K="a\\nb\\tc"\n'

        result = EnvParser().parse_string(content)

        assert result.variables["K"].value == "a\nb\tc"

    def test_single_quoted_only_decodes_backslash_and_quote(self):
        content = "K='a\\nb\\'c'\n"

        result = EnvParser().parse_string(content)

        assert result.variables["K"].value == "a\\nb'c"

    def test_close_quote_with_trailing_junk_drops_binding(self):
        """Non-comment content after the close quote makes python-dotenv
        reject the whole binding (``dotenv_values`` on ``K="a" trailing`` is
        ``{}``), so no variable is registered."""
        content = 'K="a" trailing\nNEXT=1\n'

        result = EnvParser().parse_string(content)

        assert set(result.variables) == {"NEXT"}

    def test_escaped_backslash_then_quote_reopens_like_dotenv(self):
        """``\\\\"`` mid-value: the quote after an escaped backslash is still
        backslash-preceded, so python-dotenv keeps it interior and closes at
        the next unescaped quote (``dotenv_values`` on ``K="a\\\\"b"`` is
        ``{'K': 'a\\\\"b'}``)."""
        content = 'K="a\\\\"b"\n'

        result = EnvParser().parse_string(content)

        assert result.variables["K"].value == 'a\\"b'

    def test_unquoted_value_backslashes_untouched(self):
        content = "K=a\\nb\n"

        result = EnvParser().parse_string(content)

        assert result.variables["K"].value == "a\\nb"

    def test_escape_decoding_leaves_non_ascii_intact(self):
        """Escape decoding must not mojibake non-ASCII text around the escape
        sequences (``dotenv_values`` on ``K="café\\nüber"`` is
        ``{'K': 'café\\nüber'}`` with a real newline — the é/ü survive)."""
        content = 'K="café\\nüber"\n'

        result = EnvParser().parse_string(content)

        assert result.variables["K"].value == "café\nüber"


class TestPythonDotenvParity:
    """Byte-for-byte parity with the real python-dotenv / pydantic-settings."""

    @pytest.mark.parametrize(
        "content",
        [
            pytest.param(f'CERT="{PEM_VALUE}"\nAFTER=ok\n', id="multiline-pem-double-quoted"),
            pytest.param("NOTE='line one\nline two'\nX=1\n", id="multiline-single-quoted"),
            pytest.param('MSG="say \\"hi\\"\nsecond line"\n', id="multiline-escaped-quote"),
            pytest.param('CERT="a\nb"  # trailing comment\nX=1\n', id="comment-after-close"),
            pytest.param('BLOCK="first\n# inside\n\nlast"\n', id="interior-comment-and-blank"),
            pytest.param("K=\"a\\nb\\tc\"\nS='a\\nb'\n", id="single-line-escapes"),
            pytest.param("PORT=8080 # http port\nCOLOR=#FF0000\n", id="unquoted-inline-comment"),
            pytest.param('EMPTY=""\nPADDED= "x"\nexport E="y"\n', id="quoting-shapes"),
            pytest.param('K="a" trailing\nNEXT=1\n', id="single-line-trailing-junk-dropped"),
            pytest.param('B="start\nend" garbage\nNEXT=1\n', id="multiline-trailing-junk-dropped"),
            pytest.param(
                'CERT="-----BEGIN-----\nDB_PASSWORD=oops\n-----END-----" junk\nNEXT=1\n',
                id="trailing-junk-interior-assignment",
            ),
            pytest.param('BROKEN="no closing quote\nNEXT=ok\n', id="unterminated-dropped"),
            pytest.param(
                'BROKEN="no close\nDB_PASSWORD=leak\nNEXT=ok\n',
                id="unterminated-following-lines-reparse",
            ),
            pytest.param('K="a\\"\nX=1\n', id="all-escaped-quotes-fallback-close"),
            pytest.param("K='a\\'\nX=1\n", id="single-quote-fallback-close"),
            pytest.param('K="a\\\\"b"\n', id="escaped-backslash-then-quote"),
            pytest.param('M="a\\"\nB=2\nC="x"\n', id="fallback-superseded-by-later-quote"),
            pytest.param("K=\"café\\nüber\"\nS='café\\n'\n", id="non-ascii-escapes"),
            pytest.param('A="x\ny" z\nB=1\n', id="multiline-junk-after-close"),
            pytest.param('A="x\ny" # ok\nB=1\n', id="multiline-comment-after-close"),
        ],
    )
    def test_parsed_values_match_python_dotenv(self, tmp_path, content):
        env_path = tmp_path / ".env"
        env_path.write_text(content, encoding="utf-8")

        parsed = _values(EnvParser().parse(env_path))

        assert parsed == dict(dotenv_values(env_path))

    def test_crlf_file_matches_python_dotenv(self, tmp_path):
        raw = f'CERT="{PEM_HEADER}\r\n{PEM_BODY_1}\r\n{PEM_FOOTER}"\r\nAFTER=ok\r\n'
        env_path = tmp_path / ".env"
        env_path.write_bytes(raw.encode("utf-8"))

        parsed = _values(EnvParser().parse(env_path))

        assert parsed == dict(dotenv_values(env_path))

    def test_pydantic_settings_loads_identical_multiline_value(self, tmp_path):
        """The same file, loaded by a real pydantic-settings class, yields the
        exact value the parser reports (newlines included)."""
        from pydantic_settings import BaseSettings, SettingsConfigDict

        env_path = tmp_path / ".env"
        env_path.write_text(f'CERT="{PEM_VALUE}"\n', encoding="utf-8")

        class Settings(BaseSettings):
            model_config = SettingsConfigDict(
                env_file=str(env_path), env_file_encoding="utf-8", extra="ignore"
            )

            CERT: str

        loaded = Settings()
        parsed = EnvParser().parse(env_path)

        assert loaded.CERT == parsed.variables["CERT"].value == PEM_VALUE
