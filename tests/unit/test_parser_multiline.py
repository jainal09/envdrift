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

    def test_close_quote_with_trailing_junk_falls_back_to_legacy(self):
        """A close quote followed by non-comment content is not a clean quoted
        value; the legacy per-line treatment applies (python-dotenv drops the
        binding entirely — either way no multiline value is fabricated)."""
        content = 'B="start\nend" garbage\nNEXT=1\n'

        result = EnvParser().parse_string(content)

        assert result.variables["B"].value == '"start'
        assert result.variables["NEXT"].value == "1"

    def test_unterminated_quote_keeps_legacy_per_line_parsing(self):
        """No closing quote anywhere: the legacy single-line treatment is kept
        (truncated value with the stray quote) and later lines still parse."""
        content = 'BROKEN="no closing quote\nNEXT=ok\n'

        result = EnvParser().parse_string(content)

        assert result.variables["BROKEN"].value == '"no closing quote'
        assert result.variables["NEXT"].value == "ok"

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

    def test_close_quote_with_trailing_junk_keeps_legacy_raw_value(self):
        """Non-comment content after the close quote disqualifies the quoted
        lexing; the legacy raw treatment is preserved."""
        content = 'K="a" trailing\n'

        result = EnvParser().parse_string(content)

        assert result.variables["K"].value == '"a" trailing'

    def test_unquoted_value_backslashes_untouched(self):
        content = "K=a\\nb\n"

        result = EnvParser().parse_string(content)

        assert result.variables["K"].value == "a\\nb"


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
