"""Regression tests for #486: parser edge cases match python-dotenv.

``EnvParser`` (the engine behind ``validate`` and ``diff``) diverged from
python-dotenv / pydantic-settings — the ground truth for what an application
actually loads — in five edge cases:

- ``${VAR}`` references were never expanded, so ``validate`` type-checked the
  literal and failed configs the real loader accepts.
- A mid-token apostrophe in an unquoted value (``user's data # comment``)
  toggled quote state in the old comment-stripping scan and disabled
  inline-comment stripping for the rest of the line; and a value that was
  only whitespace + ``# comment`` was zeroed to ``""`` where python-dotenv
  loads the whole ``# comment`` text (#537).
- Double-quoted escape sequences (``\\n``, ``\\t``, ...) — fixed by the #458
  quoted-value lexer; pinned here with the original #486 repros.
- Unicode line boundaries (U+2028, form feed, NEL, ...) inside a value split
  it into phantom variables via ``str.splitlines()``.
- A UTF-8 BOM was kept as part of the first key, producing an invisible
  phantom ``\\ufeffNAME`` variable.

Each class pins the corrected semantics, and ``TestPythonDotenvParity`` checks
byte-for-byte agreement with the real ``dotenv.dotenv_values`` /
pydantic-settings loading the same files in-process.
"""

from __future__ import annotations

import pytest
from dotenv import dotenv_values

from envdrift.core.parser import EncryptionStatus, EnvParser


def _values(env_file) -> dict[str, str]:
    """Plain ``{name: value}`` view of a parsed EnvFile."""
    return {name: var.value for name, var in env_file.variables.items()}


class TestInterpolation:
    """#486: ``${VAR}`` references expand exactly like dotenv_values."""

    def test_braced_reference_expands_from_file_value(self):
        """Issue repro: ``PORT=${OFFSET}234`` is 1234 to pydantic-settings."""
        result = EnvParser().parse_string("OFFSET=1\nPORT=${OFFSET}234\n")

        assert _values(result) == {"OFFSET": "1", "PORT": "1234"}

    def test_reference_expands_inside_quoted_values(self):
        """python-dotenv interpolates single- AND double-quoted values."""
        content = "A_REF=x\nB_REF='${A_REF}'\nC_REF=\"${A_REF}\"\n"

        result = EnvParser().parse_string(content)

        assert _values(result) == {"A_REF": "x", "B_REF": "x", "C_REF": "x"}

    def test_unset_name_uses_default_or_empty(self, monkeypatch):
        monkeypatch.delenv("ENVDRIFT_REF_UNSET", raising=False)
        content = "A=${ENVDRIFT_REF_UNSET:-fallback}\nB=${ENVDRIFT_REF_UNSET}\n"

        result = EnvParser().parse_string(content)

        assert _values(result) == {"A": "fallback", "B": ""}

    def test_file_value_wins_over_os_environ(self, monkeypatch):
        """dotenv_values resolves with override=True: file > os.environ."""
        monkeypatch.setenv("ENVDRIFT_REF_DUP", "os-val")
        content = "ENVDRIFT_REF_DUP=file-val\nB=${ENVDRIFT_REF_DUP}\n"

        result = EnvParser().parse_string(content)

        assert result.variables["B"].value == "file-val"

    def test_os_environ_is_the_fallback(self, monkeypatch):
        monkeypatch.setenv("ENVDRIFT_REF_OS", "from-os")

        result = EnvParser().parse_string("A=${ENVDRIFT_REF_OS}\n")

        assert result.variables["A"].value == "from-os"

    def test_resolution_is_sequential(self, monkeypatch):
        """A forward reference resolves to '' — python-dotenv resolves in
        file order, so later definitions don't affect earlier values."""
        monkeypatch.delenv("ENVDRIFT_REF_LATER", raising=False)
        content = "A=${ENVDRIFT_REF_LATER}\nENVDRIFT_REF_LATER=set-later\n"

        result = EnvParser().parse_string(content)

        assert _values(result) == {"A": "", "ENVDRIFT_REF_LATER": "set-later"}

    def test_chained_references_resolve_transitively(self):
        content = "C_BASE=base\nB_MID=${C_BASE}x\nA_TOP=${B_MID}y\n"

        result = EnvParser().parse_string(content)

        assert _values(result) == {"C_BASE": "base", "B_MID": "basex", "A_TOP": "basexy"}

    def test_replacement_text_is_not_re_expanded(self, monkeypatch):
        """python-dotenv parses atoms from the original value only; a
        resolved value containing ``${...}`` stays literal."""
        monkeypatch.setenv("ENVDRIFT_REF_LIT", "${NOPE}")

        result = EnvParser().parse_string("A=${ENVDRIFT_REF_LIT}\n")

        assert result.variables["A"].value == "${NOPE}"

    def test_unbraced_dollar_is_literal(self):
        """Only ``${...}`` interpolates — ``$NAME`` stays literal."""
        result = EnvParser().parse_string("A_REF=x\nB_REF=$A_REF\n")

        assert result.variables["B_REF"].value == "$A_REF"

    def test_reference_inside_multiline_value_expands(self):
        content = 'A_REF=x\nB_REF="line1\n${A_REF}line2"\n'

        result = EnvParser().parse_string(content)

        assert result.variables["B_REF"].value == "line1\nxline2"

    def test_environ_lookup_is_case_sensitive(self, monkeypatch):
        """python-dotenv snapshots ``os.environ`` into a plain dict and looks
        names up case-SENSITIVELY, so a mixed-case ``${name}`` misses even on
        Windows (where ``os.environ.get`` itself is case-insensitive because
        ``os._Environ`` upper-cases keys). The parser must resolve through a
        dict snapshot, not ``os.environ.get``, or ``${path}``-style references
        expand here but not in pydantic-settings (#486 review)."""
        monkeypatch.setenv("ENVDRIFT_REF_CASE", "set-upper")

        result = EnvParser().parse_string(
            "A=${envdrift_ref_case:-fell-back}\nB=${ENVDRIFT_REF_CASE}\n"
        )

        assert result.variables["A"].value == "fell-back"
        assert result.variables["B"].value == "set-upper"

    def test_alias_of_encrypted_value_inherits_encrypted_status(self):
        """Deliberate semantics (#486 review): ``B=${A}`` with ``A`` encrypted
        resolves to the ciphertext string and is classified ENCRYPTED. The
        file stores only the reference — no plaintext secret on disk — and
        classifying it PLAINTEXT would make encrypt/lock re-encrypt the
        literal ``${A}`` on every run."""
        content = 'A="encrypted:BDqDBibm4wsYqMpCjTQ46bkAqI4Kd"\nB=${A}\n'

        result = EnvParser().parse_string(content)

        alias = result.variables["B"]
        assert alias.value.startswith("encrypted:")
        assert alias.encryption_status == EncryptionStatus.ENCRYPTED
        assert alias.encryption_backend == "dotenvx"


class TestInlineCommentQuoteState:
    """#486: a mid-token quote in an unquoted value never opens a quote
    context, so inline-comment stripping keeps working (python-dotenv)."""

    def test_apostrophe_does_not_disable_comment_stripping(self):
        """Issue repro: ``MSG=user's data # comment`` equals ``user's data``."""
        result = EnvParser().parse_string("MSG=user's data # comment\n")

        assert result.variables["MSG"].value == "user's data"

    def test_multiple_apostrophes_natural_language(self):
        result = EnvParser().parse_string("LINE=it's O'Brien's # note\n")

        assert result.variables["LINE"].value == "it's O'Brien's"

    def test_mid_value_double_quote_does_not_protect_hash(self):
        """python-dotenv lexes a value that does not OPEN with a quote as
        unquoted: the first whitespace-preceded ``#`` starts the comment even
        past a mid-value quote."""
        result = EnvParser().parse_string('A=a "b # c" d\n')

        assert result.variables["A"].value == 'a "b'

    def test_existing_hash_protections_still_hold(self):
        """Leading-``#`` values and glued fragments are still values."""
        content = "COLOR=#FF0000\nURL=http://x#frag\nMIXED=a#b # c\n"

        result = EnvParser().parse_string(content)

        assert result.variables["COLOR"].value == "#FF0000"
        assert result.variables["URL"].value == "http://x#frag"
        assert result.variables["MIXED"].value == "a#b"

    def test_cleanly_quoted_value_still_protects_hash(self):
        """A value that opens AND closes with a quote keeps its ``#``."""
        result = EnvParser().parse_string("GREETING='hi # there' # trailing\n")

        assert result.variables["GREETING"].value == "hi # there"

    @pytest.mark.parametrize(
        "content",
        [
            pytest.param('K="a # b" trailing\n', id="junk-after-close-quote"),
            pytest.param('K="a" junk # comment\n', id="junk-then-comment"),
            pytest.param('K="open # tail\n', id="unterminated-quote"),
            pytest.param('K="a \\" # b" x\n', id="escaped-quote-then-junk"),
        ],
    )
    def test_malformed_quoted_binding_is_dropped(self, content):
        """A binding that OPENS with a quote but does not terminate cleanly is
        dropped whole, exactly like python-dotenv (#458 rewrite). Ground truth
        (python-dotenv 1.2.2): ``dotenv_values`` returns ``{}`` for every one
        of these shapes — its quoted-value lexer commits to the quote branch
        and the error path registers nothing."""
        result = EnvParser().parse_string(content)

        assert "K" not in result.variables


class TestValueFromRawDirectCallers:
    """``value_from_raw`` is public API: ``parse_string`` drops malformed
    quoted bindings before ever calling it (dotenv parity), but a direct
    caller passing one gets the legacy best-effort value — quote-aware
    comment strip, then strip, then one pair of surrounding quotes."""

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            pytest.param('"a # b" trailing', '"a # b" trailing', id="hash-inside-quotes-kept"),
            pytest.param('"a" junk # comment', '"a" junk', id="comment-after-quoted-span-cut"),
            pytest.param('"open # tail', '"open # tail', id="unterminated-quote-protects-hash"),
            pytest.param('"a \\" # b" x', '"a \\" # b" x', id="escaped-quote-does-not-toggle"),
            pytest.param('"a" x "b"', 'a" x "b', id="surrounding-quote-pair-stripped"),
        ],
    )
    def test_malformed_quoted_value_best_effort(self, raw, expected):
        assert EnvParser().value_from_raw(raw) == expected


class TestUnquotedLeadingCommentValue:
    """#537: an unquoted value that STARTS with ``#`` after the post-``=``
    whitespace is value content, never a comment.

    python-dotenv's ``_equal_sign`` lexer (``=[^\\S\\r\\n]*``) consumes the
    whitespace after ``=`` before the value is lexed, so the ``#`` has no
    preceding whitespace inside the value and the comment rule
    (``\\s+#.*``) never strips it. Ground truth (python-dotenv 1.2.2)::

        dotenv_values("K= # c\\nEMPTY=  # just a comment\\n")
        == {'K': '# c', 'EMPTY': '# just a comment'}
    """

    def test_issue_repro_whole_trailing_text_is_the_value(self):
        result = EnvParser().parse_string("K= # c\nEMPTY=  # just a comment\n")

        assert _values(result) == {"K": "# c", "EMPTY": "# just a comment"}

    def test_status_is_plaintext_not_empty(self):
        """The real loader receives ``'# c'`` — a non-empty value — so the
        variable must not be classified EMPTY (validate/encrypt semantics)."""
        result = EnvParser().parse_string("K= # c\n")

        assert result.variables["K"].encryption_status == EncryptionStatus.PLAINTEXT

    def test_tab_and_space_mix_before_hash(self):
        """``K= \\t # c # d``: dotenv_values yields ``'# c'`` — the leading
        whitespace is consumed, then the SECOND (whitespace-preceded) ``#``
        starts the comment."""
        result = EnvParser().parse_string("K= \t # c # d\n")

        assert result.variables["K"].value == "# c"

    def test_value_then_comment_still_stripped(self):
        """``K= v # c`` is ``'v'`` (dotenv_values) — consuming the post-``=``
        whitespace must not break ordinary inline comments."""
        result = EnvParser().parse_string("K= v # c\n")

        assert result.variables["K"].value == "v"


class TestQuotedEscapeDecoding:
    """#486 item already fixed by the #458 quoted-value lexer — pinned here
    with the original issue repros so it cannot regress."""

    def test_issue_repro_tab_escape_decoded(self):
        result = EnvParser().parse_string('MSG="tab\\there"\n')

        assert result.variables["MSG"].value == "tab\there"

    def test_length_constraints_see_the_decoded_value(self):
        """``TOKEN="abc\\ndef"`` is 7 chars to pydantic (min_length=8 must
        reject it) — not the 8-char literal."""
        result = EnvParser().parse_string('TOKEN="abc\\ndef"\n')

        value = result.variables["TOKEN"].value
        assert value == "abc\ndef"
        assert len(value) == 7


class TestUnicodeLineBoundaries:
    """#486: values split on ``\\n``/``\\r\\n``/``\\r`` ONLY — the wider
    ``str.splitlines()`` set fabricated phantom variables."""

    def test_u2028_stays_inside_the_value(self):
        """Issue repro: U+2028 inside a value is value content, not a line
        break that fabricates a phantom SECRET_PASSWORD variable."""
        content = "NOTE=part1\u2028SECRET_PASSWORD=hunter2\n"

        result = EnvParser().parse_string(content)

        assert set(result.variables) == {"NOTE"}
        assert result.variables["NOTE"].value == "part1\u2028SECRET_PASSWORD=hunter2"

    @pytest.mark.parametrize(
        "boundary",
        [
            pytest.param("\x0c", id="form-feed"),
            pytest.param("\x0b", id="vertical-tab"),
            pytest.param("\x85", id="next-line"),
            pytest.param("\u2029", id="paragraph-separator"),
            pytest.param("\x1c", id="file-separator"),
        ],
    )
    def test_exotic_boundaries_stay_inside_the_value(self, boundary):
        content = f"NOTE=part1{boundary}TAIL=x\n"

        result = EnvParser().parse_string(content)

        assert set(result.variables) == {"NOTE"}
        assert result.variables["NOTE"].value == f"part1{boundary}TAIL=x"

    def test_real_newline_variants_still_split(self):
        result = EnvParser().parse_string("A=1\r\nB=2\rC=3\nD=4")

        assert _values(result) == {"A": "1", "B": "2", "C": "3", "D": "4"}


class TestUtf8Bom:
    """#486: a UTF-8 BOM is an encoding artifact, not part of the first key."""

    BOM_CONTENT = b"\xef\xbb\xbfAPI_KEY=abc123\n"

    def test_parse_strips_bom_from_first_key(self, tmp_path):
        env_path = tmp_path / "bom.env"
        env_path.write_bytes(self.BOM_CONTENT)

        result = EnvParser().parse(env_path)

        assert set(result.variables) == {"API_KEY"}
        assert result.variables["API_KEY"].value == "abc123"

    def test_lenient_parse_has_no_phantom_bom_key(self, tmp_path):
        """``validate`` parses lenient=True; the BOM-prefixed key used to
        surface as an invisible phantom EXTRA while the clean name was
        simultaneously MISSING."""
        env_path = tmp_path / "bom.env"
        env_path.write_bytes(self.BOM_CONTENT)

        result = EnvParser().parse(env_path, lenient=True)

        assert set(result.variables) == {"API_KEY"}

    def test_parse_string_strips_a_leading_bom(self):
        result = EnvParser().parse_string("\ufeffAPI_KEY=abc123\n")

        assert set(result.variables) == {"API_KEY"}

    def test_bom_twin_parses_identically(self, tmp_path):
        """The BOM file and its BOM-less twin must parse to the same
        variables — ``diff`` reported phantom drift between them."""
        bom = tmp_path / "bom.env"
        plain = tmp_path / "plain.env"
        bom.write_bytes(self.BOM_CONTENT)
        plain.write_bytes(self.BOM_CONTENT[3:])

        parser = EnvParser()

        assert _values(parser.parse(bom)) == _values(parser.parse(plain))

    def test_bom_inside_a_value_is_kept(self, tmp_path):
        """Only a LEADING BOM is an encoding artifact; U+FEFF inside a value
        is content."""
        env_path = tmp_path / ".env"
        env_path.write_bytes(b"A=x\xef\xbb\xbfy\n")

        result = EnvParser().parse(env_path)

        assert result.variables["A"].value == "x\ufeffy"

    def test_leading_bom_is_recorded_on_the_env_file(self, tmp_path):
        """The stripped BOM is recorded so ``validate`` can warn: the real
        loader (plain UTF-8 ``dotenv_values``) still sees the BOM-prefixed
        key, so silence here would be a false green (#486 review)."""
        bom = tmp_path / "bom.env"
        plain = tmp_path / "plain.env"
        bom.write_bytes(self.BOM_CONTENT)
        plain.write_bytes(self.BOM_CONTENT[3:])

        parser = EnvParser()

        assert parser.parse(bom).leading_bom is True
        assert parser.parse(plain).leading_bom is False

    def test_bom_inside_a_value_does_not_set_the_flag(self, tmp_path):
        env_path = tmp_path / ".env"
        env_path.write_bytes(b"A=x\xef\xbb\xbfy\n")

        assert EnvParser().parse(env_path).leading_bom is False

    def test_validator_warns_on_leading_bom(self, tmp_path):
        """A BOM file otherwise valid must PASS with a warning naming the BOM
        (pydantic-settings would fail the required field at startup)."""
        from envdrift.core.schema import SchemaLoader
        from envdrift.core.validator import Validator

        schema_file = tmp_path / "sc.py"
        schema_file.write_text(
            "from pydantic_settings import BaseSettings\n\n"
            "class Settings(BaseSettings):\n    API_KEY: str\n",
            encoding="utf-8",
        )
        env_path = tmp_path / "bom.env"
        env_path.write_bytes(self.BOM_CONTENT)

        settings_cls = SchemaLoader().load("sc:Settings", tmp_path)
        schema_meta = SchemaLoader().extract_metadata(settings_cls)
        env = EnvParser().parse(env_path, lenient=True)

        result = Validator().validate(env, schema_meta, check_encryption=False)

        assert result.valid
        assert any("UTF-8 BOM" in w for w in result.warnings)


class TestPythonDotenvParity:
    """Byte-for-byte parity with the real python-dotenv / pydantic-settings."""

    # Every name referenced by the fixtures below, scrubbed from os.environ so
    # both loaders resolve interpolation deterministically.
    SCRUBBED_NAMES = (
        "OFFSET",
        "PORT",
        "MSG",
        "TOKEN",
        "NOTE",
        "TAIL",
        "A_REF",
        "B_REF",
        "C_REF",
        "ENVDRIFT_PARITY_UNSET",
        "a_ref",
        "FWD",
        "LATER",
        "EMPTY_NAME",
        "K",
        "EMPTY",
    )

    @pytest.fixture(autouse=True)
    def _scrub_env(self, monkeypatch):
        for name in self.SCRUBBED_NAMES:
            monkeypatch.delenv(name, raising=False)

    @pytest.mark.parametrize(
        "content",
        [
            pytest.param("OFFSET=1\nPORT=${OFFSET}234\n", id="interpolation-basic"),
            pytest.param(
                "A_REF=x\nB_REF='${A_REF}'\nC_REF=\"${A_REF}\"\nPORT=pre${A_REF}post\n",
                id="interpolation-quoting-shapes",
            ),
            pytest.param(
                "A_REF=${ENVDRIFT_PARITY_UNSET:-fallback}\nB_REF=${ENVDRIFT_PARITY_UNSET}\n",
                id="interpolation-defaults",
            ),
            pytest.param("FWD=${LATER}\nLATER=set-later\n", id="interpolation-forward-ref"),
            pytest.param("EMPTY_NAME=${}\n", id="interpolation-empty-name"),
            pytest.param(
                "A_REF=set\nB_REF=${a_ref:-fell-back}\n",
                id="interpolation-mixed-case-name",
            ),
            pytest.param("A_REF=x\nB_REF=$A_REF\n", id="unbraced-dollar-literal"),
            pytest.param("MSG=user's data # comment\n", id="apostrophe-inline-comment"),
            pytest.param(
                "K= # c\nEMPTY=  # just a comment\n",
                id="leading-hash-after-equals-is-the-value",
            ),
            pytest.param("K= \t # c # d\nMSG= v # c\n", id="post-equals-whitespace-comment"),
            pytest.param("MSG=it's O'Brien's # note\n", id="multi-apostrophe-comment"),
            pytest.param('MSG=a "b # c" d\n', id="mid-value-quote-comment"),
            pytest.param('MSG="tab\\there"\nTOKEN="abc\\ndef"\n', id="double-quoted-escapes"),
            pytest.param("NOTE=part1\u2028SECRET_PASSWORD=hunter2\n", id="u2028-inside-value"),
            pytest.param("NOTE=part1\x0cTAIL=x\n", id="form-feed-inside-value"),
            pytest.param("A_REF=1\r\nB_REF=2\rC_REF=3\n", id="newline-variants"),
        ],
    )
    def test_parsed_values_match_python_dotenv(self, tmp_path, content):
        env_path = tmp_path / ".env"
        env_path.write_text(content, encoding="utf-8", newline="")

        parsed = _values(EnvParser().parse(env_path))

        assert parsed == dict(dotenv_values(env_path))

    def test_pydantic_settings_loads_interpolated_port(self, tmp_path):
        """The issue's headline repro: a real pydantic-settings class loads
        PORT=${OFFSET}234 as the int 1234 — the parser must see '1234'."""
        from pydantic_settings import BaseSettings, SettingsConfigDict

        env_path = tmp_path / ".env"
        env_path.write_text("OFFSET=1\nPORT=${OFFSET}234\n", encoding="utf-8")

        class Settings(BaseSettings):
            model_config = SettingsConfigDict(
                env_file=str(env_path), env_file_encoding="utf-8", extra="ignore"
            )

            PORT: int

        loaded = Settings()
        parsed = EnvParser().parse(env_path)

        assert loaded.PORT == 1234
        assert parsed.variables["PORT"].value == "1234"

    def test_u2028_value_matches_pydantic_settings(self, tmp_path):
        """pydantic-settings loads the U+2028 line as ONE variable; so must
        the parser (no phantom SECRET_PASSWORD extra)."""
        from pydantic_settings import BaseSettings, SettingsConfigDict

        env_path = tmp_path / ".env"
        env_path.write_text(
            "NOTE=part1\u2028SECRET_PASSWORD=hunter2\n", encoding="utf-8", newline=""
        )

        class Settings(BaseSettings):
            model_config = SettingsConfigDict(
                env_file=str(env_path), env_file_encoding="utf-8", extra="forbid"
            )

            NOTE: str

        loaded = Settings()
        parsed = EnvParser().parse(env_path)

        assert parsed.variables["NOTE"].value == loaded.NOTE
        assert loaded.NOTE == "part1\u2028SECRET_PASSWORD=hunter2"

    def test_bom_divergence_from_python_dotenv_is_deliberate(self, tmp_path):
        """python-dotenv (and pydantic-settings) keep ``\\ufeffAPI_KEY`` as
        the key; envdrift strips the encoding artifact instead (#486) so its
        reports name the variable the user actually wrote. The divergence is
        not silent: ``EnvFile.leading_bom`` is set and ``validate`` warns
        (see ``TestUtf8Bom.test_validator_warns_on_leading_bom``)."""
        env_path = tmp_path / "bom.env"
        env_path.write_bytes(b"\xef\xbb\xbfAPI_KEY=abc123\n")

        parsed = EnvParser().parse(env_path)

        assert _values(parsed) == {"API_KEY": "abc123"}
        assert parsed.leading_bom is True
        assert dict(dotenv_values(env_path)) == {"\ufeffAPI_KEY": "abc123"}
