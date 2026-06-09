"""Tests for EnvParser."""

import pytest

from envdrift.core.parser import EncryptionStatus, EnvParser, EnvVar


class TestEnvParser:
    """Test cases for EnvParser."""

    def test_parse_simple_env(self, tmp_path):
        """Parse KEY=value format."""
        content = "FOO=bar\nBAZ=qux"
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        parser = EnvParser()
        result = parser.parse(env_file)

        assert len(result) == 2
        assert "FOO" in result
        assert result.variables["FOO"].value == "bar"
        assert result.variables["BAZ"].value == "qux"

    def test_parse_quoted_values(self, tmp_path):
        """Parse KEY="value" and KEY='value'."""
        content = """
DOUBLE_QUOTED="hello world"
SINGLE_QUOTED='hello world'
UNQUOTED=hello
"""
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        parser = EnvParser()
        result = parser.parse(env_file)

        assert result.variables["DOUBLE_QUOTED"].value == "hello world"
        assert result.variables["SINGLE_QUOTED"].value == "hello world"
        assert result.variables["UNQUOTED"].value == "hello"

    def test_parse_encrypted_values(self, tmp_path):
        """Detect encrypted: prefix."""
        content = """
ENCRYPTED_VAR="encrypted:BDQE1234567890..."
PLAINTEXT_VAR=just_plain_text
"""
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        parser = EnvParser()
        result = parser.parse(env_file)

        assert result.variables["ENCRYPTED_VAR"].encryption_status == EncryptionStatus.ENCRYPTED
        assert result.variables["PLAINTEXT_VAR"].encryption_status == EncryptionStatus.PLAINTEXT

    def test_parse_sops_encrypted_value(self, tmp_path):
        """Detect SOPS ENC[AES256_GCM,...] values and backend."""
        content = 'SOPS_VAR="ENC[AES256_GCM,data:abc,iv:xyz,tag:123,type:str]"'
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        parser = EnvParser()
        result = parser.parse(env_file)

        env_var = result.variables["SOPS_VAR"]
        assert env_var.encryption_status == EncryptionStatus.ENCRYPTED
        assert env_var.encryption_backend == "sops"

    def test_parse_empty_values(self, tmp_path):
        """Handle KEY= (empty value)."""
        content = """
EMPTY_VAR=
EMPTY_QUOTED=""
HAS_VALUE=something
"""
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        parser = EnvParser()
        result = parser.parse(env_file)

        assert result.variables["EMPTY_VAR"].encryption_status == EncryptionStatus.EMPTY
        assert result.variables["EMPTY_QUOTED"].encryption_status == EncryptionStatus.EMPTY
        assert result.variables["HAS_VALUE"].encryption_status == EncryptionStatus.PLAINTEXT

    def test_parse_comments(self, tmp_path):
        """
        Verifies that the parser ignores comment lines and still records them.

        Asserts that only non-comment environment variables are returned in `variables`
        and that comment lines are collected in `comments`.
        """
        content = """
# This is a comment
FOO=bar
# Another comment
BAZ=qux
"""
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        parser = EnvParser()
        result = parser.parse(env_file)

        assert len(result.variables) == 2
        assert len(result.comments) == 2

    def test_parse_line_numbers(self, tmp_path):
        """Track line numbers for error reporting."""
        content = """FOO=bar

BAZ=qux
"""
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        parser = EnvParser()
        result = parser.parse(env_file)

        assert result.variables["FOO"].line_number == 1
        assert result.variables["BAZ"].line_number == 3

    def test_parse_string(self):
        """Parse from string content."""
        content = "FOO=bar\nBAZ=qux"

        parser = EnvParser()
        result = parser.parse_string(content)

        assert len(result) == 2
        assert result.variables["FOO"].value == "bar"

    def test_file_not_found(self, tmp_path):
        """Raise FileNotFoundError for missing file."""
        parser = EnvParser()

        with pytest.raises(FileNotFoundError):
            parser.parse(tmp_path / "nonexistent.env")

    def test_env_file_is_encrypted_property(self, tmp_path):
        """Test EnvFile.is_encrypted property."""
        encrypted_content = 'FOO="encrypted:BDQE123..."'
        plaintext_content = "FOO=plaintext"

        parser = EnvParser()

        enc_file = tmp_path / ".env.enc"
        enc_file.write_text(encrypted_content)
        enc_result = parser.parse(enc_file)
        assert enc_result.is_encrypted is True

        plain_file = tmp_path / ".env.plain"
        plain_file.write_text(plaintext_content)
        plain_result = parser.parse(plain_file)
        assert plain_result.is_encrypted is False

    def test_env_file_is_fully_encrypted_property(self, tmp_path):
        """Test EnvFile.is_fully_encrypted property."""
        # Fully encrypted
        full_enc = """
FOO="encrypted:abc123"
BAR="encrypted:def456"
"""
        # Partially encrypted
        partial = """
FOO="encrypted:abc123"
BAR=plaintext
"""
        parser = EnvParser()

        full_file = tmp_path / ".env.full"
        full_file.write_text(full_enc)
        assert parser.parse(full_file).is_fully_encrypted is True

        partial_file = tmp_path / ".env.partial"
        partial_file.write_text(partial)
        assert parser.parse(partial_file).is_fully_encrypted is False

    def test_env_var_properties(self):
        """Test EnvVar properties."""
        encrypted_var = EnvVar(
            name="SECRET",
            value="encrypted:abc",
            line_number=1,
            encryption_status=EncryptionStatus.ENCRYPTED,
            raw_line="SECRET=encrypted:abc",
        )
        assert encrypted_var.is_encrypted is True
        assert encrypted_var.is_empty is False

        empty_var = EnvVar(
            name="EMPTY",
            value="",
            line_number=2,
            encryption_status=EncryptionStatus.EMPTY,
            raw_line="EMPTY=",
        )
        assert empty_var.is_encrypted is False
        assert empty_var.is_empty is True

    def test_env_file_get_method(self, tmp_path):
        """Test EnvFile.get() method."""
        content = "FOO=bar"
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        parser = EnvParser()
        result = parser.parse(env_file)

        foo_var = result.get("FOO")
        assert foo_var is not None
        assert foo_var.value == "bar"
        assert result.get("NONEXISTENT") is None

    def test_env_file_contains(self, tmp_path):
        """Test EnvFile.__contains__() method."""
        content = "FOO=bar"
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        parser = EnvParser()
        result = parser.parse(env_file)

        assert "FOO" in result
        assert "NONEXISTENT" not in result

    def test_parse_export_prefix(self, tmp_path):
        """#351: `export KEY=value` is parsed; plain assignment still works."""
        # Fake secret via concatenation to dodge push-protection.
        fake = "sk-" + "live-" + "0123456789abcdef"
        content = f"export SECRET={fake}\nPLAIN=keep\n"
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        result = EnvParser().parse(env_file)

        assert "SECRET" in result.variables
        assert result.variables["SECRET"].value == fake
        assert result.variables["PLAIN"].value == "keep"

    def test_parse_export_with_quotes(self, tmp_path):
        """#351: `export KEY="value"` unquotes correctly."""
        content = 'export TOKEN="hello world"\n'
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        result = EnvParser().parse(env_file)
        assert result.variables["TOKEN"].value == "hello world"

    def test_parse_export_does_not_strip_glued_name(self, tmp_path):
        """#351: `exportFOO=bar` keeps the glued name (real whitespace required)."""
        content = "exportFOO=bar\nEXPORTED=1\n"
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        result = EnvParser().parse(env_file)
        assert "exportFOO" in result.variables
        assert result.variables["exportFOO"].value == "bar"
        assert result.variables["EXPORTED"].value == "1"

    def test_parse_inline_comment_int(self, tmp_path):
        """#357: `PORT=8080 # comment` yields a clean, int-valid value."""
        content = "PORT=8080 # http port\n"
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        result = EnvParser().parse(env_file)
        value = result.variables["PORT"].value
        assert value == "8080"
        assert value.isdigit()  # init_cmd.py infers `int` from this

    def test_parse_inline_comment_tab_separated(self, tmp_path):
        """#357: any whitespace (e.g. a tab) before `#` delimits a comment."""
        content = "A=a\t# tab comment\n"
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        result = EnvParser().parse(env_file)
        assert result.variables["A"].value == "a"

    def test_parse_inline_comment_hash_in_quotes_preserved(self, tmp_path):
        """#357: `#` inside a quoted value is NOT treated as a comment."""
        content = 'GREETING="hi # there"\n'
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        result = EnvParser().parse(env_file)
        assert result.variables["GREETING"].value == "hi # there"

    def test_parse_inline_comment_hash_in_single_quotes_preserved(self, tmp_path):
        """#357: `#` inside a SINGLE-quoted value is NOT a comment (single-quote path)."""
        content = "GREETING='hi # there' # trailing\n"
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        result = EnvParser().parse(env_file)
        assert result.variables["GREETING"].value == "hi # there"

    def test_parse_inline_comment_quoted_url_with_fragment(self, tmp_path):
        """#357: a quoted URL keeps its `#frag` (quotes protect the hash)."""
        content = 'API="https://x.test/path#frag"\n'
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        result = EnvParser().parse(env_file)
        assert result.variables["API"].value == "https://x.test/path#frag"

    def test_parse_inline_comment_glued_hash_preserved(self, tmp_path):
        """#357: a `#` glued to a token (no preceding space) is preserved."""
        content = "URL=http://x#frag\nMIXED=a#b # c\n"
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        result = EnvParser().parse(env_file)
        # No whitespace before the first `#`, so the URL fragment survives.
        assert result.variables["URL"].value == "http://x#frag"
        # First `#` is glued (kept); the second, space-preceded `#` is a comment.
        assert result.variables["MIXED"].value == "a#b"

    def test_parse_value_starting_with_hash_not_zeroed(self, tmp_path):
        """#357 regression: a value that BEGINS with `#` (e.g. a hex color) is a
        value, not a comment, and must not be silently zeroed."""
        content = "COLOR=#FF0000\nALSO=#123 # real comment\nEMPTY=  # just a comment\n"
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        result = EnvParser().parse(env_file)
        assert result.variables["COLOR"].value == "#FF0000"
        # leading `#` value kept; the later space-preceded `#` is the comment.
        assert result.variables["ALSO"].value == "#123"
        # value is only whitespace + a space-preceded comment -> empty.
        assert result.variables["EMPTY"].value == ""

    def test_parse_inline_comment_escaped_quote(self, tmp_path):
        """#357: an escaped quote does not toggle quote state, so a `#` inside the
        quoted span stays protected."""
        content = 'Q="a \\" # b"\n'
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        result = EnvParser().parse(env_file)
        # The `\"` is escaped (quote stays open), so the `#` is inside quotes.
        assert "#" in result.variables["Q"].value

    def test_parse_inline_comment_only_is_empty(self, tmp_path):
        """#357: a value that is only a comment collapses to EMPTY."""
        content = "ONLY=   # just a comment\n"
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        result = EnvParser().parse(env_file)
        assert result.variables["ONLY"].value == ""
        assert result.variables["ONLY"].encryption_status == EncryptionStatus.EMPTY

    def test_parse_inline_comment_after_quoted_encrypted_value(self, tmp_path):
        """#357: comment stripped BEFORE unquote, so `encrypted:` is detected.

        `"encrypted:..." # note` does not end in a quote, so without stripping
        the comment first `_unquote` is a no-op and the value is misclassified
        PLAINTEXT. Stripping the comment yields `"encrypted:..."` -> unquoted to
        `encrypted:...` -> correctly ENCRYPTED/dotenvx.
        """
        # Build the fake encrypted payload via concatenation.
        payload = "encrypted:" + "BA0123456789abcdef"
        content = f'KEY="{payload}" # rotate me\n'
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        result = EnvParser().parse(env_file)
        env_var = result.variables["KEY"]
        assert env_var.value == payload
        assert env_var.encryption_status == EncryptionStatus.ENCRYPTED
        assert env_var.encryption_backend == "dotenvx"


class TestLenientParsing:
    """#443: parse(lenient=True) recovers non-identifier / non-ASCII keys the
    strict pattern rejects; the default parse stays strict."""

    CONTENT = "OK_KEY=1\n2FA_ENABLED=x\nX-API-KEY=y\nCAFÉ=z\n"

    def test_strict_default_drops_non_identifier_keys(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text(self.CONTENT, encoding="utf-8")
        env = EnvParser().parse(env_file)
        assert set(env.variables) == {"OK_KEY"}

    def test_lenient_recovers_non_identifier_and_unicode_keys(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text(self.CONTENT, encoding="utf-8")
        env = EnvParser().parse(env_file, lenient=True)
        assert set(env.variables) == {"OK_KEY", "2FA_ENABLED", "X-API-KEY", "CAFÉ"}
        # Values are unquoted exactly as strict parsing would.
        assert env.variables["X-API-KEY"].value == "y"
        assert env.variables["CAFÉ"].value == "z"
