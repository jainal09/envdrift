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

        assert result.get("FOO") is not None
        assert result.get("FOO").value == "bar"
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
