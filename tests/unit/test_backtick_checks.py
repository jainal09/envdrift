"""guard, validate and ``encrypt --check`` look inside one pair of backticks (#964).

dotenvx reads ``KEY=`value` `` as a quoted value and keeps the backticks around the
ciphertext it writes, so each check judges the value inside them, as dotenvx does.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from envdrift.core.encryption import EncryptionDetector
from envdrift.core.parser import EnvParser
from envdrift.core.schema import FieldMetadata, SchemaMetadata
from envdrift.core.validator import Validator, _collect_constraint_values
from envdrift.scanner._native_filters import (
    _content_is_encrypted,
    _encrypted_value_spans,
    _line_is_dotenvx_encrypted,
)
from envdrift.scanner.native import NativeScanner

# Built by concatenation so push protection never sees a whole secret literal.
_CIPHERTEXT = "encrypted:" + "BJcmM3MTYm+PjK7upMiPNCU1mwz76onUbudP="
_STRIPE_LIVE = "sk_" + "live_" + "0" * 24  # an obviously made-up key of the live shape
_GITHUB_TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0" + "K1l2M3n4O5p6Q7r8"  # made up, of the PAT shape
# Values the parser reads as plaintext though they start like ciphertext: dotenvx's base64
# holds no "#" (#947), and SOPS writes no backticks.
_PLAINTEXT_LOOKALIKES = [
    f"`{_CIPHERTEXT}#tail`",
    f"{_CIPHERTEXT}#tail",
    "`ENC[AES256_GCM,data:a,iv:b,tag:c,type:int]`",
]
_PLAINTEXT_LOOKALIKE_IDS = ["backticks-with-a-hash", "bare-with-a-hash", "sops-in-backticks"]


class TestGuardFilters:
    """#964.1: the native scanner's encrypted-value detection."""

    def test_backtick_ciphertext_line_is_encrypted(self) -> None:
        assert _line_is_dotenvx_encrypted(f"API_KEY=`{_CIPHERTEXT}`")

    def test_backtick_ciphertext_file_is_encrypted(self) -> None:
        assert _content_is_encrypted(f"API_KEY=`{_CIPHERTEXT}`\nPORT=`{_CIPHERTEXT}`\n")

    def test_backtick_plaintext_file_is_not_encrypted(self) -> None:
        assert not _content_is_encrypted(f"STRIPE=`{_STRIPE_LIVE}`\n")

    def test_span_covers_the_value_and_its_closing_backtick(self) -> None:
        line = f"API_KEY=`{_CIPHERTEXT}` AWS={_STRIPE_LIVE}"

        assert _encrypted_value_spans(line) == [(0, len(f"API_KEY=`{_CIPHERTEXT}`"))]

    @pytest.mark.parametrize("quote", ["`", '"', ""], ids=["backticks", "double-quotes", "bare"])
    def test_span_ends_at_a_hash(self, quote: str) -> None:
        """dotenvx's base64 holds no ``#``: the text after one is plaintext, and is scanned."""
        line = f"NOTE={quote}{_CIPHERTEXT}#{_GITHUB_TOKEN}{quote}"

        assert _encrypted_value_spans(line) == [(0, line.index("#"))]

    def test_guard_finds_a_secret_after_a_hash_in_backticks(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text(
            f"API_KEY=`{_CIPHERTEXT}`\nNOTE=`{_CIPHERTEXT}#{_GITHUB_TOKEN}`\n", encoding="utf-8"
        )

        findings = NativeScanner().scan([env_file]).findings

        assert [f.line_number for f in findings if f.rule_id == "github-pat"] == [2]


def _int_schema() -> SchemaMetadata:
    """A schema with one required ``PORT: int`` field."""
    port = FieldMetadata(
        name="PORT",
        required=True,
        sensitive=False,
        default=None,
        description=None,
        field_type=int,
        annotation="int",
    )
    return SchemaMetadata(class_name="Settings", module_path="schema_mod", fields={"PORT": port})


class TestValidator:
    """#964.2: validate skips ciphertext inside backticks, and reads plaintext inside them."""

    def test_type_check_skips_backtick_ciphertext(self) -> None:
        assert Validator()._check_type(f"`{_CIPHERTEXT}`", int) is None

    def test_type_check_reads_a_value_only_shaped_like_sops_ciphertext(self) -> None:
        """Only SOPS's ``ENC[AES256_GCM,`` envelope is its ciphertext, as everywhere else."""
        assert Validator()._check_type("ENC[AES256_GCM,data:a,iv:b,tag:c,type:int]", int) is None
        assert Validator()._check_type("ENC[not ciphertext]", int) == (
            "Expected integer, got 'ENC[not ciphertext]'"
        )

    @pytest.mark.parametrize("value", _PLAINTEXT_LOOKALIKES, ids=_PLAINTEXT_LOOKALIKE_IDS)
    def test_what_the_parser_reads_as_plaintext_is_checked(self, value: str) -> None:
        """validate skipped these as ciphertext, though the parser reads them as plaintext."""
        env = EnvParser().parse_string(f"PORT={value}\n")
        assert not env.variables["PORT"].is_encrypted
        env_by_name = {name.lower(): var for name, var in env.variables.items()}

        result = Validator().validate(env, _int_schema())

        assert Validator()._check_type(value, int) == f"Expected integer, got '{value}'"
        assert result.type_errors == {"PORT": f"Expected integer, got '{value}'"}
        assert _collect_constraint_values(_int_schema(), env_by_name) == ({"PORT": value}, set())

    def test_type_check_still_reads_a_backtick_plaintext_value(self) -> None:
        # python-dotenv keeps the backticks, so a pydantic-settings app loads "`8080`".
        assert Validator()._check_type("`8080`", int) == "Expected integer, got '`8080`'"

    def test_constraint_pass_skips_backtick_ciphertext(self) -> None:
        env = EnvParser().parse_string(f"PORT=`{_CIPHERTEXT}`\n")
        # Keyed like validate's index: lower case for a case-insensitive model.
        env_by_name = {name.lower(): var for name, var in env.variables.items()}

        values, ciphertext_fields = _collect_constraint_values(_int_schema(), env_by_name)

        assert values == {}
        assert ciphertext_fields == {"PORT"}

    def test_validate_passes_an_encrypted_int_field(self) -> None:
        env = EnvParser().parse_string(f"PORT=`{_CIPHERTEXT}`\n")

        result = Validator().validate(env, _int_schema())

        assert result.type_errors == {}
        assert result.valid

    def test_suspicious_value_inside_backticks_is_a_secret(self) -> None:
        assert Validator().is_value_suspicious(f"`{_STRIPE_LIVE}`")


class TestEncryptCheck:
    """#964.3: ``encrypt --check`` finds a plaintext secret inside backticks."""

    def test_suspicious_value_inside_backticks_is_a_secret(self) -> None:
        assert EncryptionDetector().is_value_suspicious(f"`{_STRIPE_LIVE}`")

    def test_report_lists_the_backtick_plaintext_secret(self) -> None:
        env = EnvParser().parse_string(f"STRIPE=`{_STRIPE_LIVE}`\n", lenient=True)
        detector = EncryptionDetector()

        report = detector.analyze(env)

        assert report.plaintext_secrets == {"STRIPE"}
        assert "'STRIPE' has a value that looks like a secret" in report.warnings
        assert detector.should_block_commit(report)
