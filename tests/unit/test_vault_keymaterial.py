"""Tests for the centralized vault key-material normalization/validation (#480).

``envdrift.vault.keymaterial`` is the single place where key material fetched
from any vault provider is normalized (quotes/whitespace/prefix/JSON documents/
multi-line keys blobs) and shape-validated before it may be installed into a
``.env.keys`` file. These tests drive the real functions directly — there is no
behavior to mock.
"""

from __future__ import annotations

import json

import pytest

from envdrift.vault.base import SecretValue, VaultError
from envdrift.vault.keymaterial import (
    KeyMaterialError,
    extract_key_material,
    normalize_vault_key_value,
    validate_key_material,
)

# A realistic-looking (but fake) dotenvx private key, built by concatenation so
# secret scanners / push protection never see a credential-shaped literal.
FAKE_KEY = "ec" + "0123456789abcdef" * 3 + "0123456789abcd"


class TestNormalizeSingleLine:
    """Single-line values: pre-#480 behavior must be preserved."""

    def test_bare_value_passthrough(self):
        assert normalize_vault_key_value("abc123") == ("abc123", None)

    def test_strips_whitespace_and_quotes(self):
        assert normalize_vault_key_value('  "abc123"  ') == ("abc123", None)

    def test_quoted_full_line_strips_prefix(self):
        assert normalize_vault_key_value(f'"DOTENV_PRIVATE_KEY_PRODUCTION={FAKE_KEY}"') == (
            FAKE_KEY,
            "PRODUCTION",
        )

    def test_inner_quoted_prefixed_value(self):
        assert normalize_vault_key_value("DOTENV_PRIVATE_KEY_PROD='abc123'") == (
            "abc123",
            "PROD",
        )

    def test_opaque_value_with_equals_is_untouched(self):
        assert normalize_vault_key_value("opaque=keymaterial") == ("opaque=keymaterial", None)

    def test_empty_value_key_line_yields_empty_value(self):
        # `vault kv put ... DOTENV_PRIVATE_KEY_PRODUCTION=$KEY` with $KEY unset:
        # the line must parse (empty value + suffix) so validate_key_material
        # rejects it, not fall through as an "opaque" value that gets written
        # back as a doubled DOTENV_PRIVATE_KEY prefix (#480).
        assert normalize_vault_key_value("DOTENV_PRIVATE_KEY_PRODUCTION=") == ("", "PRODUCTION")


class TestNormalizeJsonDocument:
    """JSON key/value documents (the AWS-console native storage shape)."""

    def test_extracts_sole_dotenv_field(self):
        raw = f'{{"DOTENV_PRIVATE_KEY_PRODUCTION": "{FAKE_KEY}"}}'
        assert normalize_vault_key_value(raw) == (FAKE_KEY, "PRODUCTION")

    def test_extracts_expected_field_among_many(self):
        raw = (
            f'{{"DOTENV_PRIVATE_KEY_STAGING": "other", '
            f'"DOTENV_PRIVATE_KEY_PRODUCTION": "{FAKE_KEY}"}}'
        )
        assert normalize_vault_key_value(raw, "production") == (FAKE_KEY, "PRODUCTION")

    def test_single_value_field_is_recursed(self):
        raw = f'{{"value": "DOTENV_PRIVATE_KEY_PRODUCTION={FAKE_KEY}"}}'
        assert normalize_vault_key_value(raw, "production") == (FAKE_KEY, "PRODUCTION")

    def test_document_without_usable_field_raises_naming_layout(self):
        with pytest.raises(KeyMaterialError, match="JSON key/value document") as exc_info:
            normalize_vault_key_value('{"username": "admin", "password": "hunter2"}')
        # The error names the field layout but never leaks the values.
        assert "username" in str(exc_info.value)
        assert "password" in str(exc_info.value)
        assert "hunter2" not in str(exc_info.value)

    def test_multiple_dotenv_fields_without_expected_env_raises(self):
        raw = '{"DOTENV_PRIVATE_KEY_STAGING": "a", "DOTENV_PRIVATE_KEY_PRODUCTION": "b"}'
        with pytest.raises(KeyMaterialError, match="JSON key/value document"):
            normalize_vault_key_value(raw)

    def test_json_array_raises(self):
        with pytest.raises(KeyMaterialError, match="JSON"):
            normalize_vault_key_value('["a", "b"]')

    def test_invalid_json_starting_with_brace_falls_through(self):
        # Not actually JSON: returned as-is (validate_key_material rejects later).
        value, suffix = normalize_vault_key_value("{broken")
        assert value == "{broken"
        assert suffix is None

    def test_pretty_printed_json_extracts_key(self):
        # Pretty-printed JSON (json.dumps(..., indent=2) / `az keyvault secret
        # set --file doc.json`) contains newlines; it must reach the JSON
        # handler, not be misrouted to the keys-blob handler and fail with a
        # misleading "no DOTENV_PRIVATE_KEY line" error.
        raw = json.dumps({"DOTENV_PRIVATE_KEY_PRODUCTION": FAKE_KEY}, indent=2)
        assert normalize_vault_key_value(raw, "production") == (FAKE_KEY, "PRODUCTION")

    def test_multiline_non_json_starting_with_brace_falls_back_to_blob(self):
        # A multi-line non-JSON value whose first line starts with "{" still
        # reaches the keys-blob handler after the JSON parse fails.
        raw = "{\n" + f"DOTENV_PRIVATE_KEY_PRODUCTION={FAKE_KEY}\n" + "}\n"
        assert normalize_vault_key_value(raw, "production") == (FAKE_KEY, "PRODUCTION")

    def test_field_value_carrying_full_line_is_prefix_stripped(self):
        # A whole .env.keys line copy-pasted into the console value box: the
        # redundant DOTENV_PRIVATE_KEY_<ENV>= prefix must come off, or the
        # doubled-prefix line is written to .env.keys under exit 0 (#480).
        raw = json.dumps(
            {"DOTENV_PRIVATE_KEY_PRODUCTION": f"DOTENV_PRIVATE_KEY_PRODUCTION={FAKE_KEY}"}
        )
        assert normalize_vault_key_value(raw, "production") == (FAKE_KEY, "PRODUCTION")

    def test_field_value_with_conflicting_prefix_is_not_stripped(self):
        # A field value labeled for a *different* environment is left intact
        # (validate_key_material rejects it) rather than silently installed.
        raw = json.dumps({"DOTENV_PRIVATE_KEY_PRODUCTION": "DOTENV_PRIVATE_KEY_STAGING=abc123"})
        value, suffix = normalize_vault_key_value(raw, "production")
        assert value == "DOTENV_PRIVATE_KEY_STAGING=abc123"
        assert suffix == "PRODUCTION"
        with pytest.raises(KeyMaterialError, match="prefix"):
            validate_key_material(value, secret_name="s")


class TestNormalizeMultilineBlob:
    """Whole ``.env.keys`` file contents stored as the secret value."""

    BLOB = (
        "#/------------------!DOTENV_PRIVATE_KEYS!-------------------/\n"
        "#/ private decryption keys. DO NOT commit to source control /\n"
        "\n"
        "# .env.production\n"
        f'DOTENV_PRIVATE_KEY_PRODUCTION="{FAKE_KEY}"\n'
    )

    def test_extracts_key_line_from_keys_file_blob(self):
        assert normalize_vault_key_value(self.BLOB, "production") == (FAKE_KEY, "PRODUCTION")

    def test_extracts_sole_key_line_without_expected_env(self):
        assert normalize_vault_key_value(self.BLOB) == (FAKE_KEY, "PRODUCTION")

    def test_picks_matching_line_among_multiple(self):
        blob = self.BLOB + "# .env.staging\nDOTENV_PRIVATE_KEY_STAGING=otherkey\n"
        assert normalize_vault_key_value(blob, "production") == (FAKE_KEY, "PRODUCTION")
        assert normalize_vault_key_value(blob, "staging") == ("otherkey", "STAGING")

    def test_multiple_lines_without_expected_env_raises(self):
        blob = self.BLOB + "DOTENV_PRIVATE_KEY_STAGING=otherkey\n"
        with pytest.raises(KeyMaterialError, match="multiple DOTENV_PRIVATE_KEY"):
            normalize_vault_key_value(blob)

    def test_duplicate_lines_for_expected_env_raise(self):
        blob = self.BLOB + f"DOTENV_PRIVATE_KEY_PRODUCTION={FAKE_KEY}x\n"
        with pytest.raises(KeyMaterialError, match="duplicate"):
            normalize_vault_key_value(blob, "production")

    def test_blob_without_key_line_raises(self):
        with pytest.raises(KeyMaterialError, match="multi-line"):
            normalize_vault_key_value("# just a comment\nFOO=bar\nBAZ=qux\n")

    def test_lone_mismatched_suffix_is_returned_for_caller_to_reject(self):
        # A blob holding only a STAGING key pulled for production: the suffix is
        # surfaced so callers raise their established env-mismatch error.
        blob = "# .env.staging\nDOTENV_PRIVATE_KEY_STAGING=stagekey\n"
        assert normalize_vault_key_value(blob, "production") == ("stagekey", "STAGING")


class TestValidateKeyMaterial:
    """Final shape check applied before any install."""

    def test_accepts_plain_token(self):
        assert validate_key_material(FAKE_KEY, secret_name="s") == FAKE_KEY

    def test_rejects_empty(self):
        with pytest.raises(KeyMaterialError, match="empty"):
            validate_key_material("", secret_name="s")

    def test_rejects_internal_whitespace(self):
        with pytest.raises(KeyMaterialError, match="whitespace"):
            validate_key_material("abc def", secret_name="s")

    def test_rejects_embedded_newline(self):
        with pytest.raises(KeyMaterialError, match="whitespace"):
            validate_key_material("abc\ndef", secret_name="s")

    def test_rejects_json_looking_value(self):
        with pytest.raises(KeyMaterialError, match="JSON"):
            validate_key_material("{broken", secret_name="s")

    def test_rejects_prefix_carrying_value(self):
        # Backstop for the #480 corruption class: a value still shaped like a
        # DOTENV_PRIVATE_KEY_<ENV>=... line is never bare key material.
        with pytest.raises(KeyMaterialError, match="prefix"):
            validate_key_material(f"DOTENV_PRIVATE_KEY_PRODUCTION={FAKE_KEY}", secret_name="s")

    def test_error_does_not_leak_value(self):
        with pytest.raises(KeyMaterialError) as exc_info:
            validate_key_material("super secret material", secret_name="s")
        assert "super secret material" not in str(exc_info.value)


class TestExtractKeyMaterial:
    """One-stop entry point used by vault-pull and the sync engine."""

    def test_happy_path_prefixed_secret(self):
        secret = SecretValue(name="s", value=f"DOTENV_PRIVATE_KEY_PRODUCTION={FAKE_KEY}")
        assert extract_key_material(secret, "production") == (FAKE_KEY, "PRODUCTION")

    def test_base64_marked_binary_secret_rejected(self):
        secret = SecretValue(name="bin-secret", value="//4=", metadata={"encoding": "base64"})
        with pytest.raises(KeyMaterialError, match="binary"):
            extract_key_material(secret, "production")

    def test_empty_value_key_line_rejected(self):
        # End-to-end for the #480 residual: this exact secret value used to be
        # installed verbatim, corrupting .env.keys with
        # DOTENV_PRIVATE_KEY_PRODUCTION=DOTENV_PRIVATE_KEY_PRODUCTION=.
        secret = SecretValue(name="s", value="DOTENV_PRIVATE_KEY_PRODUCTION=")
        with pytest.raises(KeyMaterialError, match="empty"):
            extract_key_material(secret, "production")

    def test_json_field_with_conflicting_embedded_prefix_rejected(self):
        raw = json.dumps({"DOTENV_PRIVATE_KEY_PRODUCTION": "DOTENV_PRIVATE_KEY_STAGING=abc123"})
        secret = SecretValue(name="s", value=raw)
        with pytest.raises(KeyMaterialError, match="prefix"):
            extract_key_material(secret, "production")

    def test_errors_name_the_secret(self):
        secret = SecretValue(name="my/secret", value='{"a": "1", "b": "2"}')
        with pytest.raises(KeyMaterialError, match="my/secret"):
            extract_key_material(secret, "production")

    def test_key_material_error_is_a_vault_error(self):
        # Callers that already handle VaultError keep failing loudly, not crashing.
        assert issubclass(KeyMaterialError, VaultError)
