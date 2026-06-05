"""Coverage-focused tests for envdrift.core.validator.

These tests target previously-uncovered branches in the Validator:
missing optional detection, float/bool/list type checks, empty-value
skip, and the fix-template optional-variable section (descriptions and
defaults).
"""

from __future__ import annotations

from envdrift.core.parser import EnvParser
from envdrift.core.schema import FieldMetadata, SchemaMetadata
from envdrift.core.validator import ValidationResult, Validator


def _field(
    name: str,
    *,
    required: bool = False,
    sensitive: bool = False,
    default: object = None,
    description: str | None = None,
    field_type: type = str,
) -> FieldMetadata:
    """Build a FieldMetadata with sensible defaults for tests."""
    return FieldMetadata(
        name=name,
        required=required,
        sensitive=sensitive,
        default=default,
        description=description,
        field_type=field_type,
        annotation=getattr(field_type, "__name__", str(field_type)),
    )


def _parse_file(tmp_path, content: str):
    """Write content to a temp .env file and parse it."""
    env_file = tmp_path / ".env"
    env_file.write_text(content)
    return EnvParser().parse(env_file)


class TestMissingOptional:
    """Cover the missing-optional detection branch (line 135)."""

    def test_missing_optional_recorded(self, tmp_path):
        """Optional fields absent from the env file land in missing_optional."""
        schema = SchemaMetadata(
            class_name="S",
            module_path="m",
            fields={
                "REQUIRED_VAR": _field("REQUIRED_VAR", required=True),
                "OPTIONAL_VAR": _field("OPTIONAL_VAR", required=False),
            },
            extra_policy="ignore",
        )
        env = _parse_file(tmp_path, "REQUIRED_VAR=present\n")

        result = Validator().validate(env, schema, check_encryption=False)

        assert "OPTIONAL_VAR" in result.missing_optional
        assert "REQUIRED_VAR" not in result.missing_optional
        # Optional being missing is a warning, not an error.
        assert result.valid is True
        assert result.warning_count >= 1


class TestCaseInsensitiveMatching:
    """Cover case-insensitive name matching (issue #306)."""

    def test_uppercase_env_matches_lowercase_schema(self, tmp_path):
        """Lowercase schema fields are satisfied by UPPERCASE env names."""
        schema = SchemaMetadata(
            class_name="S",
            module_path="m",
            fields={
                "api_key": _field("api_key", required=True),
                "database_url": _field("database_url", required=True),
            },
            extra_policy="forbid",
        )
        env = _parse_file(tmp_path, "API_KEY=x\nDATABASE_URL=y\n")

        result = Validator().validate(env, schema, check_encryption=False)

        # No false missing_required and no false extra_vars.
        assert result.missing_required == set()
        assert result.extra_vars == set()
        assert result.valid is True

    def test_genuinely_extra_uppercase_var_still_forbidden(self, tmp_path):
        """An env var with no case-insensitive schema match is still extra."""
        schema = SchemaMetadata(
            class_name="S",
            module_path="m",
            fields={"api_key": _field("api_key", required=True)},
            extra_policy="forbid",
        )
        env = _parse_file(tmp_path, "API_KEY=x\nTOTALLY_UNKNOWN=z\n")

        result = Validator().validate(env, schema, check_encryption=False)

        assert "api_key" not in result.missing_required
        assert result.extra_vars == {"TOTALLY_UNKNOWN"}
        assert result.valid is False

    def test_case_insensitive_extra_ignore_emits_warning(self, tmp_path):
        """Genuinely-extra var with extra=ignore is a warning, matched fields are not."""
        schema = SchemaMetadata(
            class_name="S",
            module_path="m",
            fields={"api_key": _field("api_key", required=True)},
            extra_policy="ignore",
        )
        env = _parse_file(tmp_path, "API_KEY=x\nUNKNOWN_EXTRA=z\n")

        result = Validator().validate(env, schema, check_encryption=False)

        assert result.extra_vars == set()
        assert result.valid is True
        assert any("UNKNOWN_EXTRA" in w for w in result.warnings)
        assert not any("API_KEY" in w for w in result.warnings)


class TestTypeChecks:
    """Cover the float/bool/list/empty branches of _check_type."""

    def test_empty_value_skips_type_check(self, tmp_path):
        """An empty value never produces a type error (line 236)."""
        schema = SchemaMetadata(
            class_name="S",
            module_path="m",
            fields={"COUNT": _field("COUNT", required=False, field_type=int)},
        )
        env = _parse_file(tmp_path, "COUNT=\n")

        result = Validator().validate(env, schema, check_encryption=False)

        assert "COUNT" not in result.type_errors

    def test_float_valid(self, tmp_path):
        """A parseable float value produces no type error."""
        schema = SchemaMetadata(
            class_name="S",
            module_path="m",
            fields={"RATIO": _field("RATIO", required=False, field_type=float)},
        )
        env = _parse_file(tmp_path, "RATIO=1.5\n")

        result = Validator().validate(env, schema, check_encryption=False)

        assert "RATIO" not in result.type_errors

    def test_float_invalid(self, tmp_path):
        """A non-numeric float value yields a float type error (lines 255-258)."""
        schema = SchemaMetadata(
            class_name="S",
            module_path="m",
            fields={"RATIO": _field("RATIO", required=False, field_type=float)},
        )
        env = _parse_file(tmp_path, "RATIO=not_a_float\n")

        result = Validator().validate(env, schema, check_encryption=False)

        assert "RATIO" in result.type_errors
        assert "float" in result.type_errors["RATIO"].lower()
        assert result.valid is False

    def test_bool_invalid(self, tmp_path):
        """A value outside the accepted bool tokens yields an error (line 263)."""
        schema = SchemaMetadata(
            class_name="S",
            module_path="m",
            fields={"ENABLED": _field("ENABLED", required=False, field_type=bool)},
        )
        env = _parse_file(tmp_path, "ENABLED=maybe\n")

        result = Validator().validate(env, schema, check_encryption=False)

        assert "ENABLED" in result.type_errors
        assert "boolean" in result.type_errors["ENABLED"].lower()

    def test_bool_valid_tokens(self, tmp_path):
        """Accepted bool tokens (yes/no/1/0/true/false) pass validation."""
        schema = SchemaMetadata(
            class_name="S",
            module_path="m",
            fields={"ENABLED": _field("ENABLED", required=False, field_type=bool)},
        )
        env = _parse_file(tmp_path, "ENABLED=yes\n")

        result = Validator().validate(env, schema, check_encryption=False)

        assert "ENABLED" not in result.type_errors

    def test_list_type_accepts_anything(self, tmp_path):
        """List-typed fields accept arbitrary values without error (line 269)."""
        schema = SchemaMetadata(
            class_name="S",
            module_path="m",
            fields={"HOSTS": _field("HOSTS", required=False, field_type=list)},
        )
        env = _parse_file(tmp_path, "HOSTS=a,b,c\n")

        result = Validator().validate(env, schema, check_encryption=False)

        assert "HOSTS" not in result.type_errors


class TestGenerateFixTemplateOptional:
    """Cover the missing-optional section of generate_fix_template."""

    def test_template_optional_with_description_and_default(self):
        """Optional field with description + default renders both (lines 300-307)."""
        schema = SchemaMetadata(
            class_name="S",
            module_path="m",
            fields={
                "LOG_LEVEL": _field(
                    "LOG_LEVEL",
                    required=False,
                    default="INFO",
                    description="Logging verbosity",
                ),
            },
        )
        result = ValidationResult(valid=True, missing_optional={"LOG_LEVEL"})

        template = Validator().generate_fix_template(result, schema)

        assert "Missing optional variables" in template
        assert "# Logging verbosity" in template
        assert "# LOG_LEVEL=INFO" in template

    def test_template_optional_without_default(self):
        """Optional field lacking a default renders a bare commented line (lines 309-310)."""
        schema = SchemaMetadata(
            class_name="S",
            module_path="m",
            fields={
                "FEATURE_X": _field("FEATURE_X", required=False, default=None),
            },
        )
        result = ValidationResult(valid=True, missing_optional={"FEATURE_X"})

        template = Validator().generate_fix_template(result, schema)

        assert "# FEATURE_X=" in template
        # No "=value" suffix because there is no default.
        assert "# FEATURE_X=None" not in template

    def test_template_required_with_description(self):
        """Required field description comment is emitted (line 292)."""
        schema = SchemaMetadata(
            class_name="S",
            module_path="m",
            fields={
                "DB_URL": _field(
                    "DB_URL",
                    required=True,
                    sensitive=True,
                    description="Primary database connection string",
                ),
            },
        )
        result = ValidationResult(valid=False, missing_required={"DB_URL"})

        template = Validator().generate_fix_template(result, schema)

        assert "# Primary database connection string" in template
        # Sensitive required fields get the encrypted placeholder.
        assert 'DB_URL="encrypted:YOUR_VALUE_HERE"' in template
