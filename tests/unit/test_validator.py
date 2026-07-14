"""Tests for Validator."""

from pydantic import AliasChoices, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from envdrift.core.parser import EnvParser
from envdrift.core.schema import SchemaLoader
from envdrift.core.validator import Validator


class TestValidator:
    """Test cases for Validator."""

    def test_validate_missing_required(self, tmp_path, test_settings_class):
        """Detect missing required vars."""
        # Missing API_KEY and JWT_SECRET
        content = """
DATABASE_URL=postgres://localhost/db
REDIS_URL=redis://localhost:6379
HOST=0.0.0.0
PORT=8000
DEBUG=true
NEW_FEATURE_FLAG=enabled
"""
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        parser = EnvParser()
        env = parser.parse(env_file)

        loader = SchemaLoader()
        schema = loader.extract_metadata(test_settings_class)

        validator = Validator()
        result = validator.validate(env, schema, check_encryption=False)

        assert result.valid is False
        assert "API_KEY" in result.missing_required
        assert "JWT_SECRET" in result.missing_required

    def test_validate_extra_vars_forbid(self, tmp_path, test_settings_class):
        """Reject extra vars when schema has extra=forbid."""
        content = """
DATABASE_URL=postgres://localhost/db
REDIS_URL=redis://localhost:6379
API_KEY=test
JWT_SECRET=secret
HOST=0.0.0.0
PORT=8000
DEBUG=true
NEW_FEATURE_FLAG=enabled
EXTRA_VAR=not_in_schema
ANOTHER_EXTRA=also_not_in_schema
"""
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        parser = EnvParser()
        env = parser.parse(env_file)

        loader = SchemaLoader()
        schema = loader.extract_metadata(test_settings_class)

        validator = Validator()
        result = validator.validate(env, schema, check_encryption=False)

        assert result.valid is False
        assert "EXTRA_VAR" in result.extra_vars
        assert "ANOTHER_EXTRA" in result.extra_vars

    def test_validate_uppercase_env_lowercase_schema_case_insensitive(self, tmp_path):
        """UPPERCASE .env satisfies lowercase Pydantic fields (issue #306).

        Pydantic Settings defaults to case_sensitive=False, so an UPPERCASE
        .env loaded into lowercase model fields must validate. The validator
        must not report the fields as missing_required NOR the env vars as
        extra_vars.
        """

        class Settings(BaseSettings):
            model_config = SettingsConfigDict(extra="forbid")

            api_key: str = Field(json_schema_extra={"sensitive": True})
            database_url: str

        content = """
API_KEY=encrypted:secret
DATABASE_URL=postgres://localhost/db
"""
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        env = EnvParser().parse(env_file)
        schema = SchemaLoader().extract_metadata(Settings)

        result = Validator().validate(env, schema, check_encryption=True)

        # No false missing_required and no false extra_vars.
        assert result.missing_required == set()
        assert result.extra_vars == set()
        assert result.valid is True
        # Encryption check should resolve API_KEY -> api_key (sensitive),
        # and since the value is encrypted it must not be flagged.
        assert result.unencrypted_secrets == set()

    def test_validate_uppercase_env_case_insensitive_detects_real_issues(self, tmp_path):
        """Case-insensitive matching still surfaces genuine missing/type/secret issues.

        With a lowercase schema and UPPERCASE .env, a truly absent required
        field is still missing_required, a plaintext sensitive value is still
        flagged unencrypted, and a bad type still errors (no false positives
        from case-folding, no false negatives either).
        """

        class Settings(BaseSettings):
            model_config = SettingsConfigDict(extra="forbid")

            api_key: str = Field(json_schema_extra={"sensitive": True})
            port: int
            missing_one: str

        content = """
API_KEY=plaintext-secret
PORT=not_a_number
"""
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        env = EnvParser().parse(env_file)
        schema = SchemaLoader().extract_metadata(Settings)

        result = Validator().validate(env, schema, check_encryption=True)

        assert "missing_one" in result.missing_required
        assert "port" in result.type_errors
        # API_KEY plaintext resolves to sensitive api_key -> unencrypted.
        assert "api_key" in result.unencrypted_secrets
        assert result.valid is False

    def test_case_insensitive_collision_is_surfaced_not_silent(self, tmp_path):
        """Two .env keys differing only in case must not be silently dropped.

        With case-insensitive matching (issue #306), ``API_KEY`` and
        ``api_key`` collapse to the same lower-cased bucket. Pydantic Settings
        resolves this last-wins; the validator must stay deterministic (last
        occurrence wins) AND surface a warning so the dropped value is not lost
        silently (greptile P2).
        """

        class Settings(BaseSettings):
            model_config = SettingsConfigDict(extra="forbid")

            api_key: str

        # Both spellings present; the last (lowercase) one wins for matching.
        content = """
API_KEY=first-value
api_key=second-value
"""
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        env = EnvParser().parse(env_file)
        schema = SchemaLoader().extract_metadata(Settings)

        result = Validator().validate(env, schema, check_encryption=False)

        # The collision must be reported, not swallowed.
        collision_warnings = [w for w in result.warnings if "collision" in w.lower()]
        assert len(collision_warnings) == 1, result.warnings
        warning = collision_warnings[0]
        assert "'API_KEY'" in warning
        assert "'api_key'" in warning
        # Deterministic last-wins: the later occurrence is kept, the earlier
        # one is reported as ignored.
        assert "value from 'api_key' is used" in warning
        assert "'API_KEY' ignored" in warning
        # Both names map to the schema field, so neither is a false extra var
        # and the required field is satisfied.
        assert result.extra_vars == set()
        assert result.missing_required == set()

    def test_no_collision_warning_without_case_clash(self, tmp_path):
        """Distinct env names that do not case-collide produce no collision warning."""

        class Settings(BaseSettings):
            api_key: str
            database_url: str

        content = """
API_KEY=secret
DATABASE_URL=postgres://localhost/db
"""
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        env = EnvParser().parse(env_file)
        schema = SchemaLoader().extract_metadata(Settings)

        result = Validator().validate(env, schema, check_encryption=False)

        assert [w for w in result.warnings if "collision" in w.lower()] == []

    def test_validate_extra_vars_ignore(self, tmp_path, permissive_settings_class):
        """Allow extra vars when schema has extra=ignore."""
        content = """
DATABASE_URL=postgres://localhost/db
HOST=0.0.0.0
EXTRA_VAR=allowed
"""
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        parser = EnvParser()
        env = parser.parse(env_file)

        loader = SchemaLoader()
        schema = loader.extract_metadata(permissive_settings_class)

        validator = Validator()
        result = validator.validate(env, schema, check_encryption=False)

        # Should be valid - extra vars are ignored
        assert result.valid is True
        assert "EXTRA_VAR" not in result.extra_vars
        # But should have a warning
        assert any("EXTRA_VAR" in w for w in result.warnings)

    def test_validate_unencrypted_secrets(self, tmp_path, test_settings_class):
        """Detect unencrypted sensitive vars."""
        content = """
DATABASE_URL=postgres://localhost/db
REDIS_URL=redis://localhost:6379
API_KEY=plaintext-secret-exposed
JWT_SECRET=another-plaintext-secret
HOST=0.0.0.0
PORT=8000
DEBUG=true
NEW_FEATURE_FLAG=enabled
"""
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        parser = EnvParser()
        env = parser.parse(env_file)

        loader = SchemaLoader()
        schema = loader.extract_metadata(test_settings_class)

        validator = Validator()
        result = validator.validate(env, schema, check_encryption=True)

        # Unencrypted secrets are warnings, not errors (valid is still True)
        assert result.valid is True
        assert result.warning_count > 0  # Has warnings for unencrypted secrets
        assert "DATABASE_URL" in result.unencrypted_secrets
        assert "REDIS_URL" in result.unencrypted_secrets
        assert "API_KEY" in result.unencrypted_secrets
        assert "JWT_SECRET" in result.unencrypted_secrets

    def test_validate_encrypted_secrets_pass(self, tmp_path, test_settings_class):
        """Pass when sensitive vars are encrypted."""
        content = """
DATABASE_URL="encrypted:BDQE123..."
REDIS_URL="encrypted:BDQE456..."
API_KEY="encrypted:BDQE789..."
JWT_SECRET="encrypted:BDQEabc..."
HOST=0.0.0.0
PORT=8000
DEBUG=true
NEW_FEATURE_FLAG=enabled
"""
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        parser = EnvParser()
        env = parser.parse(env_file)

        loader = SchemaLoader()
        schema = loader.extract_metadata(test_settings_class)

        validator = Validator()
        result = validator.validate(env, schema, check_encryption=True)

        assert result.valid is True
        assert len(result.unencrypted_secrets) == 0

    def test_validate_type_mismatch(self, tmp_path, test_settings_class):
        """Detect obvious type mismatches."""
        content = """
DATABASE_URL=postgres://localhost/db
REDIS_URL=redis://localhost:6379
API_KEY=test
JWT_SECRET=secret
HOST=0.0.0.0
PORT=not_a_number
DEBUG=true
NEW_FEATURE_FLAG=enabled
"""
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        parser = EnvParser()
        env = parser.parse(env_file)

        loader = SchemaLoader()
        schema = loader.extract_metadata(test_settings_class)

        validator = Validator()
        result = validator.validate(env, schema, check_encryption=False)

        assert result.valid is False
        assert "PORT" in result.type_errors

    def test_validate_enforces_pydantic_field_constraints(self, tmp_path):
        """#18: field constraints (ge/le/Literal/min_length/pattern) must be enforced.

        validate previously did only name-based type checks and never instantiated
        the Settings class, so a config the real Pydantic schema REJECTS sailed
        through as 'Validation PASSED' (exit 0) — a false pass on the CI gate.
        """
        from typing import Literal

        from pydantic import Field
        from pydantic_settings import BaseSettings

        class ConstrainedSettings(BaseSettings):
            PORT: int = Field(ge=1, le=65535)
            LOG_LEVEL: Literal["debug", "info", "warning", "error"]
            APP_NAME: str = Field(min_length=3)
            VERSION: str = Field(pattern=r"^v\d+\.\d+\.\d+$")

        # Type-correct values that every constraint nonetheless rejects.
        env_file = tmp_path / ".env"
        env_file.write_text("PORT=99999\nLOG_LEVEL=trace\nAPP_NAME=ab\nVERSION=not-a-version\n")

        env = EnvParser().parse(env_file)
        schema = SchemaLoader().extract_metadata(ConstrainedSettings)
        result = Validator().validate(env, schema, check_encryption=False)

        assert result.valid is False
        assert set(result.type_errors) >= {"PORT", "LOG_LEVEL", "APP_NAME", "VERSION"}

    def test_validate_runs_custom_validator_on_plain_field(self, tmp_path):
        """A custom @field_validator on a plain-typed field is still enforced.

        The field is a bare ``str`` (no constraint metadata), so the only
        validation is the custom validator — has_constraints must flag it so the
        real model_validate pass runs and surfaces the rejection.
        """
        from pydantic import field_validator
        from pydantic_settings import BaseSettings

        class Settings(BaseSettings):
            NAME: str

            @field_validator("NAME")
            @classmethod
            def _no_spaces(cls, v: str) -> str:
                if " " in v:
                    raise ValueError("must not contain spaces")
                return v

        env_file = tmp_path / ".env"
        env_file.write_text("NAME=has spaces\n")

        env = EnvParser().parse(env_file)
        schema = SchemaLoader().extract_metadata(Settings)
        assert schema.has_constraints is True  # custom validator detected

        result = Validator().validate(env, schema, check_encryption=False)
        assert result.valid is False
        assert "NAME" in result.type_errors

    def test_validate_constraint_pass_skips_missing_and_encrypted(self, tmp_path):
        """The constraint pass skips fields the env omits or encrypts, never
        double-reports a missing required field as a type error, and — per #472 —
        validates a present-but-empty value as the empty string pydantic-settings
        will actually see (so an empty min_length field fails like the real app).
        """
        from pydantic import Field
        from pydantic_settings import BaseSettings

        class Settings(BaseSettings):
            PORT: int = Field(ge=1, le=65535)  # present + valid
            SECRET: str = Field(min_length=10)  # encrypted -> can't constraint-check
            NOTES: str = Field(min_length=5)  # empty -> '' fails min_length (#472)
            REQUIRED_MISSING: str = Field(min_length=3)  # absent from env

        env_file = tmp_path / ".env"
        env_file.write_text("PORT=8080\nSECRET=encrypted:abc\nNOTES=\n")

        env = EnvParser().parse(env_file)
        schema = SchemaLoader().extract_metadata(Settings)
        result = Validator().validate(env, schema, check_encryption=False)

        # Absent required field is reported as missing, not a min_length type error.
        assert "REQUIRED_MISSING" in result.missing_required
        assert "REQUIRED_MISSING" not in result.type_errors
        # Encrypted values are not flagged by the constraint pass.
        assert "SECRET" not in result.type_errors
        # The real app sees NOTES='' and raises string_too_short at startup.
        assert "NOTES" in result.type_errors

    def test_constraint_pass_skips_empty_when_env_ignore_empty(self, tmp_path):
        """With env_ignore_empty=True the env source drops '' (the field is
        unset), so the constraint pass must not feed it to the model (#472)."""
        from pydantic import Field
        from pydantic_settings import BaseSettings, SettingsConfigDict

        class Settings(BaseSettings):
            model_config = SettingsConfigDict(env_ignore_empty=True)

            NOTES: str = Field("default-note", min_length=5)

        env_file = tmp_path / ".env"
        env_file.write_text("NOTES=\n", encoding="utf-8")

        env = EnvParser().parse(env_file)
        schema = SchemaLoader().extract_metadata(Settings)
        result = Validator().validate(env, schema, check_encryption=False)

        # The real app starts (the default is used); validate must agree.
        assert "NOTES" not in result.type_errors
        assert result.valid is True

    def test_constraint_pass_survives_non_validation_error(self, tmp_path):
        """An unexpected model error warns without echoing setting values."""
        sentinel = "do-not-echo-" + "sensitive-value"

        class Settings(BaseSettings):
            api_key: str

            @model_validator(mode="after")
            def reject(self):
                raise RuntimeError(f"bad key: {self.api_key}")

        env_file = tmp_path / ".env"
        env_file.write_text(f"API_KEY={sentinel}\n", encoding="utf-8")

        env = EnvParser().parse(env_file)
        schema = SchemaLoader().extract_metadata(Settings)
        result = Validator().validate(env, schema, check_encryption=False)

        assert result.valid is True
        assert sentinel not in "\n".join(result.warnings)
        assert result.warnings == [
            "Model-level validation raised RuntimeError; re-run the model directly for details"
        ]

    def test_validate_constraint_pass_keeps_base_type_message(self, tmp_path):
        """A field failing both the base-type check and Pydantic keeps the
        base-type message — the constraint pass must not override it.
        """
        from pydantic import Field
        from pydantic_settings import BaseSettings

        class Settings(BaseSettings):
            PORT: int = Field(ge=1, le=65535)

        env_file = tmp_path / ".env"
        env_file.write_text("PORT=not_a_number\n")

        env = EnvParser().parse(env_file)
        schema = SchemaLoader().extract_metadata(Settings)
        result = Validator().validate(env, schema, check_encryption=False)

        assert "PORT" in result.type_errors
        assert "Expected integer" in result.type_errors["PORT"]

    def test_validate_does_not_false_fail_on_complex_typed_field(self, tmp_path):
        """#443 review: a valid config with a complex (list) field must not be
        rejected. pydantic-settings parses such fields from JSON in its env source;
        the constraint pass skips them rather than reject the raw string.
        """
        from pydantic import Field
        from pydantic_settings import BaseSettings

        class Settings(BaseSettings):
            TAGS: list[str]
            PORT: int = Field(ge=1, le=65535)  # a constraint -> has_constraints True

        env_file = tmp_path / ".env"
        env_file.write_text('TAGS=["a","b","c"]\nPORT=8080\n')

        env = EnvParser().parse(env_file)
        schema = SchemaLoader().extract_metadata(Settings)
        result = Validator().validate(env, schema, check_encryption=False)

        assert result.valid is True
        assert "TAGS" not in result.type_errors

    def test_validate_suspicious_plaintext(self, tmp_path, permissive_settings_class):
        """Warn about plaintext values matching secret patterns."""
        content = """
DATABASE_URL=postgres://user:password@localhost/db
HOST=0.0.0.0
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
"""
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        parser = EnvParser()
        env = parser.parse(env_file)

        loader = SchemaLoader()
        schema = loader.extract_metadata(permissive_settings_class)

        validator = Validator()
        result = validator.validate(env, schema, check_encryption=True)

        # Should have warnings about suspicious values
        assert len(result.warnings) > 0
        assert any("GITHUB_TOKEN" in w for w in result.warnings)

    def test_is_value_suspicious(self):
        """Test secret pattern detection."""
        validator = Validator()

        # Should be suspicious
        assert validator.is_value_suspicious("sk-live-abc123") is True
        assert validator.is_value_suspicious("ghp_xxxx") is True
        assert validator.is_value_suspicious("AKIAIOSFODNN7EXAMPLE") is True
        assert validator.is_value_suspicious("postgres://user:pass@host/db") is True

        # Should not be suspicious
        assert validator.is_value_suspicious("hello") is False
        assert validator.is_value_suspicious("localhost") is False
        assert validator.is_value_suspicious("8000") is False

    def test_is_name_suspicious(self):
        """Test sensitive variable name detection."""
        validator = Validator()

        # Should be suspicious
        assert validator.is_name_suspicious("API_KEY") is True
        assert validator.is_name_suspicious("JWT_SECRET") is True
        assert validator.is_name_suspicious("DB_PASSWORD") is True
        assert validator.is_name_suspicious("AUTH_TOKEN") is True

        # Should not be suspicious
        assert validator.is_name_suspicious("HOST") is False
        assert validator.is_name_suspicious("PORT") is False
        assert validator.is_name_suspicious("DEBUG") is False

    def test_generate_fix_template(self, tmp_path, test_settings_class):
        """Test fix template generation."""
        content = """
DATABASE_URL=postgres://localhost/db
HOST=0.0.0.0
PORT=8000
DEBUG=true
"""
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        parser = EnvParser()
        env = parser.parse(env_file)

        loader = SchemaLoader()
        schema = loader.extract_metadata(test_settings_class)

        validator = Validator()
        result = validator.validate(env, schema, check_encryption=False)
        template = validator.generate_fix_template(result, schema)

        # Should include missing required vars
        assert "REDIS_URL" in template
        assert "API_KEY" in template
        assert "JWT_SECRET" in template
        assert "NEW_FEATURE_FLAG" in template

    def test_validation_result_properties(self, tmp_path, test_settings_class):
        """Test ValidationResult properties."""
        content = """
DATABASE_URL=postgres://localhost/db
HOST=0.0.0.0
PORT=not_a_number
DEBUG=true
EXTRA=extra
"""
        env_file = tmp_path / ".env"
        env_file.write_text(content)

        parser = EnvParser()
        env = parser.parse(env_file)

        loader = SchemaLoader()
        schema = loader.extract_metadata(test_settings_class)

        validator = Validator()
        result = validator.validate(env, schema, check_encryption=False)

        assert result.has_errors is True
        assert result.error_count > 0
        assert result.warning_count >= 0


class TestValidatorAliasMatching:
    """#443: a field with a Pydantic alias is matched against the .env by its
    alias (the real env-var name), so init's non-identifier-key fields validate
    instead of false-reporting MISSING (the init→validate round-trip)."""

    @staticmethod
    def _schema():
        class Settings(BaseSettings):
            model_config = SettingsConfigDict(extra="forbid")

            X_API_KEY: str = Field(alias="X-API-KEY")
            DATABASE_URL: str

        return SchemaLoader().extract_metadata(Settings)

    def test_extract_metadata_captures_alias(self):
        schema = self._schema()
        assert schema.fields["X_API_KEY"].alias == "X-API-KEY"
        assert schema.fields["DATABASE_URL"].alias is None

    def test_aliased_field_present_under_its_alias_validates(self, tmp_path):
        """The non-identifier key in the .env matches the aliased field."""
        env_file = tmp_path / ".env"
        env_file.write_text("DATABASE_URL=postgres://x\nX-API-KEY=secret\n", encoding="utf-8")
        env = EnvParser().parse(env_file, lenient=True)

        result = Validator().validate(env, self._schema(), check_encryption=False)

        assert result.valid is True, result.missing_required | result.extra_vars
        assert not result.missing_required
        # The alias key is the field, not an unknown extra under extra="forbid".
        assert not result.extra_vars

    def test_aliased_field_absent_is_reported_missing(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("DATABASE_URL=postgres://x\n", encoding="utf-8")
        env = EnvParser().parse(env_file, lenient=True)

        result = Validator().validate(env, self._schema(), check_encryption=False)

        assert result.valid is False
        assert "X_API_KEY" in result.missing_required


class TestValidatorEnvPrefix:
    """#669: validation mirrors pydantic-settings ``env_prefix`` bindings."""

    def test_prefixed_sensitive_field_validates_without_contradictory_warnings(self, tmp_path):
        class Settings(BaseSettings):
            model_config = SettingsConfigDict(env_prefix="MYAPP_", extra="forbid")

            api_key: str = Field(json_schema_extra={"sensitive": True})

        secret = "sk-" + "live-abcdef1234567890"
        env_file = tmp_path / ".env"
        env_file.write_text(f"MYAPP_API_KEY={secret}\n", encoding="utf-8")
        env = EnvParser().parse(env_file)
        schema = SchemaLoader().extract_metadata(Settings)

        result = Validator().validate(env, schema)

        assert schema.fields["api_key"].env_name == "MYAPP_api_key"
        assert result.valid is True
        assert result.missing_required == set()
        assert result.extra_vars == set()
        assert result.unencrypted_secrets == {"api_key"}
        assert not [warning for warning in result.warnings if "not marked sensitive" in warning]

    def test_prefixed_type_and_constraint_errors_use_model_field_keys(self, tmp_path):
        class Settings(BaseSettings):
            model_config = SettingsConfigDict(env_prefix="MYAPP_", extra="forbid")

            port: int
            retry_count: int = Field(ge=1)

        env_file = tmp_path / ".env"
        env_file.write_text("MYAPP_PORT=not-an-int\nMYAPP_RETRY_COUNT=0\n", encoding="utf-8")
        env = EnvParser().parse(env_file)
        schema = SchemaLoader().extract_metadata(Settings)

        result = Validator().validate(env, schema, check_encryption=False)

        assert result.missing_required == set()
        assert result.extra_vars == set()
        assert "Expected integer" in result.type_errors["port"]
        assert "greater than or equal to 1" in result.type_errors["retry_count"]
        assert result.valid is False

    def test_aliases_bypass_env_prefix(self, tmp_path):
        class Settings(BaseSettings):
            model_config = SettingsConfigDict(env_prefix="MYAPP_", extra="forbid")

            api_key: str = Field(alias="AUTH_TOKEN")
            legacy_key: str = Field(validation_alias="LEGACY_TOKEN")

        env_file = tmp_path / ".env"
        env_file.write_text("AUTH_TOKEN=value\nLEGACY_TOKEN=legacy\n", encoding="utf-8")
        env = EnvParser().parse(env_file)
        schema = SchemaLoader().extract_metadata(Settings)

        result = Validator().validate(env, schema, check_encryption=False)

        assert schema.fields["api_key"].env_name == "AUTH_TOKEN"
        assert schema.fields["legacy_key"].env_name == "LEGACY_TOKEN"
        assert result.missing_required == set()
        assert result.extra_vars == set()
        assert result.valid is True

    def test_alias_choices_first_choice_binds_without_env_prefix(self, tmp_path):
        class Settings(BaseSettings):
            model_config = SettingsConfigDict(extra="forbid")

            api_key: str = Field(validation_alias=AliasChoices("API_KEY", "LEGACY_API_KEY"))

        env_file = tmp_path / ".env"
        env_file.write_text("API_KEY=value\n", encoding="utf-8")
        env = EnvParser().parse(env_file)
        schema = SchemaLoader().extract_metadata(Settings)

        result = Validator().validate(env, schema, check_encryption=False)

        assert schema.fields["api_key"].alias == "API_KEY"
        assert schema.fields["api_key"].env_name == "API_KEY"
        assert result.missing_required == set()
        assert result.extra_vars == set()
        assert result.valid is True

    def test_alias_choices_first_choice_bypasses_prefix_and_suppresses_warning(self, tmp_path):
        class Settings(BaseSettings):
            model_config = SettingsConfigDict(env_prefix="MYAPP_", extra="forbid")

            api_key: str = Field(
                validation_alias=AliasChoices("API_KEY", "LEGACY_API_KEY"),
                json_schema_extra={"sensitive": True},
            )

        secret = "sk-" + "live-abcdef1234567890"
        env_file = tmp_path / ".env"
        env_file.write_text(f"API_KEY={secret}\n", encoding="utf-8")
        env = EnvParser().parse(env_file)
        schema = SchemaLoader().extract_metadata(Settings)

        result = Validator().validate(env, schema)

        assert schema.fields["api_key"].alias == "API_KEY"
        assert schema.fields["api_key"].env_name == "API_KEY"
        assert result.missing_required == set()
        assert result.extra_vars == set()
        assert result.unencrypted_secrets == {"api_key"}
        assert not [warning for warning in result.warnings if "not marked sensitive" in warning]
        assert result.valid is True

    def test_prefixed_empty_required_field_respects_env_ignore_empty(self, tmp_path):
        class Settings(BaseSettings):
            model_config = SettingsConfigDict(
                env_prefix="MYAPP_", env_ignore_empty=True, extra="forbid"
            )

            port: int

        env_file = tmp_path / ".env"
        env_file.write_text("MYAPP_PORT=\n", encoding="utf-8")
        env = EnvParser().parse(env_file)
        schema = SchemaLoader().extract_metadata(Settings)

        result = Validator().validate(env, schema, check_encryption=False)

        assert result.missing_required == {"port"}
        assert result.extra_vars == set()
        assert result.type_errors == {}
        assert result.valid is False

    def test_case_sensitive_prefix_and_field_name_require_exact_case(self, tmp_path):
        class Settings(BaseSettings):
            model_config = SettingsConfigDict(
                env_prefix="MyApp_", case_sensitive=True, extra="forbid"
            )

            api_key: str

        exact_file = tmp_path / ".env.exact"
        exact_file.write_text("MyApp_api_key=value\n", encoding="utf-8")
        wrong_case_file = tmp_path / ".env.wrong"
        wrong_case_file.write_text("MYAPP_API_KEY=value\n", encoding="utf-8")
        schema = SchemaLoader().extract_metadata(Settings)

        exact = Validator().validate(EnvParser().parse(exact_file), schema, check_encryption=False)
        wrong_case = Validator().validate(
            EnvParser().parse(wrong_case_file), schema, check_encryption=False
        )

        assert schema.case_sensitive is True
        assert schema.fields["api_key"].env_name == "MyApp_api_key"
        assert exact.valid is True
        assert wrong_case.missing_required == {"api_key"}
        assert wrong_case.extra_vars == {"MYAPP_API_KEY"}
        assert wrong_case.valid is False


class TestKnownValidatorGaps:
    """Regression tests for previously confirmed validator gaps."""

    def test_model_level_validator_rejection_fails_validation(self, tmp_path):
        """A @model_validator rejection must surface as an error, not a false PASS."""

        class RejectingSettings(BaseSettings):
            port: int = Field(ge=1)

            @model_validator(mode="after")
            def reject(self):
                raise ValueError("model-level rejection")

        env_file = tmp_path / ".env"
        env_file.write_text("PORT=5\n", encoding="utf-8")
        env = EnvParser().parse(env_file)
        schema = SchemaLoader().extract_metadata(RejectingSettings)

        result = Validator().validate(env, schema, check_encryption=False)

        assert result.valid is False
        assert result.type_errors.keys() == {"__model__"}
        assert "model-level rejection" in result.type_errors["__model__"]
        assert Validator().generate_fix_template(result, schema) == ""

    def test_aliased_sensitive_field_gets_no_contradictory_warning(self, tmp_path):
        """A field marked sensitive must not also warn 'not marked sensitive' via its alias."""

        class AliasedSensitiveSettings(BaseSettings):
            api_key: str = Field(alias="X_API_KEY", json_schema_extra={"sensitive": True})

        env_file = tmp_path / ".env"
        env_file.write_text("X_API_KEY=sk-live-abcdef1234567890\n", encoding="utf-8")
        env = EnvParser().parse(env_file)
        schema = SchemaLoader().extract_metadata(AliasedSensitiveSettings)

        result = Validator().validate(env, schema)

        assert "api_key" in result.unencrypted_secrets  # correctly detected as sensitive
        assert not [w for w in result.warnings if "not marked sensitive" in w]
