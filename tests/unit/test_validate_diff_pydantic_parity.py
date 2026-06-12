"""Regression tests for #472: validate/diff verdicts must match pydantic-settings.

Every test here checks envdrift's verdict against the *real* pydantic-settings
behavior: the same .env is loaded through the actual ``BaseSettings`` class
in-process, and validate's verdict must agree with whether the real app would
start. Covers the six #472 findings:

1. bool spellings Pydantic accepts (on/off/t/f/y/n) must pass validate;
2. present-but-empty values for non-str fields must fail validate;
3. complex-typed fields (list/dict/nested) must be validated via JSON like the
   real env source;
4. non-ASCII unicode digits Pydantic rejects must fail validate;
5. schema-typed diff must not equate an int field's '1' with 'true';
6. dotenvx's DOTENV_PUBLIC_KEY* artifact is exempt from extra-vars/sensitive
   checks so the documented init -> encrypt -> validate loop stays green.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import Field, create_model
from pydantic_settings import BaseSettings, SettingsConfigDict

from envdrift.core.diff import DiffEngine
from envdrift.core.parser import EnvParser
from envdrift.core.schema import SchemaLoader
from envdrift.core.validator import ValidationResult, Validator


def _real_app_starts(settings_cls: type[BaseSettings], env_path: Path) -> bool:
    """Ground truth: does the real pydantic-settings class load this .env?"""
    try:
        settings_cls(_env_file=str(env_path))
    except Exception:
        # ValidationError for value errors, SettingsError for JSON-decode
        # failures on complex fields - either way the app crashes at startup.
        return False
    return True


def _validate(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    settings_cls: type[BaseSettings],
    env_content: str,
) -> tuple[ValidationResult, bool]:
    """Run envdrift validate AND the real Settings class on the same .env.

    Clears the schema's field names from the process env first so ambient
    variables can't leak into the ground-truth instantiation.
    """
    for name in settings_cls.model_fields:
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.upper(), raising=False)

    env_file = tmp_path / ".env"
    env_file.write_text(env_content, encoding="utf-8")

    env = EnvParser().parse(env_file, lenient=True)
    schema = SchemaLoader().extract_metadata(settings_cls)
    result = Validator().validate(env, schema, check_encryption=False)
    return result, _real_app_starts(settings_cls, env_file)


class TestBoolSpellingParity:
    """#472 finding 1: every spelling Pydantic v2 lax bool parsing accepts."""

    @staticmethod
    def _settings() -> type[BaseSettings]:
        class Settings(BaseSettings):
            DEBUG: bool

        return Settings

    @pytest.mark.parametrize(
        "value", ["on", "off", "t", "f", "y", "n", "ON", "Off", "T", "Y", "true", "1", "no"]
    )
    def test_pydantic_accepted_bool_spelling_passes_validate(self, monkeypatch, tmp_path, value):
        result, real_ok = _validate(monkeypatch, tmp_path, self._settings(), f"DEBUG={value}\n")

        assert real_ok is True  # the real app loads this spelling
        assert result.type_errors == {}, result.type_errors
        assert result.valid is True

    @pytest.mark.parametrize("value", ["maybe", "2", "enabled"])
    def test_pydantic_rejected_bool_still_fails_validate(self, monkeypatch, tmp_path, value):
        result, real_ok = _validate(monkeypatch, tmp_path, self._settings(), f"DEBUG={value}\n")

        assert real_ok is False
        assert "DEBUG" in result.type_errors
        assert result.valid is False


class TestEmptyValueParity:
    """#472 finding 2: PORT= / PORT="" crash the real app; validate must fail."""

    @pytest.mark.parametrize("assignment", ["PORT=", 'PORT=""'])
    def test_empty_required_int_fails_validate(self, monkeypatch, tmp_path, assignment):
        class Settings(BaseSettings):
            PORT: int

        result, real_ok = _validate(monkeypatch, tmp_path, Settings, f"{assignment}\n")

        assert real_ok is False  # int_parsing at startup
        assert "PORT" in result.type_errors, "empty int value must be a type error"
        assert result.valid is False

    def test_empty_float_fails_validate(self, monkeypatch, tmp_path):
        class Settings(BaseSettings):
            RATIO: float

        result, real_ok = _validate(monkeypatch, tmp_path, Settings, "RATIO=\n")

        assert real_ok is False
        assert "RATIO" in result.type_errors
        assert result.valid is False

    def test_empty_str_still_passes_validate(self, monkeypatch, tmp_path):
        """Control: '' is a valid str, the real app loads it."""

        class Settings(BaseSettings):
            NAME: str

        result, real_ok = _validate(monkeypatch, tmp_path, Settings, "NAME=\n")

        assert real_ok is True
        assert result.type_errors == {}
        assert result.valid is True

    def test_empty_str_with_min_length_constraint_fails_validate(self, monkeypatch, tmp_path):
        """The constraint pass must see the empty string pydantic will see."""

        class Settings(BaseSettings):
            NOTES: str = Field(min_length=5)

        result, real_ok = _validate(monkeypatch, tmp_path, Settings, "NOTES=\n")

        assert real_ok is False  # string_too_short at startup
        assert "NOTES" in result.type_errors
        assert result.valid is False

    def test_env_ignore_empty_true_keeps_empty_as_unset(self, monkeypatch, tmp_path):
        """With env_ignore_empty=True the real source drops the empty value, so
        an optional int field falls back to its default and the app starts -
        validate must not fail it."""

        class Settings(BaseSettings):
            model_config = SettingsConfigDict(env_ignore_empty=True)

            PORT: int = 8000

        result, real_ok = _validate(monkeypatch, tmp_path, Settings, "PORT=\n")

        assert real_ok is True
        assert result.type_errors == {}
        assert result.valid is True


class TestComplexTypeParity:
    """#472 finding 3: complex fields are JSON-decoded by the real env source."""

    def test_non_json_list_value_fails_validate(self, monkeypatch, tmp_path):
        class Settings(BaseSettings):
            TAGS: list[str]

        result, real_ok = _validate(monkeypatch, tmp_path, Settings, "TAGS=a,b,c\n")

        assert real_ok is False  # SettingsError: JSON parse of the env string
        assert "TAGS" in result.type_errors
        assert result.valid is False

    def test_valid_json_list_value_passes_validate(self, monkeypatch, tmp_path):
        class Settings(BaseSettings):
            TAGS: list[str]

        result, real_ok = _validate(monkeypatch, tmp_path, Settings, 'TAGS=["a","b","c"]\n')

        assert real_ok is True
        assert result.type_errors == {}
        assert result.valid is True

    def test_json_of_wrong_shape_fails_validate(self, monkeypatch, tmp_path):
        """Valid JSON that is not a list still crashes the real app."""

        class Settings(BaseSettings):
            TAGS: list[str]

        result, real_ok = _validate(monkeypatch, tmp_path, Settings, "TAGS=123\n")

        assert real_ok is False
        assert "TAGS" in result.type_errors
        assert result.valid is False

    def test_dict_field_json_object_passes_and_garbage_fails(self, monkeypatch, tmp_path):
        class Settings(BaseSettings):
            LIMITS: dict[str, int]

        ok_result, ok_real = _validate(monkeypatch, tmp_path, Settings, 'LIMITS={"a": 1}\n')
        assert ok_real is True
        assert ok_result.valid is True

        bad_result, bad_real = _validate(monkeypatch, tmp_path, Settings, "LIMITS=nope\n")
        assert bad_real is False
        assert "LIMITS" in bad_result.type_errors
        assert bad_result.valid is False

    def test_complex_union_with_parse_failure_fallback(self, monkeypatch, tmp_path):
        """A union with a str member lets the raw string through JSON failure,
        exactly like pydantic-settings' allow_parse_failure."""

        class Settings(BaseSettings):
            ORIGINS: list[str] | str

        result, real_ok = _validate(monkeypatch, tmp_path, Settings, "ORIGINS=plain-string\n")

        assert real_ok is True
        assert result.type_errors == {}
        assert result.valid is True

    def test_complex_constraint_is_enforced_on_parsed_json(self, monkeypatch, tmp_path):
        """Constraints on a complex field apply to the *parsed* value."""

        class Settings(BaseSettings):
            TAGS: list[str] = Field(min_length=2)

        result, real_ok = _validate(monkeypatch, tmp_path, Settings, 'TAGS=["only-one"]\n')

        assert real_ok is False  # too_short at startup
        assert "TAGS" in result.type_errors
        assert result.valid is False


class TestUnicodeDigitParity:
    """#472 finding 4: Pydantic rejects non-ASCII digits Python's int() accepts."""

    def test_fullwidth_digits_fail_validate(self, monkeypatch, tmp_path):
        class Settings(BaseSettings):
            PORT: int

        # U+FF14 U+FF12 is fullwidth "42": Python's int() accepts it, pydantic doesn't.
        result, real_ok = _validate(monkeypatch, tmp_path, Settings, "PORT=\uff14\uff12\n")

        assert real_ok is False  # int_parsing at startup
        assert "PORT" in result.type_errors
        assert result.valid is False

    def test_ascii_digits_still_pass_validate(self, monkeypatch, tmp_path):
        class Settings(BaseSettings):
            PORT: int

        result, real_ok = _validate(monkeypatch, tmp_path, Settings, "PORT=42\n")

        assert real_ok is True
        assert result.valid is True


class TestDiffSchemaIntBoolParity:
    """#472 finding 5: int-typed diff must not equate '1' with 'true'."""

    @staticmethod
    def _diff(tmp_path, content1: str, content2: str, settings_cls):
        env1_file = tmp_path / ".env1"
        env1_file.write_text(content1, encoding="utf-8")
        env2_file = tmp_path / ".env2"
        env2_file.write_text(content2, encoding="utf-8")
        parser = EnvParser()
        schema = SchemaLoader().extract_metadata(settings_cls)
        return DiffEngine().diff(
            parser.parse(env1_file), parser.parse(env2_file), schema=schema, mask_values=False
        )

    @staticmethod
    def _int_settings():
        class Settings(BaseSettings):
            model_config = SettingsConfigDict(extra="ignore")

            PORT: int

        return Settings

    def test_int_field_1_vs_true_is_drift(self, tmp_path):
        """'true' crashes an int field; '1' loads. That is drift, not equality."""
        result = self._diff(tmp_path, "PORT=1\n", "PORT=true\n", self._int_settings())
        assert result.changed_count == 1

    def test_int_field_1_vs_01_is_not_drift(self, tmp_path):
        """Control (verified on main): both coerce to 1."""
        result = self._diff(tmp_path, "PORT=1\n", "PORT=01\n", self._int_settings())
        assert result.changed_count == 0

    def test_int_field_1_vs_2_is_drift(self, tmp_path):
        """Control (verified on main): genuinely different ints."""
        result = self._diff(tmp_path, "PORT=1\n", "PORT=2\n", self._int_settings())
        assert result.changed_count == 1

    def test_int_field_both_bool_aliases_is_drift(self, tmp_path):
        """Both sides fail int coercion: the universal bool-alias fallback must
        not declare 'true' == 'yes' for an int-typed field."""
        result = self._diff(tmp_path, "PORT=true\n", "PORT=yes\n", self._int_settings())
        assert result.changed_count == 1

    def test_validate_and_diff_agree_on_bool_spellings(self, monkeypatch, tmp_path):
        """The same tool must give one answer: DEBUG=on == DEBUG=true for a bool
        field (diff: no drift) AND DEBUG=on passes validate."""

        class Settings(BaseSettings):
            model_config = SettingsConfigDict(extra="ignore")

            DEBUG: bool

        diff_result = self._diff(tmp_path, "DEBUG=on\n", "DEBUG=true\n", Settings)
        assert diff_result.changed_count == 0

        validate_result, real_ok = _validate(monkeypatch, tmp_path, Settings, "DEBUG=on\n")
        assert real_ok is True
        assert validate_result.valid is True


class TestDotenvxArtifactExemption:
    """#472 finding 6: DOTENV_PUBLIC_KEY* must not fail the quickstart loop."""

    @staticmethod
    def _settings() -> type[BaseSettings]:
        class Settings(BaseSettings):
            model_config = SettingsConfigDict(extra="forbid")

            API_KEY: str = Field(json_schema_extra={"sensitive": True})
            DEBUG: bool = False

        return Settings

    @staticmethod
    def _parse(tmp_path: Path, content: str):
        env_file = tmp_path / ".env"
        env_file.write_text(content, encoding="utf-8")
        return EnvParser().parse(env_file, lenient=True)

    def test_suffixed_public_key_is_not_an_extra_var(self, tmp_path):
        """An encrypted file's DOTENV_PUBLIC_KEY_<ENV> line passes extra=forbid."""
        public_key = "03a1b2c3d4e5f60718293a4b5c6d7e8f9001122334455667788990aabbccddeeff"
        env = self._parse(
            tmp_path,
            f'DOTENV_PUBLIC_KEY_PROD="{public_key}"\n'
            'API_KEY="encrypted:BDqDBmh4Y2x0BJ9ZAJzL"\n'
            "DEBUG=false\n",
        )
        schema = SchemaLoader().extract_metadata(self._settings())

        result = Validator().validate(env, schema, check_encryption=True)

        assert result.extra_vars == set(), result.extra_vars
        assert result.valid is True

    def test_unsuffixed_public_key_gets_no_sensitive_warning(self, tmp_path):
        """The bare DOTENV_PUBLIC_KEY artifact must not trigger the
        'mark it sensitive' name warning nor the extra-vars error."""
        env = self._parse(
            tmp_path,
            'DOTENV_PUBLIC_KEY="03a1b2c3d4e5f6"\n'
            'API_KEY="encrypted:BDqDBmh4Y2x0BJ9ZAJzL"\n'
            "DEBUG=false\n",
        )
        schema = SchemaLoader().extract_metadata(self._settings())

        result = Validator().validate(env, schema, check_encryption=True)

        assert result.extra_vars == set()
        assert result.valid is True
        assert not any("DOTENV_PUBLIC_KEY" in w for w in result.warnings), result.warnings

    def test_lookalike_prefix_var_is_still_extra(self, tmp_path):
        """Control: DOTENV_PUBLIC_KEYSTORE is NOT the artifact and stays extra."""
        env = self._parse(
            tmp_path,
            'DOTENV_PUBLIC_KEYSTORE=value\nAPI_KEY="encrypted:BDqDBmh4Y2x0BJ9ZAJzL"\nDEBUG=false\n',
        )
        schema = SchemaLoader().extract_metadata(self._settings())

        result = Validator().validate(env, schema, check_encryption=True)

        assert result.extra_vars == {"DOTENV_PUBLIC_KEYSTORE"}
        assert result.valid is False

    def test_extra_ignore_policy_emits_no_artifact_warning(self, tmp_path):
        """Under extra=ignore the artifact must not produce the extra-var warning."""

        class Settings(BaseSettings):
            model_config = SettingsConfigDict(extra="ignore")

            DEBUG: bool = False

        env = self._parse(tmp_path, 'DOTENV_PUBLIC_KEY_PROD="03abc"\nDEBUG=true\n')
        schema = SchemaLoader().extract_metadata(Settings)

        result = Validator().validate(env, schema, check_encryption=False)

        assert result.valid is True
        assert not any("DOTENV_PUBLIC_KEY_PROD" in w for w in result.warnings), result.warnings


class TestFullMatrixParity:
    """Sweep: validate's verdict equals the real pydantic-settings verdict."""

    @pytest.mark.parametrize(
        ("tp", "raw"),
        [
            (bool, "on"),
            (bool, "off"),
            (bool, "garbage"),
            (int, ""),
            (int, "\uff14\uff12"),  # fullwidth "42"
            (int, "42"),
            (int, "1_000"),
            (float, "1e3"),
            (float, ""),
            (str, ""),
            (list[str], "a,b,c"),
            (list[str], '["a","b"]'),
            (dict[str, int], '{"a": 1}'),
            (dict[str, int], "oops"),
            (int | None, ""),
            (int | None, "42"),
        ],
    )
    def test_verdict_matches_real_pydantic_settings(self, monkeypatch, tmp_path, tp, raw):
        settings_cls = create_model("Settings", __base__=BaseSettings, VALUE=(tp, ...))

        result, real_ok = _validate(monkeypatch, tmp_path, settings_cls, f"VALUE={raw}\n")

        assert result.valid == real_ok, (
            f"validate said valid={result.valid} but the real app "
            f"{'starts' if real_ok else 'crashes'} for VALUE: {tp} = {raw!r} "
            f"(type_errors={result.type_errors})"
        )
