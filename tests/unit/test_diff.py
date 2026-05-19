"""Tests for DiffEngine."""

from envdrift.core.diff import DiffEngine, DiffType
from envdrift.core.parser import EnvParser


class TestDiffEngine:
    """Test cases for DiffEngine."""

    def test_diff_added_vars(self, env_file_dev, env_file_prod):
        """Detect vars in env2 but not env1."""
        parser = EnvParser()
        env1 = parser.parse(env_file_dev)
        env2 = parser.parse(env_file_prod)

        engine = DiffEngine()
        result = engine.diff(env1, env2)

        # SENTRY_DSN is only in prod
        added = result.get_added()
        assert any(d.name == "SENTRY_DSN" for d in added)
        assert result.added_count >= 1

    def test_diff_removed_vars(self, env_file_dev, env_file_prod):
        """Detect vars in env1 but not env2."""
        parser = EnvParser()
        env1 = parser.parse(env_file_dev)
        env2 = parser.parse(env_file_prod)

        engine = DiffEngine()
        result = engine.diff(env1, env2)

        # DEV_ONLY_VAR is only in dev
        removed = result.get_removed()
        assert any(d.name == "DEV_ONLY_VAR" for d in removed)
        assert result.removed_count >= 1

    def test_diff_changed_values(self, env_file_dev, env_file_prod):
        """Detect changed values."""
        parser = EnvParser()
        env1 = parser.parse(env_file_dev)
        env2 = parser.parse(env_file_prod)

        engine = DiffEngine()
        result = engine.diff(env1, env2, mask_values=False)

        # DEBUG, LOG_LEVEL, DATABASE_URL are different
        changed = result.get_changed()
        assert any(d.name == "DEBUG" for d in changed)
        assert any(d.name == "LOG_LEVEL" for d in changed)
        assert result.changed_count >= 2

    def test_diff_mask_sensitive(self, tmp_path):
        """Mask sensitive values in output."""
        from pydantic import Field
        from pydantic_settings import BaseSettings, SettingsConfigDict

        from envdrift.core.schema import SchemaLoader

        class TestSchema(BaseSettings):
            model_config = SettingsConfigDict(extra="ignore")
            SECRET: str = Field(json_schema_extra={"sensitive": True})
            PUBLIC: str

        env1_content = "SECRET=secret1\nPUBLIC=public1"
        env2_content = "SECRET=secret2\nPUBLIC=public2"

        env1_file = tmp_path / ".env1"
        env1_file.write_text(env1_content)
        env2_file = tmp_path / ".env2"
        env2_file.write_text(env2_content)

        parser = EnvParser()
        env1 = parser.parse(env1_file)
        env2 = parser.parse(env2_file)

        loader = SchemaLoader()
        schema = loader.extract_metadata(TestSchema)

        engine = DiffEngine()
        result = engine.diff(env1, env2, schema=schema, mask_values=True)

        # Find the SECRET diff
        secret_diff = next(d for d in result.differences if d.name == "SECRET")
        assert secret_diff.value1 == "********"
        assert secret_diff.value2 == "********"
        assert secret_diff.is_sensitive is True

        # PUBLIC should not be masked
        public_diff = next(d for d in result.differences if d.name == "PUBLIC")
        assert public_diff.value1 == "public1"
        assert public_diff.value2 == "public2"

    def test_diff_identical(self, tmp_path):
        """No differences when files match."""
        content = "FOO=bar\nBAZ=qux"

        env1_file = tmp_path / ".env1"
        env1_file.write_text(content)
        env2_file = tmp_path / ".env2"
        env2_file.write_text(content)

        parser = EnvParser()
        env1 = parser.parse(env1_file)
        env2 = parser.parse(env2_file)

        engine = DiffEngine()
        result = engine.diff(env1, env2)

        assert result.has_drift is False
        assert result.added_count == 0
        assert result.removed_count == 0
        assert result.changed_count == 0

    def test_diff_include_unchanged(self, tmp_path):
        """Include unchanged vars when requested."""
        content1 = "FOO=bar\nBAZ=qux"
        content2 = "FOO=bar\nBAZ=different"

        env1_file = tmp_path / ".env1"
        env1_file.write_text(content1)
        env2_file = tmp_path / ".env2"
        env2_file.write_text(content2)

        parser = EnvParser()
        env1 = parser.parse(env1_file)
        env2 = parser.parse(env2_file)

        engine = DiffEngine()

        # Without unchanged
        result1 = engine.diff(env1, env2, include_unchanged=False)
        assert len([d for d in result1.differences if d.diff_type == DiffType.UNCHANGED]) == 0

        # With unchanged
        result2 = engine.diff(env1, env2, include_unchanged=True)
        assert len([d for d in result2.differences if d.diff_type == DiffType.UNCHANGED]) == 1

    def test_diff_to_dict(self, env_file_dev, env_file_prod):
        """Convert DiffResult to dictionary."""
        parser = EnvParser()
        env1 = parser.parse(env_file_dev)
        env2 = parser.parse(env_file_prod)

        engine = DiffEngine()
        result = engine.diff(env1, env2)
        result_dict = engine.to_dict(result)

        assert "env1" in result_dict
        assert "env2" in result_dict
        assert "summary" in result_dict
        assert "differences" in result_dict
        assert "added" in result_dict["summary"]
        assert "removed" in result_dict["summary"]
        assert "changed" in result_dict["summary"]
        assert "has_drift" in result_dict["summary"]

    def test_diff_result_properties(self, env_file_dev, env_file_prod):
        """Test DiffResult properties."""
        parser = EnvParser()
        env1 = parser.parse(env_file_dev)
        env2 = parser.parse(env_file_prod)

        engine = DiffEngine()
        result = engine.diff(env1, env2, include_unchanged=True)

        assert result.has_drift is True
        assert result.unchanged_count > 0  # Common vars
        assert len(result.get_added()) == result.added_count
        assert len(result.get_removed()) == result.removed_count
        assert len(result.get_changed()) == result.changed_count


class TestDiffNormalization:
    """Normalization-driven equality (issue #251)."""

    @staticmethod
    def _diff(tmp_path, content1, content2, **kwargs):
        env1_file = tmp_path / ".env1"
        env1_file.write_text(content1)
        env2_file = tmp_path / ".env2"
        env2_file.write_text(content2)
        parser = EnvParser()
        env1 = parser.parse(env1_file)
        env2 = parser.parse(env2_file)
        return DiffEngine().diff(env1, env2, mask_values=False, **kwargs)

    def test_inside_quote_whitespace_is_equal(self, tmp_path):
        """`DATABASE_URL="foo "` vs `DATABASE_URL=foo` no longer reports drift."""
        result = self._diff(tmp_path, 'DATABASE_URL="foo "\n', "DATABASE_URL=foo\n")
        assert result.changed_count == 0

    def test_bool_casing_is_equal(self, tmp_path):
        """`DEBUG=true` vs `DEBUG=True` is unchanged under normalization."""
        result = self._diff(tmp_path, "DEBUG=true\n", "DEBUG=True\n")
        assert result.changed_count == 0

    def test_bool_aliases_are_equal(self, tmp_path):
        """Bool aliases (yes/on/1) collapse under the same canonical truthiness."""
        result = self._diff(tmp_path, "FEATURE=yes\n", "FEATURE=on\n")
        assert result.changed_count == 0

    def test_bool_opposites_still_differ(self, tmp_path):
        """Normalization must not collapse semantically opposite bool values."""
        result = self._diff(tmp_path, "DEBUG=true\n", "DEBUG=false\n")
        assert result.changed_count == 1

    def test_json_list_quote_style_is_equal(self, tmp_path):
        """JSON-equivalent lists with different quote styles compare equal."""
        result = self._diff(
            tmp_path,
            'CORS_ORIGINS=["http://x"]\n',
            "CORS_ORIGINS=['http://x']\n",
        )
        assert result.changed_count == 0

    def test_json_object_quote_style_is_equal(self, tmp_path):
        """Object/dict equivalents with different quote styles compare equal."""
        # env1: '{"a": 1}' (JSON-quoted, parser strips outer single quotes).
        # env2: {'a': 1}  (Python-literal style, no outer quote pair).
        result = self._diff(
            tmp_path,
            "TAGS='{\"a\": 1}'\n",
            "TAGS={'a': 1}\n",
        )
        assert result.changed_count == 0

    def test_case_difference_without_schema_still_reports(self, tmp_path):
        """Without schema, free-form case differences must remain CHANGED."""
        result = self._diff(tmp_path, "LOG_LEVEL=warning\n", "LOG_LEVEL=WARNING\n")
        assert result.changed_count == 1

    def test_strict_mode_disables_normalization(self, tmp_path):
        """`normalize=False` (the --strict flag) preserves legacy raw compare."""
        result = self._diff(
            tmp_path,
            "DEBUG=true\nCORS=['http://x']\n",
            'DEBUG=True\nCORS=["http://x"]\n',
            normalize=False,
        )
        assert result.changed_count == 2

    def test_unparseable_collection_falls_back_to_string(self, tmp_path):
        """If a value looks like a list but won't parse, fall through to raw compare."""
        result = self._diff(tmp_path, "RAW=[unterminated\n", "RAW=[different\n")
        assert result.changed_count == 1


class TestDiffSchemaAwareNormalization:
    """Schema-aware coercion via Pydantic when --schema is passed."""

    @staticmethod
    def _schema(model_cls):
        from envdrift.core.schema import SchemaLoader

        return SchemaLoader().extract_metadata(model_cls)

    @staticmethod
    def _diff(tmp_path, content1, content2, schema):
        env1_file = tmp_path / ".env1"
        env1_file.write_text(content1)
        env2_file = tmp_path / ".env2"
        env2_file.write_text(content2)
        parser = EnvParser()
        env1 = parser.parse(env1_file)
        env2 = parser.parse(env2_file)
        return DiffEngine().diff(env1, env2, schema=schema, mask_values=False)

    def test_bool_field_coerces_via_schema(self, tmp_path):
        from pydantic_settings import BaseSettings, SettingsConfigDict

        class Schema(BaseSettings):
            model_config = SettingsConfigDict(extra="ignore")
            DEBUG: bool

        result = self._diff(tmp_path, "DEBUG=1\n", "DEBUG=true\n", self._schema(Schema))
        assert result.changed_count == 0

    def test_int_field_coerces_quoted_vs_unquoted(self, tmp_path):
        from pydantic_settings import BaseSettings, SettingsConfigDict

        class Schema(BaseSettings):
            model_config = SettingsConfigDict(extra="ignore")
            PORT: int

        # Parser already strips outer quotes, so this also exercises that bytes
        # like "8000 " (inside-quote trailing space) coerce to the same int.
        result = self._diff(tmp_path, 'PORT="8000 "\n', "PORT=8000\n", self._schema(Schema))
        assert result.changed_count == 0

    def test_list_field_coerces_json_variants(self, tmp_path):
        from pydantic_settings import BaseSettings, SettingsConfigDict

        class Schema(BaseSettings):
            model_config = SettingsConfigDict(extra="ignore")
            CORS_ORIGINS: list[str]

        result = self._diff(
            tmp_path,
            'CORS_ORIGINS=["http://x", "http://y"]\n',
            'CORS_ORIGINS=["http://x", "http://y"]\n',
            self._schema(Schema),
        )
        # validate_strings parses both JSON strings into list[str] → equal.
        assert result.changed_count == 0

    def test_list_field_order_difference_still_reports_drift(self, tmp_path):
        from pydantic_settings import BaseSettings, SettingsConfigDict

        class Schema(BaseSettings):
            model_config = SettingsConfigDict(extra="ignore")
            CORS_ORIGINS: list[str]

        result = self._diff(
            tmp_path,
            'CORS_ORIGINS=["http://x", "http://y"]\n',
            'CORS_ORIGINS=["http://y", "http://x"]\n',
            self._schema(Schema),
        )
        # Pydantic preserves list order; universal-layer JSON fallback also
        # sees ordered lists. Different order → still drift.
        assert result.changed_count == 1

    def test_schema_coercion_falls_back_when_validation_fails(self, tmp_path):
        from pydantic_settings import BaseSettings, SettingsConfigDict

        class Schema(BaseSettings):
            model_config = SettingsConfigDict(extra="ignore")
            PORT: int

        # Neither value coerces to int — must fall through to universal layer
        # and ultimately raw string compare. Different strings → CHANGED.
        result = self._diff(tmp_path, "PORT=abc\n", "PORT=def\n", self._schema(Schema))
        assert result.changed_count == 1

    def test_str_field_still_runs_universal_normalization(self, tmp_path):
        """A `str` field would round-trip through validate_strings unchanged,
        but the universal layer must still collapse `foo ` vs `foo`."""
        from pydantic_settings import BaseSettings, SettingsConfigDict

        class Schema(BaseSettings):
            model_config = SettingsConfigDict(extra="ignore")
            DATABASE_URL: str

        result = self._diff(
            tmp_path,
            'DATABASE_URL="foo "\n',
            "DATABASE_URL=foo\n",
            self._schema(Schema),
        )
        assert result.changed_count == 0

    def test_str_field_bool_casing_still_normalized(self, tmp_path):
        """A `str`-typed bool-looking value should still normalize under the
        universal layer — schema coercion must not short-circuit it."""
        from pydantic_settings import BaseSettings, SettingsConfigDict

        class Schema(BaseSettings):
            model_config = SettingsConfigDict(extra="ignore")
            FLAG: str

        result = self._diff(tmp_path, "FLAG=true\n", "FLAG=True\n", self._schema(Schema))
        assert result.changed_count == 0

    def test_any_field_skips_schema_coercion(self, tmp_path):
        """`Any`-typed fields must skip schema coercion entirely (TypeAdapter(Any)
        is an identity check) so the universal layer can normalize them."""
        from typing import Any as AnyType

        from pydantic_settings import BaseSettings, SettingsConfigDict

        class Schema(BaseSettings):
            model_config = SettingsConfigDict(extra="ignore")
            DEBUG: AnyType = None

        result = self._diff(tmp_path, "DEBUG=true\n", "DEBUG=True\n", self._schema(Schema))
        assert result.changed_count == 0
