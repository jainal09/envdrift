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
