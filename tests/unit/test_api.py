"""Tests for envdrift.api module - public API functions."""

from __future__ import annotations

from pathlib import Path

import pytest

from envdrift.api import diff, init, validate


class TestValidateAPI:
    """Tests for public validate API."""

    def test_validate_requires_schema(self, tmp_path: Path):
        """Test that validate raises ValueError when schema is None."""
        env_file = tmp_path / ".env"
        env_file.write_text("FOO=bar")

        with pytest.raises(ValueError) as exc_info:
            validate(env_file, schema=None)
        assert "schema is required" in str(exc_info.value)

    def test_validate_file_not_found(self, tmp_path: Path):
        """Test that validate raises FileNotFoundError for missing env file."""
        with pytest.raises(FileNotFoundError):
            validate(tmp_path / "nonexistent.env", schema="app:Settings")

    def test_validate_success(self, tmp_path: Path):
        """Test successful validation with valid schema."""
        # Create env file
        env_file = tmp_path / ".env"
        env_file.write_text("APP_NAME=test\nDEBUG=false")

        # Create schema
        schema_file = tmp_path / "config.py"
        schema_file.write_text("""
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    APP_NAME: str
    DEBUG: bool = True
""")

        result = validate(env_file, schema="config:Settings", service_dir=tmp_path)
        assert result.valid

    def test_validate_missing_required_var(self, tmp_path: Path):
        """Test validation fails for missing required variable."""
        env_file = tmp_path / ".env"
        env_file.write_text("DEBUG=true")

        schema_file = tmp_path / "settings_req.py"
        schema_file.write_text("""
from pydantic_settings import BaseSettings

class SettingsReq(BaseSettings):
    REQUIRED_VAR: str
    DEBUG: bool = True
""")

        result = validate(env_file, schema="settings_req:SettingsReq", service_dir=tmp_path)
        assert not result.valid
        assert "REQUIRED_VAR" in result.missing_required


class TestDiffAPI:
    """Tests for public diff API."""

    def test_diff_no_changes(self, tmp_path: Path):
        """Test diff with identical files."""
        env1 = tmp_path / "env1"
        env2 = tmp_path / "env2"
        env1.write_text("VAR1=value1\nVAR2=value2")
        env2.write_text("VAR1=value1\nVAR2=value2")

        result = diff(env1, env2)
        assert result.added_count == 0
        assert result.removed_count == 0
        assert result.changed_count == 0

    def test_diff_with_changes(self, tmp_path: Path):
        """Test diff detects all types of changes."""
        env1 = tmp_path / "env1"
        env2 = tmp_path / "env2"
        env1.write_text("KEEP=same\nREMOVED=old\nCHANGED=before")
        env2.write_text("KEEP=same\nADDED=new\nCHANGED=after")

        result = diff(env1, env2)
        added_names = [d.name for d in result.get_added()]
        removed_names = [d.name for d in result.get_removed()]
        changed_names = [d.name for d in result.get_changed()]

        assert "ADDED" in added_names
        assert "REMOVED" in removed_names
        assert "CHANGED" in changed_names

    def test_diff_masks_sensitive_values(self, tmp_path: Path):
        """Test diff masks sensitive values by default."""
        env1 = tmp_path / "env1"
        env2 = tmp_path / "env2"
        env1.write_text("API_KEY=secret1")
        env2.write_text("API_KEY=secret2")

        # Create schema marking API_KEY as sensitive
        schema_file = tmp_path / "sensitive_config.py"
        schema_file.write_text("""
from pydantic import Field
from pydantic_settings import BaseSettings

class SensitiveSettings(BaseSettings):
    API_KEY: str = Field(json_schema_extra={"sensitive": True})
""")

        result = diff(env1, env2, schema="sensitive_config:SensitiveSettings", service_dir=tmp_path, mask_values=True)
        changed = result.get_changed()
        assert len(changed) == 1
        assert changed[0].name == "API_KEY"
        # Values should be masked for sensitive fields
        assert changed[0].is_sensitive

    def test_diff_file_not_found(self, tmp_path: Path):
        """Test diff raises error for missing file."""
        env1 = tmp_path / "env1"
        env1.write_text("FOO=bar")

        with pytest.raises(FileNotFoundError):
            diff(env1, tmp_path / "missing.env")


class TestInitAPI:
    """Tests for public init API."""

    def test_init_basic(self, tmp_path: Path):
        """Test basic init functionality."""
        env_file = tmp_path / ".env"
        env_file.write_text("NAME=test\nVALUE=123")

        output = tmp_path / "generated.py"
        result = init(env_file, output)

        assert result == output
        assert output.exists()
        content = output.read_text()
        assert "class Settings" in content
        assert "NAME: str" in content
        assert "VALUE: int = 123" in content

    def test_init_with_custom_class_name(self, tmp_path: Path):
        """Test init with custom class name."""
        env_file = tmp_path / ".env"
        env_file.write_text("FOO=bar")

        output = tmp_path / "settings.py"
        init(env_file, output, class_name="MyConfig")

        content = output.read_text()
        assert "class MyConfig(BaseSettings):" in content

    def test_init_sensitive_detection(self, tmp_path: Path):
        """Test init detects sensitive variables."""
        env_file = tmp_path / ".env"
        env_file.write_text("SECRET_KEY=abc123\nPASSWORD=hunter2\nAPP_NAME=myapp")

        output = tmp_path / "settings.py"
        init(env_file, output, detect_sensitive=True)

        content = output.read_text()
        # SECRET_KEY and PASSWORD should be marked sensitive
        assert 'json_schema_extra={"sensitive": True}' in content

    def test_init_type_inference(self, tmp_path: Path):
        """Test init correctly infers types."""
        env_file = tmp_path / ".env"
        env_file.write_text("""
STRING_VAR=hello
INT_VAR=42
BOOL_TRUE=true
BOOL_FALSE=false
""")

        output = tmp_path / "settings.py"
        init(env_file, output, detect_sensitive=False)

        content = output.read_text()
        assert "STRING_VAR: str" in content
        assert "INT_VAR: int = 42" in content
        assert "BOOL_TRUE: bool = True" in content
        assert "BOOL_FALSE: bool = False" in content
