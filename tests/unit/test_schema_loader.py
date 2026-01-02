"""Tests for envdrift.core.schema loader helpers."""

from __future__ import annotations

from textwrap import dedent
from types import SimpleNamespace

import pytest
from pydantic_settings import BaseSettings

from envdrift.core.schema import FieldMetadata, SchemaLoader, SchemaLoadError, SchemaMetadata


def test_field_metadata_helpers():
    """FieldMetadata and SchemaMetadata helpers should reflect required/optional/sensitive."""
    required = FieldMetadata(
        name="required",
        required=True,
        sensitive=False,
        default=None,
        description=None,
        field_type=str,
        annotation="str",
    )
    optional = FieldMetadata(
        name="optional",
        required=False,
        sensitive=False,
        default="x",
        description=None,
        field_type=str,
        annotation="str",
    )
    sensitive = FieldMetadata(
        name="secret",
        required=False,
        sensitive=True,
        default=None,
        description=None,
        field_type=str,
        annotation="str",
    )

    schema = SchemaMetadata(
        class_name="Settings",
        module_path="settings",
        fields={"required": required, "optional": optional, "secret": sensitive},
    )

    assert required.is_optional is False
    assert optional.is_optional is True
    assert schema.required_fields == ["required"]
    assert "optional" in schema.optional_fields
    assert "secret" in schema.optional_fields
    assert schema.sensitive_fields == ["secret"]


def test_load_uses_service_dir(tmp_path):
    """Load should resolve modules from a provided service_dir."""
    module_path = tmp_path / "mysettings.py"
    module_path.write_text(
        dedent(
            """
            from pydantic_settings import BaseSettings

            class Settings(BaseSettings):
                NAME: str = "envdrift"
            """
        ).lstrip()
    )

    loader = SchemaLoader()
    settings_cls = loader.load("mysettings:Settings", service_dir=tmp_path)

    assert settings_cls.__name__ == "Settings"


def test_load_invalid_dotted_path():
    """Invalid schema paths should raise SchemaLoadError."""
    loader = SchemaLoader()

    with pytest.raises(SchemaLoadError):
        loader.load("invalidpath")


def test_load_missing_class(tmp_path, monkeypatch):
    """Missing class names should raise SchemaLoadError."""
    module_path = tmp_path / "missing_class.py"
    module_path.write_text("class Other: pass\n")
    monkeypatch.syspath_prepend(tmp_path)

    loader = SchemaLoader()
    with pytest.raises(SchemaLoadError):
        loader.load("missing_class:Settings")


def test_load_non_settings_class(tmp_path, monkeypatch):
    """Non-BaseSettings classes should raise SchemaLoadError."""
    module_path = tmp_path / "not_settings.py"
    module_path.write_text("class NotSettings: pass\n")
    monkeypatch.syspath_prepend(tmp_path)

    loader = SchemaLoader()
    with pytest.raises(SchemaLoadError):
        loader.load("not_settings:NotSettings")


def test_extract_metadata_with_config_object_and_typing():
    """extract_metadata should handle config objects and typing annotations."""

    class Settings(BaseSettings):
        items: list[str] = []

    loader = SchemaLoader()
    Settings.model_config = SimpleNamespace(extra="forbid")
    schema = loader.extract_metadata(Settings)

    assert schema.extra_policy == "forbid"
    assert "items" in schema.fields
    assert schema.fields["items"].annotation


def test_get_schema_metadata_func_missing_module():
    """get_schema_metadata_func should return None for missing modules."""
    loader = SchemaLoader()

    assert loader.get_schema_metadata_func("missing.module") is None


def test_get_schema_metadata_func_non_callable(tmp_path, monkeypatch):
    """
    Check that get_schema_metadata_func returns None when a module-level `get_schema_metadata` attribute is not callable.

    Creates a temporary module defining `get_schema_metadata` as a non-callable value, adds its directory to sys.path, and asserts the loader returns `None`.
    """
    loader = SchemaLoader()

    module_path = tmp_path / "meta_module.py"
    module_path.write_text("get_schema_metadata = 'nope'\n")
    monkeypatch.syspath_prepend(tmp_path)
    assert loader.get_schema_metadata_func("meta_module") is None


def test_get_schema_metadata_func_callable(tmp_path, monkeypatch):
    """get_schema_metadata_func should return result when callable is present."""
    loader = SchemaLoader()

    callable_module = tmp_path / "meta_callable.py"
    callable_module.write_text(
        dedent(
            """
            def get_schema_metadata():
                return {"ok": True}
            """
        ).lstrip()
    )
    monkeypatch.syspath_prepend(tmp_path)
    assert loader.get_schema_metadata_func("meta_callable") == {"ok": True}


def test_load_and_extract(tmp_path):
    """load_and_extract should return schema metadata."""
    module_path = tmp_path / "combined.py"
    module_path.write_text(
        dedent(
            """
            from pydantic_settings import BaseSettings

            class Settings(BaseSettings):
                NAME: str
            """
        ).lstrip()
    )

    loader = SchemaLoader()
    schema = loader.load_and_extract("combined:Settings", service_dir=tmp_path)

    assert schema.class_name == "Settings"
