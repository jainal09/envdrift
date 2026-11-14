"""Validation reports display user text literally instead of parsing Rich tags (#956)."""

from __future__ import annotations

import io
from pathlib import Path

import pytest
from rich.console import Console
from typer.testing import CliRunner

from envdrift.cli import app
from envdrift.core.schema import FieldMetadata, SchemaMetadata
from envdrift.core.validator import ValidationResult
from envdrift.output import rich as rich_output


@pytest.fixture
def schema_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "markup_settings.py").write_text(
        "from pydantic import Field\n"
        "from pydantic_settings import BaseSettings\n"
        "class Settings(BaseSettings):\n"
        "    ALLOWED_PATHS: list[str] = ['/']\n"
        "    HOSTS: list[str] = []\n"
        "    SLUG: str = Field(default='app', pattern=r'^[a-z0-9-]+$')\n",
        encoding="utf-8",
    )
    return "markup_settings:Settings"


def test_invalid_bracketed_values_do_not_stop_multifile_validation(
    tmp_path: Path, schema_path: str
) -> None:
    bad = tmp_path / ".env.paths"
    good = tmp_path / ".env.good"
    bad.write_text("ALLOWED_PATHS=[/api, /health]\n", encoding="utf-8")
    good.write_text('ALLOWED_PATHS=["/api"]\n', encoding="utf-8")

    result = CliRunner().invoke(app, ["validate", str(bad), str(good), "-s", schema_path, "--ci"])

    assert result.exit_code == 1
    assert isinstance(result.exception, SystemExit), result.exception
    output = " ".join(result.output.split())
    assert "[/api, /health]" in output
    assert "Validation FAILED" in output
    assert "Validation PASSED" in output


def test_validation_preserves_bracketed_values_and_pydantic_patterns(
    tmp_path: Path, schema_path: str
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("HOSTS=[web, api]\nSLUG=My App\n", encoding="utf-8")

    result = CliRunner().invoke(app, ["validate", str(env_file), "-s", schema_path, "--ci"])

    assert result.exit_code == 1
    output = " ".join(result.output.split())
    assert "'[web, api]'" in output
    assert "'^[a-z0-9-]+$'" in output


@pytest.mark.parametrize("section", ["error", "warning"])
@pytest.mark.parametrize("message", ["Unexpected '[/api, /health]'", "Pattern '^[a-z]+$'"])
def test_validation_diagnostics_render_literal_text(
    monkeypatch: pytest.MonkeyPatch, section: str, message: str
) -> None:
    result = ValidationResult(valid=False)
    if section == "error":
        result.type_errors["FIELD[tag]"] = message
    else:
        result.warnings.append(message)
    schema = SchemaMetadata(class_name="Settings", module_path="app.config")
    output = io.StringIO()
    monkeypatch.setattr(rich_output, "console", Console(file=output, color_system=None, width=200))

    rich_output.print_validation_result(result, Path(".env"), schema)

    rendered = " ".join(output.getvalue().split())
    assert message in rendered
    if section == "error":
        assert "FIELD[tag]" in rendered


def test_validation_metadata_is_literal_in_every_report_section(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    schema = SchemaMetadata(
        class_name="Settings",
        module_path="app.config",
        fields={
            "REQUIRED[tag]": FieldMetadata(
                name="REQUIRED[tag]",
                required=True,
                sensitive=False,
                default=None,
                description="Required [/red] value",
                field_type=str,
                annotation="str",
            ),
            "OPTIONAL[tag]": FieldMetadata(
                name="OPTIONAL[tag]",
                required=False,
                sensitive=False,
                default="[default]",
                description=None,
                field_type=str,
                annotation="str",
            ),
        },
    )
    result = ValidationResult(
        valid=False,
        missing_required={"REQUIRED[tag]"},
        missing_optional={"OPTIONAL[tag]"},
        extra_vars={"EXTRA[tag]"},
        unencrypted_secrets={"SECRET[tag]"},
    )
    output = io.StringIO()
    monkeypatch.setattr(rich_output, "console", Console(file=output, color_system=None, width=200))

    rich_output.print_validation_result(result, Path(".env[tag]"), schema, verbose=True)

    rendered = " ".join(output.getvalue().split())
    for literal in (
        ".env[tag]",
        "REQUIRED[tag]",
        "Required [/red] value",
        "OPTIONAL[tag]",
        "[default]",
        "EXTRA[tag]",
        "SECRET[tag]",
    ):
        assert literal in rendered
