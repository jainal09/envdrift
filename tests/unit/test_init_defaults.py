"""Generated settings must not embed sensitive defaults or lose leading zeros (#955)."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from envdrift.api import init
from envdrift.cli import app
from envdrift.core.schema import SchemaLoader


def _generate(env_file: Path, output: Path, entrypoint: str) -> None:
    if entrypoint == "cli":
        result = CliRunner().invoke(app, ["init", str(env_file), "--output", str(output)])
        assert result.exit_code == 0, result.output
    else:
        assert init(env_file, output) == output


@pytest.mark.parametrize("entrypoint", ["cli", "api"])
@pytest.mark.parametrize(
    "case",
    [
        ("SMTP_PASSWORD", "84721956", 84721956),
        ("AUTH_TOKEN", "true", True),
        ("2FA_TOKEN", "false", False),
    ],
    ids=["numeric-secret", "boolean-secret", "aliased-boolean-secret"],
)
def test_sensitive_fields_never_embed_defaults(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    entrypoint: str,
    case: tuple[str, str, int | bool],
) -> None:
    """Sensitive ints and bools, including aliased names, remain required fields."""
    name, value, expected = case
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(name, raising=False)
    env_file = tmp_path / ".env"
    env_file.write_text(f"{name}={value}\n", encoding="utf-8")
    output = tmp_path / "generated.py"

    _generate(env_file, output, entrypoint)

    source = output.read_text(encoding="utf-8")
    assert "default=" not in source
    settings_cls = SchemaLoader().load("generated:Settings", service_dir=tmp_path)
    field_name, field = next(iter(settings_cls.model_fields.items()))
    assert field.is_required()
    assert field.json_schema_extra == {"sensitive": True}
    assert settings_cls().model_dump()[field_name] == expected

    env_file.unlink()
    with pytest.raises(ValidationError, match="Field required"):
        settings_cls()


@pytest.mark.parametrize("entrypoint", ["cli", "api"])
@pytest.mark.parametrize(
    "case",
    [("012345678901", "012345678901"), ("02134", "02134"), ("00", "00"), ("0", 0), ("8000", 8000)],
    ids=["account-number", "postal-code", "all-zero", "single-zero", "integer"],
)
def test_numeric_values_preserve_leading_zeros(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    entrypoint: str,
    case: tuple[str, str | int],
) -> None:
    """Load the generated settings to verify both value and inferred type."""
    value, expected = case
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ACCOUNT_NUMBER", raising=False)
    env_file = tmp_path / ".env"
    env_file.write_text(f"ACCOUNT_NUMBER={value}\n", encoding="utf-8")
    output = tmp_path / "generated.py"

    _generate(env_file, output, entrypoint)

    settings_cls = SchemaLoader().load("generated:Settings", service_dir=tmp_path)
    field = settings_cls.model_fields["ACCOUNT_NUMBER"]
    assert field.annotation is type(expected)
    assert settings_cls().model_dump()["ACCOUNT_NUMBER"] == expected
    assert field.is_required() == isinstance(expected, str)
    if isinstance(expected, int):
        assert field.default == expected
