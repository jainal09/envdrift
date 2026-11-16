"""``diff`` and the Python API read every key python-dotenv loads; ``--strict`` keeps raw text (#954).

The real CLI is exercised in tests/integration/test_diff_every_key_e2e.py.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest
from typer.testing import CliRunner

import envdrift
from envdrift.cli import app
from envdrift.core.parser import EnvParser

runner = CliRunner()


def _flat(text: str) -> str:
    """Whitespace collapsed, so Rich's soft wrap cannot split a phrase."""
    return " ".join(text.split())


class TestParserKeepsReferencesWhenAsked:
    """``interpolate=False`` keeps the text of a ``${VAR}`` reference."""

    def test_reference_is_kept_as_written(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("STAGING_STRIPE_KEY", "from-the-environment")
        content = "BASE=1\nA=${BASE}\nB=${STAGING_STRIPE_KEY}\nC=${UNSET:-fallback}\n"

        raw = EnvParser().parse_string(content, interpolate=False)
        expanded = EnvParser().parse_string(content)

        assert {name: var.value for name, var in raw.variables.items()} == {
            "BASE": "1",
            "A": "${BASE}",
            "B": "${STAGING_STRIPE_KEY}",
            "C": "${UNSET:-fallback}",
        }
        assert expanded.variables["B"].value == "from-the-environment"
        assert expanded.variables["C"].value == "fallback"

    def test_parse_passes_the_option_through(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("A=${NOT_SET_ANYWHERE_954}\n", encoding="utf-8")

        assert EnvParser().parse(env_file, interpolate=False).variables["A"].value == (
            "${NOT_SET_ANYWHERE_954}"
        )


class TestDiffCommand:
    """The diff command parses leniently and names the lines it skips."""

    def _write(self, tmp_path: Path, dev: str, prod: str) -> tuple[Path, Path]:
        env1, env2 = tmp_path / ".env.dev", tmp_path / ".env.prod"
        env1.write_text(dev, encoding="utf-8")
        env2.write_text(prod, encoding="utf-8")
        return env1, env2

    def test_non_identifier_keys_are_drift(self, tmp_path: Path) -> None:
        env1, env2 = self._write(tmp_path, "X-API-KEY=dev\n", "X-API-KEY=prod\n")

        result = runner.invoke(app, ["diff", str(env1), str(env2), "--ci"])

        assert result.exit_code == 1, result.output
        assert "X-API-KEY" in _flat(result.output)

    def test_strict_compares_unexpanded_references(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("STAGING_STRIPE_KEY", raising=False)
        monkeypatch.delenv("PROD_STRIPE_KEY", raising=False)
        env1, env2 = self._write(tmp_path, "K=${STAGING_STRIPE_KEY}\n", "K=${PROD_STRIPE_KEY}\n")

        strict = runner.invoke(app, ["diff", str(env1), str(env2), "--strict", "--ci"])
        normalized = runner.invoke(app, ["diff", str(env1), str(env2), "--ci"])

        assert strict.exit_code == 1, strict.output
        # The default mode still expands, as pydantic-settings would (#486): both are "".
        assert normalized.exit_code == 0, normalized.output

    def test_table_warning_names_the_unparsed_line(self, tmp_path: Path) -> None:
        env1, env2 = self._write(tmp_path, 'A=1\nBROKEN="a"junk\n', "A=1\n")

        result = runner.invoke(app, ["diff", str(env1), str(env2)])

        assert result.exit_code == 0, result.output
        assert "line(s) 2; diff ignored those lines" in _flat(result.output)

    def test_json_warning_goes_to_stderr(self, tmp_path: Path) -> None:
        env1, env2 = self._write(tmp_path, 'A=1\nBROKEN="a"junk\n', "A=1\n")

        result = runner.invoke(app, ["diff", str(env1), str(env2), "--format", "json"])

        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["summary"]["has_drift"] is False
        assert "line(s) 2; diff ignored those lines" in _flat(result.stderr)


class TestPythonApi:
    """``envdrift.diff`` and ``envdrift.validate`` parse like their commands."""

    def test_diff_compares_non_identifier_keys(self, tmp_path: Path) -> None:
        env1, env2 = tmp_path / ".env.dev", tmp_path / ".env.prod"
        env1.write_text("2FA_ENABLED=false\n", encoding="utf-8")
        env2.write_text("2FA_ENABLED=true\n", encoding="utf-8")

        result = envdrift.diff(env1, env2)

        assert [d.name for d in result.get_changed()] == ["2FA_ENABLED"]

    def test_diff_warns_about_unparsed_lines(self, tmp_path: Path) -> None:
        env1, env2 = tmp_path / ".env.dev", tmp_path / ".env.prod"
        env1.write_text('A=1\nBROKEN="a"junk\n', encoding="utf-8")
        env2.write_text("A=1\n", encoding="utf-8")

        with pytest.warns(UserWarning, match=r"line\(s\) 2; the diff ignores those lines"):
            result = envdrift.diff(env1, env2)

        assert not result.has_drift

    def test_validate_rejects_an_invalid_non_identifier_key(self, tmp_path: Path) -> None:
        (tmp_path / "settings_954.py").write_text(
            textwrap.dedent(
                """\
                from pydantic import Field
                from pydantic_settings import BaseSettings


                class Settings(BaseSettings):
                    field_2FA_ENABLED: bool = Field(alias="2FA_ENABLED", default=False)
                """
            ),
            encoding="utf-8",
        )
        env_file = tmp_path / ".env"
        env_file.write_text("2FA_ENABLED=maybe\n", encoding="utf-8")

        result = envdrift.validate(env_file, schema="settings_954:Settings", service_dir=tmp_path)

        assert not result.valid
        assert result.type_errors
