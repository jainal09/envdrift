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


_ALIASED_SETTINGS = """\
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="APP_")

    api_key: str = Field(alias="X-API-KEY", json_schema_extra={"sensitive": True})
    token: str = Field(alias="API_TOKEN", json_schema_extra={"sensitive": True})
    secret: str = Field(default="", json_schema_extra={"sensitive": True})
    port_number: int = Field(default=1, alias="PORT-NUMBER")
"""
# Built by concatenation so push protection never sees a whole secret literal.
_DEV_VALUES = {"X-API-KEY": "sk_" + "dev_value", "API_TOKEN": "tok_dev", "APP_SECRET": "s_dev"}
_PROD_VALUES = {"X-API-KEY": "sk_" + "prod_value", "API_TOKEN": "tok_prod", "APP_SECRET": "s_prod"}


class TestAliasedFields:
    """A variable is matched to the field it sets as pydantic-settings matches it.

    The lenient parse compares ``X-API-KEY``, so its sensitive field's mask must reach it;
    a field's alias and its ``env_prefix`` name were matched against the field's own name.
    """

    def _write(self, tmp_path: Path) -> tuple[Path, Path]:
        (tmp_path / "settings_aliased_954.py").write_text(_ALIASED_SETTINGS, encoding="utf-8")
        env1, env2 = tmp_path / ".env.dev", tmp_path / ".env.prod"
        env1.write_text(
            "".join(f"{k}={v}\n" for k, v in _DEV_VALUES.items()) + "PORT-NUMBER=1\n",
            encoding="utf-8",
        )
        env2.write_text(
            "".join(f"{k}={v}\n" for k, v in _PROD_VALUES.items()) + "PORT-NUMBER=true\n",
            encoding="utf-8",
        )
        return env1, env2

    def test_the_cli_masks_a_sensitive_field_under_each_of_its_names(self, tmp_path: Path) -> None:
        env1, env2 = self._write(tmp_path)

        result = runner.invoke(
            app,
            [
                "diff",
                str(env1),
                str(env2),
                "--schema",
                "settings_aliased_954:Settings",
                "--service-dir",
                str(tmp_path),
                "--format",
                "json",
            ],
        )

        assert result.exit_code == 0, result.output
        for value in [*_DEV_VALUES.values(), *_PROD_VALUES.values()]:
            assert value not in result.stdout
        changed = {d["name"]: d for d in json.loads(result.stdout)["differences"]}
        for name in _DEV_VALUES:
            assert changed[name]["sensitive"] is True
            assert changed[name]["value_env1"] == changed[name]["value_env2"] == "********"

    def test_the_api_masks_and_types_each_alias(self, tmp_path: Path) -> None:
        env1, env2 = self._write(tmp_path)

        result = envdrift.diff(
            env1, env2, schema="settings_aliased_954:Settings", service_dir=tmp_path
        )

        by_name = {d.name: d for d in result.get_changed()}
        for name in _DEV_VALUES:
            assert (by_name[name].value1, by_name[name].value2) == ("********", "********")
        # PORT-NUMBER=true crashes the app's int field, so it is drift, not a bool alias of 1.
        assert "PORT-NUMBER" in by_name

    @pytest.mark.parametrize("settings", ["SensitiveFirst", "SensitiveLast"])
    def test_a_name_fields_share_is_masked_if_one_of_them_is_sensitive(
        self, tmp_path: Path, settings: str
    ) -> None:
        """The field declared last took the name: a later plain field unmasked it."""
        (tmp_path / "settings_shared_954.py").write_text(_SHARED_ALIAS_SETTINGS, encoding="utf-8")
        env1, env2 = tmp_path / ".env.dev", tmp_path / ".env.prod"
        env1.write_text("SHARED_KEY=" + _DEV_VALUES["API_TOKEN"] + "\n", encoding="utf-8")
        env2.write_text("SHARED_KEY=" + _PROD_VALUES["API_TOKEN"] + "\n", encoding="utf-8")

        result = envdrift.diff(
            env1, env2, schema=f"settings_shared_954:{settings}", service_dir=tmp_path
        )

        [shared] = result.get_changed()
        assert (shared.name, shared.value1, shared.value2) == ("SHARED_KEY", "********", "********")
        assert shared.is_sensitive

    @pytest.mark.parametrize("settings", ["FlagThenPort", "PortThenFlag"])
    def test_a_name_fields_of_two_types_share_differs_if_one_of_them_reads_it_differently(
        self, tmp_path: Path, settings: str
    ) -> None:
        """Only the field declared first typed the name: as a bool, ``t`` and ``1`` are equal.

        The int field fails on ``t``, so the app loads one file and not the other.
        """
        (tmp_path / "settings_shared_954.py").write_text(_SHARED_ALIAS_SETTINGS, encoding="utf-8")
        env1, env2 = tmp_path / ".env.dev", tmp_path / ".env.prod"
        env1.write_text("SHARED_KEY=t\n", encoding="utf-8")
        env2.write_text("SHARED_KEY=1\n", encoding="utf-8")

        result = envdrift.diff(
            env1, env2, schema=f"settings_shared_954:{settings}", service_dir=tmp_path
        )

        assert [d.name for d in result.get_changed()] == ["SHARED_KEY"]

    def test_a_name_only_bool_fields_share_still_reads_t_as_1(self, tmp_path: Path) -> None:
        (tmp_path / "settings_shared_954.py").write_text(_SHARED_ALIAS_SETTINGS, encoding="utf-8")
        env1, env2 = tmp_path / ".env.dev", tmp_path / ".env.prod"
        env1.write_text("SHARED_KEY=t\n", encoding="utf-8")
        env2.write_text("SHARED_KEY=1\n", encoding="utf-8")

        result = envdrift.diff(
            env1, env2, schema="settings_shared_954:TwoFlags", service_dir=tmp_path
        )

        assert result.get_changed() == []


_SHARED_ALIAS_SETTINGS = """\
from pydantic import Field
from pydantic_settings import BaseSettings


class SensitiveFirst(BaseSettings):
    token: str = Field(alias="SHARED_KEY", json_schema_extra={"sensitive": True})
    label: str = Field(default="", alias="SHARED_KEY")


class SensitiveLast(BaseSettings):
    label: str = Field(default="", alias="SHARED_KEY")
    token: str = Field(alias="SHARED_KEY", json_schema_extra={"sensitive": True})


class FlagThenPort(BaseSettings):
    flag: bool = Field(default=False, alias="SHARED_KEY")
    port: int = Field(default=0, alias="SHARED_KEY")


class PortThenFlag(BaseSettings):
    port: int = Field(default=0, alias="SHARED_KEY")
    flag: bool = Field(default=False, alias="SHARED_KEY")


class TwoFlags(BaseSettings):
    flag: bool = Field(default=False, alias="SHARED_KEY")
    other_flag: bool = Field(default=False, alias="SHARED_KEY")
"""
