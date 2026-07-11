"""Regression tests for #573: dotenv key lexing matches application behavior."""

from __future__ import annotations

from io import StringIO

import pytest
from dotenv import dotenv_values
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from envdrift.core.parser import EnvParser


def _parsed_values(content: str, *, lenient: bool = False) -> dict[str, str]:
    parsed = EnvParser().parse_string(content, lenient=lenient)
    return {name: var.value for name, var in parsed.variables.items()}


def _pydantic_dotenv_values(content: str) -> dict[str, str]:
    """Values pydantic-settings can pass on from python-dotenv.

    ``dotenv_values`` exposes bare bindings as ``None``. Its Pydantic source
    deliberately filters falsy entries before model validation, so EnvDrift's
    public variable view omits bare bindings too.
    """
    return {
        name: value
        for name, value in dotenv_values(stream=StringIO(content)).items()
        if value is not None
    }


@pytest.mark.parametrize(
    "content",
    [
        pytest.param("plain\nSET=value\n", id="bare-key"),
        pytest.param("'MY KEY'=v\nNORMAL=x\n", id="quoted-key"),
        pytest.param("'\nK=1\n'\nB=2\n", id="multiline-quoted-bare-key"),
        pytest.param("'\nMY KEY\n'=value\nB=2\n", id="multiline-quoted-assigned-key"),
        pytest.param("'\nK=1\nB=2\n", id="unterminated-key-recovers-after-opener"),
        pytest.param("'\nK=1\n' junk\nB=2\n", id="junk-after-key-consumes-interior"),
        pytest.param("''=ignored\nB=2\n", id="empty-quoted-key-is-invalid"),
        pytest.param("export # comment\nB=2\n", id="export-without-key-is-ignored"),
        pytest.param(
            "export 'MY KEY' = value\nexport bare # note\nB=2\n",
            id="export-quoted-and-bare",
        ),
        pytest.param("A=first\nA\nB=2\n", id="later-bare-duplicate-wins"),
    ],
)
def test_key_binding_values_match_pydantic_dotenv_source(content):
    assert _parsed_values(content) == _pydantic_dotenv_values(content)


def test_quoted_key_is_unquoted_in_strict_and_lenient_modes():
    content = "'MY KEY'=v\n"

    assert _parsed_values(content) == {"MY KEY": "v"}
    assert _parsed_values(content, lenient=True) == {"MY KEY": "v"}


def test_multiline_quoted_key_metadata_covers_the_whole_binding():
    content = "'\nMY KEY\n'=value\nAFTER=ok\n"

    parsed = EnvParser().parse_string(content)
    variable = parsed.variables["\nMY KEY\n"]

    assert variable.line_number == 1
    assert variable.raw_line == "'\nMY KEY\n'=value"
    assert parsed.variables["AFTER"].line_number == 4


def test_multiline_bare_key_does_not_create_phantom_assignments():
    content = "'\nSECRET=not-a-binding\n'\nAFTER=ok\n"

    parsed = EnvParser().parse_string(content)

    assert set(parsed.variables) == {"AFTER"}
    assert parsed.variables["AFTER"].line_number == 4


def test_bare_key_shadows_process_environment_during_interpolation(monkeypatch):
    monkeypatch.setenv("ENVDRIFT_573_BARE", "from-process")
    content = (
        "ENVDRIFT_573_BARE\nDEFAULTED=${ENVDRIFT_573_BARE:-fallback}\nPLAIN=${ENVDRIFT_573_BARE}\n"
    )

    assert (
        _parsed_values(content)
        == _pydantic_dotenv_values(content)
        == {
            "DEFAULTED": "",
            "PLAIN": "",
        }
    )


def test_later_bare_duplicate_removes_public_value_but_keeps_assignment_history():
    parsed = EnvParser().parse_string("TOKEN=plaintext\nTOKEN\n")

    assert parsed.variables == {}
    assert [(var.name, var.value) for var in parsed.assignments] == [("TOKEN", "plaintext")]


def test_real_pydantic_settings_loads_quoted_key_and_ignores_bare_key(tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text("plain\n'MY KEY'=v\nNORMAL=x\n", encoding="utf-8")

    class Settings(BaseSettings):
        model_config = SettingsConfigDict(
            env_file=str(env_path), env_file_encoding="utf-8", extra="ignore"
        )

        plain: str = "default"
        my_key: str = Field(alias="MY KEY")
        NORMAL: str

    loaded = Settings()
    parsed = EnvParser().parse(env_path)

    assert loaded.plain == "default"
    assert loaded.my_key == parsed.variables["MY KEY"].value == "v"
    assert loaded.NORMAL == parsed.variables["NORMAL"].value == "x"
    assert "plain" not in parsed.variables
