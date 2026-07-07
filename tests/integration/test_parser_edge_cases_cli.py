"""CLI regression tests for #486: parser edge cases end-to-end.

The parser diverged from python-dotenv / pydantic-settings on ``${VAR}``
interpolation, inline-comment quote state, double-quoted escapes, Unicode
line boundaries, and UTF-8 BOM handling — so ``validate --ci`` failed configs
the real loader accepts, ``diff`` reported phantom drift between files that
parse identically, and ``encrypt --check`` saw phantom variables. These tests
drive the real ``envdrift`` CLI as a subprocess against byte-exact fixtures
and assert exit codes plus machine-readable output.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

pytestmark = [pytest.mark.integration]

# Single physical line: the U+2028 LINE SEPARATOR is value content, not a
# line boundary. Written as exact bytes in each test.
U2028_LINE = "NOTE=part1\u2028SECRET_PASSWORD=hunter2\n".encode()
BOM_LINE = b"\xef\xbb\xbfAPI_KEY=abc123\n"


def _run_cli(args: list[str], cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    """Run the envdrift CLI in-tree with deterministic output."""
    return subprocess.run(
        [sys.executable, "-m", "envdrift.cli", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
        check=False,
    )


def _write_schema(tmp_path: Path, body: str) -> None:
    (tmp_path / "sc.py").write_text(textwrap.dedent(body), encoding="utf-8")


def _validate_ci(tmp_path: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return _run_cli(
        [
            "validate",
            ".env",
            "--schema",
            "sc:Settings",
            "--service-dir",
            str(tmp_path),
            "--no-check-encryption",
            "--ci",
        ],
        cwd=tmp_path,
        env=env,
    )


def _diff_json(tmp_path: Path, env: dict[str, str], a: str, b: str) -> dict:
    result = _run_cli(["diff", a, b, "--format", "json"], cwd=tmp_path, env=env)
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads(result.stdout)


class TestValidateInterpolation:
    """#486: ${VAR} expands like dotenv_values before type checks."""

    def test_interpolated_int_passes_ci(self, tmp_path, integration_env):
        """Issue repro: PORT=${OFFSET}234 is 1234 to pydantic-settings; the
        literal used to fail the int check (false CI FAIL, exit 1)."""
        _write_schema(
            tmp_path,
            """
            from pydantic_settings import BaseSettings

            class Settings(BaseSettings):
                OFFSET: int
                PORT: int
            """,
        )
        (tmp_path / ".env").write_text("OFFSET=1\nPORT=${OFFSET}234\n", encoding="utf-8")
        env = dict(integration_env)
        env.pop("OFFSET", None)
        env.pop("PORT", None)

        result = _validate_ci(tmp_path, env)

        out = " ".join((result.stdout + result.stderr).split())
        assert result.returncode == 0, out
        assert "Validation PASSED" in out

    def test_diff_compares_expanded_values(self, tmp_path, integration_env):
        """Two files that expand to the same PORT must not drift."""
        (tmp_path / ".env.dev").write_text("OFFSET=1\nPORT=${OFFSET}234\n", encoding="utf-8")
        (tmp_path / ".env.prod").write_text("OFFSET=1\nPORT=1234\n", encoding="utf-8")
        env = dict(integration_env)
        env.pop("OFFSET", None)
        env.pop("PORT", None)

        data = _diff_json(tmp_path, env, ".env.dev", ".env.prod")

        assert data["summary"]["has_drift"] is False


class TestInlineCommentQuoteState:
    """#486: an apostrophe mid-value must not absorb the inline comment."""

    def test_validate_literal_with_apostrophe_passes_ci(self, tmp_path, integration_env):
        """Issue repro: MSG=user's data # comment equals the Literal
        "user's data"; the absorbed comment used to fail it (exit 1)."""
        _write_schema(
            tmp_path,
            """
            from typing import Literal

            from pydantic_settings import BaseSettings

            class Settings(BaseSettings):
                MSG: Literal["user's data"]
            """,
        )
        (tmp_path / ".env").write_text("MSG=user's data # comment\n", encoding="utf-8")

        result = _validate_ci(tmp_path, integration_env)

        out = " ".join((result.stdout + result.stderr).split())
        assert result.returncode == 0, out
        assert "Validation PASSED" in out

    def test_diff_ignores_inline_comment_after_apostrophe(self, tmp_path, integration_env):
        """Issue repro: the commented and uncommented twins parse identically
        in dotenv_values; diff used to report CHANGED drift."""
        (tmp_path / "a.env").write_text("MSG=user's data # comment\n", encoding="utf-8")
        (tmp_path / "b.env").write_text("MSG=user's data\n", encoding="utf-8")

        data = _diff_json(tmp_path, integration_env, "a.env", "b.env")

        assert data["summary"]["has_drift"] is False
        assert data["differences"] == []


class TestQuotedEscapeDecoding:
    """#486 item fixed by the #458 lexer on the base branch — pinned at the
    CLI level with the original issue repros."""

    def test_validate_min_length_rejects_decoded_short_value(self, tmp_path, integration_env):
        """TOKEN="abc\\ndef" decodes to 7 chars; pydantic rejects
        min_length=8, so --ci must exit 1 (this used to false-PASS)."""
        _write_schema(
            tmp_path,
            """
            from pydantic import Field
            from pydantic_settings import BaseSettings

            class Settings(BaseSettings):
                TOKEN: str = Field(min_length=8)
            """,
        )
        (tmp_path / ".env").write_text('TOKEN="abc\\ndef"\n', encoding="utf-8")

        result = _validate_ci(tmp_path, integration_env)

        out = " ".join((result.stdout + result.stderr).split())
        assert result.returncode == 1, out

    def test_diff_escape_vs_literal_tab_no_drift(self, tmp_path, integration_env):
        """MSG="tab\\there" and the literal-TAB twin parse identically in
        dotenv_values; diff used to report CHANGED drift."""
        (tmp_path / "a.env").write_text('MSG="tab\\there"\n', encoding="utf-8")
        (tmp_path / "b.env").write_text('MSG="tab\there"\n', encoding="utf-8")

        data = _diff_json(tmp_path, integration_env, "a.env", "b.env")

        assert data["summary"]["has_drift"] is False


class TestUnicodeLineBoundaries:
    """#486: U+2028 inside a value is content, not a line break."""

    def test_validate_no_phantom_extra_from_u2028(self, tmp_path, integration_env):
        """Issue repro: the single U+2028 line is ONE variable to
        pydantic-settings; validate used to report EXTRA VARIABLES:
        SECRET_PASSWORD and exit 1."""
        _write_schema(
            tmp_path,
            """
            from pydantic_settings import BaseSettings, SettingsConfigDict

            class Settings(BaseSettings):
                model_config = SettingsConfigDict(extra="forbid")

                NOTE: str
            """,
        )
        (tmp_path / ".env").write_bytes(U2028_LINE)

        result = _validate_ci(tmp_path, integration_env)

        out = " ".join((result.stdout + result.stderr).split())
        assert result.returncode == 0, out
        assert "SECRET_PASSWORD" not in out

    def test_encrypt_check_sees_no_phantom_secret(self, tmp_path, integration_env):
        """The phantom SECRET_PASSWORD fabricated from the value's tail used
        to be classified as a plaintext secret and block (exit 1)."""
        (tmp_path / ".env").write_bytes(U2028_LINE + b"APP_NAME=demo\n")

        result = _run_cli(["encrypt", ".env", "--check"], cwd=tmp_path, env=integration_env)

        out = " ".join((result.stdout + result.stderr).split())
        assert result.returncode == 0, out
        assert "SECRET_PASSWORD" not in out

    def test_diff_names_the_real_variable_not_the_phantom(self, tmp_path, integration_env):
        """Drift past the U+2028 belongs to NOTE — diff used to report it
        against a phantom SECRET_PASSWORD variable the user never wrote."""
        (tmp_path / "a.env").write_bytes(U2028_LINE)
        (tmp_path / "b.env").write_bytes(U2028_LINE.replace(b"hunter2", b"other9"))

        data = _diff_json(tmp_path, integration_env, "a.env", "b.env")

        names = {d["name"] for d in data["differences"]}
        assert data["summary"]["has_drift"] is True
        assert names == {"NOTE"}


class TestUtf8Bom:
    """#486: a UTF-8 BOM is stripped — no invisible phantom first key."""

    def test_validate_bom_file_passes_with_a_bom_warning(self, tmp_path, integration_env):
        """The BOM key used to make validate list API_KEY both MISSING and
        EXTRA (the BOM renders invisibly) and exit 1. It now passes with an
        explicit warning: pydantic-settings reads plain UTF-8, so the app
        still sees the BOM-prefixed key (dotenv_values 1.2.2 loads
        ``{'\\ufeffAPI_KEY': 'abc123'}``) — silence would be a false green."""
        _write_schema(
            tmp_path,
            """
            from pydantic_settings import BaseSettings

            class Settings(BaseSettings):
                API_KEY: str
            """,
        )
        (tmp_path / ".env").write_bytes(BOM_LINE)

        result = _validate_ci(tmp_path, integration_env)

        out = " ".join((result.stdout + result.stderr).split())
        assert result.returncode == 0, out
        assert "Validation PASSED" in out
        assert "MISSING" not in out
        assert "EXTRA" not in out
        assert "UTF-8 BOM" in out

    def test_diff_bom_twin_reports_no_drift(self, tmp_path, integration_env):
        """Issue repro: the BOM file and its BOM-less twin parse identically;
        diff used to report API_KEY added/removed phantom drift."""
        (tmp_path / "bom.env").write_bytes(BOM_LINE)
        (tmp_path / "plain.env").write_bytes(BOM_LINE[3:])

        data = _diff_json(tmp_path, integration_env, "bom.env", "plain.env")

        assert data["summary"]["has_drift"] is False
        assert data["differences"] == []
