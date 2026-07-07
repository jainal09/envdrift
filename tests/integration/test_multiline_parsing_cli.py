"""CLI regression tests for #458: multiline quoted values end-to-end.

The parser used to split quoted multiline values per physical line, so
``validate`` produced false PASS/FAIL verdicts (phantom variables satisfied or
violated the schema), ``diff`` missed drift hidden past the first line of a
value, and ``encrypt --check`` blocked commits on secrets the user never
wrote. These tests drive the real ``envdrift`` CLI as a subprocess against
multiline fixtures and assert exit codes plus machine-readable output.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

pytestmark = [pytest.mark.integration]

# PEM-style fixture material, built by concatenation so the literals never look
# like real key material (GitHub push protection).
PEM_HEADER = "-----BEGIN " + "TEST CERT-----"
PEM_FOOTER = "-----END " + "TEST CERT-----"
PEM_BODY = "QUJDREVGMDEyMzQ1Njc4OQ" + "=="
PEM_VALUE = f"{PEM_HEADER}\n{PEM_BODY}\n{PEM_FOOTER}"


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


class TestValidateMultiline:
    """validate must judge the file the way pydantic-settings parses it."""

    def test_required_var_swallowed_by_multiline_value_fails_ci(self, tmp_path, integration_env):
        """Issue #458 headline: an interior ``DB_PASSWORD=...`` line is part of
        CERT's value, so the required DB_PASSWORD is MISSING. This used to be a
        false PASS (exit 0) from the phantom variable."""
        _write_schema(
            tmp_path,
            """
            from pydantic_settings import BaseSettings

            class Settings(BaseSettings):
                CERT: str
                DB_PASSWORD: str
            """,
        )
        (tmp_path / ".env").write_text(
            'CERT="-----BEGIN CERT-----\n'
            "DB_PASSWORD=oops_interpreted_as_assignment\n"
            '-----END CERT-----"\n',
            encoding="utf-8",
        )

        result = _validate_ci(tmp_path, integration_env)

        out = " ".join((result.stdout + result.stderr).split())
        assert result.returncode == 1, out
        assert "DB_PASSWORD" in out

    def test_clean_multiline_pem_passes_without_phantom_extras(self, tmp_path, integration_env):
        """A well-formed multiline PEM under ``extra='forbid'`` must PASS: the
        interior base64 lines used to surface as phantom extra variables (false
        FAIL) and the value was truncated to the stray-quote first line."""
        _write_schema(
            tmp_path,
            """
            from pydantic_settings import BaseSettings, SettingsConfigDict

            class Settings(BaseSettings):
                model_config = SettingsConfigDict(extra="forbid")

                TLS_CERT: str
                PORT: int
            """,
        )
        (tmp_path / ".env").write_text(f'TLS_CERT="{PEM_VALUE}"\nPORT=8080\n', encoding="utf-8")

        result = _validate_ci(tmp_path, integration_env)

        out = " ".join((result.stdout + result.stderr).split())
        assert result.returncode == 0, out
        assert "Validation PASSED" in out


class TestDiffMultiline:
    """diff must compare full multiline values, not their first lines."""

    def test_drift_inside_multiline_value_is_detected(self, tmp_path, integration_env):
        """Two CERTs identical on their first physical line but different
        inside used to compare equal (false no-drift)."""
        (tmp_path / ".env.dev").write_text(
            f'CERT="{PEM_HEADER}\nAAAACONTENTDEV\n{PEM_FOOTER}"\n', encoding="utf-8"
        )
        (tmp_path / ".env.prod").write_text(
            f'CERT="{PEM_HEADER}\nBBBBCONTENTPROD\n{PEM_FOOTER}"\n', encoding="utf-8"
        )

        result = _run_cli(
            ["diff", ".env.dev", ".env.prod", "--format", "json"],
            cwd=tmp_path,
            env=integration_env,
        )

        assert result.returncode == 0, result.stdout + result.stderr
        data = json.loads(result.stdout)
        changed = {d["name"] for d in data["differences"] if d["type"] == "changed"}
        assert changed == {"CERT"}
        assert data["summary"]["has_drift"] is True

    def test_drift_on_interior_assignment_line_names_the_real_var(self, tmp_path, integration_env):
        """An interior ``DB_PASSWORD=...`` line that differs is drift in CERT —
        not in a phantom DB_PASSWORD variable."""
        (tmp_path / ".env.dev").write_text(
            f'CERT="{PEM_HEADER}\nDB_PASSWORD=devvalue\n{PEM_FOOTER}"\n',
            encoding="utf-8",
        )
        (tmp_path / ".env.prod").write_text(
            f'CERT="{PEM_HEADER}\nDB_PASSWORD=prodvalue\n{PEM_FOOTER}"\n',
            encoding="utf-8",
        )

        result = _run_cli(
            ["diff", ".env.dev", ".env.prod", "--format", "json"],
            cwd=tmp_path,
            env=integration_env,
        )

        assert result.returncode == 0, result.stdout + result.stderr
        data = json.loads(result.stdout)
        names = {d["name"] for d in data["differences"]}
        assert "CERT" in names
        assert "DB_PASSWORD" not in names


class TestEncryptCheckMultiline:
    """encrypt --check classification reads parsed values."""

    def test_no_phantom_secret_blocks_commit(self, tmp_path, integration_env):
        """A phantom DB_PASSWORD fabricated from a multiline value used to be
        classified as a plaintext secret and block (exit 1)."""
        (tmp_path / ".env").write_text(
            f'CERT="{PEM_HEADER}\nDB_PASSWORD=not_a_real_var\n{PEM_FOOTER}"\nAPP_NAME=demo\n',
            encoding="utf-8",
        )

        result = _run_cli(["encrypt", ".env", "--check"], cwd=tmp_path, env=integration_env)

        out = " ".join((result.stdout + result.stderr).split())
        assert result.returncode == 0, out
        assert "DB_PASSWORD" not in out
