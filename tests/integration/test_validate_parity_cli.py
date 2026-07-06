"""CLI regression tests for #472: validate/diff parity with pydantic-settings.

Drives the real ``envdrift`` CLI as a subprocess against scratch .env files and
generated schema modules, asserting exit codes (``--ci``) and machine-readable
diff output. Includes the quickstart's own init -> encrypt -> validate loop
(skip-gated on the dotenvx binary).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

pytestmark = [pytest.mark.integration]

DOTENVX_AVAILABLE = shutil.which("dotenvx") is not None


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


def _write_schema(tmp_path: Path, body: str, name: str = "sc.py") -> None:
    (tmp_path / name).write_text(textwrap.dedent(body), encoding="utf-8")


def _validate_ci(tmp_path: Path, integration_env: dict[str, str], env_name: str = ".env"):
    return _run_cli(
        [
            "validate",
            env_name,
            "--schema",
            "sc:Settings",
            "--service-dir",
            str(tmp_path),
            "--no-check-encryption",
            "--ci",
        ],
        cwd=tmp_path,
        env=integration_env,
    )


class TestValidateCiParity:
    """validate --ci exit codes must match whether the real app starts."""

    def test_bool_spelling_on_exits_zero(self, tmp_path, integration_env):
        """#472: DEBUG=on loads in pydantic-settings; --ci must exit 0."""
        _write_schema(
            tmp_path,
            """
            from pydantic_settings import BaseSettings

            class Settings(BaseSettings):
                DEBUG: bool
            """,
        )
        (tmp_path / ".env").write_text("DEBUG=on\n", encoding="utf-8")

        result = _validate_ci(tmp_path, integration_env)

        out = " ".join((result.stdout + result.stderr).split())
        assert result.returncode == 0, out
        assert "Validation PASSED" in out

    def test_empty_int_exits_one(self, tmp_path, integration_env):
        """#472: PORT= crashes the real app; --ci must exit 1."""
        _write_schema(
            tmp_path,
            """
            from pydantic_settings import BaseSettings

            class Settings(BaseSettings):
                PORT: int
            """,
        )
        (tmp_path / ".env").write_text("PORT=\n", encoding="utf-8")

        result = _validate_ci(tmp_path, integration_env)

        out = " ".join((result.stdout + result.stderr).split())
        assert result.returncode == 1, out
        assert "PORT" in out

    def test_non_json_list_exits_one(self, tmp_path, integration_env):
        """#472: TAGS=a,b,c raises SettingsError in the real app; --ci exits 1."""
        _write_schema(
            tmp_path,
            """
            from pydantic_settings import BaseSettings

            class Settings(BaseSettings):
                TAGS: list[str]
            """,
        )
        (tmp_path / ".env").write_text("TAGS=a,b,c\n", encoding="utf-8")

        result = _validate_ci(tmp_path, integration_env)

        out = " ".join((result.stdout + result.stderr).split())
        assert result.returncode == 1, out
        assert "TAGS" in out

    def test_valid_json_list_exits_zero(self, tmp_path, integration_env):
        """Control: a JSON list value loads in the real app; --ci exits 0."""
        _write_schema(
            tmp_path,
            """
            from pydantic_settings import BaseSettings

            class Settings(BaseSettings):
                TAGS: list[str]
            """,
        )
        (tmp_path / ".env").write_text('TAGS=["a","b","c"]\n', encoding="utf-8")

        result = _validate_ci(tmp_path, integration_env)

        out = " ".join((result.stdout + result.stderr).split())
        assert result.returncode == 0, out

    def test_fullwidth_unicode_int_exits_one(self, tmp_path, integration_env):
        """#472: pydantic rejects non-ASCII digits; --ci must exit 1."""
        _write_schema(
            tmp_path,
            """
            from pydantic_settings import BaseSettings

            class Settings(BaseSettings):
                PORT: int
            """,
        )
        # "\uff14\uff12" is fullwidth "42": int() accepts it, pydantic does not.
        (tmp_path / ".env").write_text("PORT=\uff14\uff12\n", encoding="utf-8")

        result = _validate_ci(tmp_path, integration_env)

        out = " ".join((result.stdout + result.stderr).split())
        assert result.returncode == 1, out


class TestDiffSchemaParityCli:
    """Schema-typed diff verdicts through the real CLI (--format json)."""

    @staticmethod
    def _diff_json(tmp_path, integration_env, content1, content2):
        (tmp_path / "a.env").write_text(content1, encoding="utf-8")
        (tmp_path / "b.env").write_text(content2, encoding="utf-8")
        result = _run_cli(
            [
                "diff",
                "a.env",
                "b.env",
                "--schema",
                "sc:Settings",
                "--service-dir",
                str(tmp_path),
                "--format",
                "json",
            ],
            cwd=tmp_path,
            env=integration_env,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        return json.loads(result.stdout)

    def test_int_field_1_vs_true_reports_drift(self, tmp_path, integration_env):
        """#472: under PORT: int, '1' vs 'true' is drift ('true' crashes)."""
        _write_schema(
            tmp_path,
            """
            from pydantic_settings import BaseSettings, SettingsConfigDict

            class Settings(BaseSettings):
                model_config = SettingsConfigDict(extra="ignore")
                PORT: int
            """,
        )
        payload = self._diff_json(tmp_path, integration_env, "PORT=1\n", "PORT=true\n")

        assert payload["summary"]["has_drift"] is True
        assert payload["summary"]["changed"] == 1

    def test_int_field_1_vs_01_no_drift(self, tmp_path, integration_env):
        """Control: both sides coerce to the same int."""
        _write_schema(
            tmp_path,
            """
            from pydantic_settings import BaseSettings, SettingsConfigDict

            class Settings(BaseSettings):
                model_config = SettingsConfigDict(extra="ignore")
                PORT: int
            """,
        )
        payload = self._diff_json(tmp_path, integration_env, "PORT=1\n", "PORT=01\n")

        assert payload["summary"]["has_drift"] is False

    def test_bool_field_on_vs_true_no_drift_and_validate_agrees(self, tmp_path, integration_env):
        """#472: diff says on==true for a bool field AND validate accepts 'on'."""
        _write_schema(
            tmp_path,
            """
            from pydantic_settings import BaseSettings, SettingsConfigDict

            class Settings(BaseSettings):
                model_config = SettingsConfigDict(extra="ignore")
                DEBUG: bool
            """,
        )
        payload = self._diff_json(tmp_path, integration_env, "DEBUG=on\n", "DEBUG=true\n")
        assert payload["summary"]["has_drift"] is False

        (tmp_path / ".env").write_text("DEBUG=on\n", encoding="utf-8")
        result = _validate_ci(tmp_path, integration_env)
        assert result.returncode == 0, result.stdout + result.stderr


class TestDotenvxArtifactCli:
    """#472: the quickstart's init -> encrypt -> validate --ci loop stays green."""

    def test_handwritten_encrypted_artifact_validates(self, tmp_path, integration_env):
        """A dotenvx-encrypted file's DOTENV_PUBLIC_KEY_<ENV> artifact passes an
        extra='forbid' schema (no dotenvx binary required)."""
        _write_schema(
            tmp_path,
            """
            from pydantic import Field
            from pydantic_settings import BaseSettings, SettingsConfigDict

            class Settings(BaseSettings):
                model_config = SettingsConfigDict(extra="forbid")
                API_KEY: str = Field(json_schema_extra={"sensitive": True})
                DEBUG: bool = False
            """,
        )
        # Built via concatenation so the fixture never looks like a real secret.
        public_key = "03" + "a1b2c3" * 10
        ciphertext = "encrypted:" + "BDqDBmh4Y2x0" + "BJ9ZAJzL"
        (tmp_path / ".env.prod").write_text(
            "#/---BEGIN DOTENV ENCRYPTED---/\n"
            f'DOTENV_PUBLIC_KEY_PROD="{public_key}"\n'
            f'API_KEY="{ciphertext}"\n'
            "DEBUG=false\n",
            encoding="utf-8",
        )

        result = _validate_ci(tmp_path, integration_env, env_name=".env.prod")

        out = " ".join((result.stdout + result.stderr).split())
        assert result.returncode == 0, out
        assert "EXTRA VARIABLES" not in out
        assert "DOTENV_PUBLIC_KEY" not in out

    @pytest.mark.skipif(not DOTENVX_AVAILABLE, reason="dotenvx binary not installed")
    def test_quickstart_init_encrypt_validate_flow(self, tmp_path, integration_env):
        """#472: the documented init -> encrypt -> validate --ci flow exits 0."""
        secret_value = "sk_live_" + "x" * 8
        (tmp_path / ".env.prod").write_text(
            f"API_KEY={secret_value}\nDEBUG=false\n", encoding="utf-8"
        )

        init = _run_cli(["init", ".env.prod", "-o", "config.py"], cwd=tmp_path, env=integration_env)
        assert init.returncode == 0, init.stdout + init.stderr

        encrypt = _run_cli(["encrypt", ".env.prod"], cwd=tmp_path, env=integration_env)
        assert encrypt.returncode == 0, encrypt.stdout + encrypt.stderr
        encrypted_content = (tmp_path / ".env.prod").read_text(encoding="utf-8")
        assert "DOTENV_PUBLIC_KEY" in encrypted_content, encrypted_content

        validate = _run_cli(
            [
                "validate",
                ".env.prod",
                "--schema",
                "config:Settings",
                "--service-dir",
                str(tmp_path),
                "--ci",
            ],
            cwd=tmp_path,
            env=integration_env,
        )
        out = " ".join((validate.stdout + validate.stderr).split())
        assert validate.returncode == 0, out
        assert "Validation PASSED" in out
        assert "EXTRA VARIABLES" not in out
