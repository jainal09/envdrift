"""Integration tests proving the generated pre-commit config runs as emitted (#493).

These tests drive the real ``envdrift`` CLI as a subprocess (and the real
``pre-commit`` runner where available) to assert that:

* ``hook --install`` produces a config whose hooks actually pass in a
  compliant repository, including multi-file batches (``pass_filenames: true``
  hands every matched staged file to one invocation);
* ``validate`` / ``encrypt --check`` accept multiple env-file arguments, as
  the generated hook entries require;
* ``hook --install`` preserves the user's existing YAML comments/formatting;
* ``hook --install`` fails cleanly (no traceback) on malformed YAML.
"""

from __future__ import annotations

import os
import shutil
import subprocess  # nosec B404
import sys
import textwrap
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_PATH = str(REPO_ROOT / "src")


def _cli_env(tmp_path: Path) -> dict[str, str]:
    """Subprocess env: test venv on PATH, src importable, isolated pre-commit home."""
    env = os.environ.copy()
    env["PYTHONPATH"] = SRC_PATH + os.pathsep + env.get("PYTHONPATH", "")
    env["PATH"] = str(Path(sys.executable).parent) + os.pathsep + env.get("PATH", "")
    env["PRE_COMMIT_HOME"] = str(tmp_path / "pre-commit-home")
    for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR"):
        env.pop(key, None)
    return env


def _run(cmd: list[str], *, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # nosec B603
        cmd,
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def _run_envdrift(
    args: list[str], *, cwd: Path, env: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    return _run([sys.executable, "-m", "envdrift.cli", *args], cwd=cwd, env=env)


def _init_git_repo(path: Path, env: dict[str, str]) -> str:
    git = shutil.which("git")
    if git is None:
        pytest.skip("git is not available")
    subprocess.run(  # nosec B603
        [git, "init"], cwd=str(path), env=env, check=True, capture_output=True, text=True
    )
    return git


def _diag(result: subprocess.CompletedProcess[str]) -> str:
    return f"exit={result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"


class TestGeneratedConfigRunsAsEmitted:
    """The config emitted by hook --install must pass in a compliant repo (#493)."""

    def test_installed_hooks_pass_under_real_pre_commit(self, tmp_path: Path) -> None:
        """hook --install then `pre-commit run --all-files` exits 0 with 2 env files staged.

        Regression for #493: the old config shipped an always-failing validate
        hook (``validate --ci`` without ``--schema``) and hooks that crashed
        with a Typer usage error as soon as two matched files were staged.
        """
        pytest.importorskip("pre_commit")
        if shutil.which("dotenvx") is None:
            pytest.skip("dotenvx is not installed")

        env = _cli_env(tmp_path)
        repo = tmp_path / "repo"
        repo.mkdir()
        git = _init_git_repo(repo, env)

        # Two files matched by the generated hooks' `files` regexes; encrypted so
        # a compliant repo passes both the encryption check and the guard scan.
        (repo / ".env.production").write_text("FOO=bar\n", encoding="utf-8")
        (repo / ".env.staging").write_text("BAR=baz\n", encoding="utf-8")
        for name in (".env.production", ".env.staging"):
            encrypted = _run_envdrift(["encrypt", name], cwd=repo, env=env)
            assert encrypted.returncode == 0, _diag(encrypted)

        install = _run_envdrift(["hook", "--install"], cwd=repo, env=env)
        assert install.returncode == 0, _diag(install)

        add = _run([git, "add", "-A"], cwd=repo, env=env)
        assert add.returncode == 0, _diag(add)

        result = _run([sys.executable, "-m", "pre_commit", "run", "--all-files"], cwd=repo, env=env)
        assert result.returncode == 0, f"generated hooks failed under pre-commit:\n{_diag(result)}"

    def test_encrypt_check_accepts_multiple_files(self, tmp_path: Path) -> None:
        """`envdrift encrypt --check a b` (the hook entry with 2 staged files) exits 0."""
        env = _cli_env(tmp_path)
        (tmp_path / ".env.production").write_text("FOO=bar\n", encoding="utf-8")
        (tmp_path / ".env.staging").write_text("BAR=baz\n", encoding="utf-8")

        result = _run_envdrift(
            ["encrypt", "--check", ".env.production", ".env.staging"], cwd=tmp_path, env=env
        )
        out = " ".join((result.stdout + result.stderr).split())
        assert result.returncode == 0, _diag(result)
        assert ".env.production" in out
        assert ".env.staging" in out

    def test_encrypt_check_multi_file_blocks_when_any_file_has_secret(self, tmp_path: Path) -> None:
        """A plaintext secret in the *second* file must still fail the batch."""
        env = _cli_env(tmp_path)
        (tmp_path / ".env.production").write_text("FOO=bar\n", encoding="utf-8")
        # Sensitive name pattern (*_PASSWORD) with a plaintext value.
        (tmp_path / ".env.staging").write_text("DB_PASSWORD=hunter2\n", encoding="utf-8")

        result = _run_envdrift(
            ["encrypt", "--check", ".env.production", ".env.staging"], cwd=tmp_path, env=env
        )
        assert result.returncode == 1, _diag(result)

    def test_encrypt_check_skips_companions_and_checks_remaining_files(
        self, tmp_path: Path
    ) -> None:
        """A companion must not abort a pre-commit filename batch (#579)."""
        env = _cli_env(tmp_path)
        (tmp_path / ".env.production").write_text("API_KEY=plaintext-value\n", encoding="utf-8")
        (tmp_path / ".env.example").write_text("API_KEY=example-value\n", encoding="utf-8")

        result = _run_envdrift(
            ["encrypt", "--check", ".env.production", ".env.example"], cwd=tmp_path, env=env
        )
        output = " ".join((result.stdout + result.stderr).split())

        assert result.returncode == 1, _diag(result)
        assert ".env.production" in output
        assert "Skipping .env.example" in output

    def test_encrypt_check_skips_a_companion_only_batch(self, tmp_path: Path) -> None:
        """Named plaintext companions are intentionally outside encryption policy (#579)."""
        env = _cli_env(tmp_path)
        (tmp_path / ".env.example").write_text("API_KEY=example-value\n", encoding="utf-8")

        result = _run_envdrift(["encrypt", "--check", ".env.example"], cwd=tmp_path, env=env)
        output = " ".join((result.stdout + result.stderr).split())

        assert result.returncode == 0, _diag(result)
        assert "Skipping .env.example" in output
        assert "Encryption Status" not in output

    def test_encrypt_check_blocks_plaintext_duplicate_shadowed_by_ciphertext(
        self, tmp_path: Path
    ) -> None:
        """Every on-disk assignment must be checked, not just the last duplicate (#583)."""
        env = _cli_env(tmp_path)
        (tmp_path / ".env.production").write_text(
            'SECRET_KEY=plaintext-value\nSECRET_KEY="encrypted:BDqDBJ24bUq3x"\n',
            encoding="utf-8",
        )

        result = _run_envdrift(["encrypt", "--check", ".env.production"], cwd=tmp_path, env=env)
        output = " ".join((result.stdout + result.stderr).split())

        assert result.returncode == 1, _diag(result)
        assert "Plaintext: 1" in output

    def test_validate_hook_entry_with_schema_accepts_multiple_files(self, tmp_path: Path) -> None:
        """The documented validate hook entry works with 2 staged files appended."""
        env = _cli_env(tmp_path)
        (tmp_path / "settings.py").write_text(
            textwrap.dedent(
                """\
                from pydantic_settings import BaseSettings


                class Settings(BaseSettings):
                    FOO: str = "unset"
                """
            ),
            encoding="utf-8",
        )
        (tmp_path / ".env.production").write_text("FOO=bar\n", encoding="utf-8")
        (tmp_path / ".env.staging").write_text("FOO=baz\n", encoding="utf-8")

        result = _run_envdrift(
            [
                "validate",
                "--ci",
                "--schema",
                "settings:Settings",
                ".env.production",
                ".env.staging",
            ],
            cwd=tmp_path,
            env=env,
        )
        assert result.returncode == 0, _diag(result)
        out = " ".join((result.stdout + result.stderr).split())
        assert ".env.production" in out
        assert ".env.staging" in out

    def test_validate_ci_multi_file_fails_when_any_file_invalid(self, tmp_path: Path) -> None:
        """--ci exits 1 when any one of the batched files is invalid."""
        env = _cli_env(tmp_path)
        (tmp_path / "settings.py").write_text(
            textwrap.dedent(
                """\
                from pydantic_settings import BaseSettings


                class Settings(BaseSettings):
                    FOO: str
                """
            ),
            encoding="utf-8",
        )
        (tmp_path / ".env.production").write_text("FOO=bar\n", encoding="utf-8")
        (tmp_path / ".env.staging").write_text("OTHER=value\n", encoding="utf-8")

        result = _run_envdrift(
            [
                "validate",
                "--ci",
                "--schema",
                "settings:Settings",
                ".env.production",
                ".env.staging",
            ],
            cwd=tmp_path,
            env=env,
        )
        assert result.returncode == 1, _diag(result)


class TestHookInstallPreservesUserConfig:
    """hook --install must not rewrite the user's .pre-commit-config.yaml (#493)."""

    def test_install_preserves_comments_and_formatting(self, tmp_path: Path) -> None:
        original = textwrap.dedent(
            """\
            # DO NOT EDIT without talking to the platform team
            # See https://wiki.example.com/pre-commit for the policy.
            default_language_version:
              python: python3.11  # pinned for CI parity
            repos:
              - repo: https://github.com/psf/black
                rev: 24.3.0  # bump quarterly
                hooks:
                  - id: black
            """
        )
        config_file = tmp_path / ".pre-commit-config.yaml"
        config_file.write_text(original, encoding="utf-8")

        env = _cli_env(tmp_path)
        result = _run_envdrift(["hook", "--install"], cwd=tmp_path, env=env)
        assert result.returncode == 0, _diag(result)

        updated = config_file.read_text(encoding="utf-8")
        for line in original.splitlines():
            assert line in updated.splitlines(), f"original line lost by --install: {line!r}"
        assert "envdrift-encryption" in updated
        assert "envdrift-guard" in updated

    def test_install_on_malformed_yaml_fails_cleanly(self, tmp_path: Path) -> None:
        """Malformed YAML yields a clean error and exit 1, not a traceback."""
        config_file = tmp_path / ".pre-commit-config.yaml"
        config_file.write_text("repos: [unclosed\n", encoding="utf-8")

        env = _cli_env(tmp_path)
        result = _run_envdrift(["hook", "--install"], cwd=tmp_path, env=env)
        out = " ".join((result.stdout + result.stderr).split())
        assert result.returncode == 1, _diag(result)
        assert "Traceback" not in result.stdout
        assert "Traceback" not in result.stderr
        assert "could not parse" in out.lower(), _diag(result)
        # The broken file must be left untouched.
        assert config_file.read_text(encoding="utf-8") == "repos: [unclosed\n"

    def test_install_on_non_mapping_yaml_fails_cleanly(self, tmp_path: Path) -> None:
        """A list-rooted YAML document yields a clean error, not a TypeError traceback."""
        config_file = tmp_path / ".pre-commit-config.yaml"
        config_file.write_text("- just\n- a list\n", encoding="utf-8")

        env = _cli_env(tmp_path)
        result = _run_envdrift(["hook", "--install"], cwd=tmp_path, env=env)
        out = " ".join((result.stdout + result.stderr).split())
        assert result.returncode == 1, _diag(result)
        assert "Traceback" not in result.stdout
        assert "Traceback" not in result.stderr
        assert "mapping" in out.lower(), _diag(result)
        assert config_file.read_text(encoding="utf-8") == "- just\n- a list\n"
