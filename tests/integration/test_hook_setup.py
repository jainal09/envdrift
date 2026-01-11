"""Integration tests for git hook auto-setup."""

from __future__ import annotations

import os
import shutil
import subprocess  # nosec B404
import sys
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PYTHONPATH = str(REPO_ROOT / "src")


def _run_envdrift(args: list[str], *, cwd: Path, env: dict[str, str], check: bool = True):
    cmd = [sys.executable, "-m", "envdrift.cli", *args]
    result = subprocess.run(  # nosec B603
        cmd,
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            "envdrift failed\n"
            f"cmd: {' '.join(cmd)}\n"
            f"cwd: {cwd}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    return result


def _init_git_repo(path: Path) -> None:
    git_path = shutil.which("git")
    if git_path is None:
        pytest.skip("git is not available")
    env = os.environ.copy()
    for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR"):
        env.pop(key, None)
    subprocess.run(  # nosec B603
        [git_path, "init"],
        cwd=str(path),
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )


@pytest.fixture(scope="session")
def hook_integration_env(tmp_path_factory):
    base_dir = tmp_path_factory.mktemp("envdrift-hook-integration")
    venv_dir = base_dir / ".venv"
    bin_dir = venv_dir / ("Scripts" if os.name == "nt" else "bin")
    bin_dir.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["VIRTUAL_ENV"] = str(venv_dir)
    env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
    env["PYTHONPATH"] = f"{PYTHONPATH}{os.pathsep}{env.get('PYTHONPATH', '')}"

    return {"base_dir": base_dir, "env": env}


@pytest.mark.integration
def test_hook_setup_precommit_auto_installs(hook_integration_env):
    pytest.importorskip("yaml")
    work_dir = hook_integration_env["base_dir"] / "precommit"
    work_dir.mkdir()
    _init_git_repo(work_dir)

    env = hook_integration_env["env"].copy()
    env_file = work_dir / ".env.hooks"
    env_file.write_text("API_KEY=supersecret\n")

    config = textwrap.dedent(
        """\
        [git_hook_check]
        method = "precommit.yaml"
        precommit_config = ".pre-commit-config.yaml"

        [encryption]
        backend = "dotenvx"

        [encryption.dotenvx]
        auto_install = true
        """
    )
    (work_dir / "envdrift.toml").write_text(config)

    _run_envdrift(["encrypt", env_file.name], cwd=work_dir, env=env)
    precommit_path = work_dir / ".pre-commit-config.yaml"
    # Hook checks run on encrypt/decrypt; encrypt should install the pre-commit config.
    assert precommit_path.exists()

    _run_envdrift(["decrypt", env_file.name], cwd=work_dir, env=env)
    assert precommit_path.exists()
    assert "envdrift-encryption" in precommit_path.read_text()


@pytest.mark.integration
def test_hook_setup_direct_auto_installs(hook_integration_env):
    work_dir = hook_integration_env["base_dir"] / "direct"
    work_dir.mkdir()
    _init_git_repo(work_dir)

    env = hook_integration_env["env"].copy()
    env_file = work_dir / ".env.hooks"
    env_file.write_text("API_KEY=supersecret\n")

    config = textwrap.dedent(
        """\
        [git_hook_check]
        method = "direct git hook"

        [encryption]
        backend = "dotenvx"

        [encryption.dotenvx]
        auto_install = true
        """
    )
    (work_dir / "envdrift.toml").write_text(config)

    _run_envdrift(["encrypt", env_file.name], cwd=work_dir, env=env)

    pre_commit = work_dir / ".git" / "hooks" / "pre-commit"
    pre_push = work_dir / ".git" / "hooks" / "pre-push"
    # Remove hooks created during encrypt to verify decrypt reinstalls them.
    if pre_commit.exists():
        pre_commit.unlink()
    if pre_push.exists():
        pre_push.unlink()

    _run_envdrift(["decrypt", env_file.name], cwd=work_dir, env=env)

    assert pre_commit.exists()
    assert pre_push.exists()
    assert "envdrift encrypt --check" in pre_commit.read_text()
    assert "envdrift lock --check" in pre_push.read_text()
