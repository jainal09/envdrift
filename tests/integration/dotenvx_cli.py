"""Run the real envdrift CLI and dotenvx side by side, as the key-reuse tests need.

Both must run the same dotenvx: the CLI finds it through ``VIRTUAL_ENV`` first,
so the CLI's environment names the virtualenv this process looks in (#938).
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from tests.integration.kv2_standin import TOKEN


def venv_root() -> Path | None:
    """The virtualenv this process looks for dotenvx in, or None when it finds none."""
    from envdrift.integrations.dotenvx import get_venv_bin_dir

    try:
        return get_venv_bin_dir().parent
    except RuntimeError:
        return None


def child_env(pythonpath: str, no_venv: Path) -> dict[str, str]:
    """The CLI's environment: this checkout's code, the stand-in token, no stray keys.

    ``VIRTUAL_ENV`` is the folder ``dotenvx_command`` looks in. The CLI checks
    it first, so both run the same dotenvx whatever their working directory.
    When this process finds no virtualenv, the CLI gets ``no_venv``, an empty
    folder, so it too runs the dotenvx on PATH.
    """
    env = {key: value for key, value in os.environ.items() if not key.startswith("DOTENV_")}
    env.pop("FORCE_COLOR", None)
    env["NO_COLOR"] = "1"
    env["PYTHONPATH"] = pythonpath
    env["VAULT_TOKEN"] = TOKEN
    env["VIRTUAL_ENV"] = str(venv_root() or no_venv)
    for name in ("NO_PROXY", "no_proxy"):
        env[name] = ",".join(filter(None, [env.get(name, ""), "127.0.0.1", "localhost"]))
    return env


def dotenvx_command() -> str:
    """The dotenvx the CLI under test runs: the virtualenv's, else the one on PATH."""
    from envdrift.integrations.dotenvx import get_dotenvx_path

    if venv_root() is None:
        return "dotenvx"
    venv_binary = get_dotenvx_path()
    return str(venv_binary) if venv_binary.exists() else "dotenvx"


class Cli:
    """Run the real envdrift CLI (and dotenvx) in one work directory."""

    def __init__(self, cwd: Path, envdrift_cmd: list[str], pythonpath: str) -> None:
        self.cwd = cwd
        self.envdrift_cmd = envdrift_cmd
        no_venv = cwd.parent / "no-virtualenv"
        no_venv.mkdir(exist_ok=True)
        self.env = child_env(pythonpath, no_venv)

    def run(self, *args: str) -> tuple[int, str]:
        result = subprocess.run(
            [*self.envdrift_cmd, *args],
            cwd=self.cwd,
            env=self.env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        # Width-independent: Rich soft-wraps long tmp paths at CI's width.
        return result.returncode, " ".join((result.stdout + result.stderr).split())

    def dotenvx(self, *args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [dotenvx_command(), *args],
            cwd=cwd or self.cwd,
            env=self.env,
            capture_output=True,
            text=True,
            timeout=60,
        )
