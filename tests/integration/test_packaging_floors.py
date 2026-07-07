"""Integration regression tests: the CLI must run at the declared typer floor.

Builds a scratch virtualenv with ``uv``, installs envdrift from this source
tree with ``typer`` pinned to the exact ``>=`` floor declared in
``pyproject.toml``, then drives the real ``envdrift`` console script as a
subprocess. On typer < 0.13 every invocation — including ``--help`` — crashes
with ``RuntimeError: Type not yet supported: str | None`` because the command
signatures use PEP 604 unions, and typer 0.13-0.15.3 resolve click >= 8.2,
whose ``Parameter.make_metavar()`` change crashes ``--help`` rendering; the
declared floor must always be a version the CLI actually works on.

The floor is read dynamically from ``pyproject.toml`` so future floor bumps are
re-verified automatically instead of drifting (issue #496).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from tests.helpers import REPO_ROOT, declared_dependency_floor

pytestmark = [pytest.mark.integration, pytest.mark.slow]

_UV = shutil.which("uv")

_INSTALL_TIMEOUT = 300
_CLI_TIMEOUT = 120


def _uv_env() -> dict[str, str]:
    """Subprocess env for uv: drop venv inheritance so ``--python`` wins."""
    env = os.environ.copy()
    env.pop("VIRTUAL_ENV", None)
    env.pop("PYTHONPATH", None)
    return env


def _venv_bin(venv: Path, name: str) -> Path:
    """Return the path of *name* inside the venv's scripts directory."""
    if os.name == "nt":
        return venv / "Scripts" / f"{name}.exe"
    return venv / "bin" / name


@pytest.fixture(scope="module")
def typer_floor_cli(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Install envdrift with typer pinned to its declared floor; yield the CLI path."""
    if _UV is None:
        pytest.skip("uv binary not available")

    floor = declared_dependency_floor("typer")
    venv = tmp_path_factory.mktemp("typer-floor") / "venv"

    create = subprocess.run(
        [_UV, "venv", "--python", sys.executable, str(venv)],
        capture_output=True,
        text=True,
        env=_uv_env(),
        timeout=_INSTALL_TIMEOUT,
        check=False,
    )
    assert create.returncode == 0, f"uv venv failed: {create.stdout}\n{create.stderr}"

    install = subprocess.run(
        [
            _UV,
            "pip",
            "install",
            "--python",
            str(_venv_bin(venv, "python")),
            str(REPO_ROOT),
            f"typer=={floor}",
        ],
        capture_output=True,
        text=True,
        env=_uv_env(),
        timeout=_INSTALL_TIMEOUT,
        check=False,
    )
    assert install.returncode == 0, (
        f"installing envdrift with typer=={floor} (the declared floor) failed: "
        f"{install.stdout}\n{install.stderr}"
    )
    return _venv_bin(venv, "envdrift")


def _run_cli(cli: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = _uv_env()
    env["COLUMNS"] = "200"
    return subprocess.run(
        [str(cli), *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=_CLI_TIMEOUT,
        check=False,
    )


def test_cli_help_runs_at_declared_typer_floor(typer_floor_cli: Path) -> None:
    """``envdrift --help`` must succeed with typer at the declared floor (#496)."""
    result = _run_cli(typer_floor_cli, "--help")
    combined = " ".join((result.stdout + result.stderr).split())
    assert "Type not yet supported" not in combined, (
        f"typer floor cannot handle the CLI's PEP 604 unions: {combined}"
    )
    assert result.returncode == 0, f"envdrift --help crashed at the typer floor: {combined}"
    assert "Usage" in combined


def test_cli_version_runs_at_declared_typer_floor(typer_floor_cli: Path) -> None:
    """``envdrift version`` must succeed with typer at the declared floor (#496)."""
    result = _run_cli(typer_floor_cli, "version")
    combined = " ".join((result.stdout + result.stderr).split())
    assert "Type not yet supported" not in combined, (
        f"typer floor cannot handle the CLI's PEP 604 unions: {combined}"
    )
    assert result.returncode == 0, f"envdrift version crashed at the typer floor: {combined}"
    assert "envdrift" in combined
