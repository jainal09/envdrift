"""Regression tests for ``python -m envdrift`` (#498).

``docs/support/troubleshooting.md`` recommends ``entry: python -m envdrift
validate`` as the pre-commit PATH fallback and ``docs/guides/agent-setup.md``
recommends ``python -m envdrift --version`` as the not-on-PATH escape hatch.
Before #498 the package shipped no ``__main__.py``, so both documented commands
died with ``No module named envdrift.__main__`` — a user with a PATH problem got
a second, more confusing failure.

These drive the real interpreter and the real CLI: a true ``python -m``
subprocess plus an in-process ``runpy`` run of the same module. No mocking of
the behavior under test.
"""

from __future__ import annotations

import os
import runpy
import subprocess
import sys
from pathlib import Path

import pytest

from envdrift import __version__


def _run_module(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    """Run ``python -m envdrift <args>`` exactly as the docs recommend."""
    env = os.environ.copy()
    # Keep output un-colorized and parseable even under CI's FORCE_COLOR=1.
    env.pop("FORCE_COLOR", None)
    env["NO_COLOR"] = "1"
    return subprocess.run(
        [sys.executable, "-m", "envdrift", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        cwd=cwd,
        check=False,
    )


def test_python_dash_m_envdrift_version(tmp_path: Path) -> None:
    """agent-setup.md's ``python -m envdrift --version`` must work (#498)."""
    result = _run_module("--version", cwd=tmp_path)
    combined = " ".join((result.stdout + result.stderr).split())
    assert "No module named" not in combined, combined
    assert result.returncode == 0, combined
    assert __version__ in combined


def test_python_dash_m_envdrift_validate_resolves(tmp_path: Path) -> None:
    """troubleshooting.md's ``python -m envdrift validate`` entry must resolve (#498).

    The pre-commit fallback only helps if the module invocation reaches the real
    ``validate`` command instead of dying on import.
    """
    result = _run_module("validate", "--help", cwd=tmp_path)
    combined = " ".join((result.stdout + result.stderr).split())
    assert "No module named" not in combined, combined
    assert result.returncode == 0, combined
    assert "validate" in combined


def test_dunder_main_dispatches_to_cli_app(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """``envdrift.__main__`` runs the same Typer app as the ``envdrift`` script."""
    # Keep runpy's fresh execution warning-free if another test imported the
    # module as a plain module first (order independence).
    monkeypatch.delitem(sys.modules, "envdrift.__main__", raising=False)
    monkeypatch.setattr(sys, "argv", ["envdrift", "--version"])
    with pytest.raises(SystemExit) as excinfo:
        runpy.run_module("envdrift", run_name="__main__")
    assert excinfo.value.code == 0
    out = " ".join(capsys.readouterr().out.split())
    assert f"envdrift {__version__}" in out


def test_plain_import_does_not_invoke_cli(capsys: pytest.CaptureFixture[str]) -> None:
    """Importing ``envdrift.__main__`` as a normal module must not run the app."""
    import importlib

    module = importlib.import_module("envdrift.__main__")
    assert hasattr(module, "app")
    assert capsys.readouterr().out == ""
