"""End-to-end CLI integration tests for the real envdrift CLI subprocess.

These tests drive the real ``envdrift`` CLI as a subprocess (via the
``envdrift_cmd`` fixture). No mocking of behavior under test is used — the only
environment manipulation is redirecting ``HOME``/``USERPROFILE`` to a temp dir
so the agent project registry at ``~/.envdrift/projects.json`` is fully isolated
per test (and concurrent/repeat runs never collide).

No container is required for this module — it exercises the pure-CLI agent
registry surface: ``agent register / unregister / list`` plus the registry's
corruption-recovery and 0o600-permission guarantees, observed end-to-end through
the CLI.

Run from the repo root; the ``integration_pythonpath`` fixture makes the source
tree importable for ``uv run`` fallbacks.
"""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest

# Mark all tests in this module
pytestmark = [pytest.mark.integration]

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from CLI output."""
    return _ANSI_RE.sub("", text)


def _base_env(integration_pythonpath: str, home_dir: Path) -> dict[str, str]:
    """Build a subprocess env with HOME/USERPROFILE redirected and wide output.

    ``COLUMNS`` is set wide so Rich does not truncate/wrap paths in tables or
    panels (otherwise long temp paths get an ellipsis and assertions break).
    """
    env = os.environ.copy()
    env["PYTHONPATH"] = integration_pythonpath
    env["HOME"] = str(home_dir)
    env["USERPROFILE"] = str(home_dir)
    env["COLUMNS"] = "200"
    return env


def _registry_path(home_dir: Path) -> Path:
    return home_dir / ".envdrift" / "projects.json"


def _read_projects(home_dir: Path) -> list[dict]:
    registry = _registry_path(home_dir)
    if not registry.exists():
        return []
    return json.loads(registry.read_text(encoding="utf-8")).get("projects", [])


def _run_agent(
    envdrift_cmd: list[str],
    env: dict[str, str],
    *args: str,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [*envdrift_cmd, "agent", *args],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )


class TestAgentRegistry:
    """``envdrift agent`` registry lifecycle against an isolated HOME."""

    def test_agent_register_adds_project_to_projects_json(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
        tmp_path: Path,
    ):
        """HP-16: register PATH writes the project into ~/.envdrift/projects.json."""
        home_dir = tmp_path / "home"
        home_dir.mkdir()
        project_dir = work_dir / "myproject"
        project_dir.mkdir()
        env = _base_env(integration_pythonpath, home_dir)

        result = _run_agent(envdrift_cmd, env, "register", str(project_dir))

        assert result.returncode == 0, f"stderr={result.stderr}\nstdout={result.stdout}"
        assert "Registered" in _strip_ansi(result.stdout)
        assert _registry_path(home_dir).exists()

        projects = _read_projects(home_dir)
        assert len(projects) == 1
        assert projects[0]["path"] == str(project_dir.resolve())

    def test_agent_register_duplicate_warns_exit_zero(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
        tmp_path: Path,
    ):
        """EC-08: registering the same project twice warns and does not duplicate."""
        home_dir = tmp_path / "home"
        home_dir.mkdir()
        project_dir = work_dir / "dupproject"
        project_dir.mkdir()
        env = _base_env(integration_pythonpath, home_dir)

        first = _run_agent(envdrift_cmd, env, "register", str(project_dir))
        assert first.returncode == 0, first.stderr

        second = _run_agent(envdrift_cmd, env, "register", str(project_dir))
        assert second.returncode == 0, second.stderr
        assert "already registered" in _strip_ansi(second.stdout).lower()

        assert len(_read_projects(home_dir)) == 1

    def test_agent_register_nonexistent_path_exits_one(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
        tmp_path: Path,
    ):
        """BP-18: registering a nonexistent path exits 1 and adds nothing."""
        home_dir = tmp_path / "home"
        home_dir.mkdir()
        missing = work_dir / "does_not_exist_here"
        env = _base_env(integration_pythonpath, home_dir)

        result = _run_agent(envdrift_cmd, env, "register", str(missing))

        assert result.returncode == 1, f"stdout={result.stdout}\nstderr={result.stderr}"
        combined = _strip_ansi(result.stdout + result.stderr).lower()
        assert "does not exist" in combined
        assert _read_projects(home_dir) == []

    def test_agent_register_file_not_directory_exits_one(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
        tmp_path: Path,
    ):
        """BP-19: registering a file (not a directory) exits 1."""
        home_dir = tmp_path / "home"
        home_dir.mkdir()
        a_file = work_dir / "afile.txt"
        a_file.write_text("hello\n")
        env = _base_env(integration_pythonpath, home_dir)

        result = _run_agent(envdrift_cmd, env, "register", str(a_file))

        assert result.returncode == 1, f"stdout={result.stdout}\nstderr={result.stderr}"
        combined = _strip_ansi(result.stdout + result.stderr).lower()
        assert "not a directory" in combined

    def test_agent_register_invalid_toml_warns_exit_zero(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
        tmp_path: Path,
    ):
        """BP-20: a project with invalid envdrift.toml still registers (exit 0) with a warning."""
        home_dir = tmp_path / "home"
        home_dir.mkdir()
        project_dir = work_dir / "badtomlproject"
        project_dir.mkdir()
        (project_dir / "envdrift.toml").write_text("this is not = valid toml [[[\n")
        env = _base_env(integration_pythonpath, home_dir)

        result = _run_agent(envdrift_cmd, env, "register", str(project_dir))

        assert result.returncode == 0, f"stderr={result.stderr}\nstdout={result.stdout}"
        assert "Failed to load envdrift config" in _strip_ansi(result.stdout)
        # Despite the config-load failure, the project is still registered.
        projects = _read_projects(home_dir)
        assert len(projects) == 1
        assert projects[0]["path"] == str(project_dir.resolve())

    def test_agent_register_tilde_path_expands_home(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
        tmp_path: Path,
    ):
        """EC-07: a '~/...' path expands against the redirected HOME before registration."""
        home_dir = tmp_path / "home"
        home_dir.mkdir()
        tilde_target = home_dir / "tildeproj"
        tilde_target.mkdir()
        env = _base_env(integration_pythonpath, home_dir)

        result = _run_agent(envdrift_cmd, env, "register", "~/tildeproj")

        assert result.returncode == 0, f"stderr={result.stderr}\nstdout={result.stdout}"
        projects = _read_projects(home_dir)
        assert len(projects) == 1
        assert projects[0]["path"] == str(tilde_target.resolve())

    def test_agent_unregister_removes_project(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
        tmp_path: Path,
    ):
        """HP-17: unregister removes a registered project."""
        home_dir = tmp_path / "home"
        home_dir.mkdir()
        project_dir = work_dir / "toremove"
        project_dir.mkdir()
        env = _base_env(integration_pythonpath, home_dir)

        reg = _run_agent(envdrift_cmd, env, "register", str(project_dir))
        assert reg.returncode == 0, reg.stderr
        assert len(_read_projects(home_dir)) == 1

        unreg = _run_agent(envdrift_cmd, env, "unregister", str(project_dir))
        assert unreg.returncode == 0, unreg.stderr
        assert "Unregistered" in _strip_ansi(unreg.stdout)
        assert _read_projects(home_dir) == []

    def test_agent_unregister_not_registered_warns_exit_zero(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
        tmp_path: Path,
    ):
        """EC-09: unregistering a never-registered project exits 0 with a warning."""
        home_dir = tmp_path / "home"
        home_dir.mkdir()
        project_dir = work_dir / "neverreg"
        project_dir.mkdir()
        env = _base_env(integration_pythonpath, home_dir)

        result = _run_agent(envdrift_cmd, env, "unregister", str(project_dir))

        assert result.returncode == 0, f"stderr={result.stderr}\nstdout={result.stdout}"
        assert "not registered" in _strip_ansi(result.stdout).lower()

    def test_agent_list_shows_registered_projects_table(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
        tmp_path: Path,
    ):
        """HP-18: list renders a table with registered project paths."""
        home_dir = tmp_path / "home"
        home_dir.mkdir()
        env = _base_env(integration_pythonpath, home_dir)
        alpha = work_dir / "alphaproj"
        beta = work_dir / "betaproj"
        for project in (alpha, beta):
            project.mkdir()
            reg = _run_agent(envdrift_cmd, env, "register", str(project))
            assert reg.returncode == 0, reg.stderr

        result = _run_agent(envdrift_cmd, env, "list")

        assert result.returncode == 0, f"stderr={result.stderr}\nstdout={result.stdout}"
        out = _strip_ansi(result.stdout)
        assert "Registered Projects" in out
        assert "Path" in out
        assert "alphaproj" in out
        assert "betaproj" in out
        assert len(_read_projects(home_dir)) == 2

    def test_agent_list_empty_shows_message(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
        tmp_path: Path,
    ):
        """EC-10: list with no registered projects prints the empty-state message."""
        home_dir = tmp_path / "home"
        home_dir.mkdir()
        env = _base_env(integration_pythonpath, home_dir)

        result = _run_agent(envdrift_cmd, env, "list")

        assert result.returncode == 0, f"stderr={result.stderr}\nstdout={result.stdout}"
        assert "No projects registered" in _strip_ansi(result.stdout)


class TestRegistryDurability:
    """Corruption recovery and 0o600 permissions, observed via the CLI."""

    def test_registry_corrupt_json_starts_fresh_via_cli(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
        tmp_path: Path,
    ):
        """EC-13: a corrupt projects.json is treated as empty rather than crashing."""
        home_dir = tmp_path / "home"
        home_dir.mkdir()
        env = _base_env(integration_pythonpath, home_dir)

        registry = _registry_path(home_dir)
        registry.parent.mkdir(parents=True, exist_ok=True)
        registry.write_text("{ this is not valid json ]]]")

        listed = _run_agent(envdrift_cmd, env, "list")
        assert listed.returncode == 0, listed.stderr
        assert "No projects registered" in _strip_ansi(listed.stdout)

        project_dir = work_dir / "freshproj"
        project_dir.mkdir()
        reg = _run_agent(envdrift_cmd, env, "register", str(project_dir))
        assert reg.returncode == 0, reg.stderr

        projects = _read_projects(home_dir)
        assert len(projects) == 1
        assert projects[0]["path"] == str(project_dir.resolve())

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX file permissions")
    def test_registry_save_creates_parent_dirs_and_0600_perms(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
        tmp_path: Path,
    ):
        """EC-14: first register creates ~/.envdrift and writes projects.json with 0o600."""
        home_dir = tmp_path / "home"
        home_dir.mkdir()
        project_dir = work_dir / "permproj"
        project_dir.mkdir()
        env = _base_env(integration_pythonpath, home_dir)

        result = _run_agent(envdrift_cmd, env, "register", str(project_dir))

        assert result.returncode == 0, f"stderr={result.stderr}\nstdout={result.stdout}"
        assert (home_dir / ".envdrift").is_dir()
        registry = _registry_path(home_dir)
        assert registry.exists()
        mode = stat.S_IMODE(registry.stat().st_mode)
        assert mode == 0o600, f"expected 0o600, got {oct(mode)}"
        # Atomic tempfile+rename must leave no stray temp files behind.
        leftovers = list((home_dir / ".envdrift").glob(".projects_*.json"))
        assert leftovers == [], f"stray temp files: {leftovers}"
