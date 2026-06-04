"""Coverage-focused tests for envdrift.cli_commands.agent.

These tests target previously-uncovered branches in the agent CLI module:
binary discovery (PATH and common install locations), path normalization with
``~`` expansion, the ``_get_agent_status`` error branches, the timestamp
fallback, and the ``list``/``status`` command edge cases (missing project dir,
unknown status, and the ">5 projects" truncation).
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

import envdrift.agent.registry as registry_module
from envdrift.cli import app
from envdrift.cli_commands import agent as agent_module
from envdrift.cli_commands.agent import (
    _find_agent_binary,
    _format_timestamp,
    _get_agent_status,
    _normalize_project_path,
)

runner = CliRunner()


@pytest.fixture(autouse=True)
def _reset_registry():
    """Reset the global registry singleton around each test."""
    registry_module._registry = None
    yield
    registry_module._registry = None


class TestFindAgentBinary:
    """Tests for ``_find_agent_binary`` (lines 48-50, 53-56, 62-66)."""

    def test_found_in_path(self, monkeypatch):
        """When the binary is on PATH, return its resolved Path (lines 48-50)."""
        monkeypatch.setattr(
            agent_module.shutil,
            "which",
            lambda name: "/custom/bin/envdrift-agent",
        )

        result = _find_agent_binary()

        assert result == Path("/custom/bin/envdrift-agent")

    def test_found_in_common_location(self, monkeypatch, tmp_path):
        """When not on PATH but in a common dir, return that path (lines 53-64)."""
        monkeypatch.setattr(agent_module.shutil, "which", lambda name: None)
        # Force a non-windows binary name and point HOME at a tmp dir.
        monkeypatch.setattr(agent_module.platform, "system", lambda: "Darwin")

        bin_dir = tmp_path / ".envdrift" / "bin"
        bin_dir.mkdir(parents=True)
        binary = bin_dir / "envdrift-agent"
        binary.write_text("#!/bin/sh\n")
        monkeypatch.setattr(agent_module.Path, "home", staticmethod(lambda: tmp_path))

        result = _find_agent_binary()

        assert result == binary

    def test_not_found_anywhere(self, monkeypatch, tmp_path):
        """When nowhere on disk or PATH, return None (lines 56, 62-63, 66)."""
        monkeypatch.setattr(agent_module.shutil, "which", lambda name: None)
        monkeypatch.setattr(agent_module.platform, "system", lambda: "Darwin")
        # HOME points to an empty tmp dir so the home-based candidates miss,
        # and the absolute /usr/local + /opt/homebrew candidates won't exist.
        empty_home = tmp_path / "empty_home"
        empty_home.mkdir()
        monkeypatch.setattr(agent_module.Path, "home", staticmethod(lambda: empty_home))

        with patch.object(Path, "exists", return_value=False):
            result = _find_agent_binary()

        assert result is None

    def test_windows_binary_name(self, monkeypatch, tmp_path):
        """On windows the candidate name carries the .exe suffix (lines 53-54)."""
        monkeypatch.setattr(agent_module.shutil, "which", lambda name: None)
        monkeypatch.setattr(agent_module.platform, "system", lambda: "Windows")

        bin_dir = tmp_path / ".local" / "bin"
        bin_dir.mkdir(parents=True)
        binary = bin_dir / "envdrift-agent.exe"
        binary.write_text("")
        monkeypatch.setattr(agent_module.Path, "home", staticmethod(lambda: tmp_path))

        result = _find_agent_binary()

        assert result == binary


class TestNormalizeProjectPath:
    """Tests for ``_normalize_project_path`` (line 75 - ~ expansion)."""

    def test_tilde_is_expanded(self):
        """A path starting with ~ is expanded to the home directory (line 75)."""
        result = _normalize_project_path("~")

        assert result == Path.home().resolve()
        assert "~" not in str(result)

    def test_none_uses_cwd(self):
        """None resolves to the current working directory."""
        result = _normalize_project_path(None)

        assert result == Path.cwd().resolve()


class TestGetAgentStatusErrorBranches:
    """Tests for ``_get_agent_status`` error paths (lines 125, 126-127)."""

    def test_nonzero_returncode_is_error(self, monkeypatch):
        """A non-zero status exit code maps to ('error', None) (line 125)."""
        monkeypatch.setattr(
            agent_module,
            "_find_agent_binary",
            lambda: Path("/usr/local/bin/envdrift-agent"),
        )

        def fake_run(args, **_kwargs):
            return subprocess.CompletedProcess(args, 1, stdout="", stderr="boom")

        monkeypatch.setattr(agent_module.subprocess, "run", fake_run)

        assert _get_agent_status() == ("error", None)

    def test_timeout_is_error(self, monkeypatch):
        """A TimeoutExpired is caught and mapped to ('error', None) (lines 126-127)."""
        monkeypatch.setattr(
            agent_module,
            "_find_agent_binary",
            lambda: Path("/usr/local/bin/envdrift-agent"),
        )

        def fake_run(args, **_kwargs):
            raise subprocess.TimeoutExpired(cmd=args, timeout=5)

        monkeypatch.setattr(agent_module.subprocess, "run", fake_run)

        assert _get_agent_status() == ("error", None)

    def test_oserror_is_error(self, monkeypatch):
        """An OSError from subprocess.run is caught (lines 126-127)."""
        monkeypatch.setattr(
            agent_module,
            "_find_agent_binary",
            lambda: Path("/usr/local/bin/envdrift-agent"),
        )

        def fake_run(args, **_kwargs):
            raise OSError("no such binary")

        monkeypatch.setattr(agent_module.subprocess, "run", fake_run)

        assert _get_agent_status() == ("error", None)


class TestFormatTimestamp:
    """Tests for ``_format_timestamp`` (lines 135-136 - ValueError fallback)."""

    def test_valid_iso_is_formatted(self):
        """A well-formed ISO timestamp is reformatted to Y-m-d H:M."""
        assert _format_timestamp("2025-01-02T03:04:05+00:00") == "2025-01-02 03:04"

    def test_invalid_returns_input(self):
        """An unparseable timestamp is returned verbatim (lines 135-136)."""
        assert _format_timestamp("not-a-timestamp") == "not-a-timestamp"


class TestListCommandEdgeCases:
    """Tests for the list command (lines 249, 253 - missing project dir)."""

    def test_list_with_missing_project_dir(self, tmp_path):
        """A registered-but-deleted project shows the missing marker (lines 249, 253)."""
        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        project_dir = tmp_path / "ghost"
        project_dir.mkdir()
        runner.invoke(app, ["agent", "register", str(project_dir)])

        # Remove the directory so the list command sees it as missing.
        project_dir.rmdir()

        result = runner.invoke(app, ["agent", "list"])

        assert result.exit_code == 0
        assert "missing" in result.stdout


class TestStatusCommandEdgeCases:
    """Tests for the status command (lines 285, 296)."""

    def test_status_unknown_value(self, tmp_path, monkeypatch):
        """An unrecognized status string falls through to the else branch (line 285)."""
        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        monkeypatch.setattr(
            agent_module,
            "_get_agent_status",
            lambda: ("bogus", None),
        )

        result = runner.invoke(app, ["agent", "status"])

        assert result.exit_code == 0
        assert "Unable to determine agent status" in result.stdout

    def test_status_more_than_five_projects(self, tmp_path, monkeypatch):
        """With >5 registered projects, the truncation line is shown (line 296)."""
        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        for i in range(7):
            project = tmp_path / f"project{i}"
            project.mkdir()
            runner.invoke(app, ["agent", "register", str(project)])

        monkeypatch.setattr(
            agent_module,
            "_get_agent_status",
            lambda: ("not_installed", None),
        )

        result = runner.invoke(app, ["agent", "status"])

        assert result.exit_code == 0
        assert "Registered Projects:" in result.stdout
        assert "2 more" in result.stdout
