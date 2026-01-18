"""Tests for the agent CLI commands."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

import envdrift.agent.registry as registry_module
from envdrift.cli import app

runner = CliRunner()


class TestAgentRegisterCommand:
    """Tests for 'envdrift agent register' command."""

    @pytest.fixture(autouse=True)
    def reset_registry(self):
        """Reset the global registry singleton before each test."""

        registry_module._registry = None
        yield
        registry_module._registry = None

    def test_register_current_directory(self, tmp_path: Path, monkeypatch):
        """Test registering the current directory."""

        # Set up a temp registry
        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        # Create a project with envdrift.toml
        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        (project_dir / "envdrift.toml").write_text("[envdrift]\n")

        monkeypatch.chdir(project_dir)

        result = runner.invoke(app, ["agent", "register"])

        assert result.exit_code == 0
        assert "Registered" in result.stdout or "✓" in result.stdout

    def test_register_specific_path(self, tmp_path: Path):
        """Test registering a specific path."""

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        project_dir = tmp_path / "myproject"
        project_dir.mkdir()

        result = runner.invoke(app, ["agent", "register", str(project_dir)])

        assert result.exit_code == 0
        assert "Registered" in result.stdout or "✓" in result.stdout

    def test_register_already_registered(self, tmp_path: Path):
        """Test registering a project that's already registered."""

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        project_dir = tmp_path / "myproject"
        project_dir.mkdir()

        # Register once
        runner.invoke(app, ["agent", "register", str(project_dir)])

        # Register again
        result = runner.invoke(app, ["agent", "register", str(project_dir)])

        assert result.exit_code == 0  # Not an error, just a warning
        assert "already registered" in result.stdout

    def test_register_nonexistent_path(self, tmp_path: Path):
        """Test registering a path that doesn't exist."""

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        result = runner.invoke(app, ["agent", "register", str(tmp_path / "nonexistent")])

        assert result.exit_code == 1
        assert "does not exist" in result.stdout

    def test_register_invalid_config_shows_warning(self, tmp_path: Path):
        """Test register handles invalid config gracefully."""

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        (project_dir / "envdrift.toml").write_text("""
[guardian]
idle_timeout = "invalid"
""")

        result = runner.invoke(app, ["agent", "register", str(project_dir)])

        assert result.exit_code == 0
        assert "Failed to load envdrift config" in result.stdout


class TestAgentUnregisterCommand:
    """Tests for 'envdrift agent unregister' command."""

    @pytest.fixture(autouse=True)
    def reset_registry(self):
        """Reset the global registry singleton before each test."""

        registry_module._registry = None
        yield
        registry_module._registry = None

    def test_unregister_registered_project(self, tmp_path: Path):
        """Test unregistering a registered project."""

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        project_dir = tmp_path / "myproject"
        project_dir.mkdir()

        # Register first
        runner.invoke(app, ["agent", "register", str(project_dir)])

        # Unregister
        result = runner.invoke(app, ["agent", "unregister", str(project_dir)])

        assert result.exit_code == 0
        assert "Unregistered" in result.stdout or "✓" in result.stdout

    def test_unregister_not_registered(self, tmp_path: Path):
        """Test unregistering a project that's not registered."""

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        project_dir = tmp_path / "myproject"
        project_dir.mkdir()

        result = runner.invoke(app, ["agent", "unregister", str(project_dir)])

        assert result.exit_code == 0  # Not an error, just a warning
        assert "not registered" in result.stdout


class TestAgentListCommand:
    """Tests for 'envdrift agent list' command."""

    @pytest.fixture(autouse=True)
    def reset_registry(self):
        """Reset the global registry singleton before each test."""

        registry_module._registry = None
        yield
        registry_module._registry = None

    def test_list_empty(self, tmp_path: Path):
        """Test listing when no projects are registered."""

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        result = runner.invoke(app, ["agent", "list"])

        assert result.exit_code == 0
        assert "No projects registered" in result.stdout

    def test_list_with_projects(self, tmp_path: Path):
        """Test listing registered projects."""

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        project1 = tmp_path / "project1"
        project2 = tmp_path / "project2"
        project1.mkdir()
        project2.mkdir()

        runner.invoke(app, ["agent", "register", str(project1)])
        runner.invoke(app, ["agent", "register", str(project2)])

        result = runner.invoke(app, ["agent", "list"])

        assert result.exit_code == 0
        # Check table is shown (header row)
        assert "Registered Projects" in result.stdout
        assert "Path" in result.stdout
        # Verify registry file contains both projects
        registry_data = json.loads(registry_path.read_text())
        assert len(registry_data["projects"]) == 2
        paths = [p["path"] for p in registry_data["projects"]]
        assert str(project1.resolve()) in paths
        assert str(project2.resolve()) in paths


class TestAgentStatusCommand:
    """Tests for 'envdrift agent status' command."""

    @pytest.fixture(autouse=True)
    def reset_registry(self):
        """Reset the global registry singleton before each test."""

        registry_module._registry = None
        yield
        registry_module._registry = None

    def test_status_agent_not_installed(self, tmp_path: Path):
        """Test status when agent is not installed."""

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        with patch("envdrift.cli_commands.agent._find_agent_binary", return_value=None):
            result = runner.invoke(app, ["agent", "status"])

        assert result.exit_code == 0
        assert "not installed" in result.stdout

    def test_status_shows_registered_projects(self, tmp_path: Path):
        """Test status shows count of registered projects."""

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        project = tmp_path / "myproject"
        project.mkdir()
        runner.invoke(app, ["agent", "register", str(project)])

        with patch("envdrift.cli_commands.agent._find_agent_binary", return_value=None):
            result = runner.invoke(app, ["agent", "status"])

        assert result.exit_code == 0
        assert "Registered Projects" in result.stdout
        assert "1" in result.stdout

    def test_status_missing_running_line(self, tmp_path: Path):
        """Test status handles missing Running line as error."""
        import subprocess

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        def fake_run(args, **_kwargs):
            if args[1] == "status":
                stdout = "Installed: true\nConfig:    /tmp/envdrift.toml\nenvdrift:  true\n"
                return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr="")
            if args[1] == "--version":
                return subprocess.CompletedProcess(
                    args, 0, stdout="envdrift-agent v1.2.3\n", stderr=""
                )
            return subprocess.CompletedProcess(args, 1, stdout="", stderr="")

        with patch(
            "envdrift.cli_commands.agent._find_agent_binary",
            return_value=Path("/usr/local/bin/envdrift-agent"),
        ):
            with patch("envdrift.cli_commands.agent.subprocess.run", side_effect=fake_run):
                result = runner.invoke(app, ["agent", "status"])

        assert result.exit_code == 0
        assert "Agent status check failed" in result.stdout

    def test_status_running_parses_running_line(self, tmp_path: Path):
        """Test status parses running state from the Running line."""
        import subprocess

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        def fake_run(args, **_kwargs):
            if args[1] == "status":
                stdout = (
                    "Installed: true\n"
                    "Running:   true\n"
                    "Config:    /tmp/envdrift.toml\n"
                    "envdrift:  true\n"
                )
                return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr="")
            if args[1] == "--version":
                return subprocess.CompletedProcess(
                    args, 0, stdout="envdrift-agent v1.2.3\n", stderr=""
                )
            return subprocess.CompletedProcess(args, 1, stdout="", stderr="")

        with patch(
            "envdrift.cli_commands.agent._find_agent_binary",
            return_value=Path("/usr/local/bin/envdrift-agent"),
        ):
            with patch("envdrift.cli_commands.agent.subprocess.run", side_effect=fake_run):
                result = runner.invoke(app, ["agent", "status"])

        assert result.exit_code == 0
        assert "Agent is running" in result.stdout
        assert "Version: envdrift-agent v1.2.3" in result.stdout

    def test_status_stopped_parses_running_false(self, tmp_path: Path):
        """Test status treats 'Running: false' as stopped."""
        import subprocess

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        def fake_run(args, **_kwargs):
            if args[1] == "status":
                stdout = (
                    "Installed: true\n"
                    "Running:   false\n"
                    "Config:    /tmp/envdrift.toml\n"
                    "envdrift:  true\n"
                )
                return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr="")
            if args[1] == "--version":
                return subprocess.CompletedProcess(
                    args, 0, stdout="envdrift-agent v1.2.3\n", stderr=""
                )
            return subprocess.CompletedProcess(args, 1, stdout="", stderr="")

        with patch(
            "envdrift.cli_commands.agent._find_agent_binary",
            return_value=Path("/usr/local/bin/envdrift-agent"),
        ):
            with patch("envdrift.cli_commands.agent.subprocess.run", side_effect=fake_run):
                result = runner.invoke(app, ["agent", "status"])

        assert result.exit_code == 0
        assert "Agent is stopped" in result.stdout
        assert "Version:" not in result.stdout


class TestAgentHelpCommand:
    """Tests for 'envdrift agent --help' command."""

    def test_agent_help(self):
        """Test that agent --help shows subcommands."""
        result = runner.invoke(app, ["agent", "--help"])

        assert result.exit_code == 0
        assert "register" in result.stdout
        assert "unregister" in result.stdout
        assert "list" in result.stdout
        assert "status" in result.stdout
