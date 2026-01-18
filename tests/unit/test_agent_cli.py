"""Tests for the agent CLI commands."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from envdrift.agent.registry import ProjectRegistry
from envdrift.cli import app

runner = CliRunner()


class TestAgentRegisterCommand:
    """Tests for 'envdrift agent register' command."""

    @pytest.fixture(autouse=True)
    def reset_registry(self):
        """Reset the global registry singleton before each test."""
        import envdrift.agent.registry as registry_module

        registry_module._registry = None
        yield
        registry_module._registry = None

    def test_register_current_directory(self, tmp_path: Path, monkeypatch):
        """Test registering the current directory."""
        import envdrift.agent.registry as registry_module

        # Set up a temp registry
        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = ProjectRegistry(registry_path)

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
        import envdrift.agent.registry as registry_module

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = ProjectRegistry(registry_path)

        project_dir = tmp_path / "myproject"
        project_dir.mkdir()

        result = runner.invoke(app, ["agent", "register", str(project_dir)])

        assert result.exit_code == 0
        assert "Registered" in result.stdout or "✓" in result.stdout

    def test_register_already_registered(self, tmp_path: Path):
        """Test registering a project that's already registered."""
        import envdrift.agent.registry as registry_module

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = ProjectRegistry(registry_path)

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
        import envdrift.agent.registry as registry_module

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = ProjectRegistry(registry_path)

        result = runner.invoke(app, ["agent", "register", str(tmp_path / "nonexistent")])

        assert result.exit_code == 1
        assert "does not exist" in result.stdout


class TestAgentUnregisterCommand:
    """Tests for 'envdrift agent unregister' command."""

    @pytest.fixture(autouse=True)
    def reset_registry(self):
        """Reset the global registry singleton before each test."""
        import envdrift.agent.registry as registry_module

        registry_module._registry = None
        yield
        registry_module._registry = None

    def test_unregister_registered_project(self, tmp_path: Path):
        """Test unregistering a registered project."""
        import envdrift.agent.registry as registry_module

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = ProjectRegistry(registry_path)

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
        import envdrift.agent.registry as registry_module

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = ProjectRegistry(registry_path)

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
        import envdrift.agent.registry as registry_module

        registry_module._registry = None
        yield
        registry_module._registry = None

    def test_list_empty(self, tmp_path: Path):
        """Test listing when no projects are registered."""
        import envdrift.agent.registry as registry_module

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = ProjectRegistry(registry_path)

        result = runner.invoke(app, ["agent", "list"])

        assert result.exit_code == 0
        assert "No projects registered" in result.stdout

    def test_list_with_projects(self, tmp_path: Path):
        """Test listing registered projects."""
        import envdrift.agent.registry as registry_module

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = ProjectRegistry(registry_path)

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
        import envdrift.agent.registry as registry_module

        registry_module._registry = None
        yield
        registry_module._registry = None

    def test_status_agent_not_installed(self, tmp_path: Path):
        """Test status when agent is not installed."""
        import envdrift.agent.registry as registry_module

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = ProjectRegistry(registry_path)

        with patch("envdrift.cli_commands.agent._find_agent_binary", return_value=None):
            result = runner.invoke(app, ["agent", "status"])

        assert result.exit_code == 0
        assert "not installed" in result.stdout

    def test_status_shows_registered_projects(self, tmp_path: Path):
        """Test status shows count of registered projects."""
        import envdrift.agent.registry as registry_module

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = ProjectRegistry(registry_path)

        project = tmp_path / "myproject"
        project.mkdir()
        runner.invoke(app, ["agent", "register", str(project)])

        with patch("envdrift.cli_commands.agent._find_agent_binary", return_value=None):
            result = runner.invoke(app, ["agent", "status"])

        assert result.exit_code == 0
        assert "Registered Projects" in result.stdout
        assert "1" in result.stdout


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
