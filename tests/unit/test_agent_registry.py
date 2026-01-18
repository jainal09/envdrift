"""Tests for the agent registry module."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

import envdrift.agent.registry as registry_module


class TestProjectEntry:
    """Tests for registry_module.ProjectEntry dataclass."""

    def test_from_dict_with_all_fields(self):
        """Test creating a registry_module.ProjectEntry from a complete dictionary."""
        data = {
            "path": "/home/user/project",
            "added": "2025-01-15T10:30:00+00:00",
        }
        entry = registry_module.ProjectEntry.from_dict(data)
        assert entry.path == "/home/user/project"
        assert entry.added == "2025-01-15T10:30:00+00:00"

    def test_from_dict_missing_added(self):
        """Test creating a registry_module.ProjectEntry with missing added field."""
        data = {"path": "/home/user/project"}
        entry = registry_module.ProjectEntry.from_dict(data)
        assert entry.path == "/home/user/project"
        # Should have a valid timestamp
        assert entry.added is not None
        # Should be parseable as ISO format
        datetime.fromisoformat(entry.added.replace("Z", "+00:00"))

    def test_to_dict(self):
        """Test converting a registry_module.ProjectEntry to a dictionary."""
        entry = registry_module.ProjectEntry(
            path="/home/user/project",
            added="2025-01-15T10:30:00+00:00",
        )
        data = entry.to_dict()
        assert data == {
            "path": "/home/user/project",
            "added": "2025-01-15T10:30:00+00:00",
        }


class TestProjectRegistry:
    """Tests for registry_module.ProjectRegistry class."""

    @pytest.fixture
    def temp_registry(self, tmp_path: Path):
        """Create a temporary registry file."""
        registry_path = tmp_path / ".envdrift" / "projects.json"
        return registry_module.ProjectRegistry(registry_path)

    @pytest.fixture
    def temp_project(self, tmp_path: Path):
        """Create a temporary project directory."""
        project_dir = tmp_path / "my_project"
        project_dir.mkdir(parents=True)
        return project_dir

    def test_path_default(self):
        """Test that default path is ~/.envdrift/projects.json."""
        registry = registry_module.ProjectRegistry()
        expected = Path.home() / ".envdrift" / "projects.json"
        assert registry.path == expected

    def test_path_custom(self, tmp_path: Path):
        """Test that custom path is used."""
        custom_path = tmp_path / "custom" / "registry.json"
        registry = registry_module.ProjectRegistry(custom_path)
        assert registry.path == custom_path

    def test_load_nonexistent_file(self, temp_registry: registry_module.ProjectRegistry):
        """Test loading when file doesn't exist."""
        temp_registry.load()
        assert temp_registry.projects == []

    def test_load_valid_file(self, tmp_path: Path):
        """Test loading a valid registry file."""
        registry_path = tmp_path / "projects.json"
        data = {
            "projects": [
                {"path": "/project1", "added": "2025-01-01T00:00:00Z"},
                {"path": "/project2", "added": "2025-01-02T00:00:00Z"},
            ]
        }
        registry_path.parent.mkdir(parents=True, exist_ok=True)
        registry_path.write_text(json.dumps(data))

        registry = registry_module.ProjectRegistry(registry_path)
        registry.load()

        assert len(registry.projects) == 2
        assert registry.projects[0].path == "/project1"
        assert registry.projects[1].path == "/project2"

    def test_load_corrupt_file(self, tmp_path: Path):
        """Test loading a corrupt registry file."""
        registry_path = tmp_path / "projects.json"
        registry_path.parent.mkdir(parents=True, exist_ok=True)
        registry_path.write_text("not valid json")

        registry = registry_module.ProjectRegistry(registry_path)
        registry.load()

        # Should start with empty list
        assert registry.projects == []

    def test_save_creates_directory(self, tmp_path: Path):
        """Test that save creates parent directories."""
        registry_path = tmp_path / "nested" / "dir" / "projects.json"
        registry = registry_module.ProjectRegistry(registry_path)
        registry.save()

        assert registry_path.exists()
        assert registry_path.parent.exists()

    def test_save_applies_permissions(self, tmp_path: Path, monkeypatch):
        """Test that save applies restrictive permissions."""
        registry_path = tmp_path / "projects.json"
        registry = registry_module.ProjectRegistry(registry_path)

        chmod_calls: list[int] = []

        def fake_chmod(self: Path, mode: int) -> None:
            chmod_calls.append(mode)

        monkeypatch.setattr(Path, "chmod", fake_chmod)

        registry.save()

        assert chmod_calls == [0o600]

    def test_save_writes_json(
        self, temp_registry: registry_module.ProjectRegistry, temp_project: Path
    ):
        """Test that save writes valid JSON."""
        temp_registry.register(temp_project)

        # Read the file back
        content = temp_registry.path.read_text()
        data = json.loads(content)

        assert "projects" in data
        assert len(data["projects"]) == 1
        assert data["projects"][0]["path"] == str(temp_project.resolve())

    def test_register_adds_project(
        self, temp_registry: registry_module.ProjectRegistry, temp_project: Path
    ):
        """Test registering a new project."""
        result = temp_registry.register(temp_project)

        assert result is True
        assert len(temp_registry.projects) == 1
        assert temp_registry.projects[0].path == str(temp_project.resolve())

    def test_register_duplicate(
        self, temp_registry: registry_module.ProjectRegistry, temp_project: Path
    ):
        """Test registering the same project twice."""
        temp_registry.register(temp_project)
        result = temp_registry.register(temp_project)

        assert result is False
        assert len(temp_registry.projects) == 1

    def test_unregister_removes_project(
        self, temp_registry: registry_module.ProjectRegistry, temp_project: Path
    ):
        """Test unregistering a project."""
        temp_registry.register(temp_project)
        result = temp_registry.unregister(temp_project)

        assert result is True
        assert len(temp_registry.projects) == 0

    def test_unregister_not_found(
        self, temp_registry: registry_module.ProjectRegistry, temp_project: Path
    ):
        """Test unregistering a project that's not registered."""
        result = temp_registry.unregister(temp_project)
        assert result is False

    def test_is_registered_true(
        self, temp_registry: registry_module.ProjectRegistry, temp_project: Path
    ):
        """Test is_registered returns True for registered project."""
        temp_registry.register(temp_project)
        assert temp_registry.is_registered(temp_project) is True

    def test_is_registered_false(
        self, temp_registry: registry_module.ProjectRegistry, temp_project: Path
    ):
        """Test is_registered returns False for unregistered project."""
        assert temp_registry.is_registered(temp_project) is False

    def test_get_entry_found(
        self, temp_registry: registry_module.ProjectRegistry, temp_project: Path
    ):
        """Test get_entry returns entry for registered project."""
        temp_registry.register(temp_project)
        entry = temp_registry.get_entry(temp_project)

        assert entry is not None
        assert entry.path == str(temp_project.resolve())

    def test_get_entry_not_found(
        self, temp_registry: registry_module.ProjectRegistry, temp_project: Path
    ):
        """Test get_entry returns None for unregistered project."""
        entry = temp_registry.get_entry(temp_project)
        assert entry is None

    def test_clear_removes_all(
        self, temp_registry: registry_module.ProjectRegistry, tmp_path: Path
    ):
        """Test clear removes all projects."""
        project1 = tmp_path / "project1"
        project2 = tmp_path / "project2"
        project1.mkdir()
        project2.mkdir()

        temp_registry.register(project1)
        temp_registry.register(project2)
        assert len(temp_registry.projects) == 2

        temp_registry.clear()
        assert len(temp_registry.projects) == 0


class TestModuleFunctions:
    """Tests for module-level helper functions."""

    @pytest.fixture(autouse=True)
    def reset_singleton(self):
        """Reset the global registry singleton before each test."""

        registry_module._registry = None
        yield
        registry_module._registry = None

    def test_register_project_current_dir(self, tmp_path: Path, monkeypatch):
        """Test registry_module.register_project with current directory."""
        # Set up a temporary registry

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        # Create a project directory
        project_dir = tmp_path / "myproject"
        project_dir.mkdir()

        # Change to project directory
        monkeypatch.chdir(project_dir)

        success, message = registry_module.register_project()

        assert success is True
        assert "Registered" in message

    def test_register_project_with_path(self, tmp_path: Path):
        """Test registry_module.register_project with explicit path."""

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        project_dir = tmp_path / "myproject"
        project_dir.mkdir()

        success, message = registry_module.register_project(project_dir)

        assert success is True
        assert "Registered" in message

    def test_register_project_nonexistent(self, tmp_path: Path):
        """Test registry_module.register_project with nonexistent directory."""

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        success, message = registry_module.register_project(tmp_path / "nonexistent")

        assert success is False
        assert "does not exist" in message

    def test_register_project_file_not_dir(self, tmp_path: Path):
        """Test registry_module.register_project with a file instead of directory."""

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        file_path = tmp_path / "somefile.txt"
        file_path.write_text("content")

        success, message = registry_module.register_project(file_path)

        assert success is False
        assert "Not a directory" in message

    def test_unregister_project(self, tmp_path: Path):
        """Test registry_module.unregister_project."""

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        project_dir = tmp_path / "myproject"
        project_dir.mkdir()

        # Register first
        registry_module.register_project(project_dir)

        # Then unregister
        success, message = registry_module.unregister_project(project_dir)

        assert success is True
        assert "Unregistered" in message

    def test_unregister_project_not_registered(self, tmp_path: Path):
        """Test registry_module.unregister_project with unregistered project."""

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        project_dir = tmp_path / "myproject"
        project_dir.mkdir()

        success, message = registry_module.unregister_project(project_dir)

        assert success is False
        assert "not registered" in message

    def test_list_projects(self, tmp_path: Path):
        """Test registry_module.list_projects."""

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        project1 = tmp_path / "project1"
        project2 = tmp_path / "project2"
        project1.mkdir()
        project2.mkdir()

        registry_module.register_project(project1)
        registry_module.register_project(project2)

        projects = registry_module.list_projects()

        assert len(projects) == 2
        paths = [p.path for p in projects]
        assert str(project1.resolve()) in paths
        assert str(project2.resolve()) in paths

    def test_register_project_with_tilde(self, tmp_path: Path, monkeypatch):
        """Test registry_module.register_project expands ~ to home directory."""

        registry_path = tmp_path / ".envdrift" / "projects.json"
        registry_module._registry = registry_module.ProjectRegistry(registry_path)

        # Create a subdirectory that would be expanded from ~
        project_dir = tmp_path / "myproject"
        project_dir.mkdir()

        # Mock home expansion for leading "~" only
        def fake_expanduser(path: Path) -> Path:
            path_str = str(path)
            if path_str.startswith("~"):
                return Path(path_str.replace("~", str(tmp_path), 1))
            return Path(path_str)

        monkeypatch.setattr(Path, "expanduser", fake_expanduser)

        # This should work with the ~ path
        success, _message = registry_module.register_project("~/myproject")
        assert success is True

        projects = registry_module.list_projects()
        assert len(projects) == 1
        assert projects[0].path == str(project_dir.resolve())
