"""Project registry for agent communication.

The registry is a JSON file at ~/.envdrift/projects.json that contains
the list of projects the agent should watch. The CLI registers/unregisters
projects, and the agent watches this file for changes.

File format:
{
  "projects": [
    {"path": "/Users/dev/myapp", "added": "2025-01-01T00:00:00Z"},
    {"path": "/Users/dev/api", "added": "2025-01-02T00:00:00Z"}
  ]
}
"""

from __future__ import annotations

import json
import os
import tempfile
from contextlib import suppress
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass
class ProjectEntry:
    """A registered project in the registry."""

    path: str  # Absolute path to the project directory
    added: str  # ISO 8601 timestamp when registered

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProjectEntry:
        """Create a ProjectEntry from a dictionary."""
        return cls(
            path=data["path"],
            added=data.get("added", datetime.now(UTC).isoformat()),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


class ProjectRegistry:
    """Manages the projects.json registry file.

    The registry file is located at ~/.envdrift/projects.json and contains
    the list of projects the agent should watch.
    """

    def __init__(self, registry_path: Path | None = None):
        """Initialize the registry.

        Args:
            registry_path: Path to the registry file. If None, uses
                           ~/.envdrift/projects.json
        """
        if registry_path is None:
            home_dir = Path.home()
            self._path = home_dir / ".envdrift" / "projects.json"
        else:
            self._path = registry_path
        self._projects: list[ProjectEntry] = []
        self._loaded = False

    @property
    def path(self) -> Path:
        """Return the path to the registry file."""
        return self._path

    @property
    def projects(self) -> list[ProjectEntry]:
        """Return the list of registered projects (copy to prevent mutation)."""
        if not self._loaded:
            self.load()
        return list(self._projects)

    def load(self) -> None:
        """Load the registry from disk."""
        if not self._path.exists():
            self._projects = []
            self._loaded = True
            return

        try:
            with open(self._path, encoding="utf-8") as f:
                data = json.load(f)
            self._projects = [ProjectEntry.from_dict(p) for p in data.get("projects", [])]
        except (json.JSONDecodeError, OSError, KeyError):
            # If file is corrupt or unreadable, start fresh
            self._projects = []

        self._loaded = True

    def _normalize_path(self, project_path: Path) -> Path:
        """Return a normalized absolute path.

        Note: resolve() follows symlinks, so symlinked paths are treated as their targets.
        """
        return project_path.resolve()

    def _write_atomic(self, data: dict[str, Any]) -> None:
        """Write registry data to disk atomically."""
        fd, tmp_path = tempfile.mkstemp(
            dir=self._path.parent,
            prefix=".projects_",
            suffix=".json",
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            Path(tmp_path).replace(self._path)
        except Exception:
            with suppress(OSError):
                Path(tmp_path).unlink()
            raise

    def _apply_permissions(self) -> None:
        """Apply restrictive permissions to the registry file."""
        with suppress(OSError):
            self._path.chmod(0o600)

    def save(self) -> None:
        """Save the registry to disk."""
        # Ensure parent directory exists
        self._path.parent.mkdir(parents=True, exist_ok=True)

        data = {"projects": [p.to_dict() for p in self._projects]}
        self._write_atomic(data)
        self._apply_permissions()

    def register(self, project_path: Path) -> bool:
        """Register a project with the agent.

        Args:
            project_path: Path to the project directory (must contain envdrift.toml
                         or have pyproject.toml with [tool.envdrift])
                         Paths are resolved before comparison (symlinks normalized).

        Returns:
            True if newly registered, False if already registered
        """
        if not self._loaded:
            self.load()

        # Resolve to absolute path
        abs_path = self._normalize_path(project_path)
        path_str = str(abs_path)

        # Check if already registered
        for project in self._projects:
            if project.path == path_str:
                return False

        # Add new entry
        entry = ProjectEntry(
            path=path_str,
            added=datetime.now(UTC).isoformat(),
        )
        self._projects.append(entry)
        self.save()
        return True

    def unregister(self, project_path: Path) -> bool:
        """Unregister a project from the agent.

        Args:
            project_path: Path to the project directory

        Returns:
            True if removed, False if not found
        """
        if not self._loaded:
            self.load()

        abs_path = self._normalize_path(project_path)
        path_str = str(abs_path)

        # Find and remove
        for i, project in enumerate(self._projects):
            if project.path == path_str:
                del self._projects[i]
                self.save()
                return True

        return False

    def is_registered(self, project_path: Path) -> bool:
        """Check if a project is registered.

        Args:
            project_path: Path to the project directory

        Returns:
            True if registered, False otherwise
        """
        if not self._loaded:
            self.load()

        abs_path = self._normalize_path(project_path)
        path_str = str(abs_path)

        for project in self._projects:
            if project.path == path_str:
                return True
        return False

    def get_entry(self, project_path: Path) -> ProjectEntry | None:
        """Get the registry entry for a project.

        Args:
            project_path: Path to the project directory

        Returns:
            ProjectEntry if found, None otherwise
        """
        if not self._loaded:
            self.load()

        abs_path = self._normalize_path(project_path)
        path_str = str(abs_path)

        for project in self._projects:
            if project.path == path_str:
                return project
        return None

    def clear(self) -> None:
        """Remove all registered projects."""
        self._projects = []
        self.save()


# Module-level singleton
_registry: ProjectRegistry | None = None


def get_registry() -> ProjectRegistry:
    """Get the global project registry singleton."""
    global _registry
    if _registry is None:
        _registry = ProjectRegistry()
    return _registry


def _normalize_project_path(project_path: Path | str | None) -> Path:
    """Normalize a project path for registry operations."""
    if project_path is None:
        normalized = Path.cwd()
    elif isinstance(project_path, str):
        normalized = Path(project_path)
    else:
        normalized = project_path

    if str(normalized).startswith("~"):
        normalized = normalized.expanduser()

    return normalized.resolve()


def register_project(project_path: Path | str | None = None) -> tuple[bool, str]:
    """Register a project with the agent.

    Args:
        project_path: Path to the project. If None, uses current directory.
                      Paths are resolved before comparison (symlinks normalized).

    Returns:
        Tuple of (success, message)
    """
    project_path = _normalize_project_path(project_path)

    if not project_path.exists():
        return False, f"Directory does not exist: {project_path}"

    if not project_path.is_dir():
        return False, f"Not a directory: {project_path}"

    registry = get_registry()
    if registry.register(project_path):
        return True, f"Registered project: {project_path}"
    else:
        return False, f"Project already registered: {project_path}"


def unregister_project(project_path: Path | str | None = None) -> tuple[bool, str]:
    """Unregister a project from the agent.

    Args:
        project_path: Path to the project. If None, uses current directory.

    Returns:
        Tuple of (success, message)
    """
    project_path = _normalize_project_path(project_path)

    registry = get_registry()
    if registry.unregister(project_path):
        return True, f"Unregistered project: {project_path}"
    else:
        return False, f"Project not registered: {project_path}"


def list_projects() -> list[ProjectEntry]:
    """List all registered projects.

    Returns:
        List of ProjectEntry objects
    """
    return get_registry().projects
