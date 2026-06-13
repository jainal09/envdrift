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

Robustness guarantees (#492):

- Writes (``register``/``unregister``/``clear``) hold an exclusive lock on a
  sidecar ``projects.json.lock`` file and re-read the registry from disk under
  that lock, so concurrent writers never silently lose entries.
- A corrupt or mis-shaped registry never raises out of ``load()``; it loads as
  empty with a :class:`RegistryCorruption` notice the CLI can surface.
- Before a write replaces a corrupt registry, the corrupt original is moved
  aside to ``projects.json.corrupt-<timestamp>`` so nothing is silently wiped.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from contextlib import contextmanager, suppress
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if sys.platform == "win32":
    import msvcrt
else:
    import fcntl

if TYPE_CHECKING:
    from collections.abc import Iterator

#: How long a writer waits for the registry lock before failing loudly.
DEFAULT_LOCK_TIMEOUT = 10.0

#: Poll interval while waiting for the registry lock.
_LOCK_POLL_INTERVAL = 0.05


class RegistryLockError(RuntimeError):
    """Raised when the exclusive registry lock cannot be acquired in time."""


@dataclass
class RegistryCorruption:
    """Details about a corrupt registry file encountered during load.

    Attributes:
        detail: Human-readable description of what was wrong with the file.
        backup_path: Where the corrupt file was moved before being replaced,
            if a write has happened. ``None`` while the corrupt file is still
            in place (read-only commands never touch it).
        backup_failed: True if a write replaced the corrupt file but the
            backup rename itself failed (the corrupt bytes are gone).
    """

    detail: str
    backup_path: Path | None = None
    backup_failed: bool = False


@dataclass
class ProjectEntry:
    """A registered project in the registry."""

    path: str  # Absolute path to the project directory
    added: str  # ISO 8601 timestamp when registered

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProjectEntry:
        """Create a ProjectEntry from a dictionary."""
        added = data.get("added")
        if not isinstance(added, str):
            added = datetime.now(UTC).isoformat()
        return cls(
            path=data["path"],
            added=added,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


def _parse_registry_document(data: Any) -> list[ProjectEntry]:
    """Validate the loaded JSON document shape and convert it to entries.

    Raises:
        ValueError: If the document is not a dict with a ``projects`` list of
            dicts that each carry a string ``path`` (#492: top-level arrays and
            string entries previously escaped as AttributeError/TypeError).
    """
    if not isinstance(data, dict):
        raise ValueError(f"expected a JSON object, got {type(data).__name__}")
    raw_projects = data.get("projects", [])
    if not isinstance(raw_projects, list):
        raise ValueError(f"'projects' must be a list, got {type(raw_projects).__name__}")
    entries: list[ProjectEntry] = []
    for item in raw_projects:
        if not isinstance(item, dict):
            raise ValueError(f"project entries must be objects, got {type(item).__name__}")
        if not isinstance(item.get("path"), str):
            raise ValueError("project entry is missing a string 'path'")
        entries.append(ProjectEntry.from_dict(item))
    return entries


class ProjectRegistry:
    """Manages the projects.json registry file.

    The registry file is located at ~/.envdrift/projects.json and contains
    the list of projects the agent should watch.
    """

    def __init__(
        self,
        registry_path: Path | None = None,
        lock_timeout: float = DEFAULT_LOCK_TIMEOUT,
    ):
        """Initialize the registry.

        Args:
            registry_path: Path to the registry file. If None, uses
                           ~/.envdrift/projects.json
            lock_timeout: Seconds to wait for the exclusive write lock before
                          raising :class:`RegistryLockError`.
        """
        if registry_path is None:
            home_dir = Path.home()
            self._path = home_dir / ".envdrift" / "projects.json"
        else:
            self._path = registry_path
        self._lock_timeout = lock_timeout
        self._projects: list[ProjectEntry] = []
        self._loaded = False
        self._corruption: RegistryCorruption | None = None

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

    @property
    def corruption(self) -> RegistryCorruption | None:
        """Return details of a corrupt registry encountered on load, if any."""
        if not self._loaded:
            self.load()
        return self._corruption

    def load(self) -> None:
        """Load the registry from disk.

        A corrupt or mis-shaped file never raises: the registry loads as empty
        and :attr:`corruption` records what was wrong. The file itself is left
        untouched here — it is only moved aside (backed up) by the next save.
        """
        self._corruption = None
        if not self._path.exists():
            self._projects = []
            self._loaded = True
            return

        try:
            with open(self._path, encoding="utf-8") as f:
                data = json.load(f)
            self._projects = _parse_registry_document(data)
        except json.JSONDecodeError as exc:
            self._projects = []
            self._corruption = RegistryCorruption(detail=f"invalid JSON: {exc}")
        except ValueError as exc:
            self._projects = []
            self._corruption = RegistryCorruption(detail=str(exc))
        except OSError as exc:
            self._projects = []
            self._corruption = RegistryCorruption(detail=f"unreadable: {exc}")

        self._loaded = True

    def _normalize_path(self, project_path: Path) -> Path:
        """Return a normalized absolute path.

        Note: resolve() follows symlinks, so symlinked paths are treated as their targets.
        """
        return project_path.resolve()

    @property
    def _lock_path(self) -> Path:
        """Return the sidecar lock file path (projects.json.lock)."""
        return self._path.with_name(self._path.name + ".lock")

    def _acquire_lock(self, fd: int) -> None:
        """Acquire an exclusive lock on ``fd``, polling until the timeout."""
        deadline = time.monotonic() + self._lock_timeout
        while True:
            try:
                if sys.platform == "win32":
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                else:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return
            except OSError:
                if time.monotonic() >= deadline:
                    raise RegistryLockError(
                        f"timed out after {self._lock_timeout:g}s waiting for the "
                        f"registry lock: {self._lock_path} (is another envdrift "
                        "process stuck?)"
                    ) from None
                time.sleep(_LOCK_POLL_INTERVAL)

    @staticmethod
    def _release_lock(fd: int) -> None:
        """Release the exclusive lock on ``fd`` (best-effort)."""
        with suppress(OSError):
            if sys.platform == "win32":
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(fd, fcntl.LOCK_UN)

    @contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        """Hold the exclusive inter-process registry lock.

        The lock file is a sidecar (``projects.json.lock``) so locking never
        interferes with the atomic rename of the registry itself. The lock
        file is intentionally never deleted: unlinking a lock file invites
        races where two processes lock different inodes.
        """
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self._lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            self._acquire_lock(fd)
            try:
                yield
            finally:
                self._release_lock(fd)
        finally:
            os.close(fd)

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

    def _backup_corrupt_file(self) -> None:
        """Move a corrupt registry aside before a save replaces it (#492)."""
        if self._corruption is None or self._corruption.backup_path is not None:
            return
        if not self._path.exists():
            return
        timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%f")
        backup_path = self._path.with_name(f"{self._path.name}.corrupt-{timestamp}")
        try:
            self._path.replace(backup_path)
        except OSError:
            # The save still proceeds; record that the corrupt bytes are gone
            # so the CLI reports the truth instead of a phantom backup.
            self._corruption.backup_failed = True
            return
        self._corruption.backup_path = backup_path

    def save(self) -> None:
        """Save the registry to disk.

        If the last load found the file corrupt, the corrupt original is moved
        aside to ``projects.json.corrupt-<timestamp>`` first so its contents
        are never silently destroyed.
        """
        # Ensure parent directory exists
        self._path.parent.mkdir(parents=True, exist_ok=True)

        self._backup_corrupt_file()
        data = {"projects": [p.to_dict() for p in self._projects]}
        self._write_atomic(data)
        self._apply_permissions()

    def register(self, project_path: Path) -> bool:
        """Register a project with the agent.

        Holds the exclusive registry lock and re-reads the file under it, so
        concurrent registers merge instead of overwriting each other (#492).

        Args:
            project_path: Path to the project directory (must contain envdrift.toml
                         or have pyproject.toml with [tool.envdrift])
                         Paths are resolved before comparison (symlinks normalized).

        Returns:
            True if newly registered, False if already registered

        Raises:
            RegistryLockError: If the registry lock cannot be acquired.
        """
        # Resolve to absolute path
        abs_path = self._normalize_path(project_path)
        path_str = str(abs_path)

        with self._exclusive_lock():
            # Fresh read under the lock: merge with concurrent writers.
            self.load()

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

        Holds the exclusive registry lock and re-reads the file under it.

        Args:
            project_path: Path to the project directory

        Returns:
            True if removed, False if not found

        Raises:
            RegistryLockError: If the registry lock cannot be acquired.
        """
        abs_path = self._normalize_path(project_path)
        path_str = str(abs_path)

        with self._exclusive_lock():
            self.load()

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
        """Remove all registered projects.

        Raises:
            RegistryLockError: If the registry lock cannot be acquired.
        """
        with self._exclusive_lock():
            self.load()
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

    Raises:
        RegistryLockError: If the registry lock cannot be acquired.
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

    Raises:
        RegistryLockError: If the registry lock cannot be acquired.
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
