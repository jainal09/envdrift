"""Regression tests for agent registry locking and corruption handling (#492).

Covers the three robustness gaps in ``ProjectRegistry``:

1. Concurrent registers used an unlocked load->mutate->replace cycle, so
   parallel ``register()`` calls silently lost entries (last writer wins).
2. A corrupt/truncated ``projects.json`` was silently reset to empty and then
   persisted on the next write, destroying all prior registrations.
3. Malformed-but-valid-JSON registries (top-level array, string entries)
   escaped ``load()``'s catch tuple as raw AttributeError/TypeError.

These tests drive the real ``ProjectRegistry`` against real files on disk; no
behavior under test is mocked.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

import envdrift.agent.registry as registry_module


@pytest.fixture
def registry_path(tmp_path: Path) -> Path:
    """Return a per-test registry file path under an isolated directory."""
    return tmp_path / ".envdrift" / "projects.json"


def _read_registry_file(registry_path: Path) -> dict:
    return json.loads(registry_path.read_text(encoding="utf-8"))


def _corrupt_backups(registry_path: Path) -> list[Path]:
    return sorted(registry_path.parent.glob("projects.json.corrupt-*"))


class TestMalformedRegistryShapes:
    """#492: valid-JSON-wrong-shape registries must never raise out of load()."""

    @pytest.mark.parametrize(
        "content",
        [
            pytest.param("[]", id="top-level-array"),
            pytest.param('"just a string"', id="top-level-string"),
            pytest.param('{"projects": ["/tmp/foo"]}', id="string-entries"),
            pytest.param('{"projects": "nope"}', id="projects-not-a-list"),
            pytest.param('{"projects": [{"added": "2025-01-01T00:00:00Z"}]}', id="missing-path"),
            pytest.param('{"projects": [{"path": 42}]}', id="non-string-path"),
            pytest.param("{ truncated", id="invalid-json"),
        ],
    )
    def test_load_never_raises_and_flags_corruption(self, registry_path: Path, content: str):
        """Any unreadable/mis-shaped registry loads as empty with a corruption notice."""
        registry_path.parent.mkdir(parents=True, exist_ok=True)
        registry_path.write_text(content, encoding="utf-8")

        registry = registry_module.ProjectRegistry(registry_path)
        registry.load()  # must not raise (was AttributeError/TypeError pre-#492)

        assert registry.projects == []
        assert registry.corruption is not None
        assert registry.corruption.detail

    def test_load_valid_file_has_no_corruption_notice(self, registry_path: Path):
        """A well-formed registry loads cleanly with no corruption notice."""
        registry_path.parent.mkdir(parents=True, exist_ok=True)
        registry_path.write_text(
            json.dumps({"projects": [{"path": "/p1", "added": "2025-01-01T00:00:00Z"}]}),
            encoding="utf-8",
        )

        registry = registry_module.ProjectRegistry(registry_path)
        registry.load()

        assert [p.path for p in registry.projects] == ["/p1"]
        assert registry.corruption is None

    def test_load_missing_file_has_no_corruption_notice(self, registry_path: Path):
        """A missing registry file is a normal empty state, not corruption."""
        registry = registry_module.ProjectRegistry(registry_path)
        registry.load()

        assert registry.projects == []
        assert registry.corruption is None

    def test_entry_with_non_string_added_is_normalized(self, registry_path: Path):
        """A non-string 'added' value is replaced rather than crashing later display."""
        registry_path.parent.mkdir(parents=True, exist_ok=True)
        registry_path.write_text(
            json.dumps({"projects": [{"path": "/p1", "added": 12345}]}),
            encoding="utf-8",
        )

        registry = registry_module.ProjectRegistry(registry_path)
        registry.load()

        assert len(registry.projects) == 1
        assert isinstance(registry.projects[0].added, str)


class TestCorruptRegistryPreservation:
    """#492: a corrupt registry must be backed up, never silently wiped."""

    def test_register_after_truncation_backs_up_corrupt_file(
        self, registry_path: Path, tmp_path: Path
    ):
        """Registering over a truncated registry preserves the corrupt bytes."""
        proj_a = tmp_path / "projA"
        proj_a.mkdir()
        first = registry_module.ProjectRegistry(registry_path)
        assert first.register(proj_a) is True

        # Truncate the file mid-string, as a crashed writer would leave it.
        whole = registry_path.read_text(encoding="utf-8")
        truncated = whole[: len(whole) // 2]
        registry_path.write_text(truncated, encoding="utf-8")

        proj_b = tmp_path / "projB"
        proj_b.mkdir()
        second = registry_module.ProjectRegistry(registry_path)
        assert second.register(proj_b) is True

        # The fresh registry contains only projB...
        data = _read_registry_file(registry_path)
        assert [p["path"] for p in data["projects"]] == [str(proj_b.resolve())]

        # ...but the corrupt original was moved aside, byte-for-byte.
        backups = _corrupt_backups(registry_path)
        assert len(backups) == 1, "corrupt registry must be backed up before overwrite"
        assert backups[0].read_text(encoding="utf-8") == truncated

        # And the recovery is reported, naming the backup.
        notice = second.corruption
        assert notice is not None
        assert notice.backup_path == backups[0]

    def test_read_only_load_leaves_corrupt_file_untouched(self, registry_path: Path):
        """Loading (list/status path) must not move or rewrite a corrupt registry."""
        registry_path.parent.mkdir(parents=True, exist_ok=True)
        corrupt = '{"projects": [{"path": "/p1"'
        registry_path.write_text(corrupt, encoding="utf-8")

        registry = registry_module.ProjectRegistry(registry_path)
        assert registry.projects == []

        assert registry_path.read_text(encoding="utf-8") == corrupt
        assert _corrupt_backups(registry_path) == []

    def test_unregister_miss_on_corrupt_registry_preserves_file(
        self, registry_path: Path, tmp_path: Path
    ):
        """An unregister that removes nothing must not destroy the corrupt file."""
        registry_path.parent.mkdir(parents=True, exist_ok=True)
        corrupt = "{ not json"
        registry_path.write_text(corrupt, encoding="utf-8")

        project = tmp_path / "proj"
        project.mkdir()
        registry = registry_module.ProjectRegistry(registry_path)

        assert registry.unregister(project) is False
        assert registry_path.read_text(encoding="utf-8") == corrupt
        assert _corrupt_backups(registry_path) == []

    def test_unreadable_registry_path_is_reported_not_raised(self, registry_path: Path):
        """An OSError while reading (e.g. path is a directory) is a clean notice."""
        registry_path.mkdir(parents=True)  # open() on a directory raises OSError

        registry = registry_module.ProjectRegistry(registry_path)
        registry.load()

        assert registry.projects == []
        assert registry.corruption is not None
        assert "unreadable" in registry.corruption.detail

    def test_failed_backup_is_reported_truthfully(
        self, registry_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """If the backup rename fails, the notice says so instead of inventing one."""
        registry_path.parent.mkdir(parents=True, exist_ok=True)
        registry_path.write_text("{ not json", encoding="utf-8")

        project = tmp_path / "proj"
        project.mkdir()

        original_replace = Path.replace

        def failing_backup_replace(self: Path, target):
            if ".corrupt-" in str(target):
                raise OSError("simulated rename failure")
            return original_replace(self, target)

        monkeypatch.setattr(Path, "replace", failing_backup_replace)

        registry = registry_module.ProjectRegistry(registry_path)
        assert registry.register(project) is True

        notice = registry.corruption
        assert notice is not None
        assert notice.backup_path is None
        assert notice.backup_failed is True
        assert _corrupt_backups(registry_path) == []


class TestRegistryLocking:
    """#492: register/unregister must serialize via an exclusive file lock."""

    def test_interleaved_instances_do_not_lose_updates(self, registry_path: Path, tmp_path: Path):
        """A stale in-memory snapshot must not clobber another writer's entry.

        Deterministic lost-update repro: writer B loads the (empty) registry
        first, writer A registers projA, then B registers projB. Pre-#492 B
        skipped re-reading because it was already loaded, so its save dropped
        projA on the floor.
        """
        proj_a = tmp_path / "projA"
        proj_b = tmp_path / "projB"
        proj_a.mkdir()
        proj_b.mkdir()

        writer_a = registry_module.ProjectRegistry(registry_path)
        writer_b = registry_module.ProjectRegistry(registry_path)
        writer_b.load()  # stale snapshot: empty registry

        assert writer_a.register(proj_a) is True
        assert writer_b.register(proj_b) is True

        data = _read_registry_file(registry_path)
        paths = {p["path"] for p in data["projects"]}
        assert paths == {str(proj_a.resolve()), str(proj_b.resolve())}

    def test_parallel_register_threads_lose_no_entries(self, registry_path: Path, tmp_path: Path):
        """16 racing registrations (one instance each) must all survive."""
        count = 16
        projects = []
        for i in range(count):
            project = tmp_path / f"proj{i}"
            project.mkdir()
            projects.append(project)

        barrier = threading.Barrier(count)
        failures: list[BaseException] = []

        def register(project: Path) -> None:
            registry = registry_module.ProjectRegistry(registry_path)
            barrier.wait(timeout=30)
            try:
                assert registry.register(project) is True
            except BaseException as exc:  # collected for the main thread
                failures.append(exc)

        threads = [threading.Thread(target=register, args=(p,)) for p in projects]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)

        assert failures == []
        data = _read_registry_file(registry_path)
        paths = {p["path"] for p in data["projects"]}
        assert paths == {str(p.resolve()) for p in projects}, (
            f"lost {count - len(paths)} of {count} concurrent registrations"
        )

    def test_lock_timeout_raises_clean_error(self, registry_path: Path, tmp_path: Path):
        """A held lock makes register() fail loudly instead of corrupting state."""
        project = tmp_path / "proj"
        project.mkdir()

        holder = registry_module.ProjectRegistry(registry_path)
        contender = registry_module.ProjectRegistry(registry_path, lock_timeout=0.3)

        with holder._exclusive_lock():
            with pytest.raises(registry_module.RegistryLockError):
                contender.register(project)

        # Once released, the same registration succeeds.
        assert contender.register(project) is True
