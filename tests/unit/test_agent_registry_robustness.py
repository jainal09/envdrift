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

import errno
import json
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime
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

    def test_second_save_after_failed_backup_keeps_valid_registry(
        self, registry_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """Regression (#506 review): ``backup_failed`` must block re-entry.

        After a failed backup rename the corruption notice stays set with
        ``backup_path=None``. A second ``save()`` on the same instance without
        an intervening ``load()`` must not pass the guard again and move the
        freshly written *valid* registry aside as a ``.corrupt-*`` file.
        """
        registry_path.parent.mkdir(parents=True, exist_ok=True)
        registry_path.write_text("{ not json", encoding="utf-8")

        original_replace = Path.replace

        def failing_backup_replace(self: Path, target):
            if ".corrupt-" in str(target):
                raise OSError("simulated rename failure")
            return original_replace(self, target)

        monkeypatch.setattr(Path, "replace", failing_backup_replace)

        registry = registry_module.ProjectRegistry(registry_path)
        registry.load()
        registry.save()  # backup attempt fails; a fresh valid registry is written

        notice = registry.corruption
        assert notice is not None
        assert notice.backup_failed is True

        monkeypatch.undo()  # renames work again: a buggy re-entry would now succeed
        registry.save()

        assert registry_path.exists(), "second save moved the valid registry aside"
        assert _read_registry_file(registry_path) == {"projects": []}
        assert _corrupt_backups(registry_path) == []

    def test_two_consecutive_corruptions_keep_both_backups(
        self, registry_path: Path, tmp_path: Path
    ):
        """Each corruption event gets its own backup; earlier backups survive."""
        proj_a = tmp_path / "projA"
        proj_a.mkdir()
        proj_b = tmp_path / "projB"
        proj_b.mkdir()

        registry_path.parent.mkdir(parents=True, exist_ok=True)
        first_corrupt = "{ first corruption"
        registry_path.write_text(first_corrupt, encoding="utf-8")
        assert registry_module.ProjectRegistry(registry_path).register(proj_a) is True

        second_corrupt = "{ second corruption"
        registry_path.write_text(second_corrupt, encoding="utf-8")
        assert registry_module.ProjectRegistry(registry_path).register(proj_b) is True

        backups = _corrupt_backups(registry_path)
        assert len(backups) == 2, "second corruption backup clobbered the first"
        contents = {backup.read_text(encoding="utf-8") for backup in backups}
        assert contents == {first_corrupt, second_corrupt}
        data = _read_registry_file(registry_path)
        assert [p["path"] for p in data["projects"]] == [str(proj_b.resolve())]

    def test_same_tick_backup_names_do_not_collide(
        self, registry_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """Two backups in the same clock tick get distinct suffixed names.

        Only the clock is frozen here (environment, like the rename-failure
        simulation above); the collision-avoidance logic runs for real.
        """
        registry_path.parent.mkdir(parents=True, exist_ok=True)
        frozen = datetime(2026, 1, 1, tzinfo=UTC)

        class _FrozenDatetime:
            @staticmethod
            def now(tz=None):
                return frozen

        monkeypatch.setattr(registry_module, "datetime", _FrozenDatetime)
        registry = registry_module.ProjectRegistry(registry_path)

        first = registry._next_backup_path()
        first.touch()
        second = registry._next_backup_path()

        assert second != first, "same-tick backup path collides with the existing backup"
        assert second.name.startswith(first.name)
        assert not second.exists()


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

    @staticmethod
    def _real_lock_syscall():
        """Return the platform lock syscall the registry uses."""
        if sys.platform == "win32":
            return registry_module.msvcrt.locking
        return registry_module.fcntl.flock

    @classmethod
    def _patch_lock_syscall(cls, monkeypatch: pytest.MonkeyPatch, fake) -> None:
        """Inject an environment fault into the platform lock syscall."""
        if sys.platform == "win32":
            monkeypatch.setattr(registry_module.msvcrt, "locking", fake)
        else:
            monkeypatch.setattr(registry_module.fcntl, "flock", fake)

    def test_transient_lock_oserror_retries_then_succeeds(
        self, registry_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """Regression (#506 review): a brief I/O blip must not fail the write.

        E.g. an antivirus scan briefly touching the lock file: the first two
        lock attempts fail with a non-contention OSError, then the real
        syscall takes over and the registration succeeds.
        """
        project = tmp_path / "proj"
        project.mkdir()

        real_lock = self._real_lock_syscall()
        calls = {"count": 0}

        def flaky_lock(*args):
            calls["count"] += 1
            if calls["count"] <= 2:
                raise OSError(errno.EIO, "simulated transient I/O error")
            return real_lock(*args)

        self._patch_lock_syscall(monkeypatch, flaky_lock)

        registry = registry_module.ProjectRegistry(registry_path)
        assert registry.register(project) is True
        assert calls["count"] >= 3, "lock must have been retried past the transient errors"

    def test_persistent_lock_io_error_raises_original_error_fast(
        self, registry_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """Regression (#506 review): EBADF/EIO surface as-is, not as a timeout.

        Pre-fix, every OSError was retried for the full lock timeout and then
        misreported as a misleading RegistryLockError timeout.
        """
        project = tmp_path / "proj"
        project.mkdir()

        def broken_lock(*args):
            raise OSError(errno.EBADF, "simulated persistent I/O error")

        self._patch_lock_syscall(monkeypatch, broken_lock)

        registry = registry_module.ProjectRegistry(registry_path, lock_timeout=5.0)

        start = time.monotonic()
        with pytest.raises(OSError) as excinfo:
            registry.register(project)
        elapsed = time.monotonic() - start

        assert excinfo.value.errno == errno.EBADF
        assert elapsed < 2.5, "must give up after bounded retries, not the full lock timeout"


_HAMMER_WORKER = """\
import sys
from pathlib import Path

from envdrift.agent.registry import ProjectRegistry

registry_path = Path(sys.argv[1])
worker = int(sys.argv[2])
iterations = int(sys.argv[3])
base = Path(sys.argv[4])

registry = ProjectRegistry(registry_path)
for i in range(iterations):
    assert registry.register(base / f"proj-{worker}-{i}") is True, (worker, i)
for i in range(1, iterations, 2):
    assert registry.unregister(base / f"proj-{worker}-{i}") is True, (worker, i)
"""


class TestRegistryMultiprocessBattle:
    """The PR's core claim, hammered by real concurrent OS processes.

    Threads share the CPython file-lock state; only separate processes prove
    the inter-process ``projects.json.lock`` actually serializes writers.
    """

    def test_concurrent_processes_lose_no_writes(self, registry_path: Path, tmp_path: Path):
        """4 real processes x (6 registers + 3 unregisters): exact final state.

        Any lost update, torn write, or lock failure shows up as a worker
        assert (nonzero exit), invalid JSON, or a final set mismatch. Bounded
        iterations keep the test deterministic and fast (well under 10s).
        """
        workers, iterations = 4, 6
        base = tmp_path / "projects"
        base.mkdir()

        procs = [
            subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    _HAMMER_WORKER,
                    str(registry_path),
                    str(worker),
                    str(iterations),
                    str(base),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            for worker in range(workers)
        ]
        for proc in procs:
            _, stderr = proc.communicate(timeout=30)
            assert proc.returncode == 0, stderr.decode(errors="replace")

        # Valid JSON (no torn/interleaved writes) ...
        data = _read_registry_file(registry_path)
        paths = [entry["path"] for entry in data["projects"]]
        # ... no duplicated entries ...
        assert len(paths) == len(set(paths)), "duplicate registry entries"
        # ... and exactly the even-indexed survivors from every worker.
        expected = {
            str((base / f"proj-{worker}-{i}").resolve())
            for worker in range(workers)
            for i in range(0, iterations, 2)
        }
        assert set(paths) == expected, "concurrent writes were lost or resurrected"
