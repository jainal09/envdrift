"""A scanner that never returns must not hold the run past its timeout (#870)."""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

import envdrift
from envdrift.scanner import engine as engine_module
from envdrift.scanner.base import (
    EXIT_HIGH_FINDINGS,
    EXIT_SCAN_ERROR,
    FindingSeverity,
    ScanFinding,
    ScannerBackend,
    ScanResult,
)
from envdrift.scanner.engine import GuardConfig, ScanEngine
from tests.scanner.finding_paths_helpers import FixedScanner

# A scanner that blocks forever, as a native open() on a named pipe did (#863), and one that
# finds nothing at once. The engine's clock jumps 700 s after a moment, so its limit of 600 s
# per scanner passes at once.
BLOCKED_SCANNER = """
import threading
import time
from pathlib import Path

import envdrift.scanner.engine as engine_module
from envdrift.scanner.base import ScannerBackend, ScanResult


class Blocker(ScannerBackend):
    name = "blocker"
    description = "never returns"

    def is_installed(self):
        return True

    def scan(self, paths, include_git_history=False):
        threading.Event().wait()
        return ScanResult(scanner_name="blocker")


class Quick(ScannerBackend):
    name = "quick"
    description = "finds nothing at once"

    def is_installed(self):
        return True

    def scan(self, paths, include_git_history=False):
        return ScanResult(scanner_name="quick")


real_clock = time.monotonic
start = real_clock()
engine_module.time.monotonic = lambda: real_clock() + (700 if real_clock() - start > 1.5 else 0)
engine = engine_module.ScanEngine(engine_module.GuardConfig(use_native=False, use_gitleaks=False))
engine.scanners = [Blocker(), Quick()]
result = engine.scan([Path(".")])
# Flushed at once: a process that hangs at exit never flushes what it buffered.
print("RETURNED", [(r.scanner_name, r.error) for r in result.results], flush=True)
print("EXIT CODE", result.exit_code, flush=True)
"""


def test_a_scanner_that_never_returns_does_not_hold_the_run_past_its_timeout():
    """``scan()`` returns once the blocked scanner times out, and then the process exits.

    The blocked scanner's thread never ends. ``scan()`` used to wait for it, and a thread pool
    that did not would still hang the process at exit, where the interpreter joins every pool
    worker. The run still fails: the timeout is a scanner error, so with nothing found the exit
    code is 5, and the other scanner's result is kept.
    """
    # The child imports the same package as this process.
    source = str(Path(envdrift.__file__).resolve().parents[1])
    try:
        result = subprocess.run(  # nosec B603
            [sys.executable, "-c", BLOCKED_SCANNER],
            capture_output=True,
            text=True,
            timeout=30,
            env={**os.environ, "PYTHONPATH": source},
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or b""
        if isinstance(output, bytes):  # the output so far comes undecoded on POSIX
            output = output.decode(errors="replace")
        if "RETURNED" in output:
            pytest.fail(f"scan() returned but the process did not exit:\n{output}")
        pytest.fail("scan() did not return after the scanner timed out")

    assert result.returncode == 0, result.stderr
    assert (
        "RETURNED [('blocker', 'Scanner timed out after 600s'), ('quick', None)]" in result.stdout
    ), result.stdout
    assert "EXIT CODE 5" in result.stdout, result.stdout


class _Blocker(ScannerBackend):
    """Blocks in ``scan()`` until released, as a scanner stuck on a named pipe would (#863)."""

    def __init__(self, name: str = "blocker") -> None:
        self._name = name
        self.release = threading.Event()
        self.started = threading.Event()
        self.thread: threading.Thread | None = None

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return "blocks until released"

    def is_installed(self) -> bool:
        return True

    def scan(self, paths: list[Path], include_git_history: bool = False) -> ScanResult:
        self.thread = threading.current_thread()
        self.started.set()
        # Bounded, so an engine that waits for it fails the test instead of hanging it.
        self.release.wait(timeout=30)
        return ScanResult(scanner_name=self._name, error="released after its time limit")


@pytest.fixture
def short_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    """Give each scanner a fifth of a second, checked every hundredth of a second."""
    monkeypatch.setattr(engine_module, "_SCANNER_TIMEOUT_SECONDS", 0.2)
    monkeypatch.setattr(engine_module, "_POLL_SECONDS", 0.01)


def _engine(*scanners: ScannerBackend) -> ScanEngine:
    engine = ScanEngine(GuardConfig(use_native=False, use_gitleaks=False))
    engine.scanners = list(scanners)
    return engine


@pytest.mark.usefixtures("short_limit")
def test_a_timed_out_scanner_fails_the_run_and_the_other_results_stand(tmp_path: Path):
    """The scanner past its limit is an error that fails the run; it is left on a daemon thread."""
    blocker = _Blocker()
    finding = ScanFinding(
        file_path=tmp_path / "config.py",
        line_number=1,
        rule_id="stub-rule",
        rule_description="Stub rule",
        description="Stub finding",
        severity=FindingSeverity.HIGH,
        scanner="finder",
    )
    completed: list[tuple[str, int, int, str | None]] = []
    try:
        started = time.monotonic()
        result = _engine(blocker, FixedScanner("finder", [finding])).scan(
            [tmp_path],
            on_scanner_complete=lambda name, done, total, scan_result: completed.append(
                (name, done, total, scan_result.error if scan_result else None)
            ),
        )
        elapsed = time.monotonic() - started
        # Left behind, still blocked, on a thread the interpreter does not wait for at exit.
        assert blocker.started.wait(timeout=30)
        assert blocker.thread is not None
        assert blocker.thread.is_alive()
        assert blocker.thread.daemon
    finally:
        blocker.release.set()

    assert elapsed < 10, "scan() waited for the blocked scanner"
    assert [(r.scanner_name, r.error) for r in result.results] == [
        ("blocker", "Scanner timed out after 0.2s"),
        ("finder", None),
    ]
    # Each scanner is reported once, the blocker with its timeout; which comes first depends
    # on how soon the finder's thread runs.
    assert sorted((name, error) for name, _, _, error in completed) == [
        ("blocker", "Scanner timed out after 0.2s"),
        ("finder", None),
    ]
    assert [(done, total) for _, done, total, _ in completed] == [(1, 2), (2, 2)]
    assert [f.rule_id for f in result.unique_findings] == ["stub-rule"]
    # The HIGH finding decides the exit code; below a CRITICAL threshold the timeout still
    # fails the run instead of letting it pass.
    assert result.effective_exit_code() == EXIT_HIGH_FINDINGS
    assert result.effective_exit_code(FindingSeverity.CRITICAL) == EXIT_SCAN_ERROR


@pytest.mark.usefixtures("short_limit")
def test_a_result_delivered_after_the_time_limit_is_dropped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """A scanner that ends after it was reported as timed out does not change its result."""
    monkeypatch.setattr(engine_module, "_MAX_PARALLEL_SCANNERS", 1)
    late = _Blocker("late")

    class Releaser(FixedScanner):
        """Runs in the place ``late`` left: lets it end, then waits until its result is in."""

        def scan(self, paths: list[Path], include_git_history: bool = False) -> ScanResult:
            late.release.set()
            assert late.started.wait(timeout=30)
            assert late.thread is not None
            late.thread.join(timeout=30)  # its thread puts its result in before it ends
            return super().scan(paths, include_git_history)

    completed: list[tuple[str, str | None]] = []
    try:
        result = _engine(late, Releaser("releaser", [])).scan(
            [tmp_path],
            on_scanner_complete=lambda name, done, total, scan_result: completed.append(
                (name, scan_result.error if scan_result else None)
            ),
        )
    finally:
        late.release.set()

    assert [(r.scanner_name, r.error) for r in result.results] == [
        ("late", "Scanner timed out after 0.2s"),
        ("releaser", None),
    ]
    assert completed == [("late", "Scanner timed out after 0.2s"), ("releaser", None)]


def test_a_result_that_is_in_before_the_time_limit_is_kept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """A scanner whose result waits while the engine handles another's is not timed out.

    Both scanners end at once. While the engine handles the first result, the second is
    already in and the time limit passes. The engine used to take one result, then check the
    time limits, so it reported the second scanner as timed out and dropped its findings.
    """
    monkeypatch.setattr(engine_module, "_POLL_SECONDS", 0.01)
    clock = [1000.0]
    monkeypatch.setattr(engine_module.time, "monotonic", lambda: clock[0])
    together = threading.Barrier(2, timeout=30)
    threads: dict[str, threading.Thread] = {}
    finding = ScanFinding(
        file_path=tmp_path / "config.py",
        line_number=1,
        rule_id="stub-rule",
        rule_description="Stub rule",
        description="Stub finding",
        severity=FindingSeverity.HIGH,
        scanner="second",
    )

    class Together(FixedScanner):
        def scan(self, paths: list[Path], include_git_history: bool = False) -> ScanResult:
            threads[self.name] = threading.current_thread()
            together.wait()
            return super().scan(paths, include_git_history)

    def on_complete(name: str, done: int, total: int, scan_result: ScanResult | None) -> None:
        if done == 1:
            other = "second" if name == "first" else "first"
            threads[other].join(timeout=30)  # its thread puts its result in before it ends
            clock[0] += _ONE_LIMIT_AND_MORE

    result = _engine(Together("first", []), Together("second", [finding])).scan(
        [tmp_path], on_scanner_complete=on_complete
    )

    assert sorted((r.scanner_name, r.error) for r in result.results) == [
        ("first", None),
        ("second", None),
    ]
    assert [f.rule_id for f in result.unique_findings] == ["stub-rule"]


# More than the engine's limit of 600 s per scanner.
_ONE_LIMIT_AND_MORE = 601


def test_at_most_four_scanners_run_at_once(tmp_path: Path):
    """Six scanners run four at a time: the first four meet, and no fifth joins them."""
    lock = threading.Lock()
    first_four = threading.Barrier(4, timeout=30)
    counts = {"started": 0, "running": 0, "most": 0}

    class Counted(FixedScanner):
        def scan(self, paths: list[Path], include_git_history: bool = False) -> ScanResult:
            with lock:
                counts["started"] += 1
                counts["running"] += 1
                counts["most"] = max(counts["most"], counts["running"])
                meet = counts["started"] <= 4
            try:
                if meet:
                    first_four.wait()  # passes only once four scanners run together
                return super().scan(paths, include_git_history)
            finally:
                with lock:
                    counts["running"] -= 1

    result = _engine(*(Counted(f"scanner-{i}", []) for i in range(6))).scan([tmp_path])

    assert [(r.scanner_name, r.error) for r in result.results] == [
        (f"scanner-{i}", None) for i in range(6)
    ]
    assert counts["most"] == 4


def test_the_time_limit_counts_from_when_a_scanner_starts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """A scanner queued behind another has its whole limit once it starts, not less."""
    monkeypatch.setattr(engine_module, "_MAX_PARALLEL_SCANNERS", 1)
    monkeypatch.setattr(engine_module, "_POLL_SECONDS", 0.01)
    clock = [1000.0]
    monkeypatch.setattr(engine_module.time, "monotonic", lambda: clock[0])

    class Slow(FixedScanner):
        """Takes 590 of the engine's seconds, and is still running while the engine checks."""

        def scan(self, paths: list[Path], include_git_history: bool = False) -> ScanResult:
            clock[0] += 590
            time.sleep(0.1)  # real time, in which the engine reads its clock several times
            return super().scan(paths, include_git_history)

    # The second scanner ends 1180 of those seconds after the scan started, 590 after it did.
    result = _engine(Slow("first", []), Slow("second", [])).scan([tmp_path])

    assert [(r.scanner_name, r.error) for r in result.results] == [
        ("first", None),
        ("second", None),
    ]


def test_a_scanner_thread_ended_by_a_base_exception_fails_at_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """A scanner that raises ``SystemExit`` is reported as failed instead of timing out later.

    The exception ends its thread; without a result from it, the engine would wait out the
    whole time limit and then report a timeout.
    """
    monkeypatch.setattr(engine_module, "_SCANNER_TIMEOUT_SECONDS", 30)
    monkeypatch.setattr(engine_module, "_POLL_SECONDS", 0.01)

    class Exiting(FixedScanner):
        def scan(self, paths: list[Path], include_git_history: bool = False) -> ScanResult:
            raise SystemExit(3)

    started = time.monotonic()
    result = _engine(Exiting("exiting", [])).scan([tmp_path])

    assert time.monotonic() - started < 10, "the engine waited for a result that never came"
    assert [(r.scanner_name, r.error) for r in result.results] == [("exiting", "Scanner failed: 3")]
    assert result.exit_code == EXIT_SCAN_ERROR
