"""A tool a scanner runs is killed at the scanner's time limit, not left running (#900).

These tests run their tools through ``run_tool``'s own runner, which kills a tool together with
the processes it started (#911), not through the ``subprocess.run`` seam of the unit tests.
"""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

import envdrift
import envdrift.scanner.gitleaks as gitleaks_module
from envdrift.install_integrity import atomic_install, download_file, fetch_checksums
from envdrift.scanner import engine as engine_module
from envdrift.scanner.base import ScannerBackend, ScanResult
from envdrift.scanner.engine import GuardConfig, ScanEngine
from envdrift.scanner.gitleaks import GitleaksInstaller
from envdrift.utils.deadline import (
    ScannerDeadline,
    ScannerTimedOut,
    current_deadline,
    run_tool,
    scanner_deadline,
)
from envdrift.utils.git import get_git_root

pytestmark = pytest.mark.real_tool_runner

# A tool that never ends. It rewrites its heartbeat file, which holds its pid, every 50 ms, so a
# test on any platform can tell whether it still runs, even after the process that started it
# has exited. The file is replaced whole: written in place, a tool stopped and killed between
# the truncation and the write left it empty, and the test that read its pid said it had never
# started (#924).
HEARTBEAT = """
import os, sys, time
from pathlib import Path

beat = Path(sys.argv[1])
staged = beat.with_name(beat.name + ".new")
while True:
    staged.write_text(f"{os.getpid()} {time.monotonic()}")
    try:
        os.replace(staged, beat)
    except PermissionError:  # Windows, while a test reads it: the next beat replaces it
        pass
    time.sleep(0.05)
"""

# The engine limit for these tests: long enough for the tool to start and beat.
LIMIT_SECONDS = 1.5
# How long the tool takes to start in a slow start: its timeout, which subprocess.run counts from
# then, kills it a second after the engine has given up on the scanner.
STARTUP_DELAY_SECONDS = 1.0
TIMED_OUT = f"Scanner timed out after {LIMIT_SECONDS}s"
# The timeout of a tool that starts a child, or the limit of a scanner whose tool does: long
# enough for two Python processes to start on a loaded machine. A child killed before it started
# would prove nothing (#924).
CHILD_TIMEOUT_SECONDS = 4.0


class HungTool(ScannerBackend):
    """Runs a tool that never ends with a timeout of 300 s, as the real scanners do."""

    def __init__(self, beat: Path, command: list[str] | None = None) -> None:
        self.beat = beat
        self.command = command or [sys.executable, "-c", HEARTBEAT, str(beat)]

    @property
    def name(self) -> str:
        return "hung-tool"

    @property
    def description(self) -> str:
        return "runs a tool that never ends"

    def is_installed(self) -> bool:
        return True

    def scan(self, paths: list[Path], include_git_history: bool = False) -> ScanResult:
        try:
            run_tool(
                self.command,
                capture_output=True,
                timeout=300,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return ScanResult(scanner_name=self.name, error="the tool timed out")
        return ScanResult(scanner_name=self.name)


class RepositoryRoot(ScannerBackend):
    """Asks git for the root of the repository, as detect-secrets and trufflehog do."""

    @property
    def name(self) -> str:
        return "repository-root"

    @property
    def description(self) -> str:
        return "asks git for the root of the repository"

    def is_installed(self) -> bool:
        return True

    def scan(self, paths: list[Path], include_git_history: bool = False) -> ScanResult:
        get_git_root(paths[0])
        return ScanResult(scanner_name=self.name)


class LateButClean(ScannerBackend):
    """Reports a clean scan, but only after its time limit."""

    @property
    def name(self) -> str:
        return "late-but-clean"

    @property
    def description(self) -> str:
        return "reports a clean scan after its time limit"

    def is_installed(self) -> bool:
        return True

    def scan(self, paths: list[Path], include_git_history: bool = False) -> ScanResult:
        time.sleep(LIMIT_SECONDS + 0.5)
        return ScanResult(scanner_name=self.name)


def _still_beating(beat: Path) -> bool:
    """Whether the tool writing ``beat`` still runs, given a few seconds to stop.

    The tool is resumed first: one that a kill stopped (``SIGSTOP``) but left alive does not beat.
    """
    if sys.platform != "win32":
        with contextlib.suppress(OSError, ValueError, IndexError):  # gone, or not started
            os.kill(int(beat.read_text().split()[0]), signal.SIGCONT)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        before = beat.read_text() if beat.exists() else ""
        time.sleep(0.5)
        if (beat.read_text() if beat.exists() else "") == before:
            return False
    return True


def _stop(beat: Path) -> None:
    """Kill the tool if it still runs, so a failing test leaves nothing behind."""
    try:
        pid = int(beat.read_text().split()[0])
        os.kill(pid, signal.SIGTERM)
    except (OSError, ValueError, IndexError):
        pass


def _beating_pid(beat: Path) -> int:
    """The pid of the tool writing ``beat``, once it has started."""
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        with contextlib.suppress(OSError, ValueError, IndexError):
            return int(beat.read_text().split()[0])
        time.sleep(0.05)
    raise AssertionError("the tool never started")


def _engine(
    scanner: ScannerBackend, monkeypatch: pytest.MonkeyPatch, limit: float = LIMIT_SECONDS
) -> ScanEngine:
    """An engine that runs only ``scanner``, with a time limit of ``limit``."""
    monkeypatch.setattr(engine_module, "_SCANNER_TIMEOUT_SECONDS", limit)
    monkeypatch.setattr(engine_module, "_POLL_SECONDS", 0.05)
    engine = ScanEngine(GuardConfig(use_native=False, use_gitleaks=False))
    engine.scanners = [scanner]
    return engine


def test_a_tools_timeout_is_the_time_left_to_the_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = [1000.0]
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    deadline = ScannerDeadline(1600.0)

    assert deadline.timeout(300) == 300
    assert deadline.timeout(900) == 600
    clock[0] = 1599.5
    assert deadline.timeout(300) == 0.5
    assert not deadline.passed()
    deadline.check()
    clock[0] = 1600.0
    assert deadline.timeout(300) == 0
    assert deadline.passed()
    with pytest.raises(ScannerTimedOut):
        deadline.check()


def test_a_tool_runs_with_its_own_timeout_outside_a_scan_and_within_its_time() -> None:
    probe = [sys.executable, "-c", "print('ran')"]

    assert run_tool(probe, capture_output=True, text=True, timeout=60).stdout.strip() == "ran"
    with scanner_deadline(ScannerDeadline(time.monotonic() + 60)):
        assert run_tool(probe, capture_output=True, text=True, timeout=60).stdout.strip() == "ran"


def test_no_tool_starts_once_the_deadline_has_passed(tmp_path: Path) -> None:
    """A tool started past the deadline was killed at once, if not before it could run."""
    started = tmp_path / "started"

    with (
        scanner_deadline(ScannerDeadline(time.monotonic() - 1)),
        pytest.raises(ScannerTimedOut),
    ):
        run_tool([sys.executable, "-c", f"open({str(started)!r}, 'w').close()"], timeout=60)

    assert not started.exists()


def test_a_nested_deadline_gives_the_outer_one_back() -> None:
    outer = ScannerDeadline(time.monotonic() + 60)
    inner = ScannerDeadline(time.monotonic() + 30)

    with scanner_deadline(outer):
        with scanner_deadline(inner):
            assert current_deadline() is inner
        assert current_deadline() is outer
    assert current_deadline() is None


def test_a_timed_out_scanners_tool_is_killed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The engine stops waiting for the scanner at its limit, and its tool dies with it.

    The tool used to run until its own timeout of 300 s, long after the scan was over.
    """
    beat = tmp_path / "beat"
    engine = _engine(HungTool(beat), monkeypatch)

    try:
        result = engine.scan([tmp_path])

        assert beat.exists(), "the tool never started"
        assert not _still_beating(beat), "the tool still runs after its scanner timed out"
    finally:
        _stop(beat)

    assert [r.error for r in result.results] == [TIMED_OUT]


# The run above in a process of its own, which then exits, as guard does. With "slow-start" the
# tool takes STARTUP_DELAY_SECONDS to start, so its own timeout kills it only after the engine
# has given up on the scanner.
GUARD_EXITS = """
import subprocess
import sys
import time
from pathlib import Path

import envdrift.scanner.engine as engine_module
from tests.scanner.test_tool_deadline import LIMIT_SECONDS, STARTUP_DELAY_SECONDS, HungTool

if sys.argv[2] == "slow-start":

    class SlowStart(subprocess.Popen):
        def __init__(self, *args, **kwargs):
            time.sleep(STARTUP_DELAY_SECONDS)
            super().__init__(*args, **kwargs)

    subprocess.Popen = SlowStart

engine_module._SCANNER_TIMEOUT_SECONDS = LIMIT_SECONDS
engine_module._POLL_SECONDS = 0.05
engine = engine_module.ScanEngine(engine_module.GuardConfig(use_native=False, use_gitleaks=False))
engine.scanners = [HungTool(Path(sys.argv[1]))]
result = engine.scan([Path(".")])
print("EXIT CODE", result.exit_code, flush=True)
"""


@pytest.mark.parametrize("start", ["prompt-start", "slow-start"])
def test_a_timed_out_scanners_tool_does_not_outlive_guard(tmp_path: Path, start: str) -> None:
    """The issue as reported: after guard exits, the tool of a scanner that timed out is gone.

    The tool's timeout kills it on the scanner's thread, which guard does not wait for. In a slow
    start that happens after the engine has given up on the scanner, so the engine waits for it:
    had guard exited first, the thread would have ended with it, and the tool would run on.
    """
    beat = tmp_path / "beat"
    package = str(Path(envdrift.__file__).resolve().parents[1])
    repo = str(Path(__file__).resolve().parents[2])  # for ``tests.scanner`` in the child
    env = {**os.environ, "PYTHONPATH": os.pathsep.join([package, repo])}

    try:
        result = subprocess.run(  # nosec B603
            [sys.executable, "-c", GUARD_EXITS, str(beat), start],
            capture_output=True,
            text=True,
            timeout=60,
            env=env,
            check=False,
        )

        assert result.returncode == 0, result.stderr
        assert "EXIT CODE 5" in result.stdout, result.stdout
        assert beat.exists(), "the tool never started"
        assert not _still_beating(beat), "the tool still runs after guard exited"
    finally:
        _stop(beat)


@pytest.mark.skipif(
    sys.platform == "win32", reason="the stand-in for git is a shell script, run by name"
)
def test_a_git_helper_is_held_to_the_scanners_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """get_git_root gives git 10 s of its own, but no more than the scanner has left."""
    beat = tmp_path / "beat"
    heartbeat = tmp_path / "heartbeat.py"
    heartbeat.write_text(HEARTBEAT)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    git = bin_dir / "git"
    git.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{heartbeat}" "{beat}"\n')
    git.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    engine = _engine(RepositoryRoot(), monkeypatch, limit=CHILD_TIMEOUT_SECONDS)

    try:
        result = engine.scan([tmp_path])

        assert beat.exists(), "git never started"
        assert not _still_beating(beat), "git still runs after its scanner timed out"
    finally:
        _stop(beat)

    assert [r.error for r in result.results] == [
        f"Scanner timed out after {CHILD_TIMEOUT_SECONDS}s"
    ]


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="the tool is a shell script that starts its child in the background",
)
def test_the_processes_a_timed_out_tool_started_end_with_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A tool that runs a child of its own and waits for it, as git-secrets runs git grep."""
    beat = tmp_path / "beat"
    heartbeat = tmp_path / "heartbeat.py"
    heartbeat.write_text(HEARTBEAT)
    tool = tmp_path / "tool.sh"
    tool.write_text(f'#!/bin/sh\n"{sys.executable}" "{heartbeat}" "{beat}" &\nwait\n')
    tool.chmod(0o755)
    engine = _engine(HungTool(beat, [str(tool)]), monkeypatch, limit=CHILD_TIMEOUT_SECONDS)

    try:
        engine.scan([tmp_path])

        assert beat.exists(), "the tool's child never started"
        assert not _still_beating(beat), "the tool's child still runs after its scanner timed out"
    finally:
        _stop(beat)


def test_the_runner_takes_what_subprocess_run_takes() -> None:
    """``run_tool`` runs a tool as ``subprocess.run`` would, input and errors included."""
    echo = [sys.executable, "-c", "import sys; sys.stdout.write(sys.stdin.read().upper())"]
    fail = [sys.executable, "-c", "import sys; sys.stderr.write('no'); sys.exit(3)"]

    done = run_tool(echo, input="secret", capture_output=True, text=True, timeout=60)
    assert (done.returncode, done.stdout, done.stderr) == (0, "SECRET", "")
    quiet = run_tool([sys.executable, "-c", ""], timeout=60)
    assert (quiet.returncode, quiet.stdout, quiet.stderr) == (0, None, None)
    assert run_tool(fail, capture_output=True, timeout=60).returncode == 3
    with pytest.raises(subprocess.CalledProcessError) as raised:
        run_tool(fail, capture_output=True, text=True, timeout=60, check=True)
    assert (raised.value.returncode, raised.value.stderr) == (3, "no")
    with pytest.raises(ValueError, match="stdin and input"):
        run_tool(echo, input="x", stdin=subprocess.DEVNULL, timeout=60)
    with pytest.raises(ValueError, match="capture_output"):
        run_tool(echo, capture_output=True, stdout=subprocess.DEVNULL, timeout=60)


class StuckTool(ScannerBackend):
    """Keeps a tool counted as running long after its kill, as one slow to end would."""

    def __init__(self, name: str) -> None:
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return "keeps a tool running past its kill"

    def is_installed(self) -> bool:
        return True

    def scan(self, paths: list[Path], include_git_history: bool = False) -> ScanResult:
        deadline = current_deadline()
        assert deadline is not None
        with deadline.tool():
            time.sleep(LIMIT_SECONDS + 5)
        return ScanResult(scanner_name=self.name)


@pytest.mark.parametrize("start_seconds", [0.0, 0.3], ids=["prompt starts", "slow starts"])
def test_scanners_that_time_out_together_share_one_grace_period(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, start_seconds: float
) -> None:
    """The engine waits once for the tools of all the scanners that timed out together.

    Each scanner's deadline was taken when its thread had been started. With threads slow to
    start, as on a loaded machine, the second scanner timed out a poll after the first, and the
    engine waited a grace period for each.
    """
    grace = 2.0
    engine = _engine(StuckTool("stuck-a"), monkeypatch)
    engine.scanners = [StuckTool("stuck-a"), StuckTool("stuck-b")]
    monkeypatch.setattr(engine_module, "_TOOL_KILL_GRACE_SECONDS", grace)
    start_scanner = engine._start_scanner

    def slow_start(*args: Any) -> None:
        start_scanner(*args)
        time.sleep(start_seconds)

    monkeypatch.setattr(engine, "_start_scanner", slow_start)

    started = time.monotonic()
    result = engine.scan([tmp_path])
    elapsed = time.monotonic() - started

    assert [r.error for r in result.results] == [TIMED_OUT, TIMED_OUT]
    # One grace period after the limit, not one per scanner (LIMIT_SECONDS + 2 * grace).
    assert elapsed < LIMIT_SECONDS + 1.5 * grace, f"waited {elapsed:.1f}s"


def test_a_scanner_done_only_after_its_deadline_has_timed_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A tool it ran may have been killed at the deadline, so a clean result then is no pass.

    The engine looks at the time limits only once it has waited for a result, so the late
    result is in before the engine finds the scanner past its time.
    """
    engine = _engine(LateButClean(), monkeypatch)
    monkeypatch.setattr(engine_module, "_POLL_SECONDS", 10.0)

    result = engine.scan([tmp_path])

    assert [r.error for r in result.results] == [TIMED_OUT]
    assert result.exit_code == 5


def test_an_installer_past_the_deadline_does_not_go_on_to_download(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Its version probe of the installed binary does not start, and it does not download.

    The installer reinstalls when the probe fails with any ``Exception``: the probe of a scanner
    past its deadline must stop the install instead.
    """
    installed = tmp_path / "gitleaks"
    installed.write_text("")
    monkeypatch.setattr(gitleaks_module, "get_gitleaks_path", lambda: installed)
    installer = GitleaksInstaller()
    downloads: list[Path] = []
    monkeypatch.setattr(installer, "download_and_extract", downloads.append)

    with (
        scanner_deadline(ScannerDeadline(time.monotonic() - 1)),
        pytest.raises(ScannerTimedOut),
    ):
        installer.install()

    assert downloads == []


# What the slow mirror below sends, one byte every 10 ms: 5 s in all.
TRICKLE_BYTES = 500


class _Trickle(BaseHTTPRequestHandler):
    """Sends a file one byte at a time, as a slow mirror would."""

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Length", str(TRICKLE_BYTES))
        self.end_headers()
        try:
            for _ in range(TRICKLE_BYTES):
                self.wfile.write(b"x")
                self.wfile.flush()
                time.sleep(0.01)
        except OSError:
            pass  # the client hung up

    def log_message(self, format: str, *args: object) -> None:
        pass


@pytest.fixture
def trickle_url() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Trickle)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/file"
    finally:
        server.shutdown()
        server.server_close()


def test_a_download_for_a_scanner_stops_at_its_deadline(tmp_path: Path, trickle_url: str) -> None:
    """A scanner auto-installs its tool on its own thread: the download ends at the deadline."""
    archive = tmp_path / "tool.tar.gz"
    started = time.monotonic()

    with (
        scanner_deadline(ScannerDeadline(started + 1.0)),
        pytest.raises(ScannerTimedOut),
    ):
        download_file(trickle_url, archive, timeout=60)

    assert time.monotonic() - started < 3
    assert 0 < archive.stat().st_size < TRICKLE_BYTES, "the download did not get under way"


def test_a_checksums_fetch_for_a_scanner_stops_at_its_deadline(trickle_url: str) -> None:
    """The checksums of an install are held to the deadline too, however small the file."""
    started = time.monotonic()

    with (
        scanner_deadline(ScannerDeadline(started + 1.0)),
        pytest.raises(ScannerTimedOut),
    ):
        fetch_checksums(trickle_url, timeout=60)

    assert time.monotonic() - started < 3


def test_a_scanner_past_its_deadline_installs_nothing(tmp_path: Path) -> None:
    """A download it finished in time is not installed once its time is up."""
    downloaded = tmp_path / "gitleaks.new"
    downloaded.write_bytes(b"the new binary")
    installed = tmp_path / "bin" / "gitleaks"
    installed.parent.mkdir()
    installed.write_bytes(b"the binary in place")

    with (
        scanner_deadline(ScannerDeadline(time.monotonic() - 1)),
        pytest.raises(ScannerTimedOut),
    ):
        atomic_install(downloaded, installed)

    assert installed.read_bytes() == b"the binary in place"
    assert sorted(path.name for path in installed.parent.iterdir()) == ["gitleaks"]
