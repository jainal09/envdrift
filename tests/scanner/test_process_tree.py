"""A tool killed at its timeout is killed together with the processes it started (#911, #922).

These tests run real processes, through ``run_tool``'s own runner or ``kill_process_tree``: a
tool, and a child of it that writes a heartbeat, so a test can tell whether it still runs.
"""

from __future__ import annotations

import contextlib
import errno
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from envdrift.scanner import engine as engine_module
from envdrift.utils import process_tree
from envdrift.utils.deadline import run_tool
from envdrift.utils.process_tree import _ppid_from_stat, kill_process_tree
from tests.scanner.test_tool_deadline import (
    CHILD_TIMEOUT_SECONDS,
    HEARTBEAT,
    _beating_pid,
    _still_beating,
    _stop,
)

pytestmark = pytest.mark.real_tool_runner


# A tool that starts a child, which never ends, and waits for it, on every platform.
PARENT = """
import subprocess, sys

subprocess.run([sys.executable, sys.argv[1], sys.argv[2]])
"""


def _time_out_with_child(tmp_path: Path, child: str) -> None:
    """Time ``PARENT`` out while its child runs the code ``child``: the child must end with it."""
    beat = tmp_path / "beat"
    script = tmp_path / "child.py"
    script.write_text(child)

    try:
        with pytest.raises(subprocess.TimeoutExpired):
            run_tool(
                [sys.executable, "-c", PARENT, str(script), str(beat)],
                capture_output=True,
                timeout=CHILD_TIMEOUT_SECONDS,
            )

        assert beat.exists(), "the tool's child never started"
        assert not _still_beating(beat), "the tool's child still runs after the tool timed out"
    finally:
        _stop(beat)


def test_a_tool_that_times_out_is_killed_with_the_processes_it_started(tmp_path: Path) -> None:
    """subprocess.run would kill the tool and leave its child running (#911)."""
    _time_out_with_child(tmp_path, HEARTBEAT)


# Names the process with bytes that are not UTF-8, as the kernel names one whose executable has a
# long non-ASCII name: it cuts the name at 15 bytes, here in the middle of a "€".
RENAMED = """
from pathlib import Path

Path("/proc/self/comm").write_bytes(b"tool-\\xe2\\x82")
"""


@pytest.mark.skipif(
    not Path("/proc/self/comm").is_file(), reason="a process renames itself through /proc on Linux"
)
def test_a_child_whose_name_is_not_utf8_is_killed_too(tmp_path: Path) -> None:
    """Its /proc/<pid>/stat did not decode as text, which left it out of the tree."""
    _time_out_with_child(tmp_path, RENAMED + HEARTBEAT)


@pytest.mark.skipif(sys.platform == "win32", reason="taskkill /T walks the tree on Windows")
def test_a_failed_listing_still_kills_the_processes_it_stopped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A stopped process that is not killed never ends, and Popen's exit waits for it forever.

    The second listing fails, as one does with no file descriptor left, once the tool and its
    child are stopped. They were left stopped.
    """
    beat = tmp_path / "beat"
    heartbeat = tmp_path / "heartbeat.py"
    heartbeat.write_text(HEARTBEAT)
    children_by_parent = process_tree._children_by_parent
    listings = []

    def listing(timeout: float) -> dict[int, list[int]]:
        listings.append(None)
        if len(listings) > 1:
            raise OSError(errno.EMFILE, os.strerror(errno.EMFILE))
        return children_by_parent(timeout)

    monkeypatch.setattr(process_tree, "_children_by_parent", listing)
    tool = subprocess.Popen([sys.executable, "-c", PARENT, str(heartbeat), str(beat)])
    child = None
    try:
        child = _beating_pid(beat)
        with pytest.raises(OSError) as raised:
            kill_process_tree(tool)
        assert raised.value.errno == errno.EMFILE

        try:
            returncode = tool.wait(timeout=5)
        except subprocess.TimeoutExpired:
            returncode = None
        assert returncode == -signal.SIGKILL, "the tool was left stopped"
        assert not _still_beating(beat), "the tool's child was left stopped"
    finally:
        tool.kill()  # SIGKILL ends a stopped process too; it sends nothing to a reaped tool
        tool.wait()
        if child is not None:
            with contextlib.suppress(OSError):
                os.kill(child, signal.SIGKILL)


@pytest.mark.skipif(sys.platform == "win32", reason="taskkill /T walks the tree on Windows")
def test_a_failed_listing_does_not_replace_the_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The listing's error is logged, and the tree still killed: the caller sees the timeout.

    It replaced the TimeoutExpired, which the scanners and installers catch to report a timeout.
    """
    beat = tmp_path / "beat"
    heartbeat = tmp_path / "heartbeat.py"
    heartbeat.write_text(HEARTBEAT)
    children_by_parent = process_tree._children_by_parent
    listings = []

    def listing(timeout: float) -> dict[int, list[int]]:
        listings.append(None)
        if len(listings) > 1:
            raise OSError(errno.EMFILE, os.strerror(errno.EMFILE))
        return children_by_parent(timeout)

    monkeypatch.setattr(process_tree, "_children_by_parent", listing)
    try:
        with pytest.raises(subprocess.TimeoutExpired):
            run_tool(
                [sys.executable, "-c", PARENT, str(heartbeat), str(beat)],
                capture_output=True,
                timeout=CHILD_TIMEOUT_SECONDS,
            )

        assert "Could not kill every process" in caplog.text
        assert not _still_beating(beat), "the tool's child still runs after the tool timed out"
    finally:
        _stop(beat)


@pytest.mark.xfail(
    sys.platform != "linux",
    strict=False,
    raises=AssertionError,
    reason="only Linux lists the processes that hold the tool's output (see #925)",
)
@pytest.mark.skipif(
    sys.platform == "win32",
    reason="the tool is a shell script that starts its child in the background",
)
def test_a_child_that_outlived_its_tool_ends_with_it(tmp_path: Path) -> None:
    """A tool that exits at once, leaving its child running with the tool's output pipe open.

    The child was re-parented when the tool exited, out of the walk's reach, and ran on (#922).
    It is found by the pipe it holds. A setup that goes wrong fails the test, not the xfail.
    """
    beat = tmp_path / "beat"
    heartbeat = tmp_path / "heartbeat.py"
    heartbeat.write_text(HEARTBEAT)
    tool = tmp_path / "tool.sh"
    tool.write_text(f'#!/bin/sh\n"{sys.executable}" "{heartbeat}" "{beat}" &\n')
    tool.chmod(0o755)

    try:
        with pytest.raises(subprocess.TimeoutExpired):
            run_tool([str(tool)], capture_output=True, timeout=CHILD_TIMEOUT_SECONDS)

        if not beat.exists():
            pytest.fail("the tool's child never started")
        assert not _still_beating(beat), "the tool's child still runs after the tool timed out"
    finally:
        _stop(beat)


class InterruptError(Exception):
    """Raised by a signal handler while the runner waits, as Ctrl-C raises KeyboardInterrupt."""


@pytest.mark.skipif(sys.platform == "win32", reason="the interrupt is a POSIX signal")
def test_an_interrupted_tool_is_killed_with_the_processes_it_started(tmp_path: Path) -> None:
    """An exception that breaks off the wait, as Ctrl-C's does, kills the tree as a timeout does."""
    beat = tmp_path / "beat"
    heartbeat = tmp_path / "heartbeat.py"
    heartbeat.write_text(HEARTBEAT)

    def interrupt(signum: int, frame: object) -> None:
        raise InterruptError

    previous = signal.signal(signal.SIGUSR1, interrupt)
    waiting = threading.get_ident()
    done = threading.Event()

    def interrupt_once_the_child_beats() -> None:
        # Not after a fixed time, which a slow start can outlast (#924). Sent to the thread that
        # waits for the tool: a signal to the process could go to another.
        while not beat.exists() and not done.wait(0.05):
            pass
        if not done.is_set():
            signal.pthread_kill(waiting, signal.SIGUSR1)

    watcher = threading.Thread(target=interrupt_once_the_child_beats)
    watcher.start()
    try:
        with pytest.raises(InterruptError):
            run_tool(
                [sys.executable, "-c", PARENT, str(heartbeat), str(beat)],
                capture_output=True,
                timeout=60,
            )

        assert beat.exists(), "the tool's child never started"
        assert not _still_beating(beat), "the tool's child still runs after the interrupt"
    finally:
        done.set()
        watcher.join()
        signal.signal(signal.SIGUSR1, previous)
        _stop(beat)


@pytest.mark.parametrize(
    ("stat", "ppid"),
    [
        (b"41 (git) S 7 41 41 0 -1", 7),
        (b"42 (my tool (v2)) R 9 42 42 0 -1", 9),
        (b"43 ( ) ) S 11 43 43 0 -1", 11),
        (b"44 (tool-\xe2\x82) S 13 44 44 0 -1", 13),
    ],
)
def test_the_parent_is_read_past_the_command_name(stat: bytes, ppid: int) -> None:
    """A command name in /proc/<pid>/stat may hold spaces and parentheses, and need not be text."""
    assert _ppid_from_stat(stat) == ppid


@pytest.mark.skipif(
    sys.platform == "win32" or shutil.which("ps") is None,
    reason="ps lists the processes on macOS and the BSDs",
)
def test_ps_lists_the_parent_of_each_process() -> None:
    """The listing used where there is no /proc, checked against this process's own parent."""
    assert dict(process_tree._ps_table(timeout=30))[os.getpid()] == os.getppid()


def test_without_ps_no_process_is_listed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The walk then finds no child, and the tool alone is killed, as subprocess.run kills it."""
    monkeypatch.setenv("PATH", str(tmp_path))
    assert process_tree._ps_table(timeout=30) == []


@pytest.mark.skipif(sys.platform == "win32", reason="taskkill /T walks the tree on Windows")
def test_a_listing_that_does_not_end_does_not_hold_the_kill(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The walk lists for _LISTING_SECONDS at most, then kills the processes it has stopped.

    With a ps that does not end, it waited 30 s for ps with the tool stopped, past the engine's
    grace period of 5 s, after which guard can exit and leave the stopped tool so for good.
    """
    (tmp_path / "ps").write_text("#!/bin/sh\nexec sleep 60\n")
    (tmp_path / "ps").chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setattr(process_tree, "_process_table", process_tree._ps_table)  # as on macOS
    tool = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        started = time.monotonic()
        kill_process_tree(tool)
        took = time.monotonic() - started

        try:
            returncode = tool.wait(timeout=5)
        except subprocess.TimeoutExpired:
            returncode = None
        assert returncode == -signal.SIGKILL, "the tool was left stopped"
        grace = engine_module._TOOL_KILL_GRACE_SECONDS
        assert took < grace, f"the kill took {took:.1f} s, past the engine's {grace} s grace"
    finally:
        tool.kill()  # SIGKILL ends a stopped process too; it sends nothing to a reaped tool
        tool.wait()


@pytest.mark.skipif(
    not Path("/proc/self/fd").is_dir(), reason="Linux lists a process's files in /proc"
)
def test_the_processes_that_hold_a_tools_output_are_found_by_its_pipe() -> None:
    """Each process but this one that holds the pipe of the tool's output, and no other."""
    sleep = [sys.executable, "-c", "import time; time.sleep(60)"]
    holder = subprocess.Popen(sleep, stdout=subprocess.PIPE)
    other = subprocess.Popen(sleep)
    try:
        pipes = process_tree._output_pipes(holder)
        assert len(pipes) == 1, pipes
        holders = process_tree._pipe_holders(pipes, time.monotonic() + 30)
        assert holder.pid in holders
        assert os.getpid() not in holders, "this process reads the pipe: it is not killed"
        assert other.pid not in holders
    finally:
        for process in (holder, other):
            process.kill()
            process.wait()
    assert holder.stdout is not None
    holder.stdout.close()
    assert process_tree._output_pipes(holder) == set(), "a closed pipe is no one's output"


@pytest.mark.skipif(
    not Path("/proc/self/fd").is_dir(), reason="Linux lists a process's files in /proc"
)
def test_the_search_for_a_tools_output_ends_with_the_time_for_listing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reading every process's files takes seconds on a host with many processes.

    A pass over them did not stop when the time for listing ran out: the processes the walk had
    stopped could wait past the engine's 5 seconds to be killed, and be left stopped.
    """
    holder = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"], stdout=subprocess.PIPE
    )
    try:
        pipes = process_tree._output_pipes(holder)
        fd_dir = Path(f"/proc/{holder.pid}/fd")
        assert process_tree._holds(fd_dir, pipes, time.monotonic() + 30)
        assert not process_tree._holds(fd_dir, pipes, time.monotonic()), "read past its time"
        holds, read = process_tree._holds, []

        def slow_holds(fd_dir: Path, pipes: set[str], listing_ends: float) -> bool:
            read.append(fd_dir)
            time.sleep(0.6)  # past the time for listing, as a process with many files can take
            return holds(fd_dir, pipes, listing_ends)

        monkeypatch.setattr(process_tree, "_holds", slow_holds)
        assert process_tree._pipe_holders(pipes, time.monotonic() + 0.5) == []
        assert len(read) == 1, "the search read on past the time for listing"
    finally:
        holder.kill()
        holder.wait()
        assert holder.stdout is not None
        holder.stdout.close()


@pytest.mark.skipif(
    not Path("/proc/self/fd").is_dir(), reason="Linux lists a process's files in /proc"
)
def test_a_process_with_many_files_is_read_only_until_the_time_for_listing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A process's file descriptors are read an entry at a time, and no longer than the time.

    The whole directory was listed before the time was looked at: for a process with a very
    large file table, past the time, while the tool and its processes waited stopped.
    """
    fd_dir = tmp_path / "fd"
    fd_dir.mkdir()
    for fd in range(200):
        (fd_dir / str(fd)).symlink_to(os.devnull)
    scandir, read = os.scandir, []

    class SlowListing:
        """``os.scandir``, but each entry takes 10 ms to read, as in a very large directory."""

        def __init__(self, path: Path) -> None:
            self._entries = scandir(path)

        def __enter__(self) -> SlowListing:
            return self

        def __exit__(self, *exc_info: object) -> None:
            self._entries.close()

        def __iter__(self) -> Iterator[os.DirEntry[str]]:
            for entry in self._entries:
                read.append(entry.name)
                time.sleep(0.01)
                yield entry

    monkeypatch.setattr(os, "scandir", SlowListing)
    assert not process_tree._holds(fd_dir, {"pipe:[1]"}, time.monotonic() + 0.2)
    assert 0 < len(read) < 200, f"read {len(read)} of the 200 entries"


# Looks for the process that holds a pipe twice: as it is, and once it may open only the one file
# that listing /proc takes, so that reading the holder's file descriptors fails with EMFILE.
OUT_OF_FILES = """
import os, resource, subprocess, sys, time

from envdrift.utils import process_tree

sleep = [sys.executable, "-c", "import time; time.sleep(60)"]
holder = subprocess.Popen(sleep, stdout=subprocess.PIPE)
try:
    pipes = process_tree._output_pipes(holder)
    print(process_tree._pipe_holders(pipes, time.monotonic() + 30) == [holder.pid])
    lowest = os.open(os.devnull, os.O_RDONLY)
    os.close(lowest)
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (lowest + 1, hard))
    try:
        print(process_tree._pipe_holders(pipes, time.monotonic() + 30))
    except OSError as error:
        print(error.errno)
    finally:
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))
finally:
    holder.kill()
    holder.wait()
"""


@pytest.mark.skipif(
    not Path("/proc/self/fd").is_dir(), reason="Linux lists a process's files in /proc"
)
def test_a_search_that_runs_out_of_files_fails_loud() -> None:
    """Out of file descriptors, the search for a tool's output raises EMFILE, not "no holder".

    It took this process's EMFILE for a holder that was gone: it passed over every process and
    left the holder running, and nothing said so. Raised, the error is logged by the runner,
    which still raises the timeout (``test_a_failed_listing_does_not_replace_the_timeout``).
    """
    probe = subprocess.run(
        [sys.executable, "-c", OUT_OF_FILES],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert probe.stdout.split() == ["True", str(errno.EMFILE)], probe.stdout + probe.stderr


@pytest.mark.skipif(not Path("/proc/self/stat").is_file(), reason="Linux lists processes in /proc")
def test_the_listing_passes_over_a_process_that_is_gone_but_not_its_own_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A process that exits while /proc is listed is passed over; an EMFILE of this one's is not.

    Passed over as gone, every process it hit was left out of the walk, and ran on.
    """
    read_bytes = Path.read_bytes
    errors: list[OSError] = [ProcessLookupError(errno.ESRCH, os.strerror(errno.ESRCH))]

    def read_failing_for_this_process(path: Path) -> bytes:
        if path.name == "stat" and path.parent.name == str(os.getpid()):
            raise errors[-1]
        return read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", read_failing_for_this_process)
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        table = dict(process_tree._proc_table())
        assert os.getpid() not in table
        assert table.get(child.pid) == os.getpid(), "the processes not gone were passed over too"
        errors.append(OSError(errno.EMFILE, os.strerror(errno.EMFILE)))
        with pytest.raises(OSError) as raised:
            process_tree._proc_table()
        assert raised.value.errno == errno.EMFILE
    finally:
        child.kill()
        child.wait()


@pytest.mark.skipif(sys.platform == "win32", reason="taskkill /T walks the tree on Windows")
def test_a_holder_it_cannot_stop_is_looked_for_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """One that is gone, or not this user's, ends the search instead of holding the kill up."""
    gone = 2**22 + 1  # above the highest pid of Linux (PID_MAX_LIMIT) and of macOS
    monkeypatch.setattr(process_tree, "_pipe_holders", lambda pipes, listing_ends: [gone])
    stopped: list[int] = []
    started = time.monotonic()
    process_tree._stop_pipe_holders({"pipe:[1]"}, stopped, time.monotonic() + 30)
    assert stopped == []
    assert time.monotonic() - started < 5, "it looked for the holders until the time ran out"


@pytest.mark.skipif(sys.platform == "win32", reason="taskkill /T walks the tree on Windows")
def test_a_process_it_cannot_signal_is_not_counted_as_stopped() -> None:
    """One that is gone, or not this user's, is neither stopped nor walked below."""
    gone = 2**22 + 1  # above the highest pid of Linux (PID_MAX_LIMIT) and of macOS
    assert process_tree._signal(gone, signal.SIGSTOP) is False
