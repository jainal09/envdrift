"""Kill a process together with every process it started (#911).

``subprocess.run`` kills only the process it started when its timeout passes. A tool that runs
others, such as git-secrets, a Bash script whose scan runs ``git grep``, leaves them behind:
they are re-parented to init and run on until they next write their output or their work is
done, after guard has exited. A process the tool left running in the background when it exited,
no longer below it, is found by the tool's output, which it holds open: on Linux in ``/proc``
(#922), on macOS with libproc (#925). On Windows the tool runs in a job object, which holds such
a process too (#925).
"""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess  # nosec B404
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING

from envdrift.utils import libproc_pipes

if TYPE_CHECKING:
    from envdrift.utils.win_job import Job

# A tree deeper than this is no tool's: the walk stops there.
_MAX_DEPTH = 64
# How long the walk may spend listing processes, in all. The engine gives the tools of the
# scanners that time out 5 seconds to be killed: the processes the walk has stopped must be
# killed within them, or guard could exit first and leave them stopped.
_LISTING_SECONDS = 2.0
# How reading another process's /proc files fails once it has exited, or when it is not this
# user's: it is passed over. Another error, such as EMFILE, is this process's and is raised,
# since passing over every process it hits would leave a running one out of the kill unseen.
_GONE_OR_NOT_OURS = (FileNotFoundError, ProcessLookupError, PermissionError)
# How ``_output_pipes`` names an end of a pipe by its libproc handle (macOS), where Linux has the
# ``pipe:[inode]`` that ``/proc`` shows.
_LIBPROC_PIPE = "libproc-pipe:"


def kill_process_tree(process: subprocess.Popen, job: Job | None = None) -> None:
    """Kill ``process`` and every process below it that still runs.

    On POSIX each level of the tree is stopped (``SIGSTOP``) before its children are listed, so
    that none of them can start another one unseen, and then every one is killed: when a listing
    fails, the processes stopped so far are killed before the error is raised. So are the
    processes that hold the output of ``process`` open, with those below them, found on Linux
    and macOS. On Windows ``job``, the job object that ``process`` was put in before it ran, is
    ended with every process in it: one whose parent has exited too, which a walk of the tree
    cannot reach (#925). ``taskkill /T`` walks the tree where there is no job, or where Windows
    does not end it. ``process`` itself is killed either way, as ``subprocess.run`` would.
    """
    try:
        if sys.platform == "win32":
            _kill_windows_tree(process, job)
        else:
            _kill_posix_tree(process)
    finally:
        with contextlib.suppress(OSError):
            process.kill()


def _kill_windows_tree(process: subprocess.Popen, job: Job | None) -> None:
    """End ``job``, which holds every process ``process`` started; walk the tree without one.

    The job is ended first, in one call: ``taskkill /T`` can take up to its 30-second timeout,
    and the engine waits 5 seconds for a killed tool before guard goes on, and may exit.
    """
    if job is not None and job.terminate():
        return
    _taskkill_tree(process.pid)
    if job is not None:
        raise OSError(f"could not end the job object of {process.args}")


def _kill_posix_tree(process: subprocess.Popen) -> None:
    """Stop ``process``, the processes below it and the holders of its output; then kill them all.

    The tree is stopped before its output pipes are named, so that a failure to name them, which
    is raised, still kills the processes stopped.
    """
    stopped: list[int] = []
    try:
        listing_ends = time.monotonic() + _LISTING_SECONDS
        _stop_tree([process.pid], stopped, listing_ends)
        _stop_pipe_holders(_output_pipes(process), stopped, listing_ends)
    finally:
        # Even when a listing failed: a stopped process that is not killed never ends.
        for p in stopped:
            _signal(p, signal.SIGKILL)


def _stop_tree(pids: list[int], stopped: list[int], listing_ends: float) -> None:
    """Stop ``pids`` and the processes below them, level by level, adding each to ``stopped``.

    Once the time for listing processes has run out, at ``listing_ends``, the walk ends with the
    levels it has stopped.
    """
    level = pids
    for _ in range(_MAX_DEPTH):
        frozen = [p for p in level if _signal(p, signal.SIGSTOP)]
        if not frozen:
            return
        stopped.extend(frozen)
        time_left = listing_ends - time.monotonic()
        if time_left <= 0:
            return
        children = _children_by_parent(time_left)
        level = [child for p in frozen for child in children.get(p, ()) if child not in stopped]


def _stop_pipe_holders(pipes: set[str], stopped: list[int], listing_ends: float) -> None:
    """Stop the processes that hold one of ``pipes`` open, and those below them (Linux).

    A child that the tool left running in the background when it exited was re-parented, out of
    the walk's reach, but holds the tool's output open: ``communicate()`` waited for it (#922).
    The holders are looked for again until none is new, as one found while it forks has a child
    that holds the pipes too.
    """
    seen = set(stopped)
    while pipes and time.monotonic() < listing_ends:
        holders: list[int] = []
        try:
            for pid in _pipe_holders(pipes, listing_ends):
                if pid not in seen:
                    holders.append(pid)
        finally:
            # A search that fails still stops the holders it found before then, so that the
            # kill ends them with the rest; its error reaches the caller all the same (#925).
            seen.update(holders)
            _stop_tree(holders, stopped, listing_ends)
        if not holders:
            return
        seen.update(stopped)


def _output_pipes(process: subprocess.Popen) -> set[str]:
    """The pipes this process reads the output of ``process`` from.

    On Linux each is named as ``/proc`` names it. On macOS each end of each is named by the
    handle libproc gives it, with ``_LIBPROC_PIPE`` in front (#925). Empty elsewhere. Output
    that is not captured, or that ``communicate()`` has read to its end, has no pipe to hold
    open.
    """
    fds = []
    for stream in (process.stdout, process.stderr):
        with contextlib.suppress(OSError, ValueError):  # ValueError: closed at its end
            if stream is not None:
                fds.append(stream.fileno())
    if not Path("/proc/self/fd").is_dir():
        return {f"{_LIBPROC_PIPE}{handle}" for handle in libproc_pipes.own_pipe_handles(fds)}
    pipes = set()
    for fd in fds:
        with contextlib.suppress(OSError):
            pipes.add(f"pipe:[{os.fstat(fd).st_ino}]")
    return pipes


def _pipe_holders(pipes: set[str], listing_ends: float) -> Iterator[int]:
    """The pid of every process but this one that holds one of ``pipes`` open, as it is found.

    On Linux it reads each process's ``/proc/<pid>/fd``, which, unlike its ``environ`` or
    ``cmdline``, never waits on the process: a process that is stuck cannot hold the kill up.
    Reading them all takes about 10 microseconds a file descriptor, seconds on a host with many
    processes or files, so ``/proc`` and each of them are read an entry at a time, and the
    search ends at ``listing_ends`` with the holders it has found. On macOS libproc lists them,
    within the same time (#925).
    """
    handles = {int(p.removeprefix(_LIBPROC_PIPE)) for p in pipes if p.startswith(_LIBPROC_PIPE)}
    if handles:
        yield from libproc_pipes.pipe_holders(handles, listing_ends)
        return
    me = str(os.getpid())
    with os.scandir("/proc") as entries:
        for entry in _until(entries, listing_ends):
            if not entry.name.isdigit() or entry.name == me:
                continue
            if _holds(Path(entry.path, "fd"), pipes, listing_ends):
                yield int(entry.name)


def _holds(fd_dir: Path, pipes: set[str], listing_ends: float) -> bool:
    """Whether a file descriptor in ``fd_dir`` is one of ``pipes``, read before ``listing_ends``.

    None that it may not read is.
    """
    try:
        with os.scandir(fd_dir) as fds:
            return any(_link(fd.path) in pipes for fd in _until(fds, listing_ends))
    except _GONE_OR_NOT_OURS:
        return False


def _until(entries: Iterator[os.DirEntry[str]], ends: float) -> Iterator[os.DirEntry[str]]:
    """``entries``, as they are read, until ``ends``."""
    for entry in entries:
        if time.monotonic() >= ends:
            return
        yield entry


def _link(path: str) -> str | None:
    """Where the symbolic link ``path`` points, or None once it is gone."""
    try:
        return str(Path(path).readlink())
    except _GONE_OR_NOT_OURS:  # closed since
        return None


def _signal(pid: int, sig: int) -> bool:
    """Send ``sig`` to ``pid``; return whether it was sent."""
    try:
        os.kill(pid, sig)
    except OSError:  # gone already, or not ours
        return False
    return True


def _children_by_parent(timeout: float) -> dict[int, list[int]]:
    """The pid of every process, by the pid of its parent, listed within ``timeout`` seconds."""
    children: dict[int, list[int]] = {}
    for pid, ppid in _process_table(timeout):
        children.setdefault(ppid, []).append(pid)
    return children


def _process_table(timeout: float) -> list[tuple[int, int]]:
    """``(pid, ppid)`` of every process: from ``/proc`` on Linux, from ``ps`` elsewhere.

    ``ps`` has ``timeout`` seconds; reading ``/proc`` does not wait on another process.
    """
    return _proc_table() if Path("/proc/self/stat").is_file() else _ps_table(timeout)


def _proc_table() -> list[tuple[int, int]]:
    """``(pid, ppid)`` of every process that Linux's ``/proc`` lists."""
    table = []
    for entry in Path("/proc").iterdir():
        if entry.name.isdigit():
            with contextlib.suppress(*_GONE_OR_NOT_OURS, ValueError, IndexError):
                table.append((int(entry.name), _ppid_from_stat((entry / "stat").read_bytes())))
    return table


def _ps_table(timeout: float) -> list[tuple[int, int]]:
    """``(pid, ppid)`` of every process that ``ps`` lists: none when it cannot run in time."""
    try:
        listing = subprocess.run(  # nosec B603, B607
            ["ps", "-A", "-o", "pid=,ppid="],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    table = []
    for line in listing.splitlines():
        with contextlib.suppress(ValueError):
            pid, ppid = line.split()
            table.append((int(pid), int(ppid)))
    return table


def _ppid_from_stat(stat: bytes) -> int:
    """The parent pid in the contents of ``/proc/<pid>/stat``.

    They read ``pid (comm) state ppid ...``. ``comm`` may hold spaces and parentheses, so the
    fields after it are counted from its last ``)``, and it need not be text: the kernel cuts a
    long name at 15 bytes, which can split a UTF-8 character.
    """
    return int(stat.rsplit(b")", 1)[1].split()[1])


def _taskkill_tree(pid: int) -> None:
    with contextlib.suppress(OSError, subprocess.SubprocessError):
        subprocess.run(  # nosec B603, B607
            ["taskkill", "/F", "/T", "/PID", str(pid)],
            capture_output=True,
            timeout=30,
            check=False,
        )
