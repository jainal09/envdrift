"""Kill a process together with every process it started (#911).

``subprocess.run`` kills only the process it started when its timeout passes. A tool that runs
others, such as git-secrets, a Bash script whose scan runs ``git grep``, leaves them behind:
they are re-parented to init and run on until they next write their output or their work is
done, after guard has exited.
"""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess  # nosec B404
import sys
import time
from pathlib import Path

# A tree deeper than this is no tool's: the walk stops there.
_MAX_DEPTH = 64
# How long the walk may spend listing processes, in all. The engine gives the tools of the
# scanners that time out 5 seconds to be killed: the processes the walk has stopped must be
# killed within them, or guard could exit first and leave them stopped.
_LISTING_SECONDS = 2.0


def kill_process_tree(process: subprocess.Popen) -> None:
    """Kill ``process`` and every process below it that still runs.

    On POSIX each level of the tree is stopped (``SIGSTOP``) before its children are listed, so
    that none of them can start another one unseen, and then every one is killed: when a listing
    fails, the processes stopped so far are killed before the error is raised. On Windows
    ``taskkill /T`` walks the tree. ``process`` itself is killed either way, as
    ``subprocess.run`` would.
    """
    try:
        if sys.platform == "win32":
            _taskkill_tree(process.pid)
        else:
            _kill_posix_tree(process.pid)
    finally:
        with contextlib.suppress(OSError):
            process.kill()


def _kill_posix_tree(pid: int) -> None:
    stopped: list[int] = []
    try:
        _stop_tree(pid, stopped)
    finally:
        # Even when a listing failed: a stopped process that is not killed never ends.
        for p in stopped:
            _signal(p, signal.SIGKILL)


def _stop_tree(pid: int, stopped: list[int]) -> None:
    """Stop ``pid`` and the processes below it, level by level, adding each to ``stopped``.

    Once listing the processes has taken ``_LISTING_SECONDS``, the walk ends with the levels it
    has stopped.
    """
    listing_ends = time.monotonic() + _LISTING_SECONDS
    level = [pid]
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
            with contextlib.suppress(OSError, ValueError, IndexError):
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
