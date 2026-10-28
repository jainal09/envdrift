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
from pathlib import Path

# A tree deeper than this is no tool's: the walk stops there.
_MAX_DEPTH = 64


def kill_process_tree(process: subprocess.Popen) -> None:
    """Kill ``process`` and every process below it that still runs.

    On POSIX each level of the tree is stopped (``SIGSTOP``) before its children are listed, so
    that none of them can start another one unseen, and then every one is killed. On Windows
    ``taskkill /T`` walks the tree. ``process`` itself is killed either way, as
    ``subprocess.run`` would.
    """
    if sys.platform == "win32":
        _taskkill_tree(process.pid)
    else:
        _kill_posix_tree(process.pid)
    with contextlib.suppress(OSError):
        process.kill()


def _kill_posix_tree(pid: int) -> None:
    stopped: list[int] = []
    level = [pid]
    for _ in range(_MAX_DEPTH):
        frozen = [p for p in level if _signal(p, signal.SIGSTOP)]
        if not frozen:
            break
        stopped.extend(frozen)
        children = _children_by_parent()
        level = [child for p in frozen for child in children.get(p, ()) if child not in stopped]
    for p in stopped:
        _signal(p, signal.SIGKILL)


def _signal(pid: int, sig: int) -> bool:
    """Send ``sig`` to ``pid``; return whether it was sent."""
    try:
        os.kill(pid, sig)
    except OSError:  # gone already, or not ours
        return False
    return True


def _children_by_parent() -> dict[int, list[int]]:
    """The pid of every process, by the pid of its parent."""
    children: dict[int, list[int]] = {}
    for pid, ppid in _process_table():
        children.setdefault(ppid, []).append(pid)
    return children


def _process_table() -> list[tuple[int, int]]:
    """``(pid, ppid)`` of every process: from ``/proc`` on Linux, from ``ps`` elsewhere."""
    proc = Path("/proc")
    if (proc / "self" / "stat").is_file():
        table = []
        for entry in proc.iterdir():
            if entry.name.isdigit():
                with contextlib.suppress(OSError, ValueError, IndexError):
                    table.append((int(entry.name), _ppid_from_stat((entry / "stat").read_text())))
        return table
    try:
        listing = subprocess.run(  # nosec B603, B607
            ["ps", "-A", "-o", "pid=,ppid="],
            capture_output=True,
            text=True,
            timeout=30,
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


def _ppid_from_stat(stat: str) -> int:
    """The parent pid in the text of ``/proc/<pid>/stat``.

    The text reads ``pid (comm) state ppid ...``, and ``comm`` may hold spaces and parentheses,
    so the fields after it are counted from its last ``)``.
    """
    return int(stat.rsplit(")", 1)[1].split()[1])


def _taskkill_tree(pid: int) -> None:
    with contextlib.suppress(OSError, subprocess.SubprocessError):
        subprocess.run(  # nosec B603, B607
            ["taskkill", "/F", "/T", "/PID", str(pid)],
            capture_output=True,
            timeout=30,
            check=False,
        )
