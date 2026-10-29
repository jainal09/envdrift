"""The deadline of a scanner, and the external tools it runs before it.

The engine gives each scanner a time limit and stops waiting for one still running then. A
thread cannot be stopped, so the scanner is left behind (#870). The tools it runs through
``run_tool`` are held to its deadline instead: a tool's timeout is capped at it, no tool or
download starts once it has passed, and the engine waits for the tools still running then to be
killed, so that none outlives guard (#900). A tool is killed together with the processes it
started (#911).
"""

from __future__ import annotations

import logging
import subprocess  # nosec B404
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from envdrift.utils.process_tree import kill_process_tree

logger = logging.getLogger(__name__)


class ScannerTimedOut(BaseException):
    """A scanner past its deadline asked to start a tool or a download, which did not start.

    A ``BaseException``, like ``KeyboardInterrupt``: the ``except Exception`` of a scanner that
    carries on after a failed probe cannot catch it, so the scanner stops instead of going on
    to run more tools or to download one (#900).
    """


class ScannerDeadline:
    """A scanner's deadline, a ``time.monotonic()``, and the number of tools it is running."""

    def __init__(self, deadline: float) -> None:
        self.deadline = deadline
        self._changed = threading.Condition()
        self._running = 0

    def passed(self) -> bool:
        """Whether the deadline has passed."""
        return time.monotonic() >= self.deadline

    def check(self) -> None:
        """Raise ``ScannerTimedOut`` if the deadline has passed."""
        if self.passed():
            raise ScannerTimedOut("the scanner's time limit has passed")

    def timeout(self, seconds: float) -> float:
        """``seconds``, or the time left until the deadline if that is less."""
        return max(0.0, min(seconds, self.deadline - time.monotonic()))

    @contextmanager
    def tool(self) -> Iterator[None]:
        """Count a tool as running for the block, or raise ``ScannerTimedOut`` past the deadline."""
        with self._changed:
            self.check()
            self._running += 1
        try:
            yield
        finally:
            with self._changed:
                self._running -= 1
                self._changed.notify_all()

    def wait_for_tools(self, timeout: float) -> bool:
        """Wait up to ``timeout`` seconds for the running tools to end; return whether they did.

        Past the deadline no tool starts, and each running one is killed at the deadline by its
        capped timeout, so this returns as soon as ``subprocess.run`` has killed and reaped them.
        """
        with self._changed:
            return self._changed.wait_for(lambda: self._running == 0, timeout=timeout)


# The deadline of the scanner running on this thread, if any.
_current = threading.local()


@contextmanager
def scanner_deadline(deadline: ScannerDeadline) -> Iterator[None]:
    """Hold the tools and downloads run on this thread to ``deadline`` for the block."""
    previous = current_deadline()
    _current.deadline = deadline
    try:
        yield
    finally:
        _current.deadline = previous


def current_deadline() -> ScannerDeadline | None:
    """The deadline of the scanner running on this thread, or None outside a scan."""
    return getattr(_current, "deadline", None)


def check_deadline() -> None:
    """Raise ``ScannerTimedOut`` if a scanner runs on this thread and is past its deadline."""
    deadline = current_deadline()
    if deadline is not None:
        deadline.check()


def run_tool(args: Any, *, timeout: float, **kwargs: Any) -> subprocess.CompletedProcess[Any]:
    """``subprocess.run(args, timeout=timeout, **kwargs)`` for a tool that a scanner runs.

    A tool that times out is killed together with every process it started (#911). In a
    scanner (see ``scanner_deadline``) the timeout is capped at its deadline, so the tool is
    killed then, and once the deadline has passed the tool does not start: ``ScannerTimedOut``
    is raised instead.
    """
    deadline = current_deadline()
    if deadline is None:
        return _run(args, timeout=timeout, **kwargs)
    with deadline.tool():
        return _run(args, timeout=deadline.timeout(timeout), **kwargs)


def _run(
    args: Any,
    *,
    timeout: float,
    input: Any = None,
    capture_output: bool = False,
    check: bool = False,
    **kwargs: Any,
) -> subprocess.CompletedProcess[Any]:
    """``subprocess.run``, but a timeout or an interrupt kills the processes the tool started too.

    ``subprocess.run`` kills only the process it started (#911). This follows its code, with
    ``_kill_tree`` where it calls ``process.kill()``.
    """
    if input is not None:
        if kwargs.get("stdin") is not None:
            raise ValueError("stdin and input arguments may not both be used.")
        kwargs["stdin"] = subprocess.PIPE
    if capture_output:
        if kwargs.get("stdout") is not None or kwargs.get("stderr") is not None:
            raise ValueError("stdout and stderr arguments may not be used with capture_output.")
        kwargs["stdout"] = kwargs["stderr"] = subprocess.PIPE
    with subprocess.Popen(args, **kwargs) as process:  # nosec B603
        try:
            stdout, stderr = process.communicate(input, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            _kill_tree(process)
            if sys.platform == "win32":
                # Windows reads the output on threads: collect it after the kill.
                exc.stdout, exc.stderr = process.communicate()
            else:
                # POSIX communicate() has put the output so far on the exception.
                process.wait()
            raise
        except BaseException:  # KeyboardInterrupt included, as in subprocess.run
            _kill_tree(process)
            raise
        returncode = process.wait()  # it has exited: communicate() returned
        if check and returncode:
            raise subprocess.CalledProcessError(
                returncode, process.args, output=stdout, stderr=stderr
            )
    return subprocess.CompletedProcess(process.args, returncode, stdout, stderr)


def _kill_tree(process: subprocess.Popen) -> None:
    """``kill_process_tree`` while the runner handles a timeout or an interrupt.

    The tool and the processes stopped so far are killed even when listing the processes fails.
    That error is logged, not raised: the caller must see the timeout or interrupt it handles.
    """
    try:
        kill_process_tree(process)
    except OSError as exc:
        logger.warning("Could not kill every process that %s started: %s", process.args, exc)
