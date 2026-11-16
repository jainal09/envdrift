"""Windows job objects: kill a tool with every process it started, its parent gone or not (#925).

``taskkill /T`` builds the tree from the running processes and their parent pids, starting at the
tool. A child that the tool left running when it exited has no running parent to be found from,
so it ran on, and when it held the tool's output open, ``communicate()`` waited for it. A job
object holds every process started by a process in it, whether or not its parent still runs:
``TerminateJobObject`` ends them all. Elsewhere than on Windows there are no job objects, and
``job_for`` returns None.
"""

from __future__ import annotations

import functools
import logging
import subprocess  # nosec B404
import sys
from typing import Any

logger = logging.getLogger(__name__)

# OpenProcess access rights that AssignProcessToJobObject needs.
_PROCESS_TERMINATE = 0x0001
_PROCESS_SET_QUOTA = 0x0100
# The exit code of each process the job ends: that of a process taskkill /F ends.
_KILLED_EXIT_CODE = 1


class Job:
    """A job object holding a tool and every process it starts after it was put in."""

    def __init__(self, kernel32: Any, handle: int) -> None:
        self._kernel32 = kernel32
        self._handle: int | None = handle

    def terminate(self) -> bool:
        """End every process in the job; return whether Windows did."""
        if self._handle is None:
            return False
        return bool(self._kernel32.TerminateJobObject(self._handle, _KILLED_EXIT_CODE))

    def close(self) -> None:
        """Let go of the job. It does not end the processes in it, which run on."""
        if self._handle is not None:
            self._kernel32.CloseHandle(self._handle)
            self._handle = None


def job_for(process: subprocess.Popen, kernel32: Any = None) -> Job | None:
    """Put ``process`` in a new job object, or None where that cannot be done.

    Called as soon as the process has started: a process it starts before then is not in the
    job, and is left to ``taskkill /T``. Every failure is logged and gives None, never an error:
    the tool runs as it would without a job.

    Args:
        process: A process that has just been started.
        kernel32: The kernel32 functions, for a test. Defaults to Windows' own; elsewhere
            there is none and the result is None.
    """
    if kernel32 is None:
        kernel32 = _kernel32()
        if kernel32 is None:
            return None
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        logger.debug("Could not create a job object for %s", process.args)
        return None
    handle = kernel32.OpenProcess(_PROCESS_SET_QUOTA | _PROCESS_TERMINATE, False, process.pid)
    try:
        if not handle or not kernel32.AssignProcessToJobObject(job, handle):
            logger.debug("Could not put %s in a job object", process.args)
            kernel32.CloseHandle(job)
            return None
    finally:
        if handle:
            kernel32.CloseHandle(handle)
    return Job(kernel32, job)


@functools.cache
def _kernel32() -> Any:
    """Windows' kernel32, typed for the functions ``job_for`` calls; None elsewhere."""
    return _load_kernel32()


if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    def _load_kernel32() -> Any:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.argtypes = (wintypes.LPVOID, wintypes.LPCWSTR)
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
        kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel32.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
        kernel32.TerminateJobObject.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel32.CloseHandle.restype = wintypes.BOOL
        return kernel32

else:

    def _load_kernel32() -> Any:
        return None
