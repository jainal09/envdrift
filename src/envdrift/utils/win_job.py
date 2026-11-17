"""Windows job objects: kill a tool with every process it started, its parent gone or not (#925).

``taskkill /T`` builds the tree from the running processes and their parent pids, starting at the
tool. A child that the tool left running when it exited has no running parent to be found from,
so it ran on, and when it held the tool's output open, ``communicate()`` waited for it. A job
object holds every process started by a process in it, whether or not its parent still runs:
``TerminateJobObject`` ends them all. The tool is started suspended, and runs only once it is in
its job: a child it started at once was outside a job made after it had started, and ran on.
Elsewhere than on Windows there are no job objects, and ``start_in_job`` returns None.
"""

from __future__ import annotations

import functools
import logging
import subprocess  # nosec B404
import sys
from typing import Any

logger = logging.getLogger(__name__)

# The CreateProcess flag that keeps a new process's first thread from running until it is resumed.
CREATE_SUSPENDED = 0x00000004
# OpenProcess access rights that AssignProcessToJobObject needs, and NtResumeProcess.
_PROCESS_TERMINATE = 0x0001
_PROCESS_SET_QUOTA = 0x0100
_PROCESS_SUSPEND_RESUME = 0x0800
_STATUS_SUCCESS = 0
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


def start_in_job(process: subprocess.Popen, kernel32: Any = None, ntdll: Any = None) -> Job | None:
    """Put ``process``, started with ``CREATE_SUSPENDED``, in a new job object; then let it run.

    It runs nothing until it is in the job, so every process it starts is in the job too. A job
    that cannot be made is logged, and the tool runs without one, under ``taskkill /T`` alone, as
    before. A tool that is not let run, because Windows refuses or because anything else raises
    first, a KeyboardInterrupt too, is killed, and the error raised: a suspended tool never ends.

    Args:
        process: A process started with ``CREATE_SUSPENDED``.
        kernel32: The kernel32 functions, for a test. Defaults to Windows' own; elsewhere
            there is none, nothing was started suspended, and the result is None.
        ntdll: The ntdll functions, for a test. Defaults to Windows' own.
    """
    kernel32 = _kernel32() if kernel32 is None else kernel32
    if kernel32 is None:
        return None  # not Windows: nothing was started suspended
    handle: Any = None
    job: Job | None = None
    resumed = False
    try:
        handle = _open_suspended(kernel32, process)
        job = _job_holding(kernel32, handle, process)
        resumed = _resume(_ntdll() if ntdll is None else ntdll, handle, process)
        return job
    finally:
        _release(kernel32, handle, None if resumed else job)
        if not resumed:
            process.kill()


def _open_suspended(kernel32: Any, process: subprocess.Popen) -> Any:
    """A handle to ``process`` with the rights to put it in a job and resume it; else OSError."""
    access = _PROCESS_SET_QUOTA | _PROCESS_TERMINATE | _PROCESS_SUSPEND_RESUME
    handle = kernel32.OpenProcess(access, False, process.pid)
    if not handle:
        raise OSError(f"could not open {process.args} to let it run")
    return handle


def _resume(ntdll: Any, handle: Any, process: subprocess.Popen) -> bool:
    """Let the suspended process ``handle`` opens run: True, or OSError when Windows refuses."""
    if ntdll.NtResumeProcess(handle) != _STATUS_SUCCESS:
        raise OSError(f"could not let {process.args} run")
    return True


def _release(kernel32: Any, handle: Any, job: Job | None) -> None:
    """Close the process ``handle``, if one was opened, and ``job``, unless it is None."""
    if handle:
        kernel32.CloseHandle(handle)
    if job is not None:
        job.close()


def _job_holding(kernel32: Any, handle: int, process: subprocess.Popen) -> Job | None:
    """A new job object holding the process ``handle`` opens; None, logged, when it cannot be."""
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        logger.debug("Could not create a job object for %s", process.args)
        return None
    if not kernel32.AssignProcessToJobObject(job, handle):
        logger.debug("Could not put %s in a job object", process.args)
        kernel32.CloseHandle(job)
        return None
    return Job(kernel32, job)


@functools.cache
def _kernel32() -> Any:
    """Windows' kernel32, typed for the functions ``start_in_job`` calls; None elsewhere."""
    return _load_kernel32()


@functools.cache
def _ntdll() -> Any:
    """Windows' ntdll, typed for ``NtResumeProcess``; None elsewhere."""
    return _load_ntdll()


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

    def _load_ntdll() -> Any:
        # NtResumeProcess resumes every thread of a process from its handle alone; psutil's
        # Process.resume() calls it too. Popen keeps no handle to the first thread.
        ntdll = ctypes.WinDLL("ntdll")
        ntdll.NtResumeProcess.argtypes = (wintypes.HANDLE,)
        ntdll.NtResumeProcess.restype = ctypes.c_long
        return ntdll

else:

    def _load_kernel32() -> Any:
        return None

    def _load_ntdll() -> Any:
        return None
