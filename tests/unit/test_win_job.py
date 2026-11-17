"""The job object a tool runs in on Windows (#925).

``taskkill /T`` cannot reach a process whose parent has exited; a job object holds it. The tool
starts suspended and runs only once it is in its job, so that a child it starts at once is in the
job too. These tests drive ``start_in_job``, ``Job`` and the Windows kill with stand-ins for
kernel32, ntdll and taskkill on every platform. On Windows, ``tests/scanner/test_process_tree.py``
runs a real tool in a real job.
"""

from __future__ import annotations

import sys
from typing import Any

import pytest

from envdrift.utils import process_tree, win_job
from envdrift.utils.process_tree import kill_process_tree
from envdrift.utils.win_job import Job, start_in_job

_JOB, _PROCESS = 100, 200
# PROCESS_SET_QUOTA | PROCESS_TERMINATE for AssignProcessToJobObject, PROCESS_SUSPEND_RESUME for
# NtResumeProcess.
_ACCESS = 0x0100 | 0x0001 | 0x0800


class Kernel32:
    """The kernel32 calls ``start_in_job`` makes, recorded, each failing when asked to."""

    def __init__(self, *, fail: str = "") -> None:
        self.fail = fail
        self.calls: list[tuple[Any, ...]] = []

    def CreateJobObjectW(self, attributes: object, name: object) -> int:  # noqa: N802
        self.calls.append(("CreateJobObjectW", attributes, name))
        if self.fail == "interrupt":
            raise KeyboardInterrupt  # Ctrl+C while the tool is put in its job
        return 0 if self.fail == "create" else _JOB

    def OpenProcess(self, access: int, inherit: bool, pid: int) -> int:  # noqa: N802
        self.calls.append(("OpenProcess", access, inherit, pid))
        return 0 if self.fail == "open" else _PROCESS

    def AssignProcessToJobObject(self, job: int, process: int) -> int:  # noqa: N802
        self.calls.append(("AssignProcessToJobObject", job, process))
        return 0 if self.fail == "assign" else 1

    def TerminateJobObject(self, job: int, code: int) -> int:  # noqa: N802
        self.calls.append(("TerminateJobObject", job, code))
        return 0 if self.fail == "terminate" else 1

    def CloseHandle(self, handle: int) -> int:  # noqa: N802
        self.calls.append(("CloseHandle", handle))
        return 1

    def closed(self) -> list[int]:
        return [call[1] for call in self.calls if call[0] == "CloseHandle"]

    def names(self) -> list[str]:
        return [call[0] for call in self.calls]


class Ntdll:
    """``NtResumeProcess``, recorded with the kernel32 calls, failing when asked to."""

    def __init__(self, kernel32: Kernel32, *, fail: bool = False) -> None:
        self.kernel32 = kernel32
        self.fail = fail

    def NtResumeProcess(self, process: int) -> int:  # noqa: N802
        self.kernel32.calls.append(("NtResumeProcess", process))
        return -1073741823 if self.fail else 0  # STATUS_UNSUCCESSFUL, or STATUS_SUCCESS


class Tool:
    """A tool started suspended: its pid and args, and whether it was killed."""

    pid = 4321
    args = ["tool.exe"]

    def __init__(self) -> None:
        self.killed = False

    def kill(self) -> None:
        self.killed = True


def _start(kernel32: Kernel32, *, resume_fails: bool = False) -> tuple[Job | None, Tool]:
    tool = Tool()
    job = start_in_job(tool, kernel32, Ntdll(kernel32, fail=resume_fails))  # type: ignore[arg-type]
    return job, tool


def test_the_tool_is_put_in_a_new_job_before_it_runs() -> None:
    kernel32 = Kernel32()

    job, tool = _start(kernel32)

    assert isinstance(job, Job)
    assert ("OpenProcess", _ACCESS, False, Tool.pid) in kernel32.calls
    names = kernel32.names()
    assert names.index("AssignProcessToJobObject") < names.index("NtResumeProcess"), (
        "a process the tool starts before it is in the job is outside it"
    )
    assert ("NtResumeProcess", _PROCESS) in kernel32.calls
    assert kernel32.closed() == [_PROCESS], "only the process handle is let go of"
    assert tool.killed is False


def test_ending_the_job_ends_its_processes_and_closing_it_does_not() -> None:
    kernel32 = Kernel32()
    job, _ = _start(kernel32)
    assert job is not None

    assert job.terminate() is True
    job.close()
    job.close()

    assert ("TerminateJobObject", _JOB, 1) in kernel32.calls
    assert kernel32.closed() == [_PROCESS, _JOB], "the job is let go of once"
    assert job.terminate() is False, "a job let go of ends nothing"


def test_a_job_windows_does_not_end_says_so() -> None:
    job, _ = _start(Kernel32(fail="terminate"))
    assert job is not None

    assert job.terminate() is False


@pytest.mark.parametrize("failing", ["create", "assign"])
def test_a_tool_that_cannot_be_put_in_a_job_runs_without_one(failing: str) -> None:
    """No job: the tool is let run all the same, and what was opened is let go of."""
    kernel32 = Kernel32(fail=failing)

    job, tool = _start(kernel32)

    assert job is None
    assert ("NtResumeProcess", _PROCESS) in kernel32.calls
    assert tool.killed is False
    opened = {"create": [_PROCESS], "assign": [_JOB, _PROCESS]}[failing]
    assert sorted(kernel32.closed()) == sorted(opened)


def test_a_tool_that_cannot_be_opened_is_killed_not_left_suspended() -> None:
    kernel32 = Kernel32(fail="open")
    tool = Tool()

    with pytest.raises(OSError, match="could not open"):
        start_in_job(tool, kernel32, Ntdll(kernel32))  # type: ignore[arg-type]

    assert tool.killed is True
    assert "NtResumeProcess" not in kernel32.names()
    assert "CreateJobObjectW" not in kernel32.names()
    assert kernel32.closed() == []


def test_a_tool_interrupted_on_its_way_into_its_job_is_killed_not_left_suspended() -> None:
    """Never resumed, it would neither run nor end: Popen's exit would wait for it."""
    kernel32 = Kernel32(fail="interrupt")
    tool = Tool()

    with pytest.raises(KeyboardInterrupt):
        start_in_job(tool, kernel32, Ntdll(kernel32))  # type: ignore[arg-type]

    assert tool.killed is True
    assert "NtResumeProcess" not in kernel32.names()
    assert kernel32.closed() == [_PROCESS]


def test_a_tool_that_cannot_be_let_run_is_killed_not_left_suspended() -> None:
    """It would only wait out its timeout: it is killed, and the job and handle let go of."""
    kernel32 = Kernel32()
    tool = Tool()

    with pytest.raises(OSError, match="could not let"):
        start_in_job(tool, kernel32, Ntdll(kernel32, fail=True))  # type: ignore[arg-type]

    assert tool.killed is True
    assert sorted(kernel32.closed()) == [_JOB, _PROCESS]


@pytest.mark.skipif(sys.platform == "win32", reason="Windows has job objects")
def test_there_is_no_job_where_there_are_no_job_objects() -> None:
    assert win_job._kernel32() is None
    assert win_job._ntdll() is None
    assert start_in_job(Tool()) is None  # type: ignore[arg-type]


class _EndedJob:
    """A job whose end is recorded in ``calls``; Windows ends it unless ``ends`` is False."""

    def __init__(self, calls: list[str], *, ends: bool = True) -> None:
        self.calls = calls
        self.ends = ends

    def terminate(self) -> bool:
        self.calls.append("end the job")
        return self.ends


def _kill_on_windows(monkeypatch: pytest.MonkeyPatch, job: _EndedJob | None) -> list[str]:
    """Kill a timed-out tool as on Windows; the job's end and each ``taskkill /T``, in order."""
    calls = [] if job is None else job.calls
    monkeypatch.setattr(process_tree, "_taskkill_tree", lambda pid: calls.append("taskkill /T"))
    with monkeypatch.context() as windows:
        windows.setattr(sys, "platform", "win32")
        kill_process_tree(Tool(), job)  # type: ignore[arg-type]
    return calls


def test_the_job_is_ended_at_once_and_no_tree_walked(monkeypatch: pytest.MonkeyPatch) -> None:
    """taskkill can take 30 seconds, and the engine waits 5 for the kill: it ran first."""
    assert _kill_on_windows(monkeypatch, _EndedJob([])) == ["end the job"]


def test_the_tree_is_walked_where_windows_does_not_end_the_job(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    with pytest.raises(OSError, match="could not end the job object"):
        _kill_on_windows(monkeypatch, _EndedJob(calls, ends=False))

    assert calls == ["end the job", "taskkill /T"]


def test_the_tree_is_walked_where_there_is_no_job(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _kill_on_windows(monkeypatch, None) == ["taskkill /T"]
