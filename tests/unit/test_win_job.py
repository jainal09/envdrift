"""The job object a tool runs in on Windows (#925).

``taskkill /T`` cannot reach a process whose parent has exited; a job object holds it. These
tests drive ``job_for`` and ``Job`` with a stand-in for kernel32 on every platform. On Windows,
``tests/scanner/test_process_tree.py`` runs a real tool in a real job object.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace
from typing import Any

import pytest

from envdrift.utils import win_job
from envdrift.utils.win_job import Job, job_for

_JOB, _PROCESS = 100, 200


class Kernel32:
    """The kernel32 calls ``job_for`` makes, recorded, each failing when asked to."""

    def __init__(self, *, fail: str = "") -> None:
        self.fail = fail
        self.calls: list[tuple[Any, ...]] = []

    def CreateJobObjectW(self, attributes: object, name: object) -> int:  # noqa: N802
        self.calls.append(("CreateJobObjectW", attributes, name))
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


_TOOL = SimpleNamespace(pid=4321, args=["tool.exe"])


def test_the_tool_is_put_in_a_new_job() -> None:
    kernel32 = Kernel32()

    job = job_for(_TOOL, kernel32)  # type: ignore[arg-type]

    assert isinstance(job, Job)
    # The access AssignProcessToJobObject needs: PROCESS_SET_QUOTA | PROCESS_TERMINATE.
    assert ("OpenProcess", 0x0101, False, _TOOL.pid) in kernel32.calls
    assert ("AssignProcessToJobObject", _JOB, _PROCESS) in kernel32.calls
    assert kernel32.closed() == [_PROCESS], "only the process handle is let go of"


def test_ending_the_job_ends_its_processes_and_closing_it_does_not() -> None:
    kernel32 = Kernel32()
    job = job_for(_TOOL, kernel32)  # type: ignore[arg-type]
    assert job is not None

    assert job.terminate() is True
    job.close()
    job.close()

    assert ("TerminateJobObject", _JOB, 1) in kernel32.calls
    assert kernel32.closed() == [_PROCESS, _JOB], "the job is let go of once"
    assert job.terminate() is False, "a job let go of ends nothing"


def test_a_job_windows_does_not_end_says_so() -> None:
    job = job_for(_TOOL, Kernel32(fail="terminate"))  # type: ignore[arg-type]
    assert job is not None

    assert job.terminate() is False


@pytest.mark.parametrize("failing", ["create", "open", "assign"])
def test_a_tool_that_cannot_be_put_in_a_job_runs_without_one(failing: str) -> None:
    """Every failure gives None, and lets go of what was opened: the tool runs as before."""
    kernel32 = Kernel32(fail=failing)

    assert job_for(_TOOL, kernel32) is None  # type: ignore[arg-type]

    opened = {"create": [], "open": [_JOB], "assign": [_JOB, _PROCESS]}[failing]
    assert sorted(kernel32.closed()) == sorted(opened)


@pytest.mark.skipif(sys.platform == "win32", reason="Windows has job objects")
def test_there_is_no_job_where_there_are_no_job_objects() -> None:
    assert win_job._kernel32() is None
    assert job_for(_TOOL) is None  # type: ignore[arg-type]
