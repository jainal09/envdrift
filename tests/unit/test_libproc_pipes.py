"""Finding the processes that hold a pipe with macOS's libproc (#925).

These tests run the three libproc calls ``libproc_pipes`` makes against a stand-in that fills
the same buffers from a made-up process table, so they run on every platform. On macOS,
``tests/scanner/test_process_tree.py`` finds and kills real holders with the real libproc.
"""

from __future__ import annotations

import ctypes
import errno
import os
import sys
import time

import pytest

from envdrift.utils import libproc_pipes
from envdrift.utils.libproc_pipes import (
    _PipeFdInfo,
    _PipeInfo,
    _ProcFdInfo,
    own_pipe_handles,
    pipe_holders,
)

_PIPE, _VNODE = 6, 1
# Two pipes, each with a read end and a write end.
READ, WRITE, OTHER_READ, OTHER_WRITE = 0x10, 0x11, 0x20, 0x21
_PEER = {READ: WRITE, WRITE: READ, OTHER_READ: OTHER_WRITE, OTHER_WRITE: OTHER_READ}


class Libproc:
    """libproc over ``table``: each pid's descriptors, each the pipe end it holds or None.

    It lists the pids ``listed``, by default those of ``table``: one listed and not in
    ``table`` has exited since. Its calls fail as XNU's ``bsd/kern/proc_info.c`` does: with
    ``ESRCH`` for a process that has gone, and with ``EBADF`` for the pipe of a descriptor that
    is closed or is no pipe. A call on a process in ``failing`` fails with the errno it maps it
    to, and listing the processes fails with ``listing_fails`` when it is set.
    """

    def __init__(
        self,
        table: dict[int, dict[int, int | None]],
        listed: list[int] | None = None,
        failing: dict[int, int] | None = None,
        listing_fails: int = 0,
    ) -> None:
        self.table = table
        self.listed = list(table) if listed is None else listed
        self.failing = failing or {}
        self.listing_fails = listing_fails
        self.calls: list[str] = []

    def proc_listallpids(self, *call: object) -> int:
        self.calls.append("proc_listallpids")
        buffer, size = call
        if self.listing_fails:
            return _fails(self.listing_fails, -1)
        pids = self.listed
        if buffer is None:
            return len(pids)
        assert isinstance(buffer, ctypes.Array)
        assert isinstance(size, int)
        count = min(len(pids), size // ctypes.sizeof(ctypes.c_int))
        for index, pid in enumerate(pids[:count]):
            buffer[index] = pid
        return count

    def proc_pidinfo(self, *call: object) -> int:
        self.calls.append("proc_pidinfo")
        pid, flavor, _arg, buffer, _size = call
        assert flavor == libproc_pipes._PROC_PIDLISTFDS
        assert isinstance(pid, int)
        if pid in self.failing:
            return _fails(self.failing[pid])
        fds = self.table.get(pid)
        if fds is None:
            return _fails(errno.ESRCH)
        if buffer is None:
            return len(fds) * ctypes.sizeof(_ProcFdInfo)
        assert isinstance(buffer, ctypes.Array)
        for index, (fd, end) in enumerate(fds.items()):
            buffer[index].proc_fd = fd
            buffer[index].proc_fdtype = _VNODE if end is None else _PIPE
        return len(fds) * ctypes.sizeof(_ProcFdInfo)

    def proc_pidfdinfo(self, *call: object) -> int:
        self.calls.append("proc_pidfdinfo")
        pid, fd, flavor, address, size = call
        assert flavor == libproc_pipes._PROC_PIDFDPIPEINFO
        assert isinstance(pid, int)
        assert isinstance(fd, int)
        assert isinstance(address, int)
        assert isinstance(size, int)
        if pid in self.failing:
            return _fails(self.failing[pid])
        fds = self.table.get(pid)
        if fds is None:
            return _fails(errno.ESRCH)
        if size < ctypes.sizeof(_PipeFdInfo):
            return _fails(errno.ENOMEM)
        end = fds.get(fd)
        if end is None:  # closed, or no pipe
            return _fails(errno.EBADF)
        info = _PipeFdInfo.from_address(address)
        info.pipeinfo.pipe_handle = end
        info.pipeinfo.pipe_peerhandle = _PEER[end]
        return ctypes.sizeof(_PipeFdInfo)


def _fails(error: int, result: int = 0) -> int:
    """A libproc call that fails with ``error``: it returns ``result`` and sets errno."""
    ctypes.set_errno(error)
    return result


def test_the_structures_are_laid_out_as_sys_proc_info_h_declares() -> None:
    """A wrong offset would read another field as a pipe's handle: no holder would match."""
    assert ctypes.sizeof(_ProcFdInfo) == 8
    assert ctypes.sizeof(_PipeInfo) == 160
    assert ctypes.sizeof(_PipeFdInfo) == 184
    assert _PipeFdInfo.pipeinfo.offset == 24
    assert _PipeInfo.pipe_handle.offset == 136
    assert _PipeInfo.pipe_peerhandle.offset == 144


def test_this_process_names_both_ends_of_the_pipe_it_reads() -> None:
    lib = Libproc({os.getpid(): {3: READ, 4: None}})

    assert own_pipe_handles([3, 4, 5], lib) == {READ, WRITE}


def test_the_holders_of_either_end_are_found_and_no_other_process() -> None:
    me = os.getpid()
    child, reader, other, idle = me + 1, me + 2, me + 3, me + 4
    lib = Libproc(
        {
            me: {3: READ},  # this process reads the pipe: never a holder
            child: {1: WRITE},  # the tool's child, writing its output
            reader: {0: READ},  # holds the read end
            other: {1: OTHER_WRITE, 5: None},  # another pipe, and a file
            idle: {},
        }
    )

    holders = pipe_holders({READ, WRITE}, time.monotonic() + 30, lib)

    assert holders == [child, reader]


def test_a_process_that_has_gone_or_is_not_ours_is_passed_over() -> None:
    me = os.getpid()
    child, gone, not_ours, denied = me + 1, me + 2, me + 3, me + 4
    lib = Libproc(
        {child: {1: WRITE}},
        listed=[gone, not_ours, denied, child],  # gone exited once it was listed
        failing={not_ours: errno.EPERM, denied: errno.EACCES},
    )

    assert pipe_holders({READ, WRITE}, time.monotonic() + 30, lib) == [child]


@pytest.mark.parametrize(
    "error",
    [errno.EINVAL, errno.ENOMEM, errno.EFAULT],
    ids=["EINVAL", "ENOMEM", "EFAULT"],
)
def test_a_process_libproc_cannot_list_for_another_reason_is_raised(error: int) -> None:
    """Passing over it would leave a holder running unseen: the kill must warn (#925)."""
    me = os.getpid()
    child, unreadable = me + 1, me + 2
    lib = Libproc({child: {1: WRITE}}, listed=[unreadable, child], failing={unreadable: error})

    with pytest.raises(OSError, match=f"process {unreadable}") as raised:
        pipe_holders({READ, WRITE}, time.monotonic() + 30, lib)

    assert raised.value.errno == error


def test_processes_libproc_cannot_list_are_raised() -> None:
    lib = Libproc({os.getpid() + 1: {1: WRITE}}, listing_fails=errno.ENOMEM)

    with pytest.raises(OSError, match="the processes") as raised:
        pipe_holders({READ, WRITE}, time.monotonic() + 30, lib)

    assert raised.value.errno == errno.ENOMEM


def test_a_pipe_of_its_own_libproc_cannot_name_is_raised() -> None:
    """With no handle for its output, the kill could not find the processes holding it."""
    lib = Libproc({os.getpid(): {3: READ}}, failing={os.getpid(): errno.EFAULT})

    with pytest.raises(OSError, match="file 3 of process") as raised:
        own_pipe_handles([3], lib)

    assert raised.value.errno == errno.EFAULT


def test_the_search_ends_with_the_time_for_listing() -> None:
    lib = Libproc({os.getpid() + 1: {1: WRITE}})

    assert pipe_holders({READ, WRITE}, time.monotonic(), lib) == []


def test_no_process_is_listed_once_the_time_for_listing_has_run_out() -> None:
    """Listing every process takes time the kill no longer has."""
    lib = Libproc({os.getpid() + 1: {1: WRITE}})

    assert pipe_holders({READ, WRITE}, time.monotonic(), lib) == []
    assert lib.calls == []


def test_nothing_is_looked_for_without_a_pipe_or_without_libproc() -> None:
    lib = Libproc({os.getpid() + 1: {1: WRITE}})

    assert pipe_holders(set(), time.monotonic() + 30, lib) == []
    assert libproc_pipes._load_libproc("/nonexistent/libproc.dylib") is None


@pytest.mark.skipif(sys.platform == "darwin", reason="macOS has libproc")
def test_there_is_no_libproc_elsewhere() -> None:
    assert libproc_pipes._libproc() is None
    assert own_pipe_handles([0, 1, 2]) == set()
    assert pipe_holders({READ}, time.monotonic() + 30) == []
