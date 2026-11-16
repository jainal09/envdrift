"""Finding the processes that hold a pipe with macOS's libproc (#925).

These tests run the three libproc calls ``libproc_pipes`` makes against a stand-in that fills
the same buffers from a made-up process table, so they run on every platform. On macOS,
``tests/scanner/test_process_tree.py`` finds and kills real holders with the real libproc.
"""

from __future__ import annotations

import ctypes
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
    ``table`` has exited since.
    """

    def __init__(
        self, table: dict[int, dict[int, int | None]], listed: list[int] | None = None
    ) -> None:
        self.table = table
        self.listed = list(table) if listed is None else listed

    def proc_listallpids(self, buffer: object, size: int) -> int:
        pids = self.listed
        if buffer is None:
            return len(pids)
        assert isinstance(buffer, ctypes.Array)
        count = min(len(pids), size // ctypes.sizeof(ctypes.c_int))
        for index, pid in enumerate(pids[:count]):
            buffer[index] = pid
        return count

    def proc_pidinfo(self, pid: int, flavor: int, arg: int, buffer: object, size: int) -> int:
        assert flavor == libproc_pipes._PROC_PIDLISTFDS
        fds = self.table.get(pid)
        if fds is None:  # gone, or not this user's
            return 0
        if buffer is None:
            return len(fds) * ctypes.sizeof(_ProcFdInfo)
        assert isinstance(buffer, ctypes.Array)
        for index, (fd, end) in enumerate(fds.items()):
            buffer[index].proc_fd = fd
            buffer[index].proc_fdtype = _VNODE if end is None else _PIPE
        return len(fds) * ctypes.sizeof(_ProcFdInfo)

    def proc_pidfdinfo(self, pid: int, fd: int, flavor: int, address: int, size: int) -> int:
        assert flavor == libproc_pipes._PROC_PIDFDPIPEINFO
        end = self.table.get(pid, {}).get(fd)
        if end is None or size < ctypes.sizeof(_PipeFdInfo):
            return 0
        info = _PipeFdInfo.from_address(address)
        info.pipeinfo.pipe_handle = end
        info.pipeinfo.pipe_peerhandle = _PEER[end]
        return ctypes.sizeof(_PipeFdInfo)


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
    lib = Libproc(
        {
            me: {3: READ},  # this process reads the pipe: never a holder
            101: {1: WRITE},  # the tool's child, writing its output
            102: {0: READ},  # holds the read end
            103: {1: OTHER_WRITE, 5: None},  # another pipe, and a file
            104: {},
        }
    )

    holders = pipe_holders({READ, WRITE}, time.monotonic() + 30, lib)

    assert holders == [101, 102]


def test_a_process_that_has_gone_is_passed_over() -> None:
    lib = Libproc({101: {1: WRITE}}, listed=[102, 101])  # 102 exited once it was listed

    assert pipe_holders({READ, WRITE}, time.monotonic() + 30, lib) == [101]


def test_the_search_ends_with_the_time_for_listing() -> None:
    lib = Libproc({101: {1: WRITE}})

    assert pipe_holders({READ, WRITE}, time.monotonic(), lib) == []


def test_nothing_is_looked_for_without_a_pipe_or_without_libproc() -> None:
    lib = Libproc({101: {1: WRITE}})

    assert pipe_holders(set(), time.monotonic() + 30, lib) == []
    assert libproc_pipes._load_libproc("/nonexistent/libproc.dylib") is None


@pytest.mark.skipif(sys.platform == "darwin", reason="macOS has libproc")
def test_there_is_no_libproc_elsewhere() -> None:
    assert libproc_pipes._libproc() is None
    assert own_pipe_handles([0, 1, 2]) == set()
    assert pipe_holders({READ}, time.monotonic() + 30) == []
