"""The processes that hold a pipe open, found on macOS with libproc, as ``lsof`` finds them (#925).

Linux names each process's open files in ``/proc``, and macOS has no ``/proc``. Its libproc lists
them: ``proc_listallpids`` the processes, ``proc_pidinfo(PROC_PIDLISTFDS)`` the file descriptors
of each, and ``proc_pidfdinfo(PROC_PIDFDPIPEINFO)`` the two ends of a pipe, each named by a
handle. The write end of the pipe this process reads a tool's output from is the peer of the read
end it holds. The structures follow ``<sys/proc_info.h>``.
"""

from __future__ import annotations

import ctypes
import functools
import os
import sys
import time
from typing import Any

_PROC_PIDLISTFDS = 1
_PROC_PIDFDPIPEINFO = 6
_PROX_FDTYPE_PIPE = 6
# Room for the processes and descriptors opened between the call that counts them and the
# call that lists them.
_SLACK = 64


class _ProcFdInfo(ctypes.Structure):
    _fields_ = (("proc_fd", ctypes.c_int32), ("proc_fdtype", ctypes.c_uint32))


class _ProcFileInfo(ctypes.Structure):
    _fields_ = (
        ("fi_openflags", ctypes.c_uint32),
        ("fi_status", ctypes.c_uint32),
        ("fi_offset", ctypes.c_int64),
        ("fi_type", ctypes.c_int32),
        ("fi_guardflags", ctypes.c_uint32),
    )


class _VinfoStat(ctypes.Structure):
    _fields_ = (
        ("vst_dev", ctypes.c_uint32),
        ("vst_mode", ctypes.c_uint16),
        ("vst_nlink", ctypes.c_uint16),
        ("vst_ino", ctypes.c_uint64),
        ("vst_uid", ctypes.c_uint32),
        ("vst_gid", ctypes.c_uint32),
        ("vst_atime", ctypes.c_int64),
        ("vst_atimensec", ctypes.c_int64),
        ("vst_mtime", ctypes.c_int64),
        ("vst_mtimensec", ctypes.c_int64),
        ("vst_ctime", ctypes.c_int64),
        ("vst_ctimensec", ctypes.c_int64),
        ("vst_birthtime", ctypes.c_int64),
        ("vst_birthtimensec", ctypes.c_int64),
        ("vst_size", ctypes.c_int64),
        ("vst_blocks", ctypes.c_int64),
        ("vst_blksize", ctypes.c_int32),
        ("vst_flags", ctypes.c_uint32),
        ("vst_gen", ctypes.c_uint32),
        ("vst_rdev", ctypes.c_uint32),
        ("vst_qspare", ctypes.c_int64 * 2),
    )


class _PipeInfo(ctypes.Structure):
    _fields_ = (
        ("pipe_stat", _VinfoStat),
        ("pipe_handle", ctypes.c_uint64),
        ("pipe_peerhandle", ctypes.c_uint64),
        ("pipe_status", ctypes.c_int32),
        ("rfu_1", ctypes.c_int32),
    )


class _PipeFdInfo(ctypes.Structure):
    _fields_ = (("pfi", _ProcFileInfo), ("pipeinfo", _PipeInfo))


def own_pipe_handles(fds: list[int], lib: Any = None) -> set[int]:
    """The handles of both ends of each pipe that this process holds as one of ``fds``.

    Empty where there is no libproc, or for a descriptor that is not a pipe.
    """
    lib = _libproc() if lib is None else lib
    if lib is None:
        return set()
    handles: set[int] = set()
    for fd in fds:
        ends = _pipe_ends(lib, os.getpid(), fd)
        if ends is not None:
            handles.update(ends)
    return handles


def pipe_holders(handles: set[int], ends: float, lib: Any = None) -> list[int]:
    """The pid of every process but this one that holds an end of a pipe in ``handles``.

    The search ends at ``ends`` (a ``time.monotonic()`` value) with the holders it has found.
    A process that has exited, or that is not this user's, is passed over.
    """
    lib = _libproc() if lib is None else lib
    if lib is None or not handles:
        return []
    me = os.getpid()
    holders = []
    for pid in _all_pids(lib):
        if time.monotonic() >= ends:
            break
        if pid != me and _holds(lib, pid, handles, ends):
            holders.append(pid)
    return holders


def _holds(lib: Any, pid: int, handles: set[int], ends: float) -> bool:
    for fd in _pipe_fds(lib, pid):
        if time.monotonic() >= ends:
            return False
        pipe = _pipe_ends(lib, pid, fd)
        if pipe is not None and pipe[0] in handles:
            return True
    return False


def _all_pids(lib: Any) -> list[int]:
    """Every process that libproc lists."""
    count = lib.proc_listallpids(None, 0)
    if count <= 0:
        return []
    pids = (ctypes.c_int * (count + _SLACK))()
    listed = lib.proc_listallpids(pids, ctypes.sizeof(pids))
    return [pid for pid in pids[: max(listed, 0)] if pid > 0]


def _pipe_fds(lib: Any, pid: int) -> list[int]:
    """The file descriptors of ``pid`` that are pipes; none once it has gone or is not ours."""
    size = lib.proc_pidinfo(pid, _PROC_PIDLISTFDS, 0, None, 0)
    if size <= 0:
        return []
    fds = (_ProcFdInfo * (size // ctypes.sizeof(_ProcFdInfo) + _SLACK))()
    filled = lib.proc_pidinfo(pid, _PROC_PIDLISTFDS, 0, fds, ctypes.sizeof(fds))
    if filled <= 0:
        return []
    listed = fds[: filled // ctypes.sizeof(_ProcFdInfo)]
    return [fd.proc_fd for fd in listed if fd.proc_fdtype == _PROX_FDTYPE_PIPE]


def _pipe_ends(lib: Any, pid: int, fd: int) -> tuple[int, int] | None:
    """The handles of the end of the pipe ``pid`` holds as ``fd``, and of its peer."""
    info = _PipeFdInfo()
    filled = lib.proc_pidfdinfo(
        pid, fd, _PROC_PIDFDPIPEINFO, ctypes.addressof(info), ctypes.sizeof(info)
    )
    if filled != ctypes.sizeof(info):
        return None
    return info.pipeinfo.pipe_handle, info.pipeinfo.pipe_peerhandle


@functools.cache
def _libproc() -> Any:
    """macOS's libproc, typed for the functions above; None elsewhere or when it cannot load."""
    return _load_libproc() if sys.platform == "darwin" else None


def _load_libproc(path: str = "/usr/lib/libproc.dylib") -> Any:
    """libproc at ``path``, typed for the functions above; None when it cannot load."""
    try:
        lib = ctypes.CDLL(path, use_errno=True)
    except OSError:
        return None
    lib.proc_listallpids.argtypes = (ctypes.c_void_p, ctypes.c_int)
    lib.proc_listallpids.restype = ctypes.c_int
    lib.proc_pidinfo.argtypes = (
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_uint64,
        ctypes.c_void_p,
        ctypes.c_int,
    )
    lib.proc_pidinfo.restype = ctypes.c_int
    lib.proc_pidfdinfo.argtypes = (
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_int,
    )
    lib.proc_pidfdinfo.restype = ctypes.c_int
    return lib
