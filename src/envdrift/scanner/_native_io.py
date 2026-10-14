"""Bounded file reads for the built-in scanner."""

from __future__ import annotations

import logging
import os
import stat
from pathlib import Path

logger = logging.getLogger(__name__)

# Protect default scans from large untracked logs/datasets that Git correctly
# reports as commit candidates. Dedicated scanners can handle larger artifacts.
NATIVE_MAX_SCAN_BYTES = 10 * 1024 * 1024


def read_raw_scannable_bytes(file_path: Path) -> bytes | None:
    """Return bounded file bytes, or ``None`` when unreadable, oversized or not a regular file."""
    try:
        if not stat.S_ISREG(file_path.stat().st_mode):
            # A named pipe has no size, and opening one for reading blocks until another process
            # opens the other end, which hung the whole scan (#863). A socket or a device holds
            # no file to scan either, and none is opened.
            logger.debug("Skipping native scan of non-regular file %s", file_path)
            return None
        # The file can be swapped for a named pipe after the stat above, so the open must not
        # wait for a writer, and what was opened is checked again on its descriptor.
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
        descriptor = os.open(file_path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                logger.debug("Skipping native scan of non-regular file %s", file_path)
                return None
            if info.st_size > NATIVE_MAX_SCAN_BYTES:
                logger.debug(
                    "Skipping native scan of oversized file %s (%d bytes; limit %d)",
                    file_path,
                    info.st_size,
                    NATIVE_MAX_SCAN_BYTES,
                )
                return None
            raw = stream.read(NATIVE_MAX_SCAN_BYTES + 1)
    except OSError:
        return None
    if len(raw) <= NATIVE_MAX_SCAN_BYTES:
        return raw
    logger.debug(
        "Skipping native scan of file that grew beyond %d bytes: %s",
        NATIVE_MAX_SCAN_BYTES,
        file_path,
    )
    return None
