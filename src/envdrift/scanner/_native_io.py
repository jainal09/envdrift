"""Bounded file reads for the built-in scanner."""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Protect default scans from large untracked logs/datasets that Git correctly
# reports as commit candidates. Dedicated scanners can handle larger artifacts.
NATIVE_MAX_SCAN_BYTES = 10 * 1024 * 1024


def read_raw_scannable_bytes(file_path: Path) -> bytes | None:
    """Return bounded file bytes, or ``None`` when unreadable/oversized."""
    try:
        size = file_path.stat().st_size
        if size > NATIVE_MAX_SCAN_BYTES:
            logger.debug(
                "Skipping native scan of oversized file %s (%d bytes; limit %d)",
                file_path,
                size,
                NATIVE_MAX_SCAN_BYTES,
            )
            return None
        with file_path.open("rb") as stream:
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
