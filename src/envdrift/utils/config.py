"""Configuration-related helpers."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


def normalize_max_workers(value: Any, *, warn: Callable[[str], None] | None = None) -> int | None:
    """Normalize max_workers values, optionally emitting warnings."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        if warn:
            warn("Invalid max_workers value; using default thread count")
        return None
    if value < 1:
        if warn:
            warn("max_workers must be >= 1; using default thread count")
        return None
    return value
