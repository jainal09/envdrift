"""Text helpers shared across envdrift."""

from __future__ import annotations

import re

# CSI escape sequences (colors, styles, cursor control). Go CLIs that log
# through zerolog's console writer, such as gitleaks and Infisical, emit them
# even when stderr is a pipe. Parameter bytes span the full 0x30-0x3F range
# (digits and ``:;<=>?``), so colon-form colors like ``\x1b[38:2::1:2:3m`` match.
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def strip_ansi(text: str) -> str:
    """Return ``text`` without ANSI escape sequences.

    Tool output surfaced as an error message ends up in ``--json`` and SARIF
    documents, which must stay free of terminal escapes.
    """
    return _ANSI_ESCAPE_RE.sub("", text)
