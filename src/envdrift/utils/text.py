"""Text helpers shared across envdrift."""

from __future__ import annotations

import re

# CSI escape sequences (colors, styles, cursor control). Go CLIs that log
# through zerolog's console writer, such as gitleaks and Infisical, emit them
# even when stderr is a pipe.
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


def strip_ansi(text: str) -> str:
    """Return ``text`` without ANSI escape sequences.

    Tool output surfaced as an error message ends up in ``--json`` and SARIF
    documents, which must stay free of terminal escapes.
    """
    return _ANSI_ESCAPE_RE.sub("", text)
