"""Text helpers shared across envdrift."""

from __future__ import annotations

import re

# CSI escape sequences (colors, styles, cursor control). Go CLIs that log
# through zerolog's console writer, such as gitleaks and Infisical, emit them
# even when stderr is a pipe. Parameter bytes span the full 0x30-0x3F range
# (digits and ``:;<=>?``), so colon-form colors like ``\x1b[38:2::1:2:3m`` match.
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")

# The line breaks the .env parser splits at (#486): a newline, as git, grep and the
# external scanners count lines, and a lone carriage return, a line break in old Mac
# files and to editors. str.splitlines() also breaks at \v, \f, \x1c-\x1e, \x85,
# U+2028 and U+2029 (#937).
_LINE_BREAK_RE = re.compile(r"\r\n|\r|\n")


def split_lines(text: str) -> list[str]:
    """Split ``text`` into lines at ``\\n``, ``\\r\\n`` and ``\\r`` only.

    ``str.splitlines()`` also breaks a line at a form feed, a vertical tab, or a Unicode
    line separator, where git and the external scanners see none. After one, a line
    number counted one way names another line counted the other (#937). A lone ``\\r``
    stays a line break, as it was: git and the scanners count only ``\\n``, so in a file
    with bare ``\\r`` line endings their line numbers stay apart from these. As with
    ``splitlines()``, a line break at the end starts no empty line.
    """
    lines = _LINE_BREAK_RE.split(text)
    if lines[-1] == "":
        lines.pop()
    return lines


def line_and_column(text: str, index: int) -> tuple[int, int]:
    """The 1-based line and column of ``text[index]``, its lines as :func:`split_lines` splits."""
    line, line_start = 1, 0
    for line_break in _LINE_BREAK_RE.finditer(text, 0, index):
        line += 1
        line_start = line_break.end()
    return line, index - line_start + 1


def strip_ansi(text: str) -> str:
    """Return ``text`` without ANSI escape sequences.

    Tool output surfaced as an error message ends up in ``--json`` and SARIF
    documents, which must stay free of terminal escapes.
    """
    return _ANSI_ESCAPE_RE.sub("", text)
