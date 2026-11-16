"""The files that history findings were found in, as they were in their commits (#1014).

A history scan reports a secret at the line it had in an old commit. Today's file can hold
anything at that line, such as an encrypted value or an ignore comment, so the engine's filters
judge such a finding by its file in that commit, and keep it when git cannot show that file.
"""

from __future__ import annotations

import re
from pathlib import Path

from envdrift.scanner.base import ScanFinding
from envdrift.utils.git import get_file_from_git
from envdrift.utils.text import split_lines

# A commit as scanners report it. Anything else is never handed to git, which could read it as
# an option or another revision; the finding is kept instead.
_COMMIT_ID = re.compile(r"[0-9a-fA-F]{4,64}")


class CommittedFiles:
    """Reads, once each, the files of the commits that a scan's history findings point at."""

    def __init__(self, *, history: bool) -> None:
        """Judge findings by their commits only when ``history`` is True, a history scan."""
        self._history = history
        self._texts: dict[tuple[str, str], str | None] = {}
        self._lines: dict[tuple[str, str], list[str]] = {}

    def commit_of(self, finding: ScanFinding) -> str | None:
        """The commit a history scan found ``finding`` in; None for a finding in today's files.

        Only a history scan's findings are judged by their commit: a scanner may name a commit
        for a finding in the files on disk too.
        """
        return finding.commit_sha if self._history and finding.commit_sha else None

    def text(self, file_path: Path | str, commit: str) -> str | None:
        """The text of ``file_path`` as it was in ``commit``; None when git cannot show it."""
        key = (str(file_path), commit)
        if key not in self._texts:
            readable = _COMMIT_ID.fullmatch(commit) is not None
            self._texts[key] = get_file_from_git(Path(file_path), commit) if readable else None
        return self._texts[key]

    def line(self, file_path: Path | str, commit: str, line_number: int) -> str:
        """Line ``line_number`` (1-based) of ``file_path`` in ``commit``; "" when there is none."""
        key = (str(file_path), commit)
        if key not in self._lines:
            self._lines[key] = split_lines(self.text(file_path, commit) or "")
        lines = self._lines[key]
        return lines[line_number - 1] if 1 <= line_number <= len(lines) else ""
