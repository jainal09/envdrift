"""The files that history findings were found in, as they were in their commits (#1014).

A history scan reports a secret at the line it had in an old commit. Today's file can hold
anything at that line, such as an encrypted value or an ignore comment, so the engine's filters
judge such a finding by its file in that commit, and keep it when git cannot show that file.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

from envdrift.scanner.base import ScanFinding
from envdrift.utils.git import file_at_commit
from envdrift.utils.text import split_lines

# A commit as scanners report it. Anything else is never handed to git, which could read it as
# an option or another revision; the finding is kept instead.
_COMMIT_ID = re.compile(r"[0-9a-fA-F]{4,64}")
# How many (file, commit) pairs are kept in memory, text and lines. A scanner reports the
# findings of one file in one commit together, so a few suffice, and the many revisions of
# large files that a long history holds are not all kept until the scan ends.
_CACHED_FILES = 16


class CommittedFiles:
    """Reads the files of the commits that a scan's history findings point at."""

    def __init__(self, *, history: bool) -> None:
        """Judge findings by their commits only when ``history`` is True, a history scan."""
        self._history = history
        self._text_of = lru_cache(maxsize=_CACHED_FILES)(self._read)
        self._lines_of = lru_cache(maxsize=_CACHED_FILES)(self._split)

    def commit_of(self, finding: ScanFinding) -> str | None:
        """The commit a history scan found ``finding`` in; None for a finding in today's files.

        Only a history scan's findings are judged by their commit: a scanner may name a commit
        for a finding in the files on disk too.
        """
        return finding.commit_sha if self._history and finding.commit_sha else None

    def text(self, file_path: Path | str, commit: str) -> str | None:
        """The text of ``file_path`` as it was in ``commit``; None when git cannot show it."""
        return self._text_of(str(file_path), commit)

    def line(self, file_path: Path | str, commit: str, line_number: int) -> str:
        """Line ``line_number`` (1-based) of ``file_path`` in ``commit``; "" when there is none."""
        lines = self._lines_of(str(file_path), commit)
        return lines[line_number - 1] if 1 <= line_number <= len(lines) else ""

    def _read(self, file_path: str, commit: str) -> str | None:
        if _COMMIT_ID.fullmatch(commit) is None:
            return None
        return file_at_commit(Path(file_path), commit)

    def _split(self, file_path: str, commit: str) -> list[str]:
        return split_lines(self.text(file_path, commit) or "")
