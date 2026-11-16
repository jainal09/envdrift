"""The files that history findings were found in, as they were in their commits (#1014).

A history scan reports a secret at the line it had in an old commit. Today's file can hold
anything at that line, such as an encrypted value or an ignore comment, so the engine's filters
judge such a finding by its file in that commit, and keep it when git cannot show that file.
"""

from __future__ import annotations

import re
from collections import OrderedDict
from pathlib import Path
from typing import NamedTuple

from envdrift.scanner.base import ScanFinding
from envdrift.utils.git import file_at_commit
from envdrift.utils.text import split_lines

# A commit as scanners report it. Anything else is never handed to git, which could read it as
# an option or another revision; the finding is kept instead.
_COMMIT_ID = re.compile(r"[0-9a-fA-F]{4,64}")
# How much of the files read is kept in memory, in characters. Each (file, commit) pair is
# read from git once while they fit, far more than the env files history findings point at;
# past that, the pairs read longest ago are let go, so that the many revisions of large files a
# long history holds are not all kept until the scan ends.
_CACHED_CHARACTERS = 16 * 1024 * 1024


class _CommittedFile(NamedTuple):
    text: str | None
    lines: list[str]


class CommittedFiles:
    """Reads the files of the commits that a scan's history findings point at."""

    def __init__(self, *, history: bool) -> None:
        """Judge findings by their commits only when ``history`` is True, a history scan."""
        self._history = history
        self._files: OrderedDict[tuple[str, str], _CommittedFile] = OrderedDict()
        self._size = 0

    def commit_of(self, finding: ScanFinding) -> str | None:
        """The commit a history scan found ``finding`` in; None for a finding in today's files.

        Only a history scan's findings are judged by their commit: a scanner may name a commit
        for a finding in the files on disk too.
        """
        return finding.commit_sha if self._history and finding.commit_sha else None

    def text(self, file_path: Path | str, commit: str) -> str | None:
        """The text of ``file_path`` as it was in ``commit``; None when git cannot show it."""
        return self._file(str(file_path), commit).text

    def line(self, file_path: Path | str, commit: str, line_number: int) -> str:
        """Line ``line_number`` (1-based) of ``file_path`` in ``commit``; "" when there is none."""
        lines = self._file(str(file_path), commit).lines
        return lines[line_number - 1] if 1 <= line_number <= len(lines) else ""

    def _file(self, file_path: str, commit: str) -> _CommittedFile:
        key = (file_path, commit)
        if key in self._files:
            self._files.move_to_end(key)
            return self._files[key]
        text = file_at_commit(Path(file_path), commit) if _COMMIT_ID.fullmatch(commit) else None
        read = self._files[key] = _CommittedFile(text, split_lines(text or ""))
        self._size += len(text or "")
        while self._size > _CACHED_CHARACTERS and len(self._files) > 1:
            _, oldest = self._files.popitem(last=False)
            self._size -= len(oldest.text or "")
        return read
