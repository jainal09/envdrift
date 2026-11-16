"""The files that history findings were found in, as they were in their commits (#1014).

A history scan reports a secret at the line it had in an old commit. Today's file can hold
anything at that line, such as an encrypted value or an ignore comment, so the engine's filters
judge such a finding by its file in that commit, and keep it when git cannot show that file.
"""

from __future__ import annotations

import os
import re
from collections import OrderedDict
from collections.abc import Iterable
from pathlib import Path, PurePath
from typing import NamedTuple

from envdrift.scanner.base import ScanFinding
from envdrift.utils.git import file_at_commit, get_git_root

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

    def __init__(self, *, history: bool, scanned: Iterable[Path] = ()) -> None:
        """Judge findings by their commits only when ``history`` is True, a history scan.

        ``scanned`` are the paths the scan was given. A history scan reads the history of the
        repository each one is in, so a commit is read from that repository, never from one
        found below it on disk: a clone or a worktree there holds other files at the same path.
        """
        self._history = history
        self._scanned = tuple(scanned)
        self._repositories: frozenset[Path] | None = None
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
        text = self._read(Path(file_path), commit)
        read = self._files[key] = _CommittedFile(text, _lines(text or ""))
        self._size += len(text or "")
        while self._size > _CACHED_CHARACTERS and len(self._files) > 1:
            _, oldest = self._files.popitem(last=False)
            self._size -= len(oldest.text or "")
        return read

    def _read(self, file_path: Path, commit: str) -> str | None:
        if not _COMMIT_ID.fullmatch(commit):
            return None
        located = self._in_scanned_repository(file_path)
        return None if located is None else file_at_commit(*located, commit)

    def _in_scanned_repository(self, file_path: Path) -> tuple[Path, PurePath] | None:
        """The scanned repository holding ``file_path``, and the file's path in it.

        None when no scanned repository holds it, or more than one does: which history the
        finding came from cannot be told then.
        """
        # normpath folds "a/../b" without resolving a link, as Path.resolve() would: the path
        # below the repository is the one the commit held, links made since or not.
        path = Path(os.path.normpath(file_path.absolute()))
        holders = [
            (root, below)
            for root in self._scanned_repositories()
            if (below := _below(path, root)) is not None
        ]
        return holders[0] if len(holders) == 1 else None

    def _scanned_repositories(self) -> frozenset[Path]:
        """The roots of the repositories the scanned paths are in, as git names them."""
        if self._repositories is None:
            folders = {path if path.is_dir() else path.parent for path in self._scanned}
            roots = (get_git_root(folder) for folder in folders)
            self._repositories = frozenset(root for root in roots if root is not None)
        return self._repositories


def _below(path: Path, root: Path) -> PurePath | None:
    """``path`` relative to ``root``; None when it is not below it."""
    try:
        return path.relative_to(root)
    except ValueError:
        return None


def _lines(text: str) -> list[str]:
    """The lines of ``text`` as git counts them, at ``\\n`` only.

    A history finding names the line its commit holds it on, so a lone ``\\r`` stays in its
    line here, where ``split_lines`` would break it. The ``\\r`` of a ``\\r\\n`` is no part of
    the line it ends; a final ``\\r`` with no ``\\n`` after it ends no line, and stays. As with
    ``split_lines``, a line break at the end starts no empty line.
    """
    *ended, last = text.split("\n")
    lines = [line.removesuffix("\r") for line in ended]
    return [*lines, last] if last else lines
