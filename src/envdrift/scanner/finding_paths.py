"""One display form for the file paths in scan findings (#855).

Scanners report a file in the form their scan path gave them. The native
scanner resolves a directory it walks, gitleaks and Infisical keep the path
guard passed (relative or absolute), gitleaks history findings hang off the
absolute repository root, and kingfisher and git-secrets resolve every path.
One report used to name one file in several ways. The scan engine passes every
finding through :class:`FindingPathDisplay` once, after its filters, so dedup
and every output see one form: relative to the cwd when the file is under it,
absolute otherwise. The filters match path-based ignores against the names
:meth:`FindingPathDisplay.forms` gives a file, so a pattern that matches the
path guard shows suppresses the file whichever scanner reported it, and a
relative pattern never matches a file under the cwd through the directories
above the cwd (#859).
"""

from __future__ import annotations

import os
import re
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING

from envdrift.scanner.ignores import PathForms

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from envdrift.scanner.base import ScanFinding


def _resolved(path: Path) -> Path | None:
    """``path`` with its symlinks resolved, or ``None`` when that fails."""
    try:
        return path.resolve()
    except (OSError, RuntimeError):  # RuntimeError: a symlink loop before Python 3.13
        return None


def _absolute(path: Path, cwd: Path) -> Path:
    """``path`` made absolute against ``cwd``, with ``.`` and ``..`` collapsed.

    Lexical, so symlinks keep the names they were reached by, except where
    that would name another file: on POSIX ``..`` after a symlink names the
    link target's parent, so ``linkproj/../other`` is not ``other``. When the
    lexical form resolves elsewhere than the path itself, the part up to the
    last ``..`` is resolved instead. Windows collapses ``..`` lexically
    itself, so there both forms resolve alike and the lexical one is kept.
    """
    joined = cwd / path
    lexical = Path(os.path.normpath(joined))
    if os.pardir not in joined.parts:
        return lexical
    real = _resolved(joined)
    if real is None or _resolved(lexical) == real:
        return lexical
    parts = joined.parts
    last = len(parts) - parts[::-1].index(os.pardir)
    prefix = _resolved(Path(*parts[:last]))
    return lexical if prefix is None else prefix.joinpath(*parts[last:])


def _rooted(path: Path) -> tuple[Path, ...]:
    """``path``, and a relative ``path`` also rooted (``tests/x`` -> ``/tests/x``)."""
    return (path,) if path.is_absolute() else (path, Path(os.sep) / path)


def _absolute_names(absolute: Path, reported: Path | None, real: Path | None) -> list[Path]:
    """The names an absolute pattern is matched against (see :meth:`FindingPathDisplay.forms`)."""
    names = [absolute]
    if reported is not None and reported.is_absolute():
        names.append(reported)
    if real is not None:
        names.append(real)
    return names


def _unique(names: Iterable[Path]) -> tuple[Path, ...]:
    """``names`` without repeats, in order."""
    return tuple(dict.fromkeys(names))


def _below(path: Path, base: Path) -> Path | None:
    """``path`` relative to ``base``, or ``None`` when it is not below it."""
    try:
        return path.relative_to(base)
    except ValueError:
        return None


def _rename_in(text: str, old: Path, new: Path) -> str:
    """``text`` with the path ``old`` named ``new`` wherever it stands alone.

    A path that is only the start of a longer name (``a.env`` in ``a.env.bak``)
    or the end of a longer path (``a.env`` in ``/x/a.env``) is left as it is.
    """
    pattern = rf"(?<![\w./\\-]){re.escape(str(old))}(?![\w/\\-]|\.\w)"
    return re.sub(pattern, lambda _match: str(new), text)


def display_path(path: Path, cwd: Path | None = None) -> Path:
    """``path`` relative to ``cwd`` when it is under it, absolute otherwise.

    Lexical: ``..`` components are collapsed, but symlinks are not resolved,
    so a file reached through a symlink keeps the name it was reached by (a
    ``..`` after a symlink is resolved instead, see :func:`_absolute`). On
    Windows a path on another drive than ``cwd`` has no relative form
    (``os.path.relpath`` raises ``ValueError``) and stays absolute.

    Args:
        path: A path relative to ``cwd``, or an absolute one.
        cwd: The directory paths are shown from. Defaults to the current one.

    Returns:
        The path to show.
    """
    base = Path.cwd() if cwd is None else cwd
    absolute = _absolute(path, base)
    try:
        relative = Path(os.path.relpath(absolute, base))
    except ValueError:
        return absolute
    return absolute if relative.parts[:1] == (os.pardir,) else relative


class FindingPathDisplay:
    """Rewrites the finding paths of one scan into their display form.

    A scanner that resolves symlinks reports a file below a symlinked scan
    path by where it really is. Such a path is first moved back below the
    scan path the caller gave, so the file is shown under the name the caller
    used, whichever scanner reported it (#853). :func:`display_path` then
    gives the form to show.
    """

    def __init__(
        self,
        scan_paths: list[Path],
        cwd: Path | None = None,
        aliases: Mapping[Path, Path] | None = None,
    ) -> None:
        """Prepare the rewrite for one scan.

        Args:
            scan_paths: The paths the scan was given.
            cwd: The directory paths are shown from. Defaults to the current one.
            aliases: Maps a directory of copies, resolved, to the absolute
                directory they copy: a file below the first stands for the
                file at the same path below the second. ``guard --staged``
                scans copies of the staged files in a temporary directory laid
                out like the repository: path-based ignores match the names of
                the staged file, never of its copy.
        """
        self._cwd = Path.cwd() if cwd is None else cwd
        self._real_cwd = _resolved(self._cwd) or self._cwd
        self._aliases = dict(aliases or {})
        self._scan_paths = [self._absolute(path) for path in scan_paths]
        # (real location, given path) for each scan path reached through a
        # symlink, deepest real location first so the closest one wins.
        linked = []
        for given in self._scan_paths:
            real = _resolved(given)
            if real is not None and real != given:
                linked.append((real, given))
        self._linked = sorted(linked, key=lambda pair: len(pair[0].parts), reverse=True)
        self._real_dirs: dict[Path, Path | None] = {}
        self._shown: dict[Path, Path] = {}
        self._forms: dict[Path, PathForms] = {}
        self._located: dict[Path, Path] = {}

    def _absolute(self, path: Path) -> Path:
        return _absolute(path, self._cwd)

    def path(self, path: Path) -> Path:
        """The display form of the finding path ``path``."""
        shown = self._shown.get(path)
        if shown is None:
            absolute = self._absolute(path)
            if self._linked and not any(absolute.is_relative_to(p) for p in self._scan_paths):
                absolute = self._below_given_path(absolute)
            shown = self._shown[path] = display_path(absolute, self._cwd)
        return shown

    def location(self, path: Path) -> Path:
        """Where the file at finding path ``path`` really is, with every symlink resolved.

        Two names of one file have one location: a directory scanned both directly and
        through a symlink to it (#861), or a file and a symlink to it. The scan engine
        deduplicates on it, so such a file is one finding. A path that cannot be resolved is
        located by its absolute shown path.
        """
        located = self._located.get(path)
        if located is None:
            absolute = self._absolute(self.path(path))
            resolved = _resolved(absolute)
            located = self._located[path] = absolute if resolved is None else resolved
        return located

    def is_real_name(self, path: Path) -> bool:
        """Whether the finding path ``path`` is the name the file's real location is shown under.

        False for a name reached through a symlink inside the tree, such as a link to a file or a
        second symlinked scan path. Of two findings that are otherwise equal, the one reported
        under the real name is kept. Below a symlinked scan path every name is shown under that
        path, so the file's real location is compared by the name it is shown under, which is
        the name a scanner that resolves symlinks reports it by. Of two links to one directory
        the first scan path given is the one that names the file.
        """
        return self.path(self.location(path)) == self.path(path)

    def forms(self, path: Path) -> PathForms:
        """The names of the file at finding path ``path`` that path-based ignores match.

        For a file under the cwd a relative pattern sees only names below the
        cwd: the path guard shows, that path rooted at the cwd
        (``/tests/x.py``, so ``**/tests/**`` matches a top-level ``tests``
        directory), and the same two for its real location with every symlink
        resolved when that is under the cwd too. The directories above the
        cwd never take part, so ``**/build/**`` does not hide a checkout that
        lives under ``build/`` (#859). A file is under the cwd when the path
        guard shows is, when that path runs through another spelling of the
        cwd (``"$PWD/proj"`` where ``/tmp`` links to ``/private/tmp`` is shown
        absolute), or when its real location is. An absolute pattern sees the
        absolute names: the cwd joined with the shown path, the path as
        reported when it is absolute, and the real location. So for a file
        under the cwd the verdict of a relative pattern is the same whichever
        scanner reported the file and however the scan path was spelled:
        ``guard``, ``guard .``, ``guard proj``, ``guard "$PWD/proj"``, a
        symlinked path or its target.

        For a file outside the cwd a relative pattern sees the reported path,
        the shown path and the real location, with their trailing parts:
        ``../config/*`` matches what a scanner reports for such a file under
        ``--pr-base`` run from a subdirectory. A pattern without a separator
        (``build``) is the exception: it sees the path below each scan path the
        file sits under, one view per scan path, or the file's own name when it
        is no more than a scan path or below none. The directories above a
        checkout never name it, and it is hidden only if the pattern matches in
        every view, so adding a scan path never hides what another one reports
        (#865). A copy (see ``aliases``) of a file outside the cwd is named
        by its path below the directory copied, as the copy was, so the
        directories above the repository never name a staged file.
        """
        forms = self._forms.get(path)
        if forms is None:
            forms = self._forms[path] = self._names(path)
        return forms

    def _names(self, path: Path) -> PathForms:
        """The names :meth:`forms` gives the file at finding path ``path``."""
        copied = self._copied(path)
        reported, shown = self._reported_and_shown(path, copied)
        absolute = self._cwd / shown
        real = _resolved(absolute)
        absolutes = _absolute_names(absolute, reported, real)
        below = self._names_below_cwd(shown, real)
        if below:  # under the cwd, where it was found or where it really is
            return PathForms(_unique(below), _unique(absolutes))
        if copied is not None:  # a staged file outside the cwd: its path in the repository
            return PathForms(_unique(_rooted(copied[1])), _unique(absolutes))
        outside = [name for name in (reported, shown, real) if name is not None]
        # A pattern without a separator sees what is below a scan path, not the directories
        # above it, so a checkout that merely lives under `build/` is not hidden by `build`.
        bare = self._views_below_scan_paths(absolute, real, Path(shown.name))
        return PathForms(_unique(outside), _unique(absolutes), bare)

    def _reported_and_shown(
        self, path: Path, copied: tuple[Path, Path] | None
    ) -> tuple[Path | None, Path]:
        """The path as a scanner reported it, and the path to show, for finding path ``path``.

        A scanned copy has no reported name: it is named by the file it copies, never by itself.
        """
        if copied is None:
            return path, self.path(path)
        return None, display_path(copied[0], self._cwd)

    def _names_below_cwd(self, shown: Path, real: Path | None) -> list[Path]:
        """The names below the cwd a relative pattern is matched against (see :meth:`forms`).

        Empty for a file outside the cwd. Each name is also rooted, so ``**/tests/**`` matches a
        top-level ``tests`` directory.
        """
        real_below = None if real is None else _below(real, self._real_cwd)
        below = [name for name in (self._below_cwd(shown), real_below) if name is not None]
        return [form for name in below for form in _rooted(name)]

    def _views_below_scan_paths(
        self, absolute: Path, real: Path | None, own_name: Path
    ) -> tuple[tuple[Path, ...], ...]:
        """The names the file has below each scan path it sits under, one view per scan path.

        A file below no scan path has its own name only.
        """
        views = (self._view_below(given, absolute, real, own_name) for given in self._scan_paths)
        return tuple(dict.fromkeys(view for view in views if view is not None)) or ((own_name,),)

    def _view_below(
        self, given: Path, absolute: Path, real: Path | None, own_name: Path
    ) -> tuple[Path, ...] | None:
        """The names the file has below the scan path ``given``, or ``None`` when it is not below.

        The file is seen where it was found and where it really is. A scan path that is the file
        itself gives its own name only.
        """
        candidates = ((absolute, given), (real, self._real_dir(given)))
        below = [
            found
            for name, base in candidates
            if name is not None and base is not None and (found := _below(name, base)) is not None
        ]
        if not below:
            return None
        return _unique(name for name in below if name.parts) or (own_name,)

    def _copied(self, path: Path) -> tuple[Path, Path] | None:
        """The file a scanned copy at ``path`` stands for, and its path below the directory copied.

        ``None`` for a path that is not below a directory of copies.
        """
        if not self._aliases:
            return None
        real = _resolved(self._absolute(path))
        if real is None:
            return None
        for copies, originals in self._aliases.items():
            below = _below(real, copies)
            if below is not None:
                return originals / below, below
        return None

    def _below_cwd(self, shown: Path) -> Path | None:
        """The shown path ``shown`` relative to the cwd, or ``None`` when it is not below it.

        An absolute path that runs through another spelling of the cwd, such as
        ``"$PWD/proj"`` where ``/tmp`` links to ``/private/tmp`` (shown
        absolute, see :func:`display_path`), is below the directory in it that
        resolves to the cwd.
        """
        if not shown.is_absolute():
            return shown
        for directory in reversed(shown.parents):
            if self._real_dir(directory) == self._real_cwd:
                return shown.relative_to(directory)
        return None

    def _real_dir(self, directory: Path) -> Path | None:
        """``directory`` with its symlinks resolved (cached), or ``None`` when that fails."""
        if directory not in self._real_dirs:
            self._real_dirs[directory] = _resolved(directory)
        return self._real_dirs[directory]

    def _below_given_path(self, absolute: Path) -> Path:
        """``absolute`` moved below the symlinked scan path it really sits below.

        Only the directory is resolved: a file that is itself a symlink stays
        where it was found, not where it points.
        """
        real_dir = self._real_dir(absolute.parent)
        if real_dir is None:
            return absolute
        real = real_dir / absolute.name
        for real_scan_path, given in self._linked:
            if real.is_relative_to(real_scan_path):
                return given / real.relative_to(real_scan_path)
        return absolute

    def finding(self, finding: ScanFinding) -> ScanFinding:
        """``finding`` with its path, and that path in its description, in display form."""
        shown = self.path(finding.file_path)
        if shown == finding.file_path:
            return finding
        # Scanners name the file in their message too (native: "Run 'envdrift
        # encrypt <path>'"), so the message names it the same way.
        description = _rename_in(finding.description, finding.file_path, shown)
        return replace(finding, file_path=shown, description=description)

    def findings(self, findings: list[ScanFinding]) -> list[ScanFinding]:
        """Every finding of ``findings`` in display form, in order."""
        return [self.finding(finding) for finding in findings]
