"""One display form for the file paths in scan findings (#855).

Scanners report a file in the form their scan path gave them. The native
scanner resolves a directory it walks, gitleaks and Infisical keep the path
guard passed (relative or absolute), gitleaks history findings hang off the
absolute repository root, and kingfisher and git-secrets resolve every path.
One report used to name one file in several ways. The scan engine passes every
finding through :class:`FindingPathDisplay` once, after its filters, so dedup
and every output see one form: relative to the cwd when the file is under it,
absolute otherwise. The filters match path-based ignores against every name
:meth:`FindingPathDisplay.forms` gives a file, so a pattern that matches the
path guard shows suppresses the file whichever scanner reported it.
"""

from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
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

    def __init__(self, scan_paths: list[Path], cwd: Path | None = None) -> None:
        """Prepare the rewrite for one scan.

        Args:
            scan_paths: The paths the scan was given.
            cwd: The directory paths are shown from. Defaults to the current one.
        """
        self._cwd = Path.cwd() if cwd is None else cwd
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
        self._forms: dict[Path, tuple[Path, ...]] = {}

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

    def forms(self, path: Path) -> tuple[Path, ...]:
        """Every name of the file at finding path ``path`` that path-based ignores match.

        The path as the scanner reported it, the path guard shows, and the
        path shown for its real location with every symlink resolved. A
        pattern that matches any of them suppresses the file, so the verdict is
        the same whichever scanner reported it and however the scan path was
        spelled: ``guard`` and ``guard .``, a symlinked path or its target.

        A shown path relative to the cwd is also matched rooted at the cwd
        (``/tests/x.py``), so ``**/tests/**`` matches a top-level ``tests``
        directory as it did the absolute paths some scanners report, without
        matching a directory above the cwd that the absolute path names.
        """
        forms = self._forms.get(path)
        if forms is None:
            shown = self.path(path)
            real = _resolved(self._absolute(shown))
            candidates = [path, *_rooted(shown)]
            if real is not None:
                candidates.extend(_rooted(display_path(real, self._cwd)))
            forms = self._forms[path] = tuple(dict.fromkeys(candidates))
        return forms

    def _below_given_path(self, absolute: Path) -> Path:
        """``absolute`` moved below the symlinked scan path it really sits below.

        Only the directory is resolved: a file that is itself a symlink stays
        where it was found, not where it points.
        """
        if absolute.parent not in self._real_dirs:
            self._real_dirs[absolute.parent] = _resolved(absolute.parent)
        real_dir = self._real_dirs[absolute.parent]
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
        description = finding.description.replace(str(finding.file_path), str(shown))
        return replace(finding, file_path=shown, description=description)

    def findings(self, findings: list[ScanFinding]) -> list[ScanFinding]:
        """Every finding of ``findings`` in display form, in order."""
        return [self.finding(finding) for finding in findings]
