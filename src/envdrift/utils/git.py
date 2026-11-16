"""Git utilities for envdrift.

This module provides helpers for interacting with Git to support
smart encryption that avoids unnecessary re-encryption when content
is unchanged.
"""

from __future__ import annotations

import os
import subprocess  # nosec B404
from collections.abc import Iterable, Mapping
from pathlib import Path

from envdrift.utils.deadline import run_tool

# git exports these to its hooks (githooks(5)). In a linked worktree they are absolute, and
# ``git commit -a`` or ``git commit <path>`` points GIT_INDEX_FILE at the index it is about to
# commit. A git run for some other path inherits them, and reads the hook's repository, index or
# work tree instead of that path's, or writes there (#915, #916).
GIT_LOCATION_VARIABLES = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR")

# Every subprocess call in this module pins ``encoding="utf-8"`` with
# ``errors="surrogateescape"``: ``text=True`` alone decodes git's output with the
# platform locale codec — cp1252 on Windows, US-ASCII under LC_ALL=C — which
# mangles non-ASCII repo paths / file content or raises an uncaught
# ``UnicodeDecodeError`` (#453). Git emits UTF-8 on every platform, so pin the
# codec; ``surrogateescape`` (not ``replace``) round-trips raw non-UTF-8 filename
# bytes exactly, matching how the OS surfaces such paths to Python, instead of
# rewriting them and corrupting the returned path.


class GitError(Exception):
    """Error executing git command."""

    pass


class GitignoreOverrideError(OSError):
    """git still tracks a path after its ignore entry was added: a ``!`` rule re-includes it.

    An ``OSError``, so a caller that stops on an unwritable ``.gitignore``
    stops on this too instead of writing a file git would commit.
    """


def without_git_location(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """``environ`` (``os.environ`` when None) without the git location variables.

    It is the environment for a git, or a tool that runs git, that must find the repository of
    the path it is given.
    """
    source = os.environ if environ is None else environ
    return {key: value for key, value in source.items() if key not in GIT_LOCATION_VARIABLES}


def _hook_env(git_root: Path) -> dict[str, str] | None:
    """The environment for a git run in ``git_root`` that reads or writes its index.

    In a git hook the location variables name the hook's repository, and GIT_INDEX_FILE the
    index git is about to commit, which smart encryption restores an unchanged file into. They
    are kept (None: this process's environment) when they name ``git_root``'s repository, and
    dropped for any other one, a submodule say, where git would read or write the hook's
    repository instead (#919).

    A relative value, ``.git/index`` during a plain ``git commit``, means what it means to a git
    run here, not to one run in ``git_root``: when the variables are kept, the environment then
    holds their absolute paths.
    """
    exported = {name: os.environ[name] for name in GIT_LOCATION_VARIABLES if name in os.environ}
    if not exported:
        return None
    env = without_git_location()
    paths = _hook_paths(exported)
    if paths is None or not _paths_of(paths, git_root, env):
        return env
    return None if paths == exported else {**os.environ, **paths}


def _paths_of(paths: Mapping[str, str], git_root: Path, env: Mapping[str, str]) -> bool:
    """Whether the paths that a hook's location variables point at are ``git_root``'s.

    ``paths`` is by variable name, and ``env`` the environment without them.
    """
    dirs = _git_dirs(git_root, env)
    if dirs is None:
        return False
    git_dir, common_dir = dirs
    own = {"GIT_DIR": git_dir, "GIT_COMMON_DIR": common_dir, "GIT_WORK_TREE": git_root.resolve()}
    for name, path in paths.items():
        if name == "GIT_INDEX_FILE":
            if not _index_of(Path(path).resolve(), git_dir, named="GIT_DIR" in paths, env=env):
                return False
        elif Path(path).resolve() != own[name]:
            return False
    return True


def _hook_paths(exported: Mapping[str, str]) -> dict[str, str] | None:
    """The absolute paths that the location variables ``exported`` point at, if known.

    An absolute value is its own; for a relative one, git says (``_git_paths``).
    """
    if all(Path(value).is_absolute() for value in exported.values()):
        return dict(exported)
    return _git_paths(list(exported))


# The rev-parse options that print the path each location variable names, as git reads it.
_LOCATION_OPTIONS = {
    "GIT_DIR": ("--absolute-git-dir",),
    "GIT_WORK_TREE": ("--show-toplevel",),
    "GIT_INDEX_FILE": ("--git-path", "index"),
    "GIT_COMMON_DIR": ("--git-common-dir",),
}


def _git_paths(names: list[str]) -> dict[str, str] | None:
    """Where the location variables ``names`` point for a git run here, as absolute paths.

    git reads a relative GIT_DIR or GIT_WORK_TREE against the directory it runs in, but a
    relative GIT_INDEX_FILE against the top of the work tree, which it moves to first, from a
    subdirectory say. So git, run in this process's working directory and environment, says
    where they point, relative to that directory. None when it cannot.
    """
    try:
        cwd = Path.cwd()
        result = run_tool(
            ["git", "rev-parse", *(option for name in names for option in _LOCATION_OPTIONS[name])],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="surrogateescape",
            timeout=10,
        )
    except (subprocess.TimeoutExpired, OSError):  # OSError: no git, or the directory is gone
        return None
    lines = result.stdout.splitlines()
    if result.returncode != 0 or len(lines) != len(names):
        return None
    return {name: str(cwd / line) for name, line in zip(names, lines, strict=True)}


def _git_dirs(cwd: Path, env: Mapping[str, str]) -> tuple[Path, Path] | None:
    """The git directory and the common git directory of the repository at ``cwd``, if any."""
    try:
        result = run_tool(
            ["git", "rev-parse", "--absolute-git-dir", "--git-common-dir"],
            cwd=str(cwd),
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="surrogateescape",
            timeout=10,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    lines = result.stdout.splitlines()
    if result.returncode != 0 or len(lines) != 2:
        return None
    return Path(lines[0]).resolve(), (cwd / lines[1]).resolve()


def _index_of(index: Path, git_dir: Path, *, named: bool, env: Mapping[str, str]) -> bool:
    """Whether a hook's GIT_INDEX_FILE, ``index``, is an index of the repository at ``git_dir``.

    git keeps the index it commits from in the git directory: index.lock during ``git commit
    -a``, next-index-<pid>.lock during ``git commit <path>``. An index in another git directory,
    at any depth, is that repository's. One outside every git directory is an alternate index
    that the user set, which git exports as GIT_INDEX_FILE too: it is the hook's repository's,
    the one GIT_DIR names (``named``), or else the one the hook runs in, this process's working
    directory.
    """
    for directory in index.parents:
        if directory == git_dir:
            return True
        if _is_git_dir(directory):
            return False
    if named:
        return True
    try:
        hook_dirs = _git_dirs(Path.cwd(), env)
    except OSError:  # this process's working directory is gone
        return True
    # Run outside every repository, nothing ties the index to another one: git would use it
    return hook_dirs is None or hook_dirs[0] == git_dir


def _is_git_dir(path: Path) -> bool:
    """Whether ``path`` is a git directory: a repository's, or a linked worktree's."""
    return (path / "HEAD").is_file() and (
        (path / "objects").is_dir() or (path / "commondir").is_file()
    )


def is_git_repo(path: Path) -> bool:
    """
    Check if the given path is inside a git repository.

    Parameters:
        path: Path to check.

    Returns:
        True if path is inside a git repository, False otherwise.
    """
    try:
        result = run_tool(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=str(path if path.is_dir() else path.parent),
            env=without_git_location(),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="surrogateescape",
            timeout=10,
        )
        return result.returncode == 0 and result.stdout.strip() == "true"
    # OSError, not only FileNotFoundError (no git, or a missing directory): a path below a
    # regular file has a parent git cannot run in, and NotADirectoryError escaped.
    except (subprocess.TimeoutExpired, OSError):
        return False


def get_git_root(path: Path) -> Path | None:
    """
    Get the root directory of the git repository containing the given path.

    Parameters:
        path: Path inside the git repository.

    Returns:
        Path to the git root, or None if not in a git repository.
    """
    try:
        result = run_tool(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=str(path if path.is_dir() else path.parent),
            env=without_git_location(),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="surrogateescape",
            timeout=10,
        )
        if result.returncode == 0:
            return Path(result.stdout.strip())
        return None
    # OSError as in is_git_repo: for a path below a regular file, NotADirectoryError
    # escaped and crashed push before any environment ran.
    except (subprocess.TimeoutExpired, OSError):
        return None


def has_git_head(path: Path) -> bool:
    """Return whether the repository containing ``path`` has a commit at HEAD.

    An initialized repository with no commits is a valid work tree, but history
    scanners cannot produce a trustworthy verdict for it. Keep that state
    distinct from a repository with an empty *working tree*.
    """
    git_root = get_git_root(path)
    if git_root is None:
        return False

    try:
        result = run_tool(
            ["git", "rev-parse", "--verify", "HEAD^{commit}"],
            cwd=str(git_root),
            env=without_git_location(),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="surrogateescape",
            timeout=10,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def get_file_from_git(file_path: Path, ref: str = "HEAD") -> str | None:
    """
    Get the content of a file from a git ref (default: HEAD).

    Parameters:
        file_path: Absolute path to the file.
        ref: Git ref to get the file from (default: HEAD).

    Returns:
        The file content as a string, or None if the file doesn't exist in git.
    """
    git_root = get_git_root(file_path)
    if not git_root:
        return None

    try:
        # Get relative path from git root
        relative_path = file_path.resolve().relative_to(git_root)

        # git's ``<rev>:<path>`` revision syntax does NOT normalize backslashes,
        # so the path must use forward slashes (POSIX) even on Windows — matching
        # the ``.as_posix()`` usage elsewhere in this module (e.g. line 238/267).
        result = run_tool(
            ["git", "show", f"{ref}:{relative_path.as_posix()}"],
            cwd=str(git_root),
            env=_hook_env(git_root),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="surrogateescape",
            timeout=10,
        )

        if result.returncode == 0:
            return result.stdout
        return None
    except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
        return None


def is_file_modified(file_path: Path) -> bool:
    """
    Check if a file has been modified compared to HEAD.

    Parameters:
        file_path: Absolute path to the file.

    Returns:
        True if the file is modified (staged or unstaged), False otherwise.
        Returns True if not in a git repo (treat as modified/new).
    """
    git_root = get_git_root(file_path)
    if not git_root:
        return True  # Not in git, treat as new/modified

    try:
        relative_path = file_path.resolve().relative_to(git_root)

        # Check for both staged and unstaged modifications
        result = run_tool(
            ["git", "status", "--porcelain", str(relative_path)],
            cwd=str(git_root),
            env=_hook_env(git_root),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="surrogateescape",
            timeout=10,
        )

        if result.returncode != 0:
            return True  # Error, treat as modified

        # If there's any output, the file is modified
        return bool(result.stdout.strip())
    except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
        return True  # Error, treat as modified


def restore_file_from_git(file_path: Path, ref: str = "HEAD") -> bool:
    """
    Restore a file from a git ref (default: HEAD).

    Parameters:
        file_path: Absolute path to the file to restore.
        ref: Git ref to restore from (default: HEAD).

    Returns:
        True if the file was successfully restored, False otherwise.
    """
    git_root = get_git_root(file_path)
    if not git_root:
        return False

    try:
        relative_path = file_path.resolve().relative_to(git_root)

        result = run_tool(
            ["git", "checkout", ref, "--", str(relative_path)],
            cwd=str(git_root),
            env=_hook_env(git_root),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="surrogateescape",
            timeout=10,
        )

        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
        return False


def is_file_tracked(file_path: Path, *, env: Mapping[str, str] | None = None) -> bool:
    """
    Check if a file is tracked by git.

    Parameters:
        file_path: Absolute path to the file.
        env: The environment git runs in. When None, a git hook's variables are kept if they
            name the file's repository, so that git asks the index being committed, which
            smart encryption restores the file into, and dropped otherwise.
            ``without_git_location()`` always asks the index of the file's own repository.

    Returns:
        True if the file is tracked by git, False otherwise.
    """
    git_root = get_git_root(file_path)
    if not git_root:
        return False

    try:
        relative_path = file_path.resolve().relative_to(git_root)

        result = run_tool(
            ["git", "ls-files", "--error-unmatch", str(relative_path)],
            cwd=str(git_root),
            env=_hook_env(git_root) if env is None else env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="surrogateescape",
            timeout=10,
        )

        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
        return False


def ensure_gitignore_entries(paths: Iterable[Path], *, git_root: Path | None = None) -> list[str]:
    """
    Ensure the provided paths are listed in their repository's .gitignore.

    Each path's entry goes in the .gitignore at the root of the repository that would
    stage it, the one git reports for the path's folder (``_repository_of``). For a path
    in a submodule that is the submodule, whose ``git add`` never reads the superproject's
    .gitignore. The entry is the path relative to that root, escaped so that it matches
    that path and nothing else (``gitignore_escape``).

    Parameters:
        paths: Iterable of file paths to ignore.
        git_root: Optional git root override: every entry goes in its .gitignore, and a
            path outside it is skipped. Auto-detected for each path when omitted.

    Returns:
        List of entries added, as written in their .gitignore files.
    """
    added: list[str] = []
    for root, group in _by_repository(paths, git_root).items():
        added.extend(_add_gitignore_entries(root, group))
    return added


def _by_repository(paths: Iterable[Path], git_root: Path | None) -> dict[Path, list[Path]]:
    """``paths`` by the root of the repository that would stage each.

    That is ``git_root`` for every path when it is given, else each path's own repository
    (``_repository_of``). A path outside every repository is left out.
    """
    groups: dict[Path, list[Path]] = {}
    for path in (Path(path) for path in paths):
        root = git_root if git_root is not None else _repository_of(path)
        if root is not None:
            groups.setdefault(root, []).append(path)
    return groups


def _repository_of(path: Path) -> Path | None:
    """The root of the repository that would stage the file ``path`` names.

    git reports it for the file's folder, or for its nearest existing parent when the
    folder does not exist yet. Symlinks are followed: it is the repository of the file the
    bytes are in. None when that folder is outside every repository, or git cannot say.
    """
    folder = _nearest_folder(path.resolve())
    return None if folder is None else get_git_root(folder)


def _nearest_folder(resolved: Path) -> Path | None:
    """The nearest of the parents of ``resolved`` that is a directory, if any."""
    for folder in resolved.parents:
        try:
            if folder.is_dir():
                return folder
        except OSError:  # a parent this process cannot even look at
            return None
    return None


def _add_gitignore_entries(git_root: Path, path_list: list[Path]) -> list[str]:
    """Add each path in ``path_list`` that git does not ignore yet to ``git_root``'s .gitignore.

    Returns the entries added, as written there.
    """
    gitignore_path = git_root / ".gitignore"
    content = ""
    existing_lines: list[str] = []
    if gitignore_path.exists():
        content = gitignore_path.read_text(encoding="utf-8")
        existing_lines = content.splitlines()

    existing = {line.strip() for line in existing_lines if line.strip()}
    new_entries: list[str] = []

    for path in path_list:
        if _is_path_ignored(path, git_root):
            continue
        try:
            relative_path = path.resolve().relative_to(git_root)
        except ValueError:
            continue

        entry = gitignore_escape(relative_path.as_posix())
        # Compared stripped, as the lines are: an escaped trailing space must not
        # make every run append the entry again.
        if entry.strip() not in existing:
            new_entries.append(entry)
            existing.add(entry.strip())

    if new_entries:
        with gitignore_path.open("a", encoding="utf-8") as handle:
            if content and not content.endswith("\n"):
                handle.write("\n")
            for entry in new_entries:
                handle.write(f"{entry}\n")

    return new_entries


def gitignore_escape(name: str) -> str:
    """Escape ``name`` so a ``.gitignore`` pattern matches it literally.

    ``name`` is a file or folder name, or a path relative to the repository root
    with POSIX separators. git reads ``\\``, ``*``, ``?`` and ``[`` as glob syntax, a
    leading ``!`` as a negation and a leading ``#`` as a comment, and drops trailing
    spaces. Written as it is, ``config/[prod]/.env.keys`` is a character class that
    matches ``config/p/.env.keys`` but not the folder ``[prod]``, so the private key it
    was meant to hide stayed stageable. Each of those is escaped with a backslash.
    """
    escaped = "".join(f"\\{char}" if char in "*?[\\" else char for char in name)
    if escaped[:1] in ("#", "!"):
        escaped = f"\\{escaped}"
    kept = escaped.rstrip(" ")
    return kept + "\\ " * (len(escaped) - len(kept))


def unignored_paths(
    paths: Iterable[Path], *, git_root: Path | None = None
) -> list[tuple[str, str | None]]:
    """The paths in ``paths`` that git does not confirm it ignores, each with the reason.

    The check behind ``ensure_gitignore_entries``, to run after it: an entry it wrote can
    still be overridden, by a later ``!`` rule in a .gitignore for example. Each path is
    asked about in the repository that would stage it, where ``ensure_gitignore_entries``
    writes its entry (``git_root`` when given, and then a path outside it is skipped). The
    repository's own rules count, a user's global excludes file does not.

    It fails closed: every path in a repository is listed unless git says it ignores it.
    The reason is None when git says it does not (a rule re-includes it), else why git
    could not say: it failed, timed out or could not run, for example. A path outside
    every repository is not listed, since git cannot stage it.

    Each path is shown relative to ``git_root``, else to the root of the working
    directory's repository (a submodule's key as ``sub/config/.env.keys``, say), and in
    full when it is not in there.
    """
    listed: list[tuple[Path, str | bool]] = []
    for path in (Path(path) for path in paths):
        resolved = path.resolve()
        verdict = _ignore_status(resolved, git_root)
        if verdict is not None and verdict is not True:
            listed.append((resolved, verdict))
    if not listed:
        return []
    base = git_root if git_root is not None else _working_directory_root()
    return [
        (_shown(resolved, base), None if verdict is False else str(verdict))
        for resolved, verdict in listed
    ]


def _ignore_status(resolved: Path, git_root: Path | None) -> str | bool | None:
    """``_ignore_verdict`` for ``resolved`` in the repository that would stage it.

    That is ``git_root`` when it is given, else the one git reports (``_repository_of``).
    None when there is none: ``resolved`` is outside ``git_root``, or outside every
    repository. When git reports none although a ``.git`` is above ``resolved``, git
    failed there, and the verdict says so.
    """
    if git_root is not None:
        return _ignore_verdict(resolved, git_root) if resolved.is_relative_to(git_root) else None
    root = _repository_of(resolved)
    if root is not None:
        return _ignore_verdict(resolved, root)
    checkout = _checkout_above(resolved.parent)
    if checkout is None:
        return None  # outside every repository: git cannot stage it
    return f"git did not report the repository at {checkout}"


def _working_directory_root() -> Path | None:
    """The root of the working directory's repository, if it is in one."""
    try:
        return get_git_root(Path.cwd())
    except OSError:  # the working directory is gone
        return None


def _shown(resolved: Path, base: Path | None) -> str:
    """``resolved`` relative to ``base`` when it is in there, else in full (POSIX)."""
    if base is not None and resolved.is_relative_to(base):
        return resolved.relative_to(base).as_posix()
    return resolved.as_posix()


def ensure_gitignore_glob(sample: Path, pattern: str) -> str | None:
    """Ensure files named like ``pattern`` next to ``sample`` are gitignored.

    ``sample`` is one concrete path the pattern must cover (it need not exist;
    ``git check-ignore`` works on names). When it is not ignored yet, the
    pattern is appended to the repo's ``.gitignore``, scoped to ``sample``'s
    folder (``svc/.env.keys.backup.*``, with the folder's names escaped). The
    pattern is the caller's: escape its literal part with :func:`gitignore_escape`.
    A no-op outside a git repo.

    Returns:
        The entry added, or ``None`` when nothing had to change.

    Raises:
        OSError: ``.gitignore`` could not be read or written, or git could not
            say where the repository of ``sample`` is although it is in one, or
            whether it ignores ``sample`` with the entry in place.
        GitignoreOverrideError: git still does not ignore ``sample`` with the
            entry in place, because a later ``!`` rule (in a nested
            ``.gitignore``, say) re-includes it.
    """
    git_root = get_git_root(sample.parent)
    if git_root is None:
        _require_outside_a_checkout(sample)
        return None
    if _is_path_ignored(sample, git_root):
        return None
    try:
        folder = sample.parent.resolve().relative_to(git_root)
    except ValueError:
        raise OSError(
            f"{sample.parent} is not under the repository root git reports ({git_root}), "
            f"so envdrift cannot make sure git ignores {sample.name}"
        ) from None
    scope = "/".join(gitignore_escape(part) for part in folder.parts)
    entry = f"{scope}/{pattern}" if scope else pattern
    added = _append_gitignore_entry(git_root / ".gitignore", entry)
    verdict = _ignore_verdict(sample, git_root)
    if verdict is False:
        raise GitignoreOverrideError(
            f"git would still track {sample.name}: a '!' rule in a .gitignore re-includes "
            f"files that '{entry}' ignores. Remove that rule or make it more specific, "
            f"and re-run."
        )
    if verdict is not True:
        raise OSError(f"envdrift cannot make sure git ignores {sample.name}: {verdict}")
    return added


def _require_outside_a_checkout(sample: Path) -> None:
    """Raise when git named no repository for ``sample`` but a ``.git`` is above it.

    That is git failing (a timeout, a broken repository), not a folder outside
    a repository: nothing then makes sure git ignores ``sample``.
    """
    candidate = _checkout_above(sample.parent.resolve())
    if candidate is not None:
        raise OSError(
            f"git did not report the repository at {candidate}, so envdrift cannot "
            f"make sure git ignores {sample.name}"
        )


def _checkout_above(folder: Path) -> Path | None:
    """The nearest of ``folder`` and its parents that holds a ``.git``, if any."""
    for candidate in (folder, *folder.parents):
        if (candidate / ".git").exists():
            return candidate
    return None


def _append_gitignore_entry(gitignore_path: Path, entry: str) -> str | None:
    """Append ``entry`` to ``gitignore_path`` unless a line already reads so.

    Works on bytes, so a ``.gitignore`` that is not UTF-8 is extended, not refused.
    """
    content = gitignore_path.read_bytes() if gitignore_path.exists() else b""
    line = entry.encode("utf-8")
    if line in {existing.strip() for existing in content.splitlines()}:
        return None
    with gitignore_path.open("ab") as handle:
        if content and not content.endswith(b"\n"):
            handle.write(b"\n")
        handle.write(line + b"\n")
    return entry


def _is_path_ignored(path: Path, git_root: Path) -> bool:
    """Whether git ignores ``path``; ``False`` too when git cannot say."""
    return _ignore_verdict(path, git_root) is True


def _ignore_verdict(path: Path, git_root: Path) -> str | bool:
    """Whether git ignores ``path`` in the repository at ``git_root``, or why git cannot say.

    True or False is git check-ignore's answer (exit 0 or 1). Anything else is the reason
    it gave none: ``path`` is outside ``git_root``, git failed (exit 128 for a path in a
    submodule of ``git_root``, say), timed out or could not run.

    The path follows ``--`` and starts with ``./``, so git reads it as a path. Without
    them a folder named ``-secrets`` was read as options (exit 129), and one named
    ``:secrets`` as pathspec magic: git answered for ``secrets/.env.keys`` instead.
    """
    try:
        relative_path = path.resolve().relative_to(git_root)
    except ValueError:
        return f"it is not under the repository root git reports ({git_root})"

    try:
        result = run_tool(
            [
                "git",
                "-c",
                "core.excludesfile=/dev/null",
                "check-ignore",
                "-q",
                "--",
                f"./{relative_path.as_posix()}",
            ],
            cwd=str(git_root),
            env=_hook_env(git_root),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="surrogateescape",
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        return "git check-ignore timed out"
    except OSError as exc:  # no git, or git_root is not a directory
        return f"git could not run: {exc}"
    if result.returncode in (0, 1):
        return result.returncode == 0
    detail = next((line.strip() for line in result.stderr.splitlines() if line.strip()), "")
    return f"git check-ignore exited {result.returncode}" + (f": {detail}" if detail else "")
