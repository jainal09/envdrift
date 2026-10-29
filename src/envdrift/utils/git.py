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
    run here, not to one run in ``git_root``, so a kept one is passed as absolute.
    """
    exported = {name: os.environ[name] for name in GIT_LOCATION_VARIABLES if name in os.environ}
    if not exported:
        return None
    env = without_git_location()
    relative = not all(Path(value).is_absolute() for value in exported.values())
    paths = (
        _hook_paths(exported)
        if relative
        else {name: Path(value) for name, value in exported.items()}
    )
    if paths is None or not _paths_of(paths, git_root, env):
        return env
    if relative:
        return {**os.environ, **{name: str(path) for name, path in paths.items()}}
    return None


def _paths_of(paths: Mapping[str, Path], git_root: Path, env: Mapping[str, str]) -> bool:
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
            if not _index_of(path.resolve(), git_dir, named="GIT_DIR" in paths, env=env):
                return False
        elif path.resolve() != own[name]:
            return False
    return True


# The rev-parse options that print the path each location variable names, as git reads it.
_LOCATION_OPTIONS = {
    "GIT_DIR": ("--absolute-git-dir",),
    "GIT_WORK_TREE": ("--show-toplevel",),
    "GIT_INDEX_FILE": ("--git-path", "index"),
    "GIT_COMMON_DIR": ("--git-common-dir",),
}


def _hook_paths(names: Iterable[str]) -> dict[str, Path] | None:
    """Where the location variables ``names`` point for a git run here, as absolute paths.

    git reads a relative GIT_DIR or GIT_WORK_TREE against the directory it runs in, but a
    relative GIT_INDEX_FILE against the top of the work tree, which it moves to first, from a
    subdirectory say. So git, run in this process's working directory and environment, says
    where they point, relative to that directory. None when it cannot.
    """
    names = list(names)
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
    return {name: cwd / line for name, line in zip(names, lines, strict=True)}


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
    except (subprocess.TimeoutExpired, FileNotFoundError):
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
    except (subprocess.TimeoutExpired, FileNotFoundError):
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
    Ensure the provided paths are listed in the repo's .gitignore.

    Parameters:
        paths: Iterable of file paths to ignore.
        git_root: Optional git root override; auto-detected when omitted.

    Returns:
        List of entries added to .gitignore (relative paths).
    """
    path_list = [Path(path) for path in paths]
    if not path_list:
        return []

    if git_root is None:
        git_root = get_git_root(path_list[0]) or get_git_root(Path.cwd())
    if git_root is None:
        return []

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

        entry = relative_path.as_posix()
        if entry not in existing:
            new_entries.append(entry)
            existing.add(entry)

    if new_entries:
        with gitignore_path.open("a", encoding="utf-8") as handle:
            if content and not content.endswith("\n"):
                handle.write("\n")
            for entry in new_entries:
                handle.write(f"{entry}\n")

    return new_entries


def _is_path_ignored(path: Path, git_root: Path) -> bool:
    try:
        relative_path = path.resolve().relative_to(git_root)
    except ValueError:
        return False

    try:
        result = run_tool(
            [
                "git",
                "-c",
                "core.excludesfile=/dev/null",
                "check-ignore",
                "-q",
                relative_path.as_posix(),
            ],
            cwd=str(git_root),
            env=_hook_env(git_root),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="surrogateescape",
            timeout=10,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False
