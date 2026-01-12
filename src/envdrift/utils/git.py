"""Git utilities for envdrift.

This module provides helpers for interacting with Git to support
smart encryption that avoids unnecessary re-encryption when content
is unchanged.
"""

from __future__ import annotations

import subprocess  # nosec B404
from collections.abc import Iterable
from pathlib import Path


class GitError(Exception):
    """Error executing git command."""

    pass


def is_git_repo(path: Path) -> bool:
    """
    Check if the given path is inside a git repository.

    Parameters:
        path: Path to check.

    Returns:
        True if path is inside a git repository, False otherwise.
    """
    try:
        result = subprocess.run(  # nosec B603, B607
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=str(path if path.is_dir() else path.parent),
            capture_output=True,
            text=True,
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
        result = subprocess.run(  # nosec B603, B607
            ["git", "rev-parse", "--show-toplevel"],
            cwd=str(path if path.is_dir() else path.parent),
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return Path(result.stdout.strip())
        return None
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


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

        result = subprocess.run(  # nosec B603, B607
            ["git", "show", f"{ref}:{relative_path}"],
            cwd=str(git_root),
            capture_output=True,
            text=True,
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
        result = subprocess.run(  # nosec B603, B607
            ["git", "status", "--porcelain", str(relative_path)],
            cwd=str(git_root),
            capture_output=True,
            text=True,
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

        result = subprocess.run(  # nosec B603, B607
            ["git", "checkout", ref, "--", str(relative_path)],
            cwd=str(git_root),
            capture_output=True,
            text=True,
            timeout=10,
        )

        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
        return False


def is_file_tracked(file_path: Path) -> bool:
    """
    Check if a file is tracked by git.

    Parameters:
        file_path: Absolute path to the file.

    Returns:
        True if the file is tracked by git, False otherwise.
    """
    git_root = get_git_root(file_path)
    if not git_root:
        return False

    try:
        relative_path = file_path.resolve().relative_to(git_root)

        result = subprocess.run(  # nosec B603, B607
            ["git", "ls-files", "--error-unmatch", str(relative_path)],
            cwd=str(git_root),
            capture_output=True,
            text=True,
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
        result = subprocess.run(  # nosec B603, B607
            [
                "git",
                "-c",
                "core.excludesfile=/dev/null",
                "check-ignore",
                "-q",
                relative_path.as_posix(),
            ],
            cwd=str(git_root),
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False
