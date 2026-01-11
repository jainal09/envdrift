"""Utility modules for envdrift."""

from envdrift.utils.config import normalize_max_workers
from envdrift.utils.git import (
    GitError,
    ensure_gitignore_entries,
    get_file_from_git,
    get_git_root,
    is_file_modified,
    is_file_tracked,
    is_git_repo,
    restore_file_from_git,
)

__all__ = [
    "GitError",
    "ensure_gitignore_entries",
    "get_file_from_git",
    "get_git_root",
    "is_file_modified",
    "is_file_tracked",
    "is_git_repo",
    "normalize_max_workers",
    "restore_file_from_git",
]
