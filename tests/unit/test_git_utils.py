"""Tests for git utility functions used in smart encryption."""

from __future__ import annotations

import subprocess  # nosec B404
from pathlib import Path
from unittest.mock import patch

from envdrift.utils.git import (
    ensure_gitignore_entries,
    get_file_from_git,
    get_git_root,
    is_file_modified,
    is_file_tracked,
    is_git_repo,
    restore_file_from_git,
)


class TestIsGitRepo:
    """Tests for is_git_repo function."""

    def test_returns_true_for_git_directory(self, tmp_path: Path):
        """Should return True when in a git repo."""
        # Initialize a git repo
        subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)

        assert is_git_repo(tmp_path) is True

    def test_returns_false_for_non_git_directory(self, tmp_path: Path):
        """Should return False when not in a git repo."""
        assert is_git_repo(tmp_path) is False

    def test_returns_false_when_git_not_installed(self, tmp_path: Path):
        """Should return False when git command fails."""
        with patch("subprocess.run", side_effect=FileNotFoundError):
            assert is_git_repo(tmp_path) is False


class TestGetGitRoot:
    """Tests for get_git_root function."""

    def test_returns_root_for_git_directory(self, tmp_path: Path):
        """Should return the git root directory."""
        subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)

        result = get_git_root(tmp_path)
        assert result == tmp_path.resolve()

    def test_returns_none_for_non_git_directory(self, tmp_path: Path):
        """Should return None when not in a git repo."""
        assert get_git_root(tmp_path) is None


class TestIsFileTracked:
    """Tests for is_file_tracked function."""

    def test_returns_true_for_tracked_file(self, tmp_path: Path):
        """Should return True for a tracked file."""
        subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)
        subprocess.run(
            ["git", "config", "user.email", "test@test.com"],
            cwd=tmp_path,
            capture_output=True,
        )
        subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_path, capture_output=True)

        test_file = tmp_path / "test.txt"
        test_file.write_text("content")
        subprocess.run(["git", "add", "test.txt"], cwd=tmp_path, capture_output=True)
        subprocess.run(["git", "commit", "-m", "initial"], cwd=tmp_path, capture_output=True)

        assert is_file_tracked(test_file) is True

    def test_returns_false_for_untracked_file(self, tmp_path: Path):
        """Should return False for an untracked file."""
        subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)

        test_file = tmp_path / "untracked.txt"
        test_file.write_text("content")

        assert is_file_tracked(test_file) is False

    def test_returns_false_for_non_git_repo(self, tmp_path: Path):
        """Should return False when not in a git repo."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        assert is_file_tracked(test_file) is False


class TestGetFileFromGit:
    """Tests for get_file_from_git function."""

    def test_returns_file_content_from_head(self, tmp_path: Path):
        """Should return file content from HEAD."""
        subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)
        subprocess.run(
            ["git", "config", "user.email", "test@test.com"],
            cwd=tmp_path,
            capture_output=True,
        )
        subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_path, capture_output=True)

        test_file = tmp_path / "test.txt"
        test_file.write_text("original content")
        subprocess.run(["git", "add", "test.txt"], cwd=tmp_path, capture_output=True)
        subprocess.run(["git", "commit", "-m", "initial"], cwd=tmp_path, capture_output=True)

        # Modify the file
        test_file.write_text("modified content")

        # Should still return the committed version
        result = get_file_from_git(test_file)
        assert result == "original content"

    def test_returns_none_for_untracked_file(self, tmp_path: Path):
        """Should return None for an untracked file."""
        subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)

        test_file = tmp_path / "untracked.txt"
        test_file.write_text("content")

        assert get_file_from_git(test_file) is None


class TestRestoreFileFromGit:
    """Tests for restore_file_from_git function."""

    def test_restores_file_from_head(self, tmp_path: Path):
        """Should restore file from HEAD."""
        subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)
        subprocess.run(
            ["git", "config", "user.email", "test@test.com"],
            cwd=tmp_path,
            capture_output=True,
        )
        subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_path, capture_output=True)

        test_file = tmp_path / "test.txt"
        test_file.write_text("original content")
        subprocess.run(["git", "add", "test.txt"], cwd=tmp_path, capture_output=True)
        subprocess.run(["git", "commit", "-m", "initial"], cwd=tmp_path, capture_output=True)

        # Modify the file
        test_file.write_text("modified content")
        assert test_file.read_text() == "modified content"

        # Restore
        result = restore_file_from_git(test_file)
        assert result is True
        assert test_file.read_text() == "original content"

    def test_returns_false_for_non_git_repo(self, tmp_path: Path):
        """Should return False when not in a git repo."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        assert restore_file_from_git(test_file) is False


class TestIsFileModified:
    """Tests for is_file_modified function."""

    def test_returns_false_for_unchanged_file(self, tmp_path: Path):
        """Should return False for an unchanged tracked file."""
        subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)
        subprocess.run(
            ["git", "config", "user.email", "test@test.com"],
            cwd=tmp_path,
            capture_output=True,
        )
        subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_path, capture_output=True)

        test_file = tmp_path / "test.txt"
        test_file.write_text("content")
        subprocess.run(["git", "add", "test.txt"], cwd=tmp_path, capture_output=True)
        subprocess.run(["git", "commit", "-m", "initial"], cwd=tmp_path, capture_output=True)

        assert is_file_modified(test_file) is False

    def test_returns_true_for_modified_file(self, tmp_path: Path):
        """Should return True for a modified tracked file."""
        subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)
        subprocess.run(
            ["git", "config", "user.email", "test@test.com"],
            cwd=tmp_path,
            capture_output=True,
        )
        subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_path, capture_output=True)

        test_file = tmp_path / "test.txt"
        test_file.write_text("content")
        subprocess.run(["git", "add", "test.txt"], cwd=tmp_path, capture_output=True)
        subprocess.run(["git", "commit", "-m", "initial"], cwd=tmp_path, capture_output=True)

        # Modify
        test_file.write_text("modified")

        assert is_file_modified(test_file) is True

    def test_returns_true_for_non_git_repo(self, tmp_path: Path):
        """Should return True (treat as modified) when not in a git repo."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        assert is_file_modified(test_file) is True


class TestEnsureGitignoreEntries:
    """Tests for ensure_gitignore_entries function."""

    def test_creates_gitignore_when_missing(self, tmp_path: Path):
        """Should create .gitignore and add entries when missing."""
        subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)

        target = tmp_path / ".env.production"
        added = ensure_gitignore_entries([target])

        assert added == [".env.production"]
        gitignore = tmp_path / ".gitignore"
        assert gitignore.exists()
        assert ".env.production" in gitignore.read_text()

    def test_skips_existing_entries(self, tmp_path: Path):
        """Should avoid duplicating existing entries."""
        subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)
        gitignore = tmp_path / ".gitignore"
        gitignore.write_text(".env.production\n")

        target = tmp_path / ".env.production"
        added = ensure_gitignore_entries([target])

        assert added == []
        assert gitignore.read_text().splitlines().count(".env.production") == 1

    def test_skips_when_already_ignored(self, tmp_path: Path):
        """Should avoid adding entries already ignored by patterns."""
        subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)
        gitignore = tmp_path / ".gitignore"
        gitignore.write_text(".env.*\n")

        target = tmp_path / ".env.production"
        added = ensure_gitignore_entries([target])

        assert added == []
        assert gitignore.read_text().splitlines() == [".env.*"]


class TestGitUtilsExceptions:
    """Tests for exception handling in git utilities."""

    def test_is_git_repo_handles_exceptions(self, tmp_path: Path):
        """Should return False on subprocess exceptions."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="git", timeout=10)):
            assert is_git_repo(tmp_path) is False

        with patch("subprocess.run", side_effect=FileNotFoundError):
            assert is_git_repo(tmp_path) is False

    def test_get_git_root_handles_exceptions(self, tmp_path: Path):
        """Should return None on subprocess exceptions."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="git", timeout=10)):
            assert get_git_root(tmp_path) is None

    def test_get_file_from_git_handles_exceptions(self, tmp_path: Path):
        """Should return None on exceptions."""
        # Mock get_git_root to return a path so we reach the subprocess call
        with patch("envdrift.utils.git.get_git_root", return_value=tmp_path):
            with patch("subprocess.run", side_effect=ValueError):
                assert get_file_from_git(tmp_path / "test.txt") is None

    def test_is_file_modified_handles_exceptions(self, tmp_path: Path):
        """Should return True (modified) on exceptions."""
        with patch("envdrift.utils.git.get_git_root", return_value=tmp_path):
            with patch("subprocess.run", side_effect=FileNotFoundError):
                assert is_file_modified(tmp_path / "test.txt") is True

    def test_restore_file_from_git_handles_exceptions(self, tmp_path: Path):
        """Should return False on exceptions."""
        with patch("envdrift.utils.git.get_git_root", return_value=tmp_path):
            with patch("subprocess.run", side_effect=ValueError):
                assert restore_file_from_git(tmp_path / "test.txt") is False

    def test_is_file_tracked_handles_exceptions(self, tmp_path: Path):
        """Should return False on exceptions."""
        with (
            patch("envdrift.utils.git.get_git_root", return_value=tmp_path),
            patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="git", timeout=10)),
        ):
            assert is_file_tracked(tmp_path / "test.txt") is False
