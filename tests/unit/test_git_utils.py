"""Tests for git utility functions used in smart encryption."""

from __future__ import annotations

import os
import subprocess  # nosec B404
import sys
from pathlib import Path, PurePath, PureWindowsPath
from unittest.mock import patch

import pytest

from envdrift.utils.git import (
    GitError,
    ensure_gitignore_entries,
    file_at_commit,
    get_file_from_git,
    get_git_root,
    git_tracks,
    has_git_head,
    is_file_modified,
    is_file_tracked,
    is_git_repo,
    restore_file_from_git,
)


def _repo_with(tmp_path: Path, files: dict[str, str]) -> Path:
    """A repository at ``tmp_path`` with ``files`` (name: content) in one commit."""
    for name, content in files.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        # As bytes, so the line breaks are the same on every platform.
        (tmp_path / name).write_bytes(content.encode())
    for args in (
        ["init", "-q"],
        ["config", "user.email", "test@test.com"],
        ["config", "user.name", "Test"],
        ["add", "-f", "--", *(f":(literal){name}" for name in files)],
        ["commit", "-q", "-m", "initial"],
    ):
        subprocess.run(["git", *args], cwd=tmp_path, capture_output=True, check=True)
    return tmp_path


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

    def test_returns_false_for_a_path_below_a_regular_file(self, tmp_path: Path):
        """git cannot run in a parent that is a file: not NotADirectoryError."""
        subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)
        regular_file = tmp_path / "notes.txt"
        regular_file.write_text("x\n", encoding="utf-8")

        assert is_git_repo(regular_file / "child") is False


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

    def test_returns_none_for_a_path_below_a_regular_file(self, tmp_path: Path):
        """git cannot run in a parent that is a file: no root, not NotADirectoryError.

        push asked for the root of ``<secrets_dir>/.env.keys`` with a secrets_dir that
        was a regular file, and the traceback ended the command.
        """
        subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)
        regular_file = tmp_path / ".env.secrets"
        regular_file.write_text("A=1\n", encoding="utf-8")

        assert get_git_root(regular_file / ".env.keys") is None


class TestHasGitHead:
    """Tests for distinguishing an initialized repository from committed history."""

    def test_false_for_repository_without_commits(self, tmp_path: Path):
        subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True, check=True)

        assert has_git_head(tmp_path) is False

    def test_true_after_initial_commit(self, tmp_path: Path):
        subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True, check=True)
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.com",
                "commit",
                "--allow-empty",
                "-m",
                "initial",
            ],
            cwd=tmp_path,
            capture_output=True,
            check=True,
        )

        assert has_git_head(tmp_path) is True

    def test_false_outside_repository(self, tmp_path: Path):
        assert has_git_head(tmp_path) is False


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

    def test_a_file_in_a_folder_whose_name_starts_with_a_dash_is_tracked(self, tmp_path: Path):
        """git read ``-svc/.env.keys`` as options and exited 129: "not tracked" (#1016)."""
        repo = _repo_with(tmp_path, {"-svc/.env.keys": "K=1\n"})

        assert is_file_tracked(repo / "-svc" / ".env.keys") is True

    def test_an_untracked_file_whose_name_starts_with_a_dash_is_not_tracked(self, tmp_path: Path):
        """``-x.env`` was ``-x .env``, an exclude pattern: git listed every file (#1016)."""
        repo = _repo_with(tmp_path, {"app.txt": "content\n"})
        (repo / "-x.env").write_text("A=1\n")

        assert is_file_tracked(repo / "-x.env") is False

    def test_a_glob_name_is_not_tracked_because_a_file_it_matches_is(self, tmp_path: Path):
        """``[prod].env`` matched the tracked ``p.env`` as a glob (#1016)."""
        repo = _repo_with(tmp_path, {"p.env": "A=1\n"})
        (repo / "[prod].env").write_text("A=1\n")

        assert is_file_tracked(repo / "[prod].env") is False

    def test_git_tracks_raises_when_git_cannot_tell(self, tmp_path: Path):
        """A git failure is not "not tracked" (#1016); ``is_file_tracked`` still says False."""
        repo = _repo_with(tmp_path, {".env.keys": "K=1\n"})
        (repo / ".git" / "index").write_bytes(b"not an index")

        with pytest.raises(GitError, match="git could not tell whether it tracks"):
            git_tracks(repo / ".env.keys")
        assert is_file_tracked(repo / ".env.keys") is False

    def test_git_tracks_raises_when_git_does_not_answer(self, tmp_path: Path):
        """A timeout is not "not tracked" either (#1016)."""
        timeout = subprocess.TimeoutExpired(cmd="git", timeout=10)
        with (
            patch("envdrift.utils.git.get_git_root", return_value=tmp_path),
            patch("envdrift.utils.git.run_tool", side_effect=timeout),
            pytest.raises(GitError, match="git could not tell whether it tracks"),
        ):
            git_tracks(tmp_path / "test.txt")

    def test_git_tracks_raises_when_git_cannot_use_the_repository_above(self, tmp_path: Path):
        """A ``.git`` git cannot use is not "outside a repository" (#1016).

        get_git_root gives None both outside a repository and when git fails, as it does
        here, where ``HEAD`` is unreadable: that read as "not tracked".
        """
        repo = _repo_with(tmp_path, {".env.keys": "K=1\n"})
        (repo / ".git" / "HEAD").write_text("not a ref\n")

        with pytest.raises(GitError, match="git could not tell whether it tracks"):
            git_tracks(repo / ".env.keys")
        assert is_file_tracked(repo / ".env.keys") is False

    def test_a_literal_pathspecs_environment_does_not_change_the_answers(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """Under GIT_LITERAL_PATHSPECS ``:(literal)x`` named a file called so (#1016).

        The tracked key read as untracked, its change as none, and its restore failed.
        """
        repo = _repo_with(tmp_path, {".env.keys": "K=1\n"})
        monkeypatch.setenv("GIT_LITERAL_PATHSPECS", "1")

        assert git_tracks(repo / ".env.keys") is True
        (repo / ".env.keys").write_text("K=2\n")
        assert is_file_modified(repo / ".env.keys") is True
        assert restore_file_from_git(repo / ".env.keys") is True
        assert (repo / ".env.keys").read_text() == "K=1\n"

    def test_git_tracks_says_a_file_outside_any_repository_is_not_tracked(self, tmp_path: Path):
        (tmp_path / ".env.keys").write_text("K=1\n")

        assert git_tracks(tmp_path / ".env.keys") is False

    def test_a_file_outside_the_repository_root_is_not_tracked(self, tmp_path: Path):
        """A file that resolves outside the root git reports is not one it tracks."""
        repo = tmp_path / "repo"
        repo.mkdir()
        outside = tmp_path / "outside.env"
        outside.write_text("A=1\n")

        with patch("envdrift.utils.git.get_git_root", return_value=repo):
            assert git_tracks(outside) is False


class TestFileAtCommit:
    """The text of a file as a commit holds it, for the history scan (#1014)."""

    def test_reads_the_file_as_the_commit_holds_it(self, tmp_path: Path):
        repo = _repo_with(tmp_path, {"app.env": "A=1\n"})
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True, check=True
        ).stdout.strip()
        (repo / "app.env").write_bytes(b"A=2\n")

        assert file_at_commit(repo, PurePath("app.env"), commit) == "A=1\n"

    def test_no_line_break_is_translated(self, tmp_path: Path):
        """A lone ``\\r`` stays in its line: git and the scanners count lines at ``\\n`` only."""
        repo = _repo_with(tmp_path, {"app.env": "A=1\rB=2\nC=3\n"})

        assert file_at_commit(repo, PurePath("app.env"), "HEAD") == "A=1\rB=2\nC=3\n"

    def test_a_folder_that_is_no_repository_has_none(self, tmp_path: Path):
        (tmp_path / "app.env").write_bytes(b"A=1\n")

        assert file_at_commit(tmp_path, PurePath("app.env"), "0123abcd") is None

    def test_a_commit_that_does_not_hold_the_file_has_none(self, tmp_path: Path):
        repo = _repo_with(tmp_path, {"app.env": "A=1\n"})

        assert file_at_commit(repo, PurePath("other.env"), "HEAD") is None

    def test_git_that_cannot_run_gives_none(self, tmp_path: Path):
        repo = _repo_with(tmp_path, {"app.env": "A=1\n"})

        with patch("envdrift.utils.git.run_tool", side_effect=OSError("no git")):
            assert file_at_commit(repo, PurePath("app.env"), "HEAD") is None


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

    def test_returns_content_for_subdir_file(self, tmp_path: Path):
        """Should return committed content for a file in a subdirectory.

        Regression for #413 (cluster K): smart-encryption's git lookup must work
        for non-root files, not just root-level ones.
        """
        subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)
        subprocess.run(
            ["git", "config", "user.email", "test@test.com"],
            cwd=tmp_path,
            capture_output=True,
        )
        subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_path, capture_output=True)

        subdir = tmp_path / "services" / "api"
        subdir.mkdir(parents=True)
        nested_file = subdir / ".env.production"
        nested_file.write_text("original nested content")
        subprocess.run(
            ["git", "add", "services/api/.env.production"], cwd=tmp_path, capture_output=True
        )
        subprocess.run(["git", "commit", "-m", "initial"], cwd=tmp_path, capture_output=True)

        nested_file.write_text("modified nested content")

        result = get_file_from_git(nested_file)
        assert result == "original nested content"

    def test_revision_arg_uses_forward_slashes_for_subdir(self, tmp_path: Path):
        """The ``git show`` revision arg must use POSIX (forward-slash) separators.

        Regression for #413 (cluster K): git's ``<rev>:<path>`` syntax does not
        normalize backslashes, so a Windows ``str(Path)`` (e.g. ``sub\\file.env``)
        would never resolve and ``get_file_from_git`` returned None for non-root
        files. The fix builds the revision arg from ``relative_path.as_posix()``.

        This is a deterministic, platform-independent reproducer: on macOS/Linux a
        real ``Path`` already stringifies with forward slashes, so we force the
        function's relative-path computation to yield a ``PureWindowsPath`` (which
        stringifies with backslashes everywhere). The buggy f-string then produces
        a backslash revision arg; the fixed ``.as_posix()`` call produces slashes.
        """
        subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)

        nested_file = tmp_path / ".env.production"
        nested_file.write_text("content")

        # Simulate Windows: relative path within the repo uses backslashes.
        windows_relative = PureWindowsPath(r"services\api\.env.production")
        assert "\\" in str(windows_relative)  # guard: really backslash-separated

        captured: dict[str, object] = {}
        real_run = subprocess.run

        def _spy(cmd, *args, **kwargs):
            if isinstance(cmd, list) and cmd[:2] == ["git", "show"]:
                captured["rev_arg"] = cmd[2]
            return real_run(cmd, *args, **kwargs)

        # Make ``file_path.resolve().relative_to(git_root)`` return the Windows path.
        with (
            patch.object(Path, "relative_to", return_value=windows_relative),
            patch("envdrift.utils.git.subprocess.run", side_effect=_spy),
        ):
            get_file_from_git(nested_file)

        # Fail clearly if the spy never fired (e.g. ``get_file_from_git`` returned
        # early) rather than raising a confusing ``KeyError`` on the lookup below.
        assert "rev_arg" in captured, "git show was never invoked; spy did not capture a rev arg"
        rev_arg = captured["rev_arg"]
        assert isinstance(rev_arg, str)
        # ``HEAD:services/api/.env.production`` — forward slashes, no backslashes.
        assert "\\" not in rev_arg
        assert rev_arg == "HEAD:services/api/.env.production"


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

    def test_restores_nothing_but_the_file_it_names(self, tmp_path: Path):
        """``[p].env`` is not restored by checking out ``p.env`` (#1016).

        As a glob it matched the tracked ``p.env``, so the restore "succeeded" by discarding
        the local changes to another file.
        """
        repo = _repo_with(tmp_path, {"p.env": "committed\n"})
        (repo / "p.env").write_text("local change\n")
        (repo / "[p].env").write_text("untracked\n")

        assert restore_file_from_git(repo / "[p].env") is False
        assert (repo / "p.env").read_text() == "local change\n"


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

    def test_an_unchanged_file_whose_name_starts_with_a_dash_is_not_modified(self, tmp_path: Path):
        """git read ``-x.env`` as options, and the error read as "modified" (#1016)."""
        repo = _repo_with(tmp_path, {"-x.env": "A=1\n"})

        assert is_file_modified(repo / "-x.env") is False

    def test_a_glob_name_is_not_modified_because_a_file_it_matches_is(self, tmp_path: Path):
        """``[prod].env`` reported the changes to ``p.env`` (#1016)."""
        repo = _repo_with(tmp_path, {"p.env": "A=1\n", "[prod].env": "A=1\n"})
        (repo / "p.env").write_text("A=2\n")

        assert is_file_modified(repo / "[prod].env") is False

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

    @pytest.mark.parametrize(
        ("path", "decoy"),
        [
            ("config/[prod]/.env.keys", "config/p/.env.keys"),
            ("a*b/.env.keys", "aXb/.env.keys"),
            ("q?/.env.keys", "qz/.env.keys"),
            ("back\\slash/.env.keys", None),
            ("!bang/.env.keys", None),
            ("#hash/.env.keys", None),
            ("trailing  ", "trailing"),
        ],
    )
    def test_entry_matches_exactly_its_own_path(
        self, tmp_path: Path, path: str, decoy: str | None
    ) -> None:
        """A path with gitignore syntax in it is ignored, and nothing else is.

        Written raw, ``config/[prod]/.env.keys`` is a character class: it ignores
        ``config/p/.env.keys`` but not the private key in the folder ``[prod]``.
        """
        if sys.platform == "win32" and _not_a_windows_file_name(path):
            pytest.skip("not a valid Windows file name")
        repo = tmp_path.resolve()  # git's own spelling of the root (macOS: /private/var)
        subprocess.run(["git", "init"], cwd=repo, capture_output=True, check=True)

        added = ensure_gitignore_entries([repo / path], git_root=repo)

        assert len(added) == 1, added
        assert _check_ignore(repo, path) == 0, (repo / ".gitignore").read_text()
        if decoy is not None:
            assert _check_ignore(repo, decoy) == 1, (repo / ".gitignore").read_text()
        # A second run finds it ignored and writes nothing.
        assert ensure_gitignore_entries([repo / path], git_root=repo) == []


def _not_a_windows_file_name(path: str) -> bool:
    """``*``, ``?`` and ``\\`` cannot be in a Windows file name, nor can a trailing space."""
    return any(ch in path for ch in "*?\\") or path.endswith(" ")


def _check_ignore(repo: Path, path: str) -> int:
    """``git check-ignore``'s exit code for ``path``: 0 ignored, 1 not."""
    return subprocess.run(
        ["git", "check-ignore", "-q", "--no-index", "--", path], cwd=repo, capture_output=True
    ).returncode


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
            patch(
                "envdrift.utils.git.run_tool",
                side_effect=subprocess.TimeoutExpired(cmd="git", timeout=10),
            ),
        ):
            assert is_file_tracked(tmp_path / "test.txt") is False


class TestNonAsciiLocaleSafety:
    """#453: git output pipes must decode as UTF-8, not the platform locale codec."""

    def test_get_git_root_survives_non_utf8_locale_with_non_ascii_root(self, tmp_path: Path):
        """A non-ASCII repo root resolves correctly in a child forced off UTF-8.

        ``get_git_root`` used to decode ``git rev-parse --show-toplevel`` with the
        locale codec (``text=True`` and no ``encoding=``): under a C locale the
        UTF-8 path bytes raised an uncaught ``UnicodeDecodeError``; under Windows
        cp1252 they were silently mangled, mis-rooting every downstream git call
        (e.g. guard's combined-file .gitignore security check). Run the lookup in
        a child interpreter with the locale forced away from UTF-8 and assert the
        exact repo-root name round-trips.
        """
        repo = tmp_path / "秘密-répo"
        repo.mkdir()
        subprocess.run(["git", "init"], cwd=repo, capture_output=True, check=True)

        # Same locale-forcing pattern as the #453 e2e tests: LC_ALL/LANG pin the
        # POSIX locale codec to US-ASCII (Windows ignores them and natively uses
        # its ANSI code page), PYTHONUTF8=0 pins UTF-8 mode off (PEP 540) and
        # PYTHONCOERCECLOCALE=0 stops glibc coercion to C.UTF-8 (PEP 538).
        # PYTHONIOENCODING keeps the child's *own* stdout UTF-8 so printing the
        # name cannot crash — only the git pipe codec under test is locale-bound.
        env = os.environ | {
            "LC_ALL": "C",
            "LANG": "C",
            "PYTHONUTF8": "0",
            "PYTHONCOERCECLOCALE": "0",
            "PYTHONIOENCODING": "utf-8",
        }
        script = (
            "import pathlib, sys\n"
            "from envdrift.utils.git import get_git_root\n"
            "root = get_git_root(pathlib.Path(sys.argv[1]))\n"
            "print('NONE' if root is None else root.name)\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", script, str(repo)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            timeout=60,
        )
        assert "Traceback" not in result.stderr, result.stderr
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == repo.name
