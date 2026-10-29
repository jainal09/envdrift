"""Tests for git utility functions used in smart encryption."""

from __future__ import annotations

import os
import subprocess  # nosec B404
import sys
from pathlib import Path, PureWindowsPath
from unittest.mock import patch

import pytest

from envdrift.utils.git import (
    _hook_env,
    ensure_gitignore_entries,
    get_file_from_git,
    get_git_root,
    has_git_head,
    is_file_modified,
    is_file_tracked,
    is_git_repo,
    restore_file_from_git,
    without_git_location,
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


def _git(cwd: Path, *args: str) -> None:
    config = ["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"]
    subprocess.run(["git", *config, *args], cwd=cwd, check=True, capture_output=True)


class TestHookGitVariables:
    """The repository lookups answer for the path's repository, whatever a git hook exported.

    git exports GIT_DIR, GIT_INDEX_FILE and the like to its hooks (#915). is_file_tracked asks
    the index the hook was given unless it is passed ``without_git_location()``.
    """

    def test_without_git_location_drops_the_location_variables_only(self):
        environ = {
            "GIT_DIR": "/hook/.git",
            "GIT_WORK_TREE": "/hook",
            "GIT_INDEX_FILE": "/hook/.git/index.lock",
            "GIT_COMMON_DIR": "/hook/.git",
            "GIT_AUTHOR_NAME": "t",
            "PATH": "/usr/bin",
        }

        assert without_git_location(environ) == {"GIT_AUTHOR_NAME": "t", "PATH": "/usr/bin"}

    def test_without_git_location_reads_os_environ_by_default(self, monkeypatch):
        monkeypatch.setenv("GIT_INDEX_FILE", "/hook/.git/index.lock")
        monkeypatch.setenv("ENVDRIFT_TEST_PROBE", "kept")

        environ = without_git_location()

        assert "GIT_INDEX_FILE" not in environ
        assert environ["ENVDRIFT_TEST_PROBE"] == "kept"

    def test_lookups_in_a_linked_worktree_answer_for_the_worktree(
        self, tmp_path: Path, monkeypatch
    ):
        """In a linked worktree, git exports an absolute GIT_DIR and GIT_INDEX_FILE to each hook.

        With GIT_DIR set, git took the directory it ran in as the top of the work tree, so the
        root of ``src`` was ``src`` itself and its tracked file read as untracked.
        """
        repo = tmp_path / "repo"
        (repo / "src").mkdir(parents=True)
        _git(repo, "init", "-q")
        (repo / "src" / "app.txt").write_text("hello\n")
        _git(repo, "add", "src/app.txt")
        _git(repo, "commit", "-qm", "init")
        worktree = tmp_path / "worktree"
        _git(repo, "worktree", "add", "-q", str(worktree))
        git_dir = Path((worktree / ".git").read_text().split(":", 1)[1].strip())
        monkeypatch.setenv("GIT_DIR", str(git_dir))
        monkeypatch.setenv("GIT_INDEX_FILE", str(git_dir / "index"))

        assert get_git_root(worktree / "src") == worktree.resolve()
        assert is_file_tracked(worktree / "src" / "app.txt") is True

    def test_lookups_answer_for_the_path_under_another_repositorys_variables(
        self, tmp_path: Path, monkeypatch
    ):
        """GIT_DIR and GIT_INDEX_FILE of another repository do not change the answers."""
        hook = tmp_path / "hook"
        hook.mkdir()
        _git(hook, "init", "-q")
        scanned = tmp_path / "scanned"
        scanned.mkdir()
        _git(scanned, "init", "-q")
        (scanned / "app.txt").write_text("hello\n")
        _git(scanned, "add", "app.txt")
        _git(scanned, "commit", "-qm", "init")
        monkeypatch.setenv("GIT_DIR", str(hook / ".git"))
        monkeypatch.setenv("GIT_INDEX_FILE", str(hook / ".git" / "index"))

        assert is_git_repo(scanned) is True
        assert has_git_head(scanned) is True
        assert is_file_tracked(scanned / "app.txt", env=without_git_location()) is True

    def test_is_file_tracked_asks_the_index_a_hook_exported_by_default(
        self, tmp_path: Path, monkeypatch
    ):
        """Smart encryption restores a file into the index a git hook exported, so it asks that one.

        ``without_git_location()`` asks the index of the file's own repository.
        """
        repo = tmp_path / "repo"
        repo.mkdir()
        _git(repo, "init", "-q")
        (repo / "app.txt").write_text("hello\n")
        (repo / "other.txt").write_text("hello\n")
        _git(repo, "add", "app.txt")
        hook_index = repo / ".git" / "hook-index"
        subprocess.run(
            ["git", "add", "other.txt"],
            cwd=repo,
            env={**os.environ, "GIT_INDEX_FILE": str(hook_index)},
            check=True,
            capture_output=True,
        )
        monkeypatch.setenv("GIT_INDEX_FILE", str(hook_index))

        assert is_file_tracked(repo / "other.txt") is True
        assert is_file_tracked(repo / "app.txt") is False
        assert is_file_tracked(repo / "other.txt", env=without_git_location()) is False
        assert is_file_tracked(repo / "app.txt", env=without_git_location()) is True

    def test_helpers_answer_for_another_repository_from_a_worktree_hook(
        self, tmp_path: Path, monkeypatch
    ):
        """A linked worktree's hook exports an absolute GIT_DIR and GIT_INDEX_FILE (#919).

        For a file of another repository, get_file_from_git read the hook repository's commit,
        and is_file_tracked its index.
        """
        hook_repo, other = tmp_path / "hook", tmp_path / "other"
        for repo, content in ((hook_repo, "hook\n"), (other, "other\n")):
            repo.mkdir()
            _git(repo, "init", "-q")
            (repo / "app.txt").write_text(content)
            _git(repo, "add", "app.txt")
            _git(repo, "commit", "-qm", "init")
        (other / "own.txt").write_text("own\n")
        _git(other, "add", "own.txt")
        worktree = tmp_path / "worktree"
        _git(hook_repo, "worktree", "add", "-q", str(worktree))
        git_dir = Path((worktree / ".git").read_text().split(":", 1)[1].strip())
        monkeypatch.setenv("GIT_DIR", str(git_dir))
        monkeypatch.setenv("GIT_INDEX_FILE", str(git_dir / "index"))

        assert get_file_from_git(other / "app.txt") == "other\n"
        assert is_file_tracked(other / "own.txt") is True

    def test_ensure_gitignore_entries_reads_the_excludes_of_the_files_repository(
        self, tmp_path: Path, monkeypatch
    ):
        """Under another repository's GIT_DIR, git check-ignore read that repository's excludes.

        A key file they listed counted as ignored, so it was left out of its own repository's
        .gitignore (#919).
        """
        hook_repo, other = tmp_path / "hook", tmp_path / "other"
        for repo in (hook_repo, other):
            repo.mkdir()
            _git(repo, "init", "-q")
        with (hook_repo / ".git" / "info" / "exclude").open("a") as exclude:
            exclude.write(".env.keys\n")
        (other / ".env.keys").write_text("DOTENV_PRIVATE_KEY=k\n")
        monkeypatch.setenv("GIT_DIR", str(hook_repo / ".git"))

        assert ensure_gitignore_entries([other / ".env.keys"]) == [".env.keys"]
        assert (other / ".gitignore").read_text() == ".env.keys\n"

    def test_hook_env_drops_the_variables_when_git_cannot_place_the_repository(
        self, tmp_path: Path, monkeypatch
    ):
        """Unable to tell which repository the variables name, git runs without them."""
        monkeypatch.setenv("GIT_INDEX_FILE", str(tmp_path / "index.lock"))

        env = _hook_env(tmp_path)

        assert env is not None
        assert "GIT_INDEX_FILE" not in env

    def test_hook_env_keeps_an_alternate_index_of_the_repository_the_hook_runs_in(
        self, tmp_path: Path, monkeypatch
    ):
        """An index the user set outside the git directory, which git exports to the hook too."""
        repo = tmp_path / "repo"
        repo.mkdir()
        _git(repo, "init", "-q")
        monkeypatch.setenv("GIT_INDEX_FILE", str(tmp_path / "alternate" / "index.lock"))
        monkeypatch.chdir(repo)

        assert _hook_env(repo) is None

    def test_hook_env_drops_an_alternate_index_for_another_repository(
        self, tmp_path: Path, monkeypatch
    ):
        """The hook runs in its own repository: a file of another one gets that one's index."""
        hook_repo, other = tmp_path / "hook", tmp_path / "other"
        for repo in (hook_repo, other):
            repo.mkdir()
            _git(repo, "init", "-q")
        monkeypatch.setenv("GIT_INDEX_FILE", str(tmp_path / "alternate" / "index.lock"))
        monkeypatch.chdir(hook_repo)

        env = _hook_env(other)

        assert env is not None
        assert "GIT_INDEX_FILE" not in env

    def test_hook_env_places_an_index_by_the_git_directory_above_it(
        self, tmp_path: Path, monkeypatch
    ):
        """An index in a subdirectory of a git directory is that repository's, wherever git runs.

        Only the index's own directory was checked: deeper in another repository's git directory,
        it passed for an alternate index of the repository the hook runs in, and the reverse.
        """
        hook_repo, other = tmp_path / "hook", tmp_path / "other"
        for repo in (hook_repo, other):
            repo.mkdir()
            _git(repo, "init", "-q")
        monkeypatch.setenv("GIT_INDEX_FILE", str(hook_repo / ".git" / "tmp" / "index"))
        monkeypatch.chdir(other)

        env = _hook_env(other)

        assert env is not None
        assert "GIT_INDEX_FILE" not in env, "another repository's index was kept"
        assert _hook_env(hook_repo) is None, "the repository's own index was dropped"

    def test_hook_env_keeps_an_alternate_index_of_the_git_dir_it_names(
        self, tmp_path: Path, monkeypatch
    ):
        """GIT_DIR names the repository wherever the hook runs: the index is its alternate one."""
        repo = tmp_path / "repo"
        repo.mkdir()
        _git(repo, "init", "-q")
        monkeypatch.setenv("GIT_DIR", str(repo / ".git"))
        monkeypatch.setenv("GIT_INDEX_FILE", str(tmp_path / "alternate" / "index"))
        monkeypatch.chdir(tmp_path)

        assert _hook_env(repo) is None

    def test_hook_env_keeps_an_alternate_index_run_outside_every_repository(
        self, tmp_path: Path, monkeypatch
    ):
        """Nothing ties the index to another repository, so git uses it, as it would here."""
        repo = tmp_path / "repo"
        repo.mkdir()
        _git(repo, "init", "-q")
        (tmp_path / "outside").mkdir()
        monkeypatch.setenv("GIT_INDEX_FILE", str(tmp_path / "alternate" / "index"))
        monkeypatch.chdir(tmp_path / "outside")

        assert _hook_env(repo) is None

    @pytest.mark.skipif(sys.platform == "win32", reason="Windows cannot remove a working directory")
    def test_hook_env_keeps_an_alternate_index_when_the_working_directory_is_gone(
        self, tmp_path: Path, monkeypatch
    ):
        """No working directory names a repository either."""
        repo = tmp_path / "repo"
        repo.mkdir()
        _git(repo, "init", "-q")
        (tmp_path / "gone").mkdir()
        monkeypatch.setenv("GIT_INDEX_FILE", str(tmp_path / "alternate" / "index"))
        monkeypatch.chdir(tmp_path / "gone")
        (tmp_path / "gone").rmdir()

        assert _hook_env(repo) is None
