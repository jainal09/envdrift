"""Tests for the git variables a hook exports, under which the repository lookups still answer
for the path's own repository (#915, #919)."""

from __future__ import annotations

import os
import subprocess  # nosec B404
import sys
from pathlib import Path

import pytest

from envdrift.utils.git import (
    _hook_env,
    ensure_gitignore_entries,
    get_file_from_git,
    get_git_root,
    has_git_head,
    is_file_tracked,
    is_git_repo,
    without_git_location,
)


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
