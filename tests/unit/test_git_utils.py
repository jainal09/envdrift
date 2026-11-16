"""Tests for git utility functions used in smart encryption."""

from __future__ import annotations

import os
import shutil
import subprocess  # nosec B404
import sys
from pathlib import Path, PureWindowsPath
from unittest.mock import patch

import pytest

from envdrift.utils.git import (
    ensure_gitignore_entries,
    get_file_from_git,
    get_git_root,
    has_git_head,
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


def unignored_paths(paths: list[Path], **kwargs) -> list[tuple[str, str | None]]:
    """``envdrift.utils.git.unignored_paths``, imported here so this module still
    collects, and its other tests still run, against code without it."""
    from envdrift.utils.git import unignored_paths as _unignored_paths

    return _unignored_paths(paths, **kwargs)


def _git(cwd: Path, *args: str) -> None:
    config = ["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"]
    subprocess.run(["git", *config, *args], cwd=cwd, check=True, capture_output=True)


def _repo(path: Path) -> Path:
    """A new repository at ``path``, as git spells its root (macOS: /private/var)."""
    path.mkdir(parents=True, exist_ok=True)
    _git(path, "init", "-q")
    return path.resolve()


def _untracked(repo: Path) -> set[str]:
    """What ``git add -A`` in ``repo`` would add: its untracked files, by path.

    Read from ``git status``, which names every file, so a path is never taken for
    options or pathspec magic. The user's global excludes file does not count.
    """
    status = subprocess.run(
        [
            "git",
            "-c",
            "core.excludesfile=/dev/null",
            "status",
            "--porcelain",
            "-z",
            "--untracked-files=all",
        ],
        cwd=repo,
        capture_output=True,
        check=True,
    ).stdout
    return {os.fsdecode(entry[3:]) for entry in status.split(b"\0") if entry.startswith(b"?? ")}


def _without_git(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Take git off PATH, so that git cannot run."""
    empty = tmp_path / "no-git-here"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))


def _corrupt_index(repo: Path) -> None:
    """Make git check-ignore fail in ``repo`` (exit 128); git still reports its root."""
    (repo / ".git" / "index").write_bytes(b"not an index")


def _superproject(tmp_path: Path) -> tuple[Path, Path]:
    """A repository with a real submodule at ``sub``: (superproject, submodule)."""
    upstream = _repo(tmp_path / "upstream")
    _git(upstream, "commit", "-q", "--allow-empty", "-m", "init")
    superproject = _repo(tmp_path / "super")
    _git(
        superproject,
        "-c",
        "protocol.file.allow=always",
        "submodule",
        "add",
        "-q",
        "../upstream",
        "sub",
    )
    return superproject, superproject / "sub"


class TestUnignoredPaths:
    """``unignored_paths`` asks git, after the entries are written, what it still sees."""

    def test_lists_a_path_a_deeper_rule_re_includes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True, check=True)
        (tmp_path / "config").mkdir()
        (tmp_path / "config" / ".gitignore").write_text("!.env.keys\n", encoding="utf-8")
        key_file = tmp_path / "config" / ".env.keys"
        monkeypatch.chdir(tmp_path)  # shown relative to this repository's root

        assert ensure_gitignore_entries([key_file]) == ["config/.env.keys"]
        # None: git answered that it does not ignore the file, it did not fail.
        assert unignored_paths([key_file]) == [("config/.env.keys", None)]

    def test_an_ignored_path_is_not_listed(self, tmp_path: Path) -> None:
        subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True, check=True)
        (tmp_path / "config").mkdir()
        key_file = tmp_path / "config" / ".env.keys"

        ensure_gitignore_entries([key_file])

        assert unignored_paths([key_file]) == []

    def test_paths_outside_the_repository_are_not_listed(self, tmp_path: Path) -> None:
        repo = tmp_path / "repo"
        repo.mkdir()
        subprocess.run(["git", "init"], cwd=repo, capture_output=True, check=True)

        assert unignored_paths([tmp_path / "elsewhere" / ".env.keys"], git_root=repo) == []

    def test_a_path_is_listed_when_git_cannot_run(self, tmp_path: Path) -> None:
        """No git to ask: the path is listed, saying so, and the entry is still written.

        It used to be left out, so push went on as if git had said it ignores the key.
        """
        key_file = tmp_path / "config" / ".env.keys"

        with patch("subprocess.run", side_effect=FileNotFoundError("git")):
            assert unignored_paths([key_file], git_root=tmp_path.resolve()) == [
                ("config/.env.keys", "git could not run: git")
            ]
            assert ensure_gitignore_entries([key_file], git_root=tmp_path.resolve()) == [
                "config/.env.keys"
            ]

    def test_a_path_is_listed_when_git_times_out(self, tmp_path: Path) -> None:
        """A git check-ignore that times out gave no answer: listed, saying so."""
        key_file = tmp_path / "config" / ".env.keys"

        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("git", 10)):
            assert unignored_paths([key_file], git_root=tmp_path.resolve()) == [
                ("config/.env.keys", "git check-ignore timed out")
            ]

    def test_a_path_in_a_repository_is_listed_when_git_is_not_installed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """git cannot even report the repository, but its ``.git`` is there: listed."""
        repo = _repo(tmp_path / "repo")
        key_file = repo / "config" / ".env.keys"
        _without_git(monkeypatch, tmp_path)

        assert unignored_paths([key_file]) == [
            (key_file.as_posix(), f"git did not report the repository at {repo}")
        ]

    def test_a_path_git_fails_for_is_listed_with_git_s_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """git check-ignore exits 128: the path is listed, with git's error, not left out."""
        repo = _repo(tmp_path / "repo")
        _corrupt_index(repo)
        monkeypatch.chdir(repo)

        listed = unignored_paths([repo / "config" / ".env.keys"])

        assert len(listed) == 1, listed
        shown, reason = listed[0]
        assert shown == "config/.env.keys"
        assert reason is not None and reason.startswith("git check-ignore exited 128: fatal:"), (
            reason
        )

    @pytest.mark.parametrize("re_included", [True, False], ids=["re-included", "ignored"])
    def test_a_path_starting_with_a_dash_is_a_path_not_options(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, re_included: bool
    ) -> None:
        """git read ``-secrets/.env.keys`` as options and exited 129, which counted as ignored.

        So a ``!`` rule in ``-secrets/.gitignore`` left the private key stageable while push
        went on.
        """
        repo = _repo(tmp_path / "repo")
        (repo / "-secrets").mkdir()
        if re_included:
            (repo / "-secrets" / ".gitignore").write_text("!.env.keys\n", encoding="utf-8")
        key_file = repo / "-secrets" / ".env.keys"
        key_file.write_text("DOTENV_PRIVATE_KEY=k\n", encoding="utf-8")
        monkeypatch.chdir(repo)

        assert ensure_gitignore_entries([key_file]) == ["-secrets/.env.keys"]

        if re_included:
            assert unignored_paths([key_file]) == [("-secrets/.env.keys", None)]
            assert "-secrets/.env.keys" in _untracked(repo)
        else:
            assert unignored_paths([key_file]) == []
            assert "-secrets/.env.keys" not in _untracked(repo)

    @pytest.mark.skipif(sys.platform == "win32", reason="':' is not allowed in a Windows name")
    def test_a_path_starting_with_a_colon_is_not_read_as_pathspec_magic(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """git read ``:secrets/.env.keys`` as the pathspec ``secrets/.env.keys``, and said
        that one is ignored (by ``secrets/.gitignore``). So no entry was written for the
        key in ``:secrets``, and ``git add`` staged it.
        """
        repo = _repo(tmp_path / "repo")
        (repo / "secrets").mkdir()
        (repo / "secrets" / ".gitignore").write_text(".env.keys\n", encoding="utf-8")
        (repo / ":secrets").mkdir()
        key_file = repo / ":secrets" / ".env.keys"
        key_file.write_text("DOTENV_PRIVATE_KEY=k\n", encoding="utf-8")
        monkeypatch.chdir(repo)

        assert ensure_gitignore_entries([key_file]) == [":secrets/.env.keys"]
        assert ":secrets/.env.keys" not in _untracked(repo)
        assert unignored_paths([key_file]) == []

        (repo / ":secrets" / ".gitignore").write_text("!.env.keys\n", encoding="utf-8")
        assert unignored_paths([key_file]) == [(":secrets/.env.keys", None)]

    def test_nothing_is_listed_outside_a_repository(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)  # not the envdrift checkout the suite runs in

        assert unignored_paths([tmp_path / ".env.keys"]) == []


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
class TestSubmodules:
    """A key file in a git submodule is ignored, and checked, in the submodule.

    ``git add`` in a submodule never reads the superproject's .gitignore, and
    ``git check-ignore`` in the superproject exits 128 for a path in a submodule. Both
    helpers used the first path's repository for every path, so the submodule's key went
    in the superproject's .gitignore, where it ignores nothing, and the 128 was dropped:
    push went on with a key ``git add .`` in the submodule stages. With the submodule's
    environment first, the main checkout's key got no entry at all.
    """

    @pytest.mark.parametrize("submodule_first", [False, True], ids=["main-first", "sub-first"])
    def test_each_entry_goes_in_the_repository_that_would_stage_it(
        self, tmp_path: Path, submodule_first: bool
    ) -> None:
        superproject, submodule = _superproject(tmp_path)
        key_files = [superproject / "config" / ".env.keys", submodule / "config" / ".env.keys"]
        for key_file in key_files:
            key_file.parent.mkdir()
            key_file.write_text("DOTENV_PRIVATE_KEY=k\n", encoding="utf-8")
        if submodule_first:
            key_files.reverse()

        added = ensure_gitignore_entries(key_files)

        assert added == ["config/.env.keys", "config/.env.keys"]
        for repo in (superproject, submodule):
            gitignore = (repo / ".gitignore").read_text(encoding="utf-8")
            assert gitignore.splitlines() == ["config/.env.keys"], (repo, gitignore)
            assert "config/.env.keys" not in _untracked(repo), repo
        assert unignored_paths(key_files) == []

    def test_a_key_file_a_submodule_rule_re_includes_is_named_with_its_folder(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        superproject, submodule = _superproject(tmp_path)
        (submodule / "config").mkdir()
        (submodule / "config" / ".gitignore").write_text("!.env.keys\n", encoding="utf-8")
        key_file = submodule / "config" / ".env.keys"
        monkeypatch.chdir(superproject)

        assert ensure_gitignore_entries([key_file]) == ["config/.env.keys"]
        assert unignored_paths([key_file]) == [("sub/config/.env.keys", None)]

    def test_a_path_git_cannot_answer_for_in_the_given_repository_is_listed(
        self, tmp_path: Path
    ) -> None:
        """Asked in the superproject, git exits 128 for the submodule's key: listed."""
        superproject, submodule = _superproject(tmp_path)

        listed = unignored_paths([submodule / "config" / ".env.keys"], git_root=superproject)

        assert len(listed) == 1, listed
        shown, reason = listed[0]
        assert shown == "sub/config/.env.keys"
        assert reason is not None and reason.startswith("git check-ignore exited 128"), reason
        assert "submodule" in reason, reason


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


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
class TestEnsureGitignoreGlob:
    """N2: backups of ``.env.keys`` are ignored by a folder-scoped glob."""

    @staticmethod
    def _repo(tmp_path: Path) -> Path:
        subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)  # nosec B603 B607
        return tmp_path

    def test_outside_a_repository_nothing_changes(self, tmp_path: Path):
        from envdrift.utils.git import ensure_gitignore_glob

        assert ensure_gitignore_glob(tmp_path / ".env.keys.backup.1", ".env.keys.backup.*") is None
        assert not (tmp_path / ".gitignore").exists()

    def test_root_folder_entry_has_no_prefix(self, tmp_path: Path):
        from envdrift.utils.git import ensure_gitignore_glob

        repo = self._repo(tmp_path)
        (repo / ".gitignore").write_text("node_modules", encoding="utf-8")  # no trailing newline

        added = ensure_gitignore_glob(repo / ".env.keys.backup.1", ".env.keys.backup.*")

        assert added == ".env.keys.backup.*"
        assert (repo / ".gitignore").read_text(encoding="utf-8") == (
            "node_modules\n.env.keys.backup.*\n"
        )

    def test_an_already_ignored_name_adds_nothing(self, tmp_path: Path):
        from envdrift.utils.git import ensure_gitignore_glob

        repo = self._repo(tmp_path)
        (repo / ".gitignore").write_text("*.backup.*\n", encoding="utf-8")

        assert (
            ensure_gitignore_glob(repo / "svc" / ".env.keys.backup.1", ".env.keys.backup.*") is None
        )
        assert (repo / ".gitignore").read_text(encoding="utf-8") == "*.backup.*\n"

    def test_a_folder_starting_with_a_dash(self, tmp_path: Path):
        """git read ``-svc/...`` as options and never said the backups were ignored, so
        every backup there was refused over a ``!`` rule that was not there."""
        from envdrift.utils.git import ensure_gitignore_glob

        repo = self._repo(tmp_path)
        (repo / "-svc").mkdir()
        sample = repo / "-svc" / ".env.keys.backup.1"

        assert ensure_gitignore_glob(sample, ".env.keys.backup.*") == "-svc/.env.keys.backup.*"
        sample.write_text("DOTENV_PRIVATE_KEY=k\n", encoding="utf-8")
        assert "-svc/.env.keys.backup.1" not in _untracked(repo)

    @pytest.mark.skipif(sys.platform == "win32", reason="':' is not allowed in a Windows name")
    def test_a_folder_starting_with_a_colon(self, tmp_path: Path):
        """git read ``:svc/...`` as the pathspec ``svc/...``, which ``svc/.gitignore``
        ignores, so no entry was written and the backups in ``:svc`` were stageable."""
        from envdrift.utils.git import ensure_gitignore_glob

        repo = self._repo(tmp_path)
        (repo / "svc").mkdir()
        (repo / "svc" / ".gitignore").write_text("*.backup.*\n", encoding="utf-8")
        (repo / ":svc").mkdir()
        sample = repo / ":svc" / ".env.keys.backup.1"

        assert ensure_gitignore_glob(sample, ".env.keys.backup.*") == ":svc/.env.keys.backup.*"
        sample.write_text("DOTENV_PRIVATE_KEY=k\n", encoding="utf-8")
        assert ":svc/.env.keys.backup.1" not in _untracked(repo)

    def test_git_failing_is_not_called_a_rule(self, tmp_path: Path):
        """git cannot say (exit 128): the error names git's failure, not a ``!`` rule."""
        from envdrift.utils.git import GitignoreOverrideError, ensure_gitignore_glob

        repo = self._repo(tmp_path)
        _corrupt_index(repo)

        with pytest.raises(OSError) as caught:
            ensure_gitignore_glob(repo / ".env.keys.backup.1", ".env.keys.backup.*")

        assert not isinstance(caught.value, GitignoreOverrideError)
        message = str(caught.value)
        assert message.startswith(
            "envdrift cannot make sure git ignores .env.keys.backup.1: git check-ignore exited 128"
        ), message
