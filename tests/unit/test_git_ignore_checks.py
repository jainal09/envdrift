"""git ignores the files envdrift asks it to, as git itself answers.

After envdrift writes a .gitignore entry, ``unignored_paths`` and
``ensure_gitignore_glob`` ask git whether it ignores the file, in the repository that
would stage it (a submodule's, for a file in one). Both fail closed: a path counts as
exposed unless git says it ignores it.
"""

from __future__ import annotations

import os
import shutil
import subprocess  # nosec B404
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from envdrift.utils.git import ensure_gitignore_entries


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


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
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
