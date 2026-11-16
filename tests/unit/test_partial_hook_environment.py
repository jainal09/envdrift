"""pull-partial and push mark a secret file in the repository that tracks it, even in a git hook.

After a decrypt, envdrift marks the plaintext secret file ``git update-index --skip-worktree``,
so that a plain ``git add .`` does not stage it, and runs git in the file's folder (``git -C``),
so that a file in a submodule is marked in the submodule. In a git hook, though, git exports
GIT_INDEX_FILE, GIT_DIR and the like (githooks(5)), and they beat ``-C``. Run from a
superproject's hook, git marked the superproject's file at the same path and exited 0: the pull
called the submodule's plaintext protected while ``git add .`` in the submodule staged it.
Without such a file the mark failed, and the warning called a tracked file untracked, or outside
a git repository. And in a linked worktree's hook, whose GIT_DIR makes git take the folder it
runs in for the top of the work tree, a tracked file in a subdirectory could not be marked.

Everything here runs real git in real repositories, with the variables git exports to a hook
set as git sets them. Only dotenvx's decrypt is a stand-in, in the ``pull-partial`` test.
"""

from __future__ import annotations

import os
import shutil
import subprocess  # nosec B404
import sys
from collections.abc import Mapping
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

import envdrift
from envdrift.cli import app
from envdrift.config import PartialEncryptionEnvironmentConfig
from envdrift.core.partial_encryption import (
    _git_skip_worktree,
    push_partial_encryption,
    unprotected_reason,
)

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")

# The variables the tests export as a git hook gets them. The helper git below never sees them.
_HOOK_VARIABLES = ("GIT_DIR", "GIT_INDEX_FILE", "GIT_WORK_TREE")

# How git runs a hook of the superproject, by the variables it exports to it.
_HOOKS = [
    # git commit -a: the index it is about to commit, which it renames over .git/index after.
    "commit -a",
    # A plain git commit: the index, as a path relative to the top of the work tree.
    "commit",
    # GIT_DIR, as git gives a linked worktree's hooks, here with its index.
    "GIT_DIR",
    # GIT_DIR with GIT_WORK_TREE, as ``git --git-dir=... --work-tree=...`` exports them.
    "GIT_WORK_TREE",
]

_ENCRYPTED = 'DOTENV_PUBLIC_KEY_PRODUCTION="03abc"\nJWT_SECRET="encrypted:BAAA"\n'


def _git(cwd: Path, *args: str, env: Mapping[str, str] | None = None) -> str:
    """Run git in ``cwd``, outside the hook unless ``env`` is given."""
    if env is None:
        env = {key: value for key, value in os.environ.items() if key not in _HOOK_VARIABLES}
    config = ["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"]
    return subprocess.run(
        ["git", *config, *args], cwd=cwd, env=env, capture_output=True, text=True, check=True
    ).stdout


def _flag(repo: Path, path: str, *, in_the_hook: bool = False) -> str:
    """``git ls-files -v``'s tag for ``path`` in ``repo``: ``S`` skip-worktree, ``H`` tracked.

    Asked outside the hook, or ``in_the_hook``: of the index the hook's git uses.
    """
    env = dict(os.environ) if in_the_hook else None
    return _git(repo, "ls-files", "-v", "--", path, env=env).split(" ", 1)[0]


@pytest.fixture
def superproject(tmp_path: Path) -> Path:
    """A superproject with a real submodule at ``sub``; both track ``config/.env.secret``.

    The submodule tracks ``config/.env.other`` too, which the superproject does not.
    """
    upstream = tmp_path / "upstream"
    (upstream / "config").mkdir(parents=True)
    _git(upstream, "init", "-q")
    for name in (".env.secret", ".env.other"):
        (upstream / "config" / name).write_text("JWT_SECRET=" + "sub-plain\n", encoding="utf-8")
    _git(upstream, "add", ".")
    _git(upstream, "commit", "-q", "-m", "upstream")
    superproject = tmp_path / "super"
    (superproject / "config").mkdir(parents=True)
    _git(superproject, "init", "-q")
    (superproject / "config" / ".env.secret").write_text(
        "JWT_SECRET=" + "super-plain\n", encoding="utf-8"
    )
    _git(superproject, "add", ".")
    _git(superproject, "commit", "-q", "-m", "superproject")
    allow_local = ("-c", "protocol.file.allow=always")  # git refuses a local one otherwise
    _git(superproject, *allow_local, "submodule", "add", "-q", "../upstream", "sub")
    _git(superproject, "commit", "-q", "-m", "submodule")
    return superproject.resolve()  # as git spells it (macOS: /private/var)


def _in_a_hook_of(superproject: Path, hook: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Export the variables git gives ``hook`` (see ``_HOOKS``), and run where git runs it."""
    git_dir = superproject / ".git"
    if hook == "commit -a":
        shutil.copyfile(git_dir / "index", git_dir / "index.lock")
        monkeypatch.setenv("GIT_INDEX_FILE", str(git_dir / "index.lock"))
    elif hook == "commit":
        monkeypatch.setenv("GIT_INDEX_FILE", ".git/index")
    elif hook == "GIT_DIR":
        monkeypatch.setenv("GIT_DIR", str(git_dir))
        monkeypatch.setenv("GIT_INDEX_FILE", str(git_dir / "index"))
    else:
        monkeypatch.setenv("GIT_DIR", str(git_dir))
        monkeypatch.setenv("GIT_WORK_TREE", str(superproject))
    monkeypatch.chdir(superproject)  # git runs a hook at the top of the work tree


def _environment(folder: Path) -> PartialEncryptionEnvironmentConfig:
    """A combine-mode environment whose files are in ``folder``."""
    (folder / ".env.production.clear").write_text("DEBUG=false\n", encoding="utf-8")
    return PartialEncryptionEnvironmentConfig(
        name="production",
        clear_file=str(folder / ".env.production.clear"),
        secret_file=str(folder / ".env.secret"),
        combined_file=str(folder / ".env.production"),
    )


@pytest.mark.parametrize("hook", _HOOKS)
class TestInASuperprojectsHook:
    def test_a_submodule_file_is_marked_in_the_submodule(
        self, superproject: Path, monkeypatch: pytest.MonkeyPatch, hook: str
    ) -> None:
        """The superproject's file at the same path got the mark, or the mark failed."""
        _in_a_hook_of(superproject, hook, monkeypatch)

        assert _git_skip_worktree(superproject / "sub" / "config" / ".env.secret") is True

        assert _flag(superproject / "sub", "config/.env.secret") == "S"
        assert _flag(superproject, "config/.env.secret", in_the_hook=True) == "H"

    def test_push_lifts_the_mark_in_the_submodule(
        self, superproject: Path, monkeypatch: pytest.MonkeyPatch, hook: str
    ) -> None:
        """push lifts the mark from a submodule file it encrypted: git sees the ciphertext."""
        submodule = superproject / "sub"
        environment = _environment(submodule / "config")
        (submodule / "config" / ".env.secret").write_text(_ENCRYPTED, encoding="utf-8")
        _git(submodule, "update-index", "--skip-worktree", "--", "config/.env.secret")
        _in_a_hook_of(superproject, hook, monkeypatch)

        push_partial_encryption(environment)

        assert _flag(submodule, "config/.env.secret") == "H"
        assert _flag(superproject, "config/.env.secret", in_the_hook=True) == "H"

    def test_the_reason_is_the_submodules(
        self, superproject: Path, monkeypatch: pytest.MonkeyPatch, hook: str
    ) -> None:
        """A tracked submodule file git cannot mark, while another git holds the submodule's
        index, was called untracked or outside a git repository: git asked the hook's index."""
        submodule = superproject / "sub"
        git_dir = Path(_git(submodule, "rev-parse", "--absolute-git-dir").strip())
        (git_dir / "index.lock").write_text("", encoding="utf-8")
        other = submodule / "config" / ".env.other"
        _in_a_hook_of(superproject, hook, monkeypatch)

        assert _git_skip_worktree(other) is False
        assert unprotected_reason(other) == "skip-worktree failed"

    def test_a_file_outside_every_repository_is_named_so(
        self,
        superproject: Path,
        tmp_path_factory: pytest.TempPathFactory,
        monkeypatch: pytest.MonkeyPatch,
        hook: str,
    ) -> None:
        """With GIT_DIR, git asked the superproject's index, and called the file untracked."""
        outside = tmp_path_factory.mktemp("outside") / ".env.secret"
        outside.write_text("JWT_SECRET=" + "plain\n", encoding="utf-8")
        _in_a_hook_of(superproject, hook, monkeypatch)

        assert _git_skip_worktree(outside) is False
        assert unprotected_reason(outside) == "outside a git repository"

    def test_a_file_of_the_hooks_own_repository_is_marked_in_the_index_it_commits(
        self, superproject: Path, monkeypatch: pytest.MonkeyPatch, hook: str
    ) -> None:
        """The hook's variables name the file's own repository: git keeps them, and marks the
        index the hook commits. With GIT_DIR, git took the file's folder for the top of the work
        tree, and could not mark it."""
        _in_a_hook_of(superproject, hook, monkeypatch)

        assert _git_skip_worktree(superproject / "config" / ".env.secret") is True

        assert _flag(superproject, "config/.env.secret", in_the_hook=True) == "S"
        if hook == "commit -a":  # git commits that index: it becomes .git/index
            (superproject / ".git" / "index.lock").replace(superproject / ".git" / "index")
        assert _flag(superproject, "config/.env.secret") == "S"


def test_a_linked_worktrees_hook_marks_a_file_in_a_subdirectory(
    superproject: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """git gives a linked worktree's hooks (post-checkout, pre-commit) its GIT_DIR, which made git
    take the secret file's folder for the top of the work tree: the file read as untracked."""
    worktree = tmp_path / "worktree"
    _git(superproject, "worktree", "add", "-q", str(worktree))
    worktree = worktree.resolve()
    monkeypatch.setenv("GIT_DIR", _git(worktree, "rev-parse", "--absolute-git-dir").strip())
    monkeypatch.chdir(worktree)

    assert _git_skip_worktree(worktree / "config" / ".env.secret") is True

    assert _flag(worktree, "config/.env.secret") == "S"


def _decrypt(path: Path) -> None:
    """Stand-in for a dotenvx decrypt that succeeds: each value in plaintext."""
    path.write_text(path.read_text(encoding="utf-8").replace("encrypted:BAAA", "decrypted"))


def test_pull_partial_in_a_superprojects_hook_protects_the_submodules_secret(
    superproject: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The real pull-partial, from the superproject's ``git commit -a`` hook.

    It said a submodule's decrypted secret file was marked skip-worktree, while the mark had
    gone on the superproject's file at the same path, and ``git add .`` in the submodule staged
    the plaintext.
    """
    submodule = superproject / "sub"
    (submodule / "config" / ".env.secret").write_text(_ENCRYPTED, encoding="utf-8")
    _git(submodule, "commit", "-q", "-a", "-m", "encrypted")
    (superproject / "envdrift.toml").write_text(
        "[partial_encryption]\n"
        "enabled = true\n\n"
        "[[partial_encryption.environments]]\n"
        'name = "production"\n'
        'clear_file = "sub/config/.env.production.clear"\n'
        'secret_file = "sub/config/.env.secret"\n'
        'combined_file = "sub/config/.env.production"\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("COLUMNS", "1000")  # no path in a panel is folded mid-path
    _in_a_hook_of(superproject, "commit -a", monkeypatch)

    with patch("envdrift.core.partial_encryption.DotenvxWrapper") as wrapper:
        wrapper.return_value.decrypt.side_effect = _decrypt
        result = CliRunner().invoke(app, ["pull-partial"])

    output = " ".join(result.output.replace("│", " ").split())
    assert result.exit_code == 0, output
    assert "Decrypted: 1" in output, output
    assert "No Git Protection Applied" not in output, output
    assert "They are marked skip-worktree" in output, output
    assert _flag(submodule, "config/.env.secret") == "S"
    assert _flag(superproject, "config/.env.secret", in_the_hook=True) == "H"
    assert "config/.env.secret" not in _git(submodule, "add", "--dry-run", "-A")


class _KnownLostMarkError(AssertionError):
    """The false success #1031 describes; any other failure stays a real test failure."""


@pytest.mark.xfail(
    strict=False,
    raises=_KnownLostMarkError,
    reason="a mark made in a partial commit's hook is lost with its index (see #1031)",
)
def test_a_mark_a_partial_commit_drops_is_not_called_applied(tmp_path: Path) -> None:
    """``git commit <path>`` gives its hooks a temporary index, which git discards after.

    A real ``pre-commit`` hook marks the secret file. The mark goes into that index, so
    envdrift must not call the file protected unless the mark is still there once the
    commit is done.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "config").mkdir()
    (repo / "config" / ".env.secret").write_text("API_KEY=x\n", encoding="utf-8")
    (repo / "a.txt").write_text("a\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "init")
    hooks = repo / ".git" / "hooks"
    hooks.mkdir(exist_ok=True)
    mark = (
        "from pathlib import Path; "
        "from envdrift.core.partial_encryption import _git_skip_worktree; "
        "print('MARKED=' + str(_git_skip_worktree(Path('config/.env.secret').resolve())))"
    )
    python = Path(sys.executable).as_posix()
    (hooks / "pre-commit").write_text(f'#!/bin/sh\nexec "{python}" -c "{mark}"\n', encoding="utf-8")
    (hooks / "pre-commit").chmod(0o755)
    (repo / "a.txt").write_text("a\nb\n", encoding="utf-8")
    env = {key: value for key, value in os.environ.items() if key not in _HOOK_VARIABLES}
    env["PYTHONPATH"] = str(Path(envdrift.__file__).resolve().parents[1])

    commit = subprocess.run(
        ["git", "-c", f"core.hooksPath={hooks.as_posix()}", "-c", "user.name=t"]
        + ["-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"]
        + ["commit", "-qm", "partial", "a.txt"],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
    )

    hook_output = commit.stdout + commit.stderr  # git sends a hook's stdout to stderr
    assert commit.returncode == 0, hook_output
    assert "MARKED=" in hook_output, hook_output
    marked = "MARKED=True" in hook_output
    flag = _flag(repo, "config/.env.secret")
    if marked and flag == "H":
        raise _KnownLostMarkError("the hook's mark was called applied; .git/index has H")
    assert not marked or flag == "S", (hook_output, flag)
