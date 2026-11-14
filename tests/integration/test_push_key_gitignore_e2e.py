"""``push`` / ``pull-partial`` gitignore the key files dotenvx really writes (#961).

``DotenvxWrapper`` passes ``-fk`` with the ``.env.keys`` next to the secret file,
so dotenvx writes the private key there. ``push`` (and ``pull-partial``) added
``./.env.keys`` in the working directory to ``.gitignore`` instead. From the
repository root a bare ``.env.keys`` entry matches at any depth, which hid the
bug; from a subdirectory the entry is anchored (``app/.env.keys``) and the real
key file (``app/config/.env.keys``) stayed visible, so ``git add .`` staged the
private key. With a recursive secrets-only pattern, dotenvx writes one key file
per folder, and none was ignored.

Every test runs the real ``envdrift`` CLI, the real dotenvx binary and real git,
and asks git itself whether the key files are ignored.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        shutil.which("dotenvx") is None,
        reason="dotenvx binary not installed (required to write real .env.keys files)",
    ),
]

# Built by concatenation so push protection never sees a whole secret literal.
_JWT_VALUE = "super-" + "secret-" + "key"


def _run_envdrift(
    args: list[str],
    *,
    cwd: Path,
    integration_pythonpath: str,
    envdrift_cmd: list[str],
) -> subprocess.CompletedProcess[str]:
    """Run the real envdrift CLI as a subprocess and capture its output."""
    env = os.environ.copy()
    env["PYTHONPATH"] = integration_pythonpath
    return subprocess.run(
        [*envdrift_cmd, *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


def _flat(result: subprocess.CompletedProcess[str]) -> str:
    return " ".join((result.stdout + result.stderr).split())


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, check=check)


def _assert_ignored(repo: Path, key_file: str) -> None:
    """The key file exists, git ignores it, and `git add -A` does not stage it."""
    assert (repo / key_file).is_file(), f"dotenvx did not write {key_file}"
    assert _git(repo, "check-ignore", "-q", key_file, check=False).returncode == 0, (
        f"{key_file} is not gitignored; .gitignore:\n"
        + (repo / ".gitignore").read_text(encoding="utf-8")
    )
    untracked = _git(repo, "status", "--porcelain", "--untracked-files=all").stdout
    assert key_file not in untracked, untracked
    _git(repo, "add", "-A")
    staged = _git(repo, "diff", "--cached", "--name-only").stdout.split()
    assert key_file not in staged, staged


def _write_combine_config(directory: Path) -> None:
    (directory / "envdrift.toml").write_text(
        "[partial_encryption]\n"
        "enabled = true\n\n"
        "[[partial_encryption.environments]]\n"
        'name = "production"\n'
        'clear_file = "config/.env.production.clear"\n'
        'secret_file = "config/.env.production.secret"\n'
        'combined_file = "config/.env.production"\n',
        encoding="utf-8",
    )
    (directory / "config").mkdir()
    (directory / "config" / ".env.production.clear").write_text("DEBUG=false\n", encoding="utf-8")
    (directory / "config" / ".env.production.secret").write_text(
        f"JWT_SECRET={_JWT_VALUE}\n", encoding="utf-8"
    )


class TestPushIgnoresTheRealKeyFile:
    def test_combine_mode_from_a_repository_subdirectory(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        app = git_repo / "app"
        app.mkdir()
        _write_combine_config(app)

        result = _run_envdrift(
            ["push"],
            cwd=app,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        assert result.returncode == 0, _flat(result)
        assert "app/config/.env.keys" in _flat(result)
        _assert_ignored(git_repo, "app/config/.env.keys")

    def test_secrets_only_recursive_pattern_from_a_subdirectory(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        sub = git_repo / "sub"
        (sub / "secrets" / "api").mkdir(parents=True)
        (sub / "secrets" / "db").mkdir()
        (sub / "envdrift.toml").write_text(
            "[partial_encryption]\n"
            "enabled = true\n\n"
            "[[partial_encryption.environments]]\n"
            'name = "production"\n'
            "secrets_only = true\n"
            'secrets_dir = "secrets"\n'
            'pattern = "**/.env*"\n',
            encoding="utf-8",
        )
        (sub / "secrets" / ".env.top").write_text("TOP=" + "v0\n", encoding="utf-8")
        (sub / "secrets" / "api" / ".env.api").write_text("API=" + "v1\n", encoding="utf-8")
        (sub / "secrets" / "db" / ".env.db").write_text("DB=" + "v2\n", encoding="utf-8")

        result = _run_envdrift(
            ["push"],
            cwd=sub,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        assert result.returncode == 0, _flat(result)
        for key_file in (
            "sub/secrets/.env.keys",
            "sub/secrets/api/.env.keys",
            "sub/secrets/db/.env.keys",
        ):
            _assert_ignored(git_repo, key_file)

    def test_combine_mode_from_the_repository_root(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        """Non-regression: the case that used to hide the bug still works."""
        _write_combine_config(git_repo)

        result = _run_envdrift(
            ["push"],
            cwd=git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        assert result.returncode == 0, _flat(result)
        _assert_ignored(git_repo, "config/.env.keys")


def test_pull_partial_ignores_a_key_file_placed_next_to_the_secret_file(
    git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
) -> None:
    """A teammate puts the shared key beside the secret file, then pulls."""
    app = git_repo / "app"
    app.mkdir()
    _write_combine_config(app)
    push = _run_envdrift(
        ["push"], cwd=app, integration_pythonpath=integration_pythonpath, envdrift_cmd=envdrift_cmd
    )
    assert push.returncode == 0, _flat(push)
    _git(git_repo, "add", "app/envdrift.toml", "app/config/.env.production.clear")
    _git(git_repo, "add", "app/config/.env.production.secret")
    _git(git_repo, "commit", "-q", "-m", "encrypted secret")
    # A fresh clone has no .gitignore entries yet; the key arrives out of band.
    (git_repo / ".gitignore").unlink()

    pull = _run_envdrift(
        ["pull-partial"],
        cwd=app,
        integration_pythonpath=integration_pythonpath,
        envdrift_cmd=envdrift_cmd,
    )

    assert pull.returncode == 0, _flat(pull)
    _assert_ignored(git_repo, "app/config/.env.keys")
