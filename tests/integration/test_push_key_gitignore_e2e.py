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


def _write_bad_secrets_only_config(directory: Path, case: str) -> str:
    """A secrets-only ``staging`` that push refuses, listed before a valid ``production``.

    Returns the error the command gives for ``staging``. Naming its key files used to
    crash before any environment ran: ``Path.glob`` raised NotImplementedError for an
    absolute pattern, and git NotADirectoryError for a key path below a regular file.
    ``production`` is secrets-only too: a combined file would come first in the list
    of paths to gitignore and hide the second crash.
    """
    if case == "absolute-pattern":
        (directory / "staging").mkdir()
        (directory / "staging" / ".env.api").write_text("API=" + "v1\n", encoding="utf-8")
        staging = f'secrets_dir = "staging"\npattern = "{(directory / ".env*").as_posix()}"\n'
        error = "staging: Non-relative patterns are unsupported"
    else:
        (directory / ".env.secrets").write_text("API=" + "v1\n", encoding="utf-8")
        staging = 'secrets_dir = ".env.secrets"\n'
        error = "staging: secrets_dir not found or not a directory: .env.secrets"
    (directory / "envdrift.toml").write_text(
        "[partial_encryption]\n"
        "enabled = true\n\n"
        "[[partial_encryption.environments]]\n"
        'name = "staging"\n'
        "secrets_only = true\n"
        f"{staging}\n"
        "[[partial_encryption.environments]]\n"
        'name = "production"\n'
        "secrets_only = true\n"
        'secrets_dir = "secrets"\n',
        encoding="utf-8",
    )
    (directory / "secrets").mkdir()
    (directory / "secrets" / ".env.prod").write_text(f"JWT_SECRET={_JWT_VALUE}\n", encoding="utf-8")
    return error


@pytest.mark.parametrize("case", ["absolute-pattern", "secrets-dir-is-a-file"])
class TestBadSecretsOnlyConfigIsReportedPerEnvironment:
    """A bad secrets-only environment is an error for it alone, as it was before #961."""

    def test_push_reports_it_and_still_pushes_the_other_environment(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str], case: str
    ) -> None:
        error = _write_bad_secrets_only_config(git_repo, case)

        result = _run_envdrift(
            ["push"],
            cwd=git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        out = _flat(result)
        assert result.returncode == 1, out
        assert "Traceback" not in out, out
        assert f"• {error}" in out, out
        assert "Encrypted 1 file(s) in secrets" in out, out
        secret = (git_repo / "secrets" / ".env.prod").read_text(encoding="utf-8")
        assert "JWT_SECRET=encrypted:" in secret, secret
        _assert_ignored(git_repo, "secrets/.env.keys")

    def test_pull_partial_reports_it_and_still_pulls_the_other_environment(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str], case: str
    ) -> None:
        error = _write_bad_secrets_only_config(git_repo, case)

        result = _run_envdrift(
            ["pull-partial"],
            cwd=git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        out = _flat(result)
        assert result.returncode == 1, out
        assert "Traceback" not in out, out
        assert f"• {error}" in out, out
        assert "secrets (all 1 file(s) already decrypted)" in out, out
