"""``pull-partial`` / ``pull`` failure modes against the real CLI, dotenvx and git.

Every test runs the real ``envdrift`` CLI as a subprocess and asserts the true
outcome: the exit code, the summary, the bytes on disk, and git's view.

- #948: dotenvx decrypts value by value. With one value encrypted under another
  key it writes the values it could decrypt and exits 1. ``pull-partial`` then
  raised before marking the file skip-worktree, so the plaintext sat in a
  tracked file that ``git add .`` staged, under ``Decrypted: 0``. The failed
  file must be left as it was; in secrets-only mode the files decrypted before
  it must be counted, protected, and announced by the plaintext notice.
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
        reason="dotenvx binary not installed (required for real pull-partial failures)",
    ),
]

# Built by concatenation so push protection never sees a whole secret literal.
_JWT_VALUE = "super-" + "secret-" + "key"
_API_VALUE = "api-" + "secret-" + "value"
_DB_VALUE = "db-" + "secret-" + "value"
_FOREIGN_VALUE = "sk_" + "other_" + "abc123"


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
    """stdout+stderr with whitespace collapsed, so wrapping cannot split a phrase."""
    return " ".join((result.stdout + result.stderr).split())


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True, check=True
    ).stdout


def _append_foreign_value(
    repo: Path,
    target: Path,
    *,
    integration_pythonpath: str,
    envdrift_cmd: list[str],
) -> None:
    """Append a ``STRIPE_API_KEY`` line encrypted under another folder's key."""
    other = repo / "other" / target.name
    other.parent.mkdir(exist_ok=True)
    other.write_text(f"STRIPE_API_KEY={_FOREIGN_VALUE}\n", encoding="utf-8")
    enc = _run_envdrift(
        ["encrypt", str(other.relative_to(repo))],
        cwd=repo,
        integration_pythonpath=integration_pythonpath,
        envdrift_cmd=envdrift_cmd,
    )
    assert enc.returncode == 0, _flat(enc)
    foreign = next(
        line
        for line in other.read_text(encoding="utf-8").splitlines()
        if line.startswith("STRIPE_API_KEY=")
    )
    with target.open("a", encoding="utf-8") as handle:
        handle.write(foreign + "\n")


def _push(repo: Path, *, integration_pythonpath: str, envdrift_cmd: list[str]) -> None:
    push = _run_envdrift(
        ["push"],
        cwd=repo,
        integration_pythonpath=integration_pythonpath,
        envdrift_cmd=envdrift_cmd,
    )
    assert push.returncode == 0, _flat(push)


def _skip_worktree_flag(repo: Path, path: str) -> str:
    """``S`` when git marks ``path`` skip-worktree, ``H`` for a normal tracked file."""
    return _git(repo, "ls-files", "-v", "--", path).split(" ", 1)[0]


class TestPartlyFailedPullPartial:
    """#948: a pull that fails part way leaves nothing unprotected or uncounted."""

    def test_combine_mode_restores_the_secret_file(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        (git_repo / "envdrift.toml").write_text(
            "[partial_encryption]\n"
            "enabled = true\n\n"
            "[[partial_encryption.environments]]\n"
            'name = "production"\n'
            'clear_file = ".env.production.clear"\n'
            'secret_file = ".env.production.secret"\n'
            'combined_file = ".env.production"\n',
            encoding="utf-8",
        )
        (git_repo / ".env.production.clear").write_text("DEBUG=false\n", encoding="utf-8")
        secret = git_repo / ".env.production.secret"
        secret.write_text(f"JWT_SECRET={_JWT_VALUE}\n", encoding="utf-8")
        _push(git_repo, integration_pythonpath=integration_pythonpath, envdrift_cmd=envdrift_cmd)
        _append_foreign_value(
            git_repo,
            secret,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )
        _git(git_repo, "add", ".env.production.secret", ".env.production.clear")
        _git(git_repo, "commit", "-q", "-m", "secret with one value under another key")
        committed = secret.read_bytes()

        result = _run_envdrift(
            ["pull-partial"],
            cwd=git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        out = _flat(result)
        assert result.returncode == 1, out
        # The secret file is exactly the committed ciphertext: JWT_SECRET was
        # not left decrypted, so "Decrypted: 0" is now the truth.
        assert secret.read_bytes() == committed
        assert _JWT_VALUE not in secret.read_text(encoding="utf-8")
        assert "Decrypted: 0" in out and "Errors: 1" in out, out
        assert "STRIPE_API_KEY" in out, out
        assert ".env.production.secret was left as it was" in out, out
        # A routine `git add .` stages nothing from the secret file.
        _git(git_repo, "add", ".")
        staged = _git(git_repo, "diff", "--cached", "--name-only").split()
        assert ".env.production.secret" not in staged, staged

    def test_secrets_only_counts_and_protects_the_files_decrypted_first(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        (git_repo / "envdrift.toml").write_text(
            "[partial_encryption]\n"
            "enabled = true\n\n"
            "[[partial_encryption.environments]]\n"
            'name = "production"\n'
            "secrets_only = true\n"
            'secrets_dir = "secrets"\n',
            encoding="utf-8",
        )
        secrets = git_repo / "secrets"
        secrets.mkdir()
        api = secrets / ".env.api"  # sorted first: decrypts
        db = secrets / ".env.db"  # sorted second: one value under another key
        api.write_text(f"API_KEY={_API_VALUE}\n", encoding="utf-8")
        db.write_text(f"DB_PASS={_DB_VALUE}\n", encoding="utf-8")
        _push(git_repo, integration_pythonpath=integration_pythonpath, envdrift_cmd=envdrift_cmd)
        _append_foreign_value(
            git_repo,
            db,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )
        _git(git_repo, "add", "secrets/.env.api", "secrets/.env.db")
        _git(git_repo, "commit", "-q", "-m", "secrets-only files")
        db_committed = db.read_bytes()

        result = _run_envdrift(
            ["pull-partial"],
            cwd=git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        out = _flat(result)
        assert result.returncode == 1, out
        # The true tally: one file decrypted before the failure.
        assert "Decrypted: 1" in out and "Errors: 1" in out, out
        assert "STRIPE_API_KEY" in out, out
        # .env.api is plaintext, so the notice is shown despite the error, and
        # the file really is protected.
        assert "SECRET FILES ARE NOW PLAINTEXT" in out, out
        assert f"API_KEY={_API_VALUE}" in api.read_text(encoding="utf-8")
        assert _skip_worktree_flag(git_repo, "secrets/.env.api") == "S"
        # The failing file was left as it was and is not hidden from git.
        assert db.read_bytes() == db_committed
        assert _skip_worktree_flag(git_repo, "secrets/.env.db") == "H"
        assert "secrets/.env.db was left as it was" in out, out

    def test_pull_counts_the_secrets_only_files_decrypted_first(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        """``envdrift pull`` runs the same secrets-only step and reports the tally."""
        partial = (
            "[partial_encryption]\n"
            "enabled = true\n\n"
            "[[partial_encryption.environments]]\n"
            'name = "production"\n'
            "secrets_only = true\n"
            'secrets_dir = "secrets"\n'
        )
        (git_repo / "envdrift.toml").write_text(partial, encoding="utf-8")
        secrets = git_repo / "secrets"
        secrets.mkdir()
        (secrets / ".env.api").write_text(f"API_KEY={_API_VALUE}\n", encoding="utf-8")
        db = secrets / ".env.db"
        db.write_text(f"DB_PASS={_DB_VALUE}\n", encoding="utf-8")
        _push(git_repo, integration_pythonpath=integration_pythonpath, envdrift_cmd=envdrift_cmd)
        _append_foreign_value(
            git_repo,
            db,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )
        db_committed = db.read_bytes()
        # pull needs a [vault.sync] section; --skip-sync never contacts the
        # dummy vault, and the mapping's plaintext .env.production is skipped.
        (git_repo / ".env.production").write_text("DEBUG=false\n", encoding="utf-8")
        (git_repo / "envdrift.toml").write_text(
            "[vault]\n"
            'provider = "azure"\n\n'
            "[vault.azure]\n"
            'vault_url = "https://dummy.vault.azure.net/"\n\n'
            "[vault.sync]\n"
            'default_vault_name = "dummy"\n\n'
            "[[vault.sync.mappings]]\n"
            'secret_name = "unused"\n'
            'folder_path = "."\n'
            'environment = "production"\n\n' + partial,
            encoding="utf-8",
        )

        result = _run_envdrift(
            ["pull", "--skip-sync"],
            cwd=git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        out = _flat(result)
        assert result.returncode == 1, out
        summary = out.split("Partial Encryption Summary", 1)[1]
        assert "Decrypted: 1" in summary and "Errors: 1" in summary, out
        assert db.read_bytes() == db_committed
