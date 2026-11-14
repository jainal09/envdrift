"""``envdrift decrypt`` failure modes against the real CLI, binaries and git.

Every test runs the real ``envdrift`` CLI as a subprocess and asserts the true
outcome: the exit code, the message, and the bytes on disk.

- #962: dotenvx decrypts value by value. With one value encrypted under another
  key it writes the values it could decrypt and exits 1, which used to leave
  those secrets as plaintext in the tracked file. The failed decrypt must leave
  the file byte for byte as it was, name the value, and print the
  ``dotenvx decryption failed:`` prefix once.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import typer

pytestmark = [pytest.mark.integration]

_needs_dotenvx = pytest.mark.skipif(
    shutil.which("dotenvx") is None,
    reason="dotenvx binary not installed (required for the real partial-decrypt failure)",
)

# Built by concatenation so push protection never sees a whole secret literal.
_JWT_VALUE = "super-" + "secret-" + "key"
_DB_VALUE = "hun" + "ter2"
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


def _commit_partly_foreign_file(
    repo: Path,
    *,
    integration_pythonpath: str,
    envdrift_cmd: list[str],
    crlf: bool,
) -> bytes:
    """Commit ``.env.production``: two values under its key, one under another.

    Both files are encrypted by the real ``envdrift encrypt`` (real dotenvx).
    The ``STRIPE_API_KEY`` line comes from ``other/``, encrypted under that
    folder's own key, as happens after a merge or through key drift.
    """
    target = repo / ".env.production"
    target.write_text(f"JWT_SECRET={_JWT_VALUE}\nDB_PASS={_DB_VALUE}\n", encoding="utf-8")
    other = repo / "other" / ".env.production"
    other.parent.mkdir()
    other.write_text(f"STRIPE_API_KEY={_FOREIGN_VALUE}\n", encoding="utf-8")
    for path in ("other/.env.production", ".env.production"):
        enc = _run_envdrift(
            ["encrypt", path],
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
    text = target.read_text(encoding="utf-8") + foreign + "\n"
    assert _JWT_VALUE not in text and "JWT_SECRET=encrypted:" in text
    data = text.encode("utf-8")
    if crlf:
        data = data.replace(b"\n", b"\r\n")
    target.write_bytes(data)
    _git(repo, "add", ".env.production")
    _git(repo, "commit", "-q", "-m", "encrypted, one value under another key")
    return data


@_needs_dotenvx
class TestPartlyFailedDecryptLeavesTheFileAsItWas:
    """#962: a dotenvx decrypt that fails part way never leaves plaintext behind."""

    @pytest.mark.parametrize("crlf", [False, True], ids=["lf", "crlf"])
    def test_decrypt_restores_the_file_byte_for_byte(
        self,
        git_repo: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
        crlf: bool,
    ) -> None:
        committed = _commit_partly_foreign_file(
            git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
            crlf=crlf,
        )

        result = _run_envdrift(
            ["decrypt", ".env.production"],
            cwd=git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        out = _flat(result)
        assert result.returncode == 1, out
        # The file is exactly the committed ciphertext, CRLF included: no
        # decrypted value survived, and git sees no change.
        assert (git_repo / ".env.production").read_bytes() == committed
        assert _git(git_repo, "status", "--porcelain", "--", ".env.production") == ""
        # dotenvx's reason (the value it could not decrypt) and the outcome.
        assert "STRIPE_API_KEY" in out, out
        assert ".env.production was left as it was" in out, out
        # The prefix is printed once, not "dotenvx decryption failed: dotenvx ...".
        assert out.count("dotenvx decryption failed:") == 1, out
        # Nor dotenvx's "◇ decrypted .env.production" status line, which read as
        # a success right before "was left as it was".
        assert "decrypted .env.production" not in out, out
        assert _JWT_VALUE not in out and _DB_VALUE not in out

    def test_pull_skip_sync_restores_the_file(
        self,
        git_repo: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """``pull`` decrypts through the same backend and restores the file too."""
        committed = _commit_partly_foreign_file(
            git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
            crlf=False,
        )
        # pull belongs to the vault-sync family, so it needs a [vault.sync]
        # section; --skip-sync never contacts the (dummy) vault.
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
            'environment = "production"\n',
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
        assert (git_repo / ".env.production").read_bytes() == committed
        assert _git(git_repo, "status", "--porcelain", "--", ".env.production") == ""
        assert "Errors: 1" in out, out
        assert "STRIPE_API_KEY" in out, out
        assert "was left as it was" in out, out


@_needs_dotenvx
def test_vault_pull_env_file_failure_puts_back_the_header_too(
    git_repo: Path,
    integration_pythonpath: str,
    envdrift_cmd: list[str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """vault-pull's decrypt step with ``--env-file``, against the real dotenvx.

    It rewrites a custom file's dotenvx header to the environment's name before it
    decrypts, and the backend's snapshot comes after that rewrite. A failed decrypt
    left the rewritten header in the file while the error said the file "was left
    as it was". Fetching the key needs a vault; this step does not.
    """
    from envdrift.cli_commands.vault_helpers import (
        VaultConnectionOptions,
        VaultPullRequest,
        _decrypt_pull_target,
    )

    monkeypatch.chdir(git_repo)
    _commit_partly_foreign_file(
        git_repo,
        integration_pythonpath=integration_pythonpath,
        envdrift_cmd=envdrift_cmd,
        crlf=False,
    )
    # The same file as a custom one, with the header dotenvx gives custom.env.
    custom = git_repo / "custom.env"
    custom.write_text(
        (git_repo / ".env.production")
        .read_text(encoding="utf-8")
        .replace("DOTENV_PUBLIC_KEY_PRODUCTION=", "DOTENV_PUBLIC_KEY_CUSTOM=")
        .replace("# .env.production\n", "# custom.env\n"),
        encoding="utf-8",
    )
    before = custom.read_bytes()
    assert b"DOTENV_PUBLIC_KEY_CUSTOM=" in before
    request = VaultPullRequest(
        folder=git_repo,
        secret_name="unused",
        environment="production",
        connection=VaultConnectionOptions(
            config=None, provider=None, vault_url=None, region=None, project_id=None
        ),
        no_decrypt=False,
        env_file=Path("custom.env"),
    )

    with pytest.raises(typer.Exit) as excinfo:
        _decrypt_pull_target(request, custom, git_repo / ".env.keys")

    err = " ".join(capsys.readouterr().err.split())
    assert excinfo.value.exit_code == 1, err
    assert "STRIPE_API_KEY" in err, err
    assert "was left as it was" in err, err
    assert custom.read_bytes() == before
