"""``encrypt`` and ``decrypt`` read backtick-quoted values as dotenvx does (#950).

dotenvx accepts a value quoted with backticks and keeps the backticks around the
ciphertext it writes: ``API_KEY=`encrypted:...` ``. envdrift's ciphertext check
knew only ``"`` and ``'``, so a successful encryption was reported as "Encryption
did not take effect ... the encryption key was missing or invalid" (exit 1), the
freshly minted ``.env.keys`` was never gitignored, ``decrypt`` called the
encrypted file "Nothing to decrypt" (exit 0), and ``encrypt --check`` called the
ciphertext plaintext.

Every test runs the real ``envdrift`` CLI, the real dotenvx binary and real git,
and asserts the exit code, the message and the bytes on disk.
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
        reason="dotenvx binary not installed (required for real backtick ciphertext)",
    ),
]

# Built by concatenation so push protection never sees a whole secret literal.
_API_KEY = "sk_" + "test_" + "abc123"


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


def _is_ignored(repo: Path, path: str) -> bool:
    """Ask git itself whether ``path`` is gitignored."""
    result = subprocess.run(
        ["git", "check-ignore", "-q", path], cwd=repo, capture_output=True, check=False
    )
    return result.returncode == 0


class TestBacktickQuotedValueRoundTrip:
    """#950: a backtick-quoted value encrypts, is checked and decrypts truthfully."""

    def test_encrypt_reports_success_and_gitignores_the_new_key(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        env_file = git_repo / ".env"
        env_file.write_text(f"API_KEY=`{_API_KEY}`\n", encoding="utf-8")

        result = _run_envdrift(
            ["encrypt", ".env"],
            cwd=git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        output = _flat(result)
        assert result.returncode == 0, output
        assert "Encrypted .env using dotenvx" in output
        assert "did not take effect" not in output
        text = env_file.read_text(encoding="utf-8")
        assert "API_KEY=`encrypted:" in text
        assert _API_KEY not in text
        assert (git_repo / ".env.keys").is_file()
        assert _is_ignored(git_repo, ".env.keys"), "the new private key is not gitignored"

    def test_check_counts_the_backtick_ciphertext_as_encrypted(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        (git_repo / ".env").write_text(f"API_KEY=`{_API_KEY}`\n", encoding="utf-8")
        encrypted = _run_envdrift(
            ["encrypt", ".env"],
            cwd=git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )
        assert encrypted.returncode == 0, _flat(encrypted)

        check = _run_envdrift(
            ["encrypt", "--check", ".env"],
            cwd=git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        output = _flat(check)
        assert check.returncode == 0, output
        assert "File is fully encrypted" in output
        assert "PLAINTEXT SECRETS DETECTED" not in output

    def test_decrypt_decrypts_the_backtick_ciphertext(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        env_file = git_repo / ".env"
        env_file.write_text(f"API_KEY=`{_API_KEY}`\n", encoding="utf-8")
        encrypted = _run_envdrift(
            ["encrypt", ".env"],
            cwd=git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )
        assert encrypted.returncode == 0, _flat(encrypted)

        result = _run_envdrift(
            ["decrypt", ".env"],
            cwd=git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        output = _flat(result)
        assert result.returncode == 0, output
        assert "Decrypted .env using dotenvx" in output
        assert "Nothing to decrypt" not in output
        assert f"API_KEY=`{_API_KEY}`" in env_file.read_text(encoding="utf-8")


class TestFailedEncryptStillProtectsTheKeyDotenvxWrote:
    """#950: a key dotenvx minted is gitignored even when encrypt then reports a failure."""

    def test_key_written_during_a_failed_encrypt_is_gitignored(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        # dotenvx never encrypts a ``*_PLAIN`` key, so the value stays plaintext after it
        # encrypted API_KEY with a key it just created. Whatever encrypt then reports, that
        # key must not be left for ``git add .`` to stage.
        (git_repo / ".env").write_text(f"API_KEY={_API_KEY}\nNOTE_PLAIN=hello\n", encoding="utf-8")

        result = _run_envdrift(
            ["encrypt", ".env"],
            cwd=git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        assert (git_repo / ".env.keys").is_file(), _flat(result)
        assert _is_ignored(git_repo, ".env.keys"), (
            f"exit {result.returncode}, key left unprotected: {_flat(result)}"
        )
