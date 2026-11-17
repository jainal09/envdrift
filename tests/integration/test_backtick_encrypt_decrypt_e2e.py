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
from collections.abc import Callable
from pathlib import Path

import pytest
from tests.helpers import native_path

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        shutil.which("dotenvx") is None,
        reason="dotenvx binary not installed (required for real backtick ciphertext)",
    ),
]

# Built by concatenation so push protection never sees a whole secret literal.
_API_KEY = "sk_" + "test_" + "abc123"

_MAPPING_CONFIG = """\
[vault]
provider = "aws"

[vault.aws]
region = "us-east-1"

[encryption]
backend = "dotenvx"

[[vault.sync.mappings]]
secret_name = "svc-key"
folder_path = "svc"
environment = "production"
"""


_Run = Callable[..., "subprocess.CompletedProcess[str]"]


@pytest.fixture
def envdrift(git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]) -> _Run:
    """The real envdrift CLI as a subprocess, run in ``git_repo`` unless given a ``cwd``."""

    def run(args: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath
        return subprocess.run(
            [*envdrift_cmd, *args],
            cwd=cwd or git_repo,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )

    return run


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
        self, git_repo: Path, envdrift: _Run
    ) -> None:
        env_file = git_repo / ".env"
        env_file.write_text(f"API_KEY=`{_API_KEY}`\n", encoding="utf-8")

        result = envdrift(["encrypt", ".env"])

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
        self, git_repo: Path, envdrift: _Run
    ) -> None:
        (git_repo / ".env").write_text(f"API_KEY=`{_API_KEY}`\n", encoding="utf-8")
        encrypted = envdrift(["encrypt", ".env"])
        assert encrypted.returncode == 0, _flat(encrypted)

        check = envdrift(["encrypt", "--check", ".env"])

        output = _flat(check)
        assert check.returncode == 0, output
        assert "File is fully encrypted" in output
        assert "PLAINTEXT SECRETS DETECTED" not in output

    def test_decrypt_decrypts_the_backtick_ciphertext(self, git_repo: Path, envdrift: _Run) -> None:
        env_file = git_repo / ".env"
        env_file.write_text(f"API_KEY=`{_API_KEY}`\n", encoding="utf-8")
        encrypted = envdrift(["encrypt", ".env"])
        assert encrypted.returncode == 0, _flat(encrypted)

        result = envdrift(["decrypt", ".env"])

        output = _flat(result)
        assert result.returncode == 0, output
        assert "Decrypted .env using dotenvx" in output
        assert "Nothing to decrypt" not in output
        assert f"API_KEY=`{_API_KEY}`" in env_file.read_text(encoding="utf-8")


class TestFailedEncryptStillProtectsTheKeyDotenvxWrote:
    """#950: a key dotenvx minted is gitignored even when encrypt then reports a failure."""

    def test_key_written_during_a_failed_encrypt_is_gitignored(
        self, git_repo: Path, envdrift: _Run
    ) -> None:
        # python-dotenv loads CAFÉ, but dotenvx reads only ASCII names and leaves its value
        # plaintext after it encrypted API_KEY with a key it just created, so encrypt fails.
        # That key must not be left for ``git add .`` to stage.
        (git_repo / ".env").write_text(f"API_KEY={_API_KEY}\nCAFÉ=hello\n", encoding="utf-8")

        result = envdrift(["encrypt", ".env"])

        assert result.returncode == 1, _flat(result)
        assert (git_repo / ".env.keys").is_file(), _flat(result)
        assert _is_ignored(git_repo, ".env.keys"), (
            f"exit {result.returncode}, key left unprotected: {_flat(result)}"
        )


class TestPullAndLockReadQuotedCiphertext:
    """``pull`` and ``lock`` see the ciphertext dotenvx keeps inside a value's quotes (#950).

    Their check knew only ``KEY=encrypted:...``. A file whose values were all quoted, in
    backticks or in ``"`` or ``'``, was "skipped (not encrypted)" by ``pull``, which then
    printed "[OK] Setup complete!" over a file still encrypted, and ``lock --check`` said it
    "would be encrypted" (exit 1) after every lock.
    """

    @pytest.mark.parametrize("quote", ["", '"', "'", "`"], ids=["bare", "double", "single", "tick"])
    def test_lock_check_passes_and_pull_decrypts(
        self,
        git_repo: Path,
        envdrift: _Run,
        quote: str,
    ) -> None:
        (git_repo / "envdrift.toml").write_text(_MAPPING_CONFIG, encoding="utf-8")
        folder = git_repo / "svc"
        folder.mkdir()
        env_file = folder / ".env.production"
        env_file.write_text(f"API_KEY={quote}{_API_KEY}{quote}\n", encoding="utf-8")
        subprocess.run(
            ["dotenvx", "encrypt", "-f", env_file.name, "-fk", ".env.keys"],
            cwd=folder,
            capture_output=True,
            check=True,
            timeout=120,
        )
        assert f"API_KEY={quote}encrypted:" in env_file.read_text(encoding="utf-8")

        def run(*args: str) -> subprocess.CompletedProcess[str]:
            return envdrift(list(args))

        check = run("lock", "--check")
        pull = run("pull", "--skip-sync")

        assert check.returncode == 0, _flat(check)
        assert "skipped (already encrypted)" in _flat(check)
        output = _flat(pull)
        assert pull.returncode == 0, output
        assert "skipped (not encrypted)" not in output
        assert f"{native_path('svc/.env.production')} - decrypted" in output
        text = env_file.read_text(encoding="utf-8")
        assert f"API_KEY={quote}{_API_KEY}{quote}" in text and "encrypted:" not in text

    def test_a_quoted_example_in_a_comment_is_no_ciphertext(
        self, git_repo: Path, envdrift: _Run
    ) -> None:
        """pull called a plaintext file "decrypted" for a comment that shows a quoted value."""
        (git_repo / "envdrift.toml").write_text(_MAPPING_CONFIG, encoding="utf-8")
        env_file = git_repo / "svc" / ".env.production"
        env_file.parent.mkdir()
        env_file.write_text(
            f'# example: API_KEY="encrypted:..."\nAPI_KEY={_API_KEY}\n', encoding="utf-8"
        )
        before = env_file.read_bytes()

        def run(*args: str) -> subprocess.CompletedProcess[str]:
            return envdrift(list(args))

        pull = run("pull", "--skip-sync")
        check = run("lock", "--check")

        assert pull.returncode == 0, _flat(pull)
        assert f"{native_path('svc/.env.production')} - skipped (not encrypted)" in _flat(pull)
        assert env_file.read_bytes() == before
        assert check.returncode == 1, _flat(check)
        assert "would be encrypted" in _flat(check)
