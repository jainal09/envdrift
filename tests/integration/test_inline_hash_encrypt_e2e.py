"""``encrypt`` never leaves the part of a value after a ``#`` in plaintext (#947).

dotenvx ends an unquoted value at its first ``#`` and keeps the rest of the line as a
comment. python-dotenv, which envdrift follows, starts a comment only at a ``#``
after whitespace, so ``DB_PASSWORD=hunter2#Spring2024!`` holds
``hunter2#Spring2024!``. dotenvx encrypted only ``hunter2`` and left
``#Spring2024!`` in the file, while envdrift printed ``[OK]`` and
``encrypt --check`` reported 100%.

Every test runs the real ``envdrift`` CLI and the real dotenvx binary.
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
        reason="dotenvx binary not installed (required to see how it reads a #)",
    ),
]

# Built by concatenation so push protection never sees a whole secret literal.
_PASSWORD = "hunter2" + "#" + "Spring2024!"
_STRIPE = "abc" + "#" + "def456ghi"


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


class TestEncryptRefusesAValueDotenvxWouldCutAtAHash:
    """The refusal comes before dotenvx runs, so nothing is changed."""

    @pytest.mark.parametrize(
        ("content", "names"),
        [
            (
                f"DB_PASSWORD={_PASSWORD}\nSTRIPE_SECRET={_STRIPE}\n",
                ["DB_PASSWORD", "STRIPE_SECRET"],
            ),
            ("API_KEY=abc123\nCOLOR=#FF0000\n", ["COLOR"]),
            ("export TOKEN=abc\\#def\n", ["TOKEN"]),
        ],
        ids=["glued", "leading", "escaped"],
    )
    def test_encrypt_refuses_and_leaves_the_file_as_it_was(
        self,
        git_repo: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
        content: str,
        names: list[str],
    ) -> None:
        env_file = git_repo / ".env.production"
        env_file.write_text(content, encoding="utf-8")

        result = _run_envdrift(
            ["encrypt", ".env.production"],
            cwd=git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        output = _flat(result)
        assert result.returncode == 1, output
        assert "[OK]" not in output
        assert "Nothing was changed" in output
        for name in names:
            assert name in output
        assert env_file.read_text(encoding="utf-8") == content
        assert not (git_repo / ".env.keys").exists()

    def test_a_quoted_value_keeps_its_hash_through_the_round_trip(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        env_file = git_repo / ".env.production"
        env_file.write_text(
            f'DB_PASSWORD="{_PASSWORD}"\nNOTE=plain # a real comment\n', encoding="utf-8"
        )

        encrypted = _run_envdrift(
            ["encrypt", ".env.production"],
            cwd=git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )
        assert encrypted.returncode == 0, _flat(encrypted)
        text = env_file.read_text(encoding="utf-8")
        assert "Spring2024" not in text and "NOTE=encrypted:" in text

        decrypted = _run_envdrift(
            ["decrypt", ".env.production"],
            cwd=git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )
        assert decrypted.returncode == 0, _flat(decrypted)
        assert f'DB_PASSWORD="{_PASSWORD}"' in env_file.read_text(encoding="utf-8")


class TestCheckReportsPlaintextLeftAfterTheHash:
    """A file dotenvx already cut at a ``#`` is not called fully encrypted."""

    def test_check_flags_the_plaintext_tail(
        self, work_dir: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        env_file = work_dir / ".env.production"
        env_file.write_text(f"DB_PASSWORD={_PASSWORD}\nSTRIPE_SECRET={_STRIPE}\n", encoding="utf-8")
        # The file as dotenvx itself leaves it: ciphertext, then the plaintext after each #.
        subprocess.run(
            ["dotenvx", "encrypt", "-f", ".env.production", "-fk", ".env.keys"],
            cwd=work_dir,
            capture_output=True,
            check=True,
            timeout=120,
        )
        assert "#Spring2024!" in env_file.read_text(encoding="utf-8")

        result = _run_envdrift(
            ["encrypt", "--check", ".env.production"],
            cwd=work_dir,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        output = _flat(result)
        assert result.returncode == 1, output
        assert "File is fully encrypted" not in output
        assert "PLAINTEXT SECRETS DETECTED" in output
        assert "DB_PASSWORD" in output and "STRIPE_SECRET" in output


class TestPushRefusesAValueDotenvxWouldCutAtAHash:
    """The partial-encryption push reaches dotenvx through the same wrapper."""

    def test_push_refuses_and_leaves_the_secret_file_as_it_was(
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
        (git_repo / ".env.production.clear").write_text("APP=shop\n", encoding="utf-8")
        secret = git_repo / ".env.production.secret"
        content = f"DB_PASSWORD={_PASSWORD}\n"
        secret.write_text(content, encoding="utf-8")

        result = _run_envdrift(
            ["push"],
            cwd=git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        output = _flat(result)
        assert result.returncode == 1, output
        assert "Push complete" not in output
        assert "DB_PASSWORD" in output
        assert secret.read_text(encoding="utf-8") == content


_LOCK_CONFIG = """\
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


class TestLockReportsPlaintextInsideTheQuotes:
    """Inside quotes a ``#`` is value text: ``"encrypted:... #hunter2"`` holds plaintext."""

    def test_lock_check_does_not_call_it_encrypted(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        """It was read as ciphertext then a comment, and lock --check passed (exit 0)."""
        (git_repo / "envdrift.toml").write_text(_LOCK_CONFIG, encoding="utf-8")
        folder = git_repo / "svc"
        folder.mkdir()
        env_file = folder / ".env.production"
        env_file.write_text("API_KEY=abc123\n", encoding="utf-8")
        subprocess.run(
            ["dotenvx", "encrypt", "-f", ".env.production", "-fk", ".env.keys"],
            cwd=folder,
            capture_output=True,
            check=True,
            timeout=120,
        )
        text = env_file.read_text(encoding="utf-8")
        ciphertext = next(
            line.partition("=")[2] for line in text.splitlines() if line.startswith("API_KEY=")
        )
        env_file.write_text(
            text.replace(f"API_KEY={ciphertext}", f'API_KEY="{ciphertext} #hunter2"'),
            encoding="utf-8",
        )

        result = _run_envdrift(
            ["lock", "--check"],
            cwd=git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )

        output = _flat(result)
        assert result.returncode == 1, output
        assert "plaintext values remain" in output
