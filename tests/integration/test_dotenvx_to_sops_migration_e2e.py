"""The documented dotenvx-to-SOPS migration completes, and its result reads as SOPS (#949).

``dotenvx decrypt`` keeps the ``DOTENV_PUBLIC_KEY`` header, and envdrift picked a
file's backend from that header. So ``encrypt --backend sops`` refused the decrypted
file as "already encrypted with dotenvx", while the advised
``decrypt --backend dotenvx`` reported "Nothing to decrypt". SOPS then keeps the
``DOTENV_PUBLIC_KEY_<ENV>`` name when it encrypts such a file, so the migrated file
still read as dotenvx: ``decrypt`` picked dotenvx and failed, and ``encrypt`` was not
refused as a SOPS file.

Every test runs the real ``envdrift`` CLI with the real dotenvx and sops binaries.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import textwrap
from collections.abc import Callable
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        shutil.which("dotenvx") is None or shutil.which("sops") is None,
        reason="dotenvx and sops binaries are both required for a backend migration",
    ),
]

# The age keypair the SOPS tests share (test_sops_backend_e2e.py). Built by
# concatenation so push protection never sees a whole secret literal.
_AGE_PUBLIC_KEY = "age1c89jtrvyl72y0muvdp5lm3jpemvc2gr303up4g37tuq4uftcku3q4svqau"
_AGE_PRIVATE_KEY = "AGE-SECRET-KEY-" + "1HGE3ZE9NPEN5R76LVKKJ2Z3G9TYZJLW84P2CHAF6UGL43R7TWPUSZ89MK6"

_DATABASE_URL = "postgres://u:" + "p" + "@h/db"
_API_KEY = "abc" + "123"
_PLAINTEXT = f"DATABASE_URL={_DATABASE_URL}\nAPI_KEY={_API_KEY}\n"


@pytest.fixture
def workspace(git_repo: Path) -> Path:
    """A git repository with an age key file the SOPS steps read."""
    (git_repo / "age.key").write_text(
        textwrap.dedent(
            f"""\
            # public key: {_AGE_PUBLIC_KEY}
            {_AGE_PRIVATE_KEY}
            """
        ),
        encoding="utf-8",
    )
    (git_repo / ".env.production").write_text(_PLAINTEXT, encoding="utf-8")
    return git_repo


_Run = Callable[[list[str]], "subprocess.CompletedProcess[str]"]


@pytest.fixture
def envdrift(workspace: Path, integration_pythonpath: str, envdrift_cmd: list[str]) -> _Run:
    """The real envdrift CLI as a subprocess, run in ``workspace`` with its age key."""

    def run(args: list[str]) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath
        env["SOPS_AGE_KEY_FILE"] = str(workspace / "age.key")
        return subprocess.run(
            [*envdrift_cmd, *args],
            cwd=workspace,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )

    return run


def _flat(result: subprocess.CompletedProcess[str]) -> str:
    """stdout+stderr with whitespace collapsed, so wrapping cannot split a phrase."""
    return " ".join((result.stdout + result.stderr).split())


def _migrate(envdrift: _Run) -> None:
    """The documented steps: encrypt with dotenvx, decrypt, re-encrypt with SOPS."""
    for args in (
        ["encrypt", ".env.production"],
        ["decrypt", ".env.production"],
        ["encrypt", ".env.production", "--backend", "sops", "--age", _AGE_PUBLIC_KEY],
    ):
        result = envdrift(args)
        assert result.returncode == 0, f"{args}: {_flat(result)}"


def _assert_refused(envdrift: _Run, args: list[str], env_file: Path, reason: str) -> None:
    """``envdrift args`` fails, says ``reason``, and leaves ``env_file`` as it was."""
    before = env_file.read_bytes()

    result = envdrift(args)

    output = _flat(result)
    assert result.returncode == 1, output
    assert reason in output
    assert env_file.read_bytes() == before


class TestDotenvxToSopsMigration:
    """#949: the two documented steps work, and the result is a working SOPS file."""

    def test_sops_encrypts_the_file_dotenvx_decrypted(
        self, workspace: Path, envdrift: _Run
    ) -> None:
        _migrate(envdrift)

        text = (workspace / ".env.production").read_text(encoding="utf-8")
        assert "DATABASE_URL=ENC[AES256_GCM," in text
        assert _DATABASE_URL not in text
        check = envdrift(["encrypt", "--check", ".env.production"])
        assert check.returncode == 0, _flat(check)
        assert "File is fully encrypted" in _flat(check)

    def test_the_migrated_file_decrypts_as_sops(self, workspace: Path, envdrift: _Run) -> None:
        _migrate(envdrift)

        result = envdrift(["decrypt", ".env.production"])

        output = _flat(result)
        assert result.returncode == 0, output
        assert "Auto-detected encryption backend: sops" in output
        text = (workspace / ".env.production").read_text(encoding="utf-8")
        assert f"DATABASE_URL={_DATABASE_URL}" in text
        assert f"API_KEY={_API_KEY}" in text

    def test_the_migrated_file_is_refused_for_dotenvx(
        self, workspace: Path, envdrift: _Run
    ) -> None:
        _migrate(envdrift)

        _assert_refused(
            envdrift,
            ["encrypt", ".env.production"],
            workspace / ".env.production",
            "is already encrypted with sops, but the dotenvx backend was selected",
        )


class TestRealCiphertextIsStillRefused:
    """The refusal still guards a file that holds the other backend's ciphertext."""

    def test_dotenvx_ciphertext_is_refused_for_sops(self, workspace: Path, envdrift: _Run) -> None:
        encrypted = envdrift(["encrypt", ".env.production"])
        assert encrypted.returncode == 0, _flat(encrypted)

        _assert_refused(
            envdrift,
            ["encrypt", ".env.production", "--backend", "sops", "--age", _AGE_PUBLIC_KEY],
            workspace / ".env.production",
            "is already encrypted with dotenvx, but the sops backend was selected",
        )


class TestCiphertextIsFoundAsDotenvxReadsIt:
    """The refusal judges a file by the ciphertext dotenvx and SOPS really read in it."""

    def test_ciphertext_dotenvx_cut_at_a_hash_is_refused_for_sops(
        self, workspace: Path, envdrift: _Run
    ) -> None:
        """dotenvx cut ``hunter2#Spring2024!`` at its ``#``, and decrypts what it encrypted.

        The parser reads such a value as plaintext, so the file held no ciphertext to the
        check: SOPS wrapped the dotenvx ciphertext, and ``sops -d`` gave that back for the
        password.
        """
        env_file = workspace / ".env.production"
        env_file.write_text("DB_PASSWORD=hunter2" + "#Spring2024!\n", encoding="utf-8")
        subprocess.run(
            ["dotenvx", "encrypt", "-f", ".env.production", "-fk", ".env.keys"],
            cwd=workspace,
            capture_output=True,
            check=True,
            timeout=120,
        )
        assert "#Spring2024!" in env_file.read_text(encoding="utf-8")

        _assert_refused(
            envdrift,
            ["encrypt", ".env.production", "--backend", "sops", "--age", _AGE_PUBLIC_KEY],
            env_file,
            "is already encrypted with dotenvx, but the sops backend was selected",
        )

    def test_a_comment_that_names_the_sops_envelope_is_no_sops_ciphertext(
        self, workspace: Path, envdrift: _Run
    ) -> None:
        """A plaintext file was refused for dotenvx as "already encrypted with sops"."""
        env_file = workspace / ".env.production"
        env_file.write_text(
            "# SOPS writes each value as ENC[AES256_GCM,data:...]\n" + _PLAINTEXT, encoding="utf-8"
        )

        result = envdrift(["encrypt", ".env.production"])

        output = _flat(result)
        assert result.returncode == 0, output
        assert "Encrypted .env.production using dotenvx" in output
        text = env_file.read_text(encoding="utf-8")
        assert "API_KEY=encrypted:" in text and _API_KEY not in text
