"""``decrypt`` and ``pull-partial`` give every value back exactly as it was written (#946).

dotenvx writes a decrypted file the way ``dotenvx run`` would load it: it expands
``$VAR`` and ``${VAR}`` from the decrypting process's environment, runs ``$(...)``,
drops the backslash of ``\\$``, and takes a same-named variable's value from that
environment. It rewrites the plaintext values of a partly encrypted file the same way.
So ``DB_PASSWORD=Xk9$mQ2zz!`` came back as ``DB_PASSWORD=Xk9!`` under ``[OK]``, and the
documented ``pull-partial`` then ``push`` routine re-encrypted the mangled secret.

Every test runs the real ``envdrift`` CLI and the real dotenvx binary, with variables
set that the expansion would pick up.
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
        reason="dotenvx binary not installed (required to see what its decrypt writes)",
    ),
]

# Built by concatenation so push protection never sees a whole secret literal.
_PASSWORD = "Xk9" + "$mQ2zz" + "!"
_TOKEN = "tok_" + "$abc_123"
_VALUE_LINES = [
    f"DB_PASSWORD={_PASSWORD}",
    f"API_TOKEN={_TOKEN}",
    "BRACED=pre${mQ2zz}post",
    f'QUOTED="{_PASSWORD}"',
    f"SINGLE='{_PASSWORD}'",
    f"TICK=`{_PASSWORD}`",
    "ESCAPED=a\\$b",
    "SUBSTITUTED=pre$(echo ran)post",
    "PW=pa$word123",
]
# What the expansion would read: a same-named variable, and the names the values reference.
_DECRYPT_ENV = {"mQ2zz": "FROM_ENV", "abc_123": "FROM_ENV", "word123": "XYZ"}


def _run_envdrift(
    args: list[str],
    *,
    cwd: Path,
    integration_pythonpath: str,
    envdrift_cmd: list[str],
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run the real envdrift CLI as a subprocess and capture its output."""
    env = os.environ.copy()
    env["PYTHONPATH"] = integration_pythonpath
    env.update(extra_env or {})
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


def _value_lines(path: Path) -> list[str]:
    """The file's assignment lines, without dotenvx's header block and public key."""
    return [
        line
        for line in path.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith(("#", "DOTENV_PUBLIC_KEY"))
    ]


class TestDecryptKeepsEveryValue:
    """``envdrift decrypt`` writes back the literal each value was encrypted from."""

    def test_encrypt_then_decrypt_restores_the_text(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        env_file = git_repo / ".env.staging"
        env_file.write_text("\n".join(_VALUE_LINES) + "\n", encoding="utf-8")
        encrypted = _run_envdrift(
            ["encrypt", ".env.staging"],
            cwd=git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )
        assert encrypted.returncode == 0, _flat(encrypted)
        assert "mQ2zz" not in env_file.read_text(encoding="utf-8")

        result = _run_envdrift(
            ["decrypt", ".env.staging"],
            cwd=git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
            extra_env=_DECRYPT_ENV,
        )

        assert result.returncode == 0, _flat(result)
        assert "Decrypted .env.staging using dotenvx" in _flat(result)
        assert _value_lines(env_file) == _VALUE_LINES

    def test_a_same_named_variable_does_not_replace_the_secret(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        env_file = git_repo / ".env.staging"
        env_file.write_text(f"DB_PASSWORD={_PASSWORD}\nOTHER=x\n", encoding="utf-8")
        encrypted = _run_envdrift(
            ["encrypt", ".env.staging"],
            cwd=git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )
        assert encrypted.returncode == 0, _flat(encrypted)

        result = _run_envdrift(
            ["decrypt", ".env.staging"],
            cwd=git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
            extra_env={"DB_PASSWORD": "FROM_THE_SHELL", "OTHER": "FROM_THE_SHELL"},
        )

        assert result.returncode == 0, _flat(result)
        assert _value_lines(env_file) == [f"DB_PASSWORD={_PASSWORD}", "OTHER=x"]

    def test_plaintext_lines_of_a_partly_encrypted_file_stay_byte_for_byte(
        self, git_repo: Path, integration_pythonpath: str, envdrift_cmd: list[str]
    ) -> None:
        env_file = git_repo / ".env.staging"
        env_file.write_text(f"DB_PASSWORD={_PASSWORD}\n", encoding="utf-8")
        encrypted = _run_envdrift(
            ["encrypt", ".env.staging"],
            cwd=git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
        )
        assert encrypted.returncode == 0, _flat(encrypted)
        plaintext = "PLAIN_REF=http://${HOST}/x\nPLAIN_DOLLAR=a$b\nSPACED = kept as is\n"
        with env_file.open("a", encoding="utf-8") as handle:
            handle.write(plaintext)

        result = _run_envdrift(
            ["decrypt", ".env.staging"],
            cwd=git_repo,
            integration_pythonpath=integration_pythonpath,
            envdrift_cmd=envdrift_cmd,
            extra_env={"HOST": "example.com", "b": "FROM_ENV"},
        )

        assert result.returncode == 0, _flat(result)
        text = env_file.read_text(encoding="utf-8")
        assert f"DB_PASSWORD={_PASSWORD}\n" in text
        assert text.endswith(plaintext)


class TestPullPartialThenPushKeepsSecrets:
    """The documented ``pull-partial`` then ``push`` routine never changes a secret."""

    def test_round_trip_keeps_values_that_hold_a_dollar(
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
        secret.write_text(f"DB_PASSWORD={_PASSWORD}\nAPI_TOKEN={_TOKEN}\n", encoding="utf-8")

        def run(*args: str) -> subprocess.CompletedProcess[str]:
            result = _run_envdrift(
                list(args),
                cwd=git_repo,
                integration_pythonpath=integration_pythonpath,
                envdrift_cmd=envdrift_cmd,
                extra_env=_DECRYPT_ENV,
            )
            assert result.returncode == 0, f"{args}: {_flat(result)}"
            return result

        run("push")
        subprocess.run(["git", "add", "-A"], cwd=git_repo, check=True)
        subprocess.run(["git", "commit", "-qm", "init"], cwd=git_repo, check=True)

        run("pull-partial")
        assert _value_lines(secret) == [f"DB_PASSWORD={_PASSWORD}", f"API_TOKEN={_TOKEN}"]
        run("push")
        run("pull-partial")

        assert _value_lines(secret) == [f"DB_PASSWORD={_PASSWORD}", f"API_TOKEN={_TOKEN}"]


def test_decrypt_reads_the_values_back_whatever_the_line_endings_windows_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Windows writes text with \r\n line endings, and decrypt found no value (#946).

    The copy dotenvx decrypts was written as text, so on Windows its lines ended with
    \r\n, and dotenvx's output kept them: every decrypt failed with "its output ... did
    not hold every decrypted value". Here every text write ends its lines as Windows does,
    and the real dotenvx decrypts the copy.
    """
    from envdrift.integrations.dotenvx import DotenvxWrapper

    env_file = tmp_path / ".env.staging"
    env_file.write_bytes(f"DB_PASSWORD={_PASSWORD}\nAPI_TOKEN={_TOKEN}\n".encode())
    subprocess.run(
        ["dotenvx", "encrypt", "-f", env_file.name, "-fk", ".env.keys"],
        cwd=tmp_path,
        capture_output=True,
        check=True,
        timeout=120,
    )
    write_text = Path.write_text

    def as_on_windows(path: Path, data: str, *args: object, **kwargs: object) -> int:
        return write_text(path, data.replace("\n", "\r\n"), *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "write_text", as_on_windows)

    DotenvxWrapper().decrypt(env_file, env_keys_file=tmp_path / ".env.keys", cwd=tmp_path)

    text = env_file.read_bytes().decode()
    assert text.endswith(f"DB_PASSWORD={_PASSWORD}\nAPI_TOKEN={_TOKEN}\n"), text
    assert "encrypted:" not in text and "\r" not in text
