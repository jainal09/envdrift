"""End to end: envdrift uses the keys file and the key the folder holds.

Covers #943 (``[vault.sync] env_keys_filename`` was ignored whenever pull, lock
and vault-push --all ran dotenvx).

Everything runs for real: the ``envdrift`` CLI as a subprocess, the pinned
``dotenvx`` binary, and git. Only the vault is a stand-in: a small KV-v2 HTTP
server (``kv2_standin``) that the CLI's real ``hvac`` client talks to, so no
containers are needed. "Decrypts with K1 alone" is checked by copying the file
next to a keys file that holds nothing but K1, which is what a teammate or CI
with the vault key has.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest
from tests.integration.kv2_standin import TOKEN, KV2StandIn

from envdrift.integrations.dotenvx_keys import (
    assignment_values,
    public_key_for,
    public_key_values,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("dotenvx") is None, reason="dotenvx binary not installed"),
]

PRODUCTION = "DOTENV_PRIVATE_KEY_PRODUCTION"


# --- helpers ------------------------------------------------------------------


def _child_env(pythonpath: str) -> dict[str, str]:
    """The CLI's environment: this checkout's code, the stand-in token, no stray keys."""
    env = {key: value for key, value in os.environ.items() if not key.startswith("DOTENV_")}
    env.pop("FORCE_COLOR", None)
    env["NO_COLOR"] = "1"
    env["PYTHONPATH"] = pythonpath
    env["VAULT_TOKEN"] = TOKEN
    for name in ("NO_PROXY", "no_proxy"):
        env[name] = ",".join(filter(None, [env.get(name, ""), "127.0.0.1", "localhost"]))
    return env


class _Cli:
    """Run the real envdrift CLI (and dotenvx) in one work directory."""

    def __init__(self, cwd: Path, envdrift_cmd: list[str], pythonpath: str) -> None:
        self.cwd = cwd
        self.envdrift_cmd = envdrift_cmd
        self.env = _child_env(pythonpath)

    def run(self, *args: str) -> tuple[int, str]:
        result = subprocess.run(
            [*self.envdrift_cmd, *args],
            cwd=self.cwd,
            env=self.env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        # Width-independent: Rich soft-wraps long tmp paths at CI's width.
        return result.returncode, " ".join((result.stdout + result.stderr).split())

    def dotenvx(self, *args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["dotenvx", *args],
            cwd=cwd or self.cwd,
            env=self.env,
            capture_output=True,
            text=True,
            timeout=60,
        )


@pytest.fixture
def cli(tmp_path: Path, envdrift_cmd: list[str], integration_pythonpath: str) -> _Cli:
    work = tmp_path / "work"
    work.mkdir()
    return _Cli(work, envdrift_cmd, integration_pythonpath)


@pytest.fixture
def vault() -> Iterator[KV2StandIn]:
    pytest.importorskip("hvac")
    with KV2StandIn() as standin:
        yield standin


def _mint_key(cli: _Cli, scratch: Path) -> str:
    """Return a fresh private key minted by the real dotenvx binary."""
    scratch.mkdir(parents=True, exist_ok=True)
    (scratch / ".env").write_text("SEED=1\n", encoding="utf-8")
    result = cli.dotenvx("encrypt", "-f", ".env", "-fk", ".env.keys", cwd=scratch)
    assert result.returncode == 0, result.stderr
    keys = (scratch / ".env.keys").read_text(encoding="utf-8")
    return assignment_values(keys, "DOTENV_PRIVATE_KEY")[0]


def _held(keys_file: Path, name: str = PRODUCTION) -> list[str]:
    """Every value the keys file holds under ``name``, as dotenvx reads it."""
    return assignment_values(keys_file.read_text(encoding="utf-8"), name)


def _decrypt_with_only(cli: _Cli, env_file: Path, key: str, scratch: Path) -> dict[str, str]:
    """Decrypt a copy of ``env_file`` with a keys file holding nothing but ``key``.

    Returns every decrypted value, or fails the test when dotenvx cannot.
    """
    scratch.mkdir(parents=True, exist_ok=True)
    copy = scratch / env_file.name
    shutil.copyfile(env_file, copy)
    (scratch / "only.keys").write_text(f"DOTENV_PRIVATE_KEY_ONLY={key}\n", encoding="utf-8")
    result = cli.dotenvx("decrypt", "-f", copy.name, "-fk", "only.keys", "--stdout", cwd=scratch)
    assert result.returncode == 0, (
        f"{env_file.name} does not decrypt with that key alone: {result.stderr}"
    )
    parsed = {
        name: values[-1]
        for name, values in _parse(result.stdout).items()
        if not name.startswith("DOTENV_PUBLIC_KEY")
    }
    assert not any(value.startswith("encrypted:") for value in parsed.values()), parsed
    return parsed


def _parse(text: str) -> dict[str, list[str]]:
    from envdrift.integrations.dotenvx_keys import parse_assignments

    return parse_assignments(text)


def _write_config(cli: _Cli, vault_url: str, mappings: str, sync_options: str = "") -> None:
    (cli.cwd / "envdrift.toml").write_text(
        '[vault]\nprovider = "hashicorp"\n'
        f'[vault.hashicorp]\nurl = "{vault_url}"\n'
        f"[vault.sync]\n{sync_options}\n{mappings}",
        encoding="utf-8",
    )


def _mapping(secret: str, folder: str = "svc", env: str = "production", extra: str = "") -> str:
    return (
        "[[vault.sync.mappings]]\n"
        f'secret_name = "{secret}"\nfolder_path = "{folder}"\nenvironment = "{env}"\n{extra}'
    )


def _snapshot(*paths: Path) -> dict[Path, bytes | None]:
    return {path: path.read_bytes() if path.exists() else None for path in paths}


# --- the arithmetic agrees with the pinned binary -------------------------------


def test_public_key_for_matches_a_pair_minted_by_the_pinned_dotenvx(cli: _Cli, tmp_path: Path):
    scratch = tmp_path / "pair"
    key = _mint_key(cli, scratch)
    header = public_key_values((scratch / ".env").read_text(encoding="utf-8"))
    assert header == [public_key_for(key)]


# --- #943: [vault.sync] env_keys_filename reaches every dotenvx call ------------


def _custom_keys_config(cli: _Cli, vault_url: str) -> Path:
    _write_config(
        cli, vault_url, _mapping("app-key"), sync_options='env_keys_filename = ".secrets.keys"\n'
    )
    svc = cli.cwd / "svc"
    svc.mkdir()
    return svc


def test_pull_decrypts_with_the_configured_keys_file(cli: _Cli):
    svc = _custom_keys_config(cli, "http://127.0.0.1:1")
    (svc / ".env.production").write_text("API_TOKEN=" + "s3" + "cret\n", encoding="utf-8")
    assert (
        cli.dotenvx("encrypt", "-f", ".env.production", "-fk", ".secrets.keys", cwd=svc).returncode
        == 0
    )

    code, out = cli.run("pull", "--skip-sync")

    assert code == 0, out
    assert assignment_values(
        (svc / ".env.production").read_text(encoding="utf-8"), "API_TOKEN"
    ) == ["s3" + "cret"]
    assert not (svc / ".env.keys").exists()


def test_lock_writes_the_key_into_the_configured_keys_file(cli: _Cli, tmp_path: Path):
    svc = _custom_keys_config(cli, "http://127.0.0.1:1")
    (svc / ".env.production").write_text("API_TOKEN=new\n", encoding="utf-8")

    code, out = cli.run("lock", "--force")

    assert code == 0, out
    assert not (svc / ".env.keys").exists()
    (key,) = _held(svc / ".secrets.keys")
    assert _decrypt_with_only(cli, svc / ".env.production", key, tmp_path / "d") == {
        "API_TOKEN": "new"
    }


def test_vault_push_all_writes_and_pushes_the_configured_keys_file(
    cli: _Cli, vault: KV2StandIn, tmp_path: Path
):
    """#943: the key dotenvx creates lands in env_keys_filename, and that key is pushed."""
    svc = _custom_keys_config(cli, vault.url)
    (svc / ".env.production").write_text("API_TOKEN=new\n", encoding="utf-8")

    code, out = cli.run("vault-push", "--all", "--force")

    assert code == 0, out
    assert not (svc / ".env.keys").exists()
    (key,) = _held(svc / ".secrets.keys")
    assert vault.get("app-key") == {"value": f"{PRODUCTION}={key}"}
    assert _decrypt_with_only(cli, svc / ".env.production", key, tmp_path / "d") == {
        "API_TOKEN": "new"
    }
