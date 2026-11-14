"""End to end: envdrift encrypts with the key the folder holds, or fails closed.

Covers #938 (lock/encrypt minted a new dotenvx key next to the folder's key, or
replaced it, and still reported success) and #943 (``[vault.sync]
env_keys_filename`` was ignored whenever pull, lock and vault-push --all ran
dotenvx).

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
    private_keys,
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


# --- #938: lock and encrypt reuse the folder's key ------------------------------


def test_lock_verify_vault_reuses_the_synced_vault_key(
    cli: _Cli, vault: KV2StandIn, tmp_path: Path
):
    """#938 case 1: a new file is encrypted with the vault key, not a fresh one."""
    k1 = _mint_key(cli, tmp_path / "k1")
    vault.put("app-key", {"value": f"{PRODUCTION}={k1}"})
    _write_config(cli, vault.url, _mapping("app-key"))
    svc = cli.cwd / "svc"
    svc.mkdir()
    secret = "brand-new-" + "secret"
    (svc / ".env.production").write_text(f"API_TOKEN={secret}\n", encoding="utf-8")

    assert cli.run("sync", "--force")[0] == 0
    code, out = cli.run("lock", "--verify-vault", "--force")

    assert code == 0, out
    assert _held(svc / ".env.keys") == [k1]
    assert _decrypt_with_only(cli, svc / ".env.production", k1, tmp_path / "d") == {
        "API_TOKEN": secret
    }
    # The checks now hold on a correct state.
    assert cli.run("sync", "--verify", "--check-decryption", "--ci")[0] == 0
    assert cli.run("lock", "--verify-vault", "--check")[0] == 0


def test_checks_fail_a_file_encrypted_with_a_second_minted_key(
    cli: _Cli, vault: KV2StandIn, tmp_path: Path
):
    """#938: K1 then a minted K2 under one name must fail every check.

    The broken state is made the way the bug made it: the real dotenvx 2.x
    encrypting a file without a public key next to a keys file holding K1.
    dotenvx decrypts with any key in the file, so a check that hands it the
    whole keys file passed; the checks must test K1 alone.
    """
    k1 = _mint_key(cli, tmp_path / "k1")
    vault.put("app-key", {"value": f"{PRODUCTION}={k1}"})
    _write_config(cli, vault.url, _mapping("app-key"))
    svc = cli.cwd / "svc"
    svc.mkdir()
    (svc / ".env.keys").write_text(f"# .env.production\n{PRODUCTION}={k1}\n", encoding="utf-8")
    (svc / ".env.production").write_text("API_TOKEN=minted\n", encoding="utf-8")
    assert (
        cli.dotenvx("encrypt", "-f", ".env.production", "-fk", ".env.keys", cwd=svc).returncode == 0
    )
    assert len(_held(svc / ".env.keys")) == 2  # dotenvx appended a second key
    before = _snapshot(svc / ".env.keys", svc / ".env.production")

    assert cli.run("sync", "--verify", "--check-decryption", "--ci")[0] == 1
    code, out = cli.run("lock", "--verify-vault", "--check")
    assert code == 1, out
    assert "KEY MISMATCH" in out
    code, out = cli.run("lock", "--force")
    assert code == 1, out
    assert f"holds 2 different keys under {PRODUCTION}" in out
    assert _snapshot(svc / ".env.keys", svc / ".env.production") == before


def test_second_lock_of_a_mapped_env_file_keeps_the_first_key(cli: _Cli, tmp_path: Path):
    """#938 case 2: the canonical header is kept, so the second lock reuses K1."""
    _write_config(cli, "http://127.0.0.1:1", _mapping("svc-key", extra='env_file = ".env.prod"\n'))
    svc = cli.cwd / "svc"
    svc.mkdir()
    env_file = svc / ".env.prod"
    env_file.write_text("DB_PASSWORD=prod-pass\n", encoding="utf-8")
    assert cli.run("lock", "--force")[0] == 0
    (k1,) = _held(svc / ".env.keys")

    with env_file.open("a", encoding="utf-8") as handle:
        handle.write("NEW_TOKEN=tok123\n")
    code, out = cli.run("lock", "--force")

    assert code == 0, out
    assert _held(svc / ".env.keys") == [k1]
    assert _decrypt_with_only(cli, env_file, k1, tmp_path / "d") == {
        "DB_PASSWORD": "prod-pass",
        "NEW_TOKEN": "tok123",
    }


def test_encrypt_after_a_rename_keeps_the_files_key(cli: _Cli, tmp_path: Path):
    """#938: a renamed file keeps its lone header, so old and new values share a key.

    The old header cleanup stripped a header whose name no longer matched the
    filename, and dotenvx then created a second key for the new values.
    """
    svc = cli.cwd
    (svc / ".env.staging").write_text("OLD=old-value\n", encoding="utf-8")
    assert cli.run("encrypt", ".env.staging")[0] == 0
    (key,) = _held(svc / ".env.keys", "DOTENV_PRIVATE_KEY_STAGING")
    (svc / ".env.staging").rename(svc / ".env.production")
    with (svc / ".env.production").open("a", encoding="utf-8") as handle:
        handle.write("NEW=new-value\n")

    code, out = cli.run("encrypt", ".env.production")

    assert code == 0, out
    assert list(private_keys((svc / ".env.keys").read_text(encoding="utf-8"))) == [
        "DOTENV_PRIVATE_KEY_STAGING"
    ]
    assert _decrypt_with_only(cli, svc / ".env.production", key, tmp_path / "d") == {
        "OLD": "old-value",
        "NEW": "new-value",
    }


@pytest.mark.parametrize(
    "line_form",
    [
        pytest.param('export {name} = "{key}" # the vault key', id="export-spaces-quotes-comment"),
        pytest.param(chr(0xFEFF) + "{name}={key}", id="utf8-bom"),
        pytest.param("{name}: {key}", id="colon-form"),
    ],
)
def test_encrypt_reads_the_key_line_the_way_dotenvx_does(cli: _Cli, tmp_path: Path, line_form: str):
    """S2: a key line dotenvx loads is the key envdrift seeds (no second key)."""
    key = _mint_key(cli, tmp_path / "k")
    keys_file = cli.cwd / ".env.keys"
    keys_file.write_text(line_form.format(name=PRODUCTION, key=key) + "\n", encoding="utf-8")
    keys_before = keys_file.read_bytes()
    (cli.cwd / ".env.production").write_text("A=one\n", encoding="utf-8")

    code, out = cli.run("encrypt", ".env.production")

    assert code == 0, out
    assert keys_file.read_bytes() == keys_before
    assert _decrypt_with_only(cli, cli.cwd / ".env.production", key, tmp_path / "d") == {"A": "one"}


def test_encrypt_names_a_multi_part_file_like_dotenvx(cli: _Cli, tmp_path: Path):
    """N1: .env.prod.eu.west's key is DOTENV_PRIVATE_KEY_PROD_EU, as dotenvx names it."""
    key = _mint_key(cli, tmp_path / "k")
    keys_file = cli.cwd / ".env.keys"
    keys_file.write_text(f"DOTENV_PRIVATE_KEY_PROD_EU={key}\n", encoding="utf-8")
    keys_before = keys_file.read_bytes()
    (cli.cwd / ".env.prod.eu.west").write_text("A=one\n", encoding="utf-8")

    code, out = cli.run("encrypt", ".env.prod.eu.west")

    assert code == 0, out
    assert keys_file.read_bytes() == keys_before
    env_file = cli.cwd / ".env.prod.eu.west"
    assert _decrypt_with_only(cli, env_file, key, tmp_path / "d") == {"A": "one"}


def test_encrypt_refuses_a_garbage_key_with_an_accurate_message(cli: _Cli):
    """B2: fail closed and say the key is invalid; nothing is changed."""
    (cli.cwd / ".env").write_text("API_KEY=" + "super" + "secret123\n", encoding="utf-8")
    (cli.cwd / ".env.keys").write_text(
        "garbage not a key\nDOTENV_PRIVATE_KEY=zzz_not_hex\n", encoding="utf-8"
    )
    before = _snapshot(cli.cwd / ".env", cli.cwd / ".env.keys")

    code, out = cli.run("encrypt", ".env")

    assert code == 1, out
    assert "DOTENV_PRIVATE_KEY" in out
    assert "is not a valid dotenvx key" in out
    assert "different keys" not in out
    assert _snapshot(cli.cwd / ".env", cli.cwd / ".env.keys") == before


def test_encrypt_refuses_two_keys_and_restores_crlf_byte_for_byte(cli: _Cli, tmp_path: Path):
    """#938 + N3: refused before dotenvx; the CRLF file is left exactly as it was."""
    k1 = _mint_key(cli, tmp_path / "k1")
    k2 = _mint_key(cli, tmp_path / "k2")
    keys_file = cli.cwd / ".env.keys"
    keys_file.write_text(f"{PRODUCTION}={k1}\n{PRODUCTION}={k2}\n", encoding="utf-8")
    env_file = cli.cwd / ".env.production"
    env_file.write_bytes(b"A=one\r\nB=two\r\n")
    before = _snapshot(env_file, keys_file)

    code, out = cli.run("encrypt", ".env.production")

    assert code == 1, out
    assert f"holds 2 different keys under {PRODUCTION}" in out
    assert _snapshot(env_file, keys_file) == before


def test_encrypt_corrects_another_keys_header_before_anything_is_encrypted(
    cli: _Cli, tmp_path: Path
):
    """B4: no encrypted values yet, so the header is rewritten to the held key."""
    k1 = _mint_key(cli, tmp_path / "k1")
    k2 = _mint_key(cli, tmp_path / "k2")
    (cli.cwd / ".env.keys").write_text(f"{PRODUCTION}={k1}\n", encoding="utf-8")
    env_file = cli.cwd / ".env.production"
    env_file.write_text(
        f'DOTENV_PUBLIC_KEY_PRODUCTION="{public_key_for(k2)}"\nA=one\n', encoding="utf-8"
    )

    code, out = cli.run("encrypt", ".env.production")

    assert code == 0, out
    assert public_key_values(env_file.read_text(encoding="utf-8")) == [public_key_for(k1)]
    assert _decrypt_with_only(cli, env_file, k1, tmp_path / "d") == {"A": "one"}


def test_encrypt_refuses_a_file_already_encrypted_under_another_key(cli: _Cli, tmp_path: Path):
    """B4: values encrypted under K2 and a held K1 must not be mixed in one file."""
    k1 = _mint_key(cli, tmp_path / "k1")
    k2 = _mint_key(cli, tmp_path / "k2")
    env_file = cli.cwd / ".env.production"
    (cli.cwd / "k2.keys").write_text(f"{PRODUCTION}={k2}\n", encoding="utf-8")
    env_file.write_text(
        f'DOTENV_PUBLIC_KEY_PRODUCTION="{public_key_for(k2)}"\nOLD=old\n', encoding="utf-8"
    )
    assert cli.dotenvx("encrypt", "-f", env_file.name, "-fk", "k2.keys").returncode == 0
    with env_file.open("a", encoding="utf-8") as handle:
        handle.write("NEW=new\n")
    (cli.cwd / ".env.keys").write_text(f"{PRODUCTION}={k1}\n", encoding="utf-8")
    before = _snapshot(env_file, cli.cwd / ".env.keys")

    code, out = cli.run("encrypt", ".env.production")

    assert code == 1, out
    assert "encrypted with another public key" in out
    assert _snapshot(env_file, cli.cwd / ".env.keys") == before


# --- B3: a key conflict is a clean, per-command error ---------------------------


def _conflicting_keys(svc: Path, k1: str, k2: str) -> Path:
    """A keys file holding the canonical K1 and a different K2 dotenvx made for .env.prod."""
    keys_file = svc / ".env.keys"
    keys_file.write_text(
        f"# .env.production\n{PRODUCTION}={k1}\n\n# .env.prod\nDOTENV_PRIVATE_KEY_PROD={k2}\n",
        encoding="utf-8",
    )
    return keys_file


def test_lock_refuses_a_key_conflict_before_touching_either_file(cli: _Cli, tmp_path: Path):
    """B3: checked before the env file's header is rewritten; both files unchanged."""
    k1 = _mint_key(cli, tmp_path / "k1")
    k2 = _mint_key(cli, tmp_path / "k2")
    _write_config(cli, "http://127.0.0.1:1", _mapping("svc-key", extra='env_file = ".env.prod"\n'))
    svc = cli.cwd / "svc"
    svc.mkdir()
    keys_file = _conflicting_keys(svc, k1, k2)
    env_file = svc / ".env.prod"
    env_file.write_text(
        f'DOTENV_PUBLIC_KEY_PROD="{public_key_for(k2)}"\n\n# .env.prod\nDB=plain\n',
        encoding="utf-8",
    )
    before = _snapshot(env_file, keys_file)

    code, out = cli.run("lock", "--force")

    assert code == 1, out
    assert "holds two different keys for .env.prod" in out
    assert "Lock complete" not in out
    assert _snapshot(env_file, keys_file) == before


def test_pull_reports_a_key_conflict_without_claiming_to_encrypt(cli: _Cli, tmp_path: Path):
    """B3: pull encrypts nothing, so its error says the file was not decrypted."""
    k1 = _mint_key(cli, tmp_path / "k1")
    k2 = _mint_key(cli, tmp_path / "k2")
    _write_config(cli, "http://127.0.0.1:1", _mapping("svc-key", extra='env_file = ".env.prod"\n'))
    svc = cli.cwd / "svc"
    svc.mkdir()
    (svc / "k2.keys").write_text(f"DOTENV_PRIVATE_KEY_PROD={k2}\n", encoding="utf-8")
    (svc / ".env.prod").write_text("DB=secret\n", encoding="utf-8")
    assert cli.dotenvx("encrypt", "-f", ".env.prod", "-fk", "k2.keys", cwd=svc).returncode == 0
    keys_file = _conflicting_keys(svc, k1, k2)
    before = _snapshot(svc / ".env.prod", keys_file)

    code, out = cli.run("pull", "--skip-sync")

    assert code == 1, out
    assert "not decrypted" in out
    assert "holds two different keys for .env.prod" in out
    assert "encrypted" not in out.split("not decrypted", 1)[1].split("Decrypt Summary")[0]
    assert _snapshot(svc / ".env.prod", keys_file) == before


def test_vault_push_all_reports_each_mapping_and_continues(
    cli: _Cli, vault: KV2StandIn, tmp_path: Path
):
    """B3: one mapping's refused key change does not abort the others; exit 1."""
    k1 = _mint_key(cli, tmp_path / "k1")
    k2 = _mint_key(cli, tmp_path / "k2")
    _write_config(
        cli,
        vault.url,
        _mapping("a-key", folder="svc-a", extra='env_file = ".env.prod"\n')
        + _mapping("b-key", folder="svc-b"),
    )
    svc_a = cli.cwd / "svc-a"
    svc_a.mkdir()
    keys_a = _conflicting_keys(svc_a, k1, k2)
    (svc_a / ".env.prod").write_text("DB=plain\n", encoding="utf-8")
    before_a = _snapshot(svc_a / ".env.prod", keys_a)
    svc_b = cli.cwd / "svc-b"
    svc_b.mkdir()
    (svc_b / ".env.production").write_text("B=bee\n", encoding="utf-8")

    code, out = cli.run("vault-push", "--all", "--force")

    assert code == 1, out
    assert "Pushed: 1" in out
    assert "Errors: 1" in out
    assert vault.get("a-key") is None
    pushed = vault.get("b-key")
    assert pushed is not None
    b_key = pushed["value"].split("=", 1)[1]
    assert _decrypt_with_only(cli, svc_b / ".env.production", b_key, tmp_path / "d") == {"B": "bee"}
    assert _snapshot(svc_a / ".env.prod", keys_a) == before_a


# --- B5: a renamed file's key is re-labeled, not re-encrypted -------------------


def test_lock_relabels_a_renamed_files_key(cli: _Cli, tmp_path: Path):
    """B5: the same key under the expected name and header; ciphertext unchanged."""
    _write_config(cli, "http://127.0.0.1:1", _mapping("s", env="localenv"))
    svc = cli.cwd / "svc"
    svc.mkdir()
    (svc / ".env.local").write_text("A=one\nB=two\n", encoding="utf-8")
    assert cli.dotenvx("encrypt", "-f", ".env.local", "-fk", ".env.keys", cwd=svc).returncode == 0
    (key,) = _held(svc / ".env.keys", "DOTENV_PRIVATE_KEY_LOCAL")
    (svc / ".env.local").rename(svc / ".env.localenv")
    values_before = {
        name: values
        for name, values in _parse((svc / ".env.localenv").read_text(encoding="utf-8")).items()
        if not name.startswith("DOTENV_PUBLIC_KEY")
    }

    code, out = cli.run("lock", "--force")

    assert code == 0, out
    assert "key re-labeled (DOTENV_PRIVATE_KEY_LOCAL -> DOTENV_PRIVATE_KEY_LOCALENV)" in out
    assert "re-encrypted with new key" not in out
    assert _held(svc / ".env.keys", "DOTENV_PRIVATE_KEY_LOCALENV") == [key]
    env_text = (svc / ".env.localenv").read_text(encoding="utf-8")
    assert assignment_values(env_text, "DOTENV_PUBLIC_KEY_LOCALENV") == [public_key_for(key)]
    values_after = {
        name: values
        for name, values in _parse(env_text).items()
        if not name.startswith("DOTENV_PUBLIC_KEY")
    }
    assert values_after == values_before  # the same ciphertext, not re-encrypted
    assert _decrypt_with_only(cli, svc / ".env.localenv", key, tmp_path / "d") == {
        "A": "one",
        "B": "two",
    }
    code, out = cli.run("lock", "--force")
    assert code == 0, out
    assert "already encrypted" in out


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


def test_vault_push_all_pushes_the_held_key_that_decrypts_the_file(
    cli: _Cli, vault: KV2StandIn, tmp_path: Path
):
    """#938 + #943: the key already in env_keys_filename encrypts the file and is pushed."""
    svc = _custom_keys_config(cli, vault.url)
    k1 = _mint_key(cli, tmp_path / "k1")
    (svc / ".secrets.keys").write_text(f"{PRODUCTION}={k1}\n", encoding="utf-8")
    (svc / ".env.production").write_text("API_TOKEN=new\n", encoding="utf-8")

    code, out = cli.run("vault-push", "--all", "--force")

    assert code == 0, out
    assert not (svc / ".env.keys").exists()
    assert _held(svc / ".secrets.keys") == [k1]
    assert vault.get("app-key") == {"value": f"{PRODUCTION}={k1}"}
    assert _decrypt_with_only(cli, svc / ".env.production", k1, tmp_path / "d") == {
        "API_TOKEN": "new"
    }
