"""Regression tests for issue #473: vault verification flows must be truthful.

All three vault-verification flows gave wrong verdicts or had destructive side
effects:

- ``lock --verify-vault`` degraded "cannot verify" (missing ``.env.keys`` or a
  missing vault secret) to a warning, minted a fresh LOCAL-ONLY key in Step 2,
  and exited 0 "ready to commit" — teammates holding the vault key could not
  decrypt the committed file.
- ``decrypt --verify-vault`` false-failed ("Vault key CANNOT decrypt this
  file!", exit 1, destructive ``git restore`` advice) when the vault stored the
  key in the quoted dotenvx ``.env.keys`` line format that lock/sync accept.
- ``sync --check-decryption`` reported "Decryption: FAILED" for every mapping
  with a relative ``folder_path`` (dotenvx ran with the folder-prefixed path
  AND ``cwd`` set to that folder), and a PASSING check rewrote every tested
  encrypted file in place (decrypt + re-encrypt of the LIVE file).

These tests drive the real ``envdrift`` CLI as a subprocess with the real
``dotenvx`` binary against the live HashiCorp Vault container
(``tests/docker-compose.test.yml``). Every vault path is namespaced under a
unique per-test prefix and cleaned up afterwards.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import os
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from tests.integration.conftest import VAULT_ROOT_TOKEN

if TYPE_CHECKING:
    from collections.abc import Generator

HVAC_AVAILABLE = importlib.util.find_spec("hvac") is not None

pytestmark = [
    pytest.mark.integration,
    pytest.mark.vault,
    pytest.mark.skipif(shutil.which("dotenvx") is None, reason="dotenvx binary not installed"),
    pytest.mark.skipif(
        not HVAC_AVAILABLE,
        reason="hvac not installed - install with: pip install envdrift[hashicorp]",
    ),
]


def _config_toml(secret_name: str, folder_path: str) -> str:
    """Minimal envdrift.toml with one dotenvx-backed hashicorp sync mapping."""
    return f"""\
[encryption]
backend = "dotenvx"

[vault]
provider = "hashicorp"

[[vault.sync.mappings]]
secret_name = "{secret_name}"
folder_path = "{folder_path}"
environment = "production"
"""


def _run(
    envdrift_cmd: list[str],
    args: list[str],
    cwd: Path,
    env: dict[str, str],
    timeout: int = 120,
) -> subprocess.CompletedProcess[str]:
    """Run the real envdrift CLI as a subprocess in ``cwd``."""
    return subprocess.run(
        [*envdrift_cmd, *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )


def _norm(result: subprocess.CompletedProcess[str]) -> str:
    """Normalize Rich output (line wraps under narrow CI consoles) for substring asserts."""
    return " ".join((result.stdout + result.stderr).split())


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def vault_prefix(vault_client) -> Generator[str, None, None]:
    """Unique KV v2 path prefix for this test; deletes everything under it after."""
    prefix = f"test/verify473-{uuid.uuid4().hex[:12]}"
    created: list[str] = []

    yield prefix

    # Best-effort cleanup of every secret created under the prefix. Secrets are
    # stored at `<prefix>/<leaf>`, so list the prefix itself (a KV v2 directory)
    # and delete each leaf.
    with contextlib.suppress(Exception):
        listed = vault_client.secrets.kv.v2.list_secrets(path=prefix, mount_point="secret")
        created = [f"{prefix}/{key}" for key in listed.get("data", {}).get("keys", [])]
    for path in created:
        with contextlib.suppress(Exception):
            vault_client.secrets.kv.v2.delete_metadata_and_all_versions(
                path=path, mount_point="secret"
            )


def _store_vault_value(vault_client, path: str, value: str) -> None:
    """Store ``value`` at KV v2 ``path`` (under the ``secret/`` mount)."""
    vault_client.secrets.kv.v2.create_or_update_secret(
        path=path, secret={"value": value}, mount_point="secret"
    )


def _child_env(vault_endpoint: str, integration_pythonpath: str) -> dict[str, str]:
    """Subprocess env: parent env + PYTHONPATH + vault auth, no stray dotenvx keys."""
    env = os.environ.copy()
    env["PYTHONPATH"] = integration_pythonpath
    env["VAULT_ADDR"] = vault_endpoint
    env["VAULT_TOKEN"] = VAULT_ROOT_TOKEN
    # Stray parent keys must not leak into dotenvx invocations under test.
    for key in [k for k in env if k.startswith("DOTENV_PRIVATE_KEY")]:
        env.pop(key)
    env.pop("DOTENV_KEY", None)
    return env


def _make_real_keypair(
    envdrift_cmd: list[str], env: dict[str, str], tmp_path: Path
) -> tuple[str, str]:
    """Generate a real dotenvx keypair via a throwaway encrypt.

    Returns ``(private_key, public_key_line_file_text)`` — the private key hex
    and the full encrypted file text (carrying the matching public-key header).
    """
    scratch = tmp_path / f"keygen-{uuid.uuid4().hex[:8]}"
    scratch.mkdir()
    env_file = scratch / ".env.production"
    env_file.write_text("SEED_SECRET=seed-value\n", encoding="utf-8")
    result = _run(envdrift_cmd, ["encrypt", ".env.production"], scratch, env)
    assert result.returncode == 0, f"setup encrypt failed:\n{result.stdout}\n{result.stderr}"

    from envdrift.sync.operations import EnvKeysFile

    private_key = EnvKeysFile(scratch / ".env.keys").read_key("DOTENV_PRIVATE_KEY_PRODUCTION")
    assert private_key, "dotenvx did not write DOTENV_PRIVATE_KEY_PRODUCTION"
    return private_key, env_file.read_text(encoding="utf-8")


def _encrypt_in_project(
    envdrift_cmd: list[str], env: dict[str, str], project: Path, rel_path: str, pairs: list[str]
) -> Path:
    """Write ``pairs`` to ``rel_path`` under ``project`` and encrypt with real dotenvx."""
    file = project / rel_path
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text("\n".join(pairs) + "\n", encoding="utf-8")
    result = _run(envdrift_cmd, ["encrypt", rel_path], project, env)
    assert result.returncode == 0, f"setup encrypt failed:\n{result.stdout}\n{result.stderr}"
    assert "encrypted:" in file.read_text(encoding="utf-8")
    return file


class TestLockVerifyVaultCannotVerify:
    """Item 1 of #473: 'cannot verify' must be a hard error, never a key mint."""

    def test_missing_env_keys_fails_loudly_and_mints_no_key(
        self,
        tmp_path: Path,
        vault_endpoint: str,
        vault_client,
        vault_prefix: str,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """The damaging first-run repro: vault holds K1, no local .env.keys,
        plaintext env file. lock --verify-vault --force must exit non-zero,
        encrypt nothing, and never mint a fresh local-only key (K2 != K1)."""
        env = _child_env(vault_endpoint, integration_pythonpath)
        secret_path = f"{vault_prefix}/svc-key"

        # Vault holds a REAL key K1 (as vault-push --all would store it).
        k1, _ = _make_real_keypair(envdrift_cmd, env, tmp_path)
        _store_vault_value(vault_client, secret_path, f"DOTENV_PRIVATE_KEY_PRODUCTION={k1}")

        project = tmp_path / "project"
        (project / "svc").mkdir(parents=True)
        (project / "envdrift.toml").write_text(_config_toml(secret_path, "svc"), encoding="utf-8")
        plaintext_file = project / "svc" / ".env.production"
        plaintext_file.write_text("DB_PASSWORD=plainvalue\n", encoding="utf-8")
        before = plaintext_file.read_bytes()

        result = _run(
            envdrift_cmd,
            ["lock", "--verify-vault", "--force", "-p", "hashicorp", "--vault-url", vault_endpoint],
            project,
            env,
        )

        out = _norm(result)
        assert result.returncode == 1, (
            f"lock --verify-vault blessed an unverifiable state with exit "
            f"{result.returncode}:\n{result.stdout}\n{result.stderr}"
        )
        # No fresh local-only key was minted and the file was not encrypted.
        assert not (project / "svc" / ".env.keys").exists(), (
            "lock minted a fresh local-only .env.keys despite failed verification"
        )
        assert plaintext_file.read_bytes() == before, (
            "lock encrypted the file despite failed verification"
        )
        # The error steers the user to --sync-keys, not to a silent key mint.
        assert "cannot verify" in out.lower()
        assert "--sync-keys" in out

    def test_missing_vault_secret_fails_loudly(
        self,
        tmp_path: Path,
        vault_endpoint: str,
        vault_client,
        vault_prefix: str,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """A vault secret that does not exist is 'cannot verify', not a warning."""
        env = _child_env(vault_endpoint, integration_pythonpath)
        # This path is never created in vault.
        secret_path = f"{vault_prefix}/never-pushed"

        project = tmp_path / "project"
        (project / "svc").mkdir(parents=True)
        (project / "envdrift.toml").write_text(_config_toml(secret_path, "svc"), encoding="utf-8")
        env_file = _encrypt_in_project(
            envdrift_cmd, env, project, "svc/.env.production", ["API_KEY=value1"]
        )
        before = env_file.read_bytes()

        result = _run(
            envdrift_cmd,
            ["lock", "--verify-vault", "--force", "-p", "hashicorp", "--vault-url", vault_endpoint],
            project,
            env,
        )

        assert result.returncode == 1, (
            f"lock --verify-vault exited {result.returncode} although the vault secret "
            f"does not exist:\n{result.stdout}\n{result.stderr}"
        )
        assert "not found" in _norm(result).lower()
        assert env_file.read_bytes() == before

    def test_matching_keys_still_verify_and_encrypt(
        self,
        tmp_path: Path,
        vault_endpoint: str,
        vault_client,
        vault_prefix: str,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """Happy path stays green: matching local/vault keys verify and lock encrypts."""
        env = _child_env(vault_endpoint, integration_pythonpath)
        secret_path = f"{vault_prefix}/svc-key"

        project = tmp_path / "project"
        (project / "svc").mkdir(parents=True)
        (project / "envdrift.toml").write_text(_config_toml(secret_path, "svc"), encoding="utf-8")
        _encrypt_in_project(envdrift_cmd, env, project, "svc/.env.production", ["API_KEY=value1"])

        from envdrift.sync.operations import EnvKeysFile

        local_key = EnvKeysFile(project / "svc" / ".env.keys").read_key(
            "DOTENV_PRIVATE_KEY_PRODUCTION"
        )
        assert local_key
        _store_vault_value(vault_client, secret_path, f"DOTENV_PRIVATE_KEY_PRODUCTION={local_key}")

        # Add a fresh plaintext secret so Step 2 has real work to do.
        env_file = project / "svc" / ".env.production"
        env_file.write_text(
            env_file.read_text(encoding="utf-8") + "NEW_SECRET=fresh-plain\n", encoding="utf-8"
        )

        result = _run(
            envdrift_cmd,
            ["lock", "--verify-vault", "--force", "-p", "hashicorp", "--vault-url", vault_endpoint],
            project,
            env,
        )

        out = _norm(result)
        assert result.returncode == 0, f"happy path broke:\n{result.stdout}\n{result.stderr}"
        assert "keys match vault" in out
        assert "fresh-plain" not in env_file.read_text(encoding="utf-8")


class TestLockSyncKeysVerifySemantics:
    """#663: lock's key-sync phase makes a verification claim and must honor it."""

    def test_deleted_secret_without_env_file_fails_closed(
        self,
        tmp_path: Path,
        vault_endpoint: str,
        vault_client,
        vault_prefix: str,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """A deleted secret is an error even when no local env file exists."""
        env = _child_env(vault_endpoint, integration_pythonpath)
        secret_path = f"{vault_prefix}/deleted-lock-key"
        _store_vault_value(
            vault_client,
            secret_path,
            "DOTENV_PRIVATE_KEY_PRODUCTION=deleted-key-value",
        )
        vault_client.secrets.kv.v2.delete_metadata_and_all_versions(
            path=secret_path,
            mount_point="secret",
        )

        project = tmp_path / "project"
        (project / "svc").mkdir(parents=True)
        (project / "envdrift.toml").write_text(
            _config_toml(secret_path, "svc"),
            encoding="utf-8",
        )

        result = _run(
            envdrift_cmd,
            ["lock", "--sync-keys", "--force", "-p", "hashicorp", "--vault-url", vault_endpoint],
            project,
            env,
        )

        out = _norm(result)
        assert result.returncode == 1, (
            f"lock --sync-keys accepted a deleted secret with no env file:\n"
            f"{result.stdout}\n{result.stderr}"
        )
        assert "Verifying keys with vault" in out
        assert secret_path in out
        assert "not found" in out.lower()
        assert "All services synced successfully" not in out
        assert "Encrypting environment files" not in out
        assert not (project / "svc" / ".env.keys").exists()


class TestDecryptVerifyVaultQuotedValue:
    """Item 2 of #473: the quoted dotenvx vault value format must verify, not false-fail."""

    def test_quoted_vault_value_verifies_ok_and_leaves_file_untouched(
        self,
        tmp_path: Path,
        vault_endpoint: str,
        vault_client,
        vault_prefix: str,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """A vault value of DOTENV_PRIVATE_KEY_PRODUCTION="<hex>" (quoted, the
        format lock --verify-vault and sync already accept) must verify with
        exit 0 — not "Vault key CANNOT decrypt this file!" + git-restore advice."""
        env = _child_env(vault_endpoint, integration_pythonpath)
        secret_path = f"{vault_prefix}/quoted-key"

        project = tmp_path / "project"
        project.mkdir()
        env_file = _encrypt_in_project(
            envdrift_cmd, env, project, ".env.production", ["API_KEY=value1"]
        )

        from envdrift.sync.operations import EnvKeysFile

        private_key = EnvKeysFile(project / ".env.keys").read_key("DOTENV_PRIVATE_KEY_PRODUCTION")
        assert private_key

        # The QUOTED dotenvx .env.keys line format.
        _store_vault_value(
            vault_client, secret_path, f'DOTENV_PRIVATE_KEY_PRODUCTION="{private_key}"'
        )
        before = env_file.read_bytes()

        result = _run(
            envdrift_cmd,
            [
                "decrypt",
                ".env.production",
                "--verify-vault",
                "-p",
                "hashicorp",
                "--vault-url",
                vault_endpoint,
                "--secret",
                secret_path,
            ],
            project,
            env,
        )

        out = _norm(result)
        assert result.returncode == 0, (
            f"decrypt --verify-vault false-failed on the quoted vault value format:\n"
            f"{result.stdout}\n{result.stderr}"
        )
        assert "can decrypt" in out.lower()
        assert "cannot decrypt" not in out.lower()
        # Verification is read-only: the live file is byte-identical.
        assert env_file.read_bytes() == before

    def test_wrong_key_still_fails(
        self,
        tmp_path: Path,
        vault_endpoint: str,
        vault_client,
        vault_prefix: str,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """Normalization must not turn verification into a rubber stamp: a vault
        key from a DIFFERENT keypair (also quoted) still fails with exit 1."""
        env = _child_env(vault_endpoint, integration_pythonpath)
        secret_path = f"{vault_prefix}/wrong-key"

        project = tmp_path / "project"
        project.mkdir()
        env_file = _encrypt_in_project(
            envdrift_cmd, env, project, ".env.production", ["API_KEY=value1"]
        )
        before = env_file.read_bytes()

        # A real but UNRELATED private key.
        wrong_key, _ = _make_real_keypair(envdrift_cmd, env, tmp_path)
        _store_vault_value(
            vault_client, secret_path, f'DOTENV_PRIVATE_KEY_PRODUCTION="{wrong_key}"'
        )

        result = _run(
            envdrift_cmd,
            [
                "decrypt",
                ".env.production",
                "--verify-vault",
                "-p",
                "hashicorp",
                "--vault-url",
                vault_endpoint,
                "--secret",
                secret_path,
            ],
            project,
            env,
        )

        assert result.returncode == 1, (
            f"a wrong vault key verified successfully:\n{result.stdout}\n{result.stderr}"
        )
        assert "cannot decrypt" in _norm(result).lower()
        assert env_file.read_bytes() == before


class TestSyncCheckDecryption:
    """Items 3+4 of #473: --check-decryption must work from any cwd and never mutate."""

    def _project_with_mapping(
        self,
        tmp_path: Path,
        envdrift_cmd: list[str],
        env: dict[str, str],
        vault_client,
        secret_path: str,
        folder_path: str,
    ) -> tuple[Path, Path]:
        """Build a project with one encrypted mapping whose key is in vault.

        Returns ``(project_root, encrypted_env_file)``.
        """
        project = tmp_path / "project"
        (project / folder_path).mkdir(parents=True, exist_ok=True)
        (project / "envdrift.toml").write_text(
            _config_toml(secret_path, folder_path), encoding="utf-8"
        )
        env_file = _encrypt_in_project(
            envdrift_cmd,
            env,
            project,
            f"{folder_path}/.env.production",
            ["API_KEY=value1", "DB_PASS=value2"],
        )

        from envdrift.sync.operations import EnvKeysFile

        key = EnvKeysFile(project / folder_path / ".env.keys").read_key(
            "DOTENV_PRIVATE_KEY_PRODUCTION"
        )
        assert key
        _store_vault_value(vault_client, secret_path, f"DOTENV_PRIVATE_KEY_PRODUCTION={key}")
        return project, env_file

    def test_relative_folder_path_passes_from_project_root(
        self,
        tmp_path: Path,
        vault_endpoint: str,
        vault_client,
        vault_prefix: str,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """A known-good key with folder_path = "services/api" must report PASSED.

        The old roundtrip ran ``dotenvx decrypt -f services/api/.env.production``
        with ``cwd=services/api`` — a doubled relative path (MISSING_ENV_FILE) —
        so every relative monorepo mapping reported "Decryption: FAILED"."""
        env = _child_env(vault_endpoint, integration_pythonpath)
        secret_path = f"{vault_prefix}/relpath-key"
        project, _ = self._project_with_mapping(
            tmp_path, envdrift_cmd, env, vault_client, secret_path, "services/api"
        )

        result = _run(
            envdrift_cmd,
            [
                "sync",
                "--force",
                "--check-decryption",
                "-p",
                "hashicorp",
                "--vault-url",
                vault_endpoint,
            ],
            project,
            env,
        )

        out = _norm(result)
        assert result.returncode == 0, (
            f"sync --check-decryption failed for a relative folder_path:\n"
            f"{result.stdout}\n{result.stderr}"
        )
        assert "Passed: 1" in out, f"expected 'Passed: 1' in output:\n{result.stdout}"
        assert "Failed: 1" not in out
        assert "Decryption: FAILED" not in out

    def test_passing_check_is_byte_exact_and_leaves_no_backup(
        self,
        tmp_path: Path,
        vault_endpoint: str,
        vault_client,
        vault_prefix: str,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """A PASSING check must not rewrite the live encrypted file.

        dotenvx ECIES encryption is non-deterministic, so the old in-place
        decrypt + re-encrypt roundtrip produced fresh ciphertext on every run
        (hash differs although the check PASSED) and opened a plaintext window
        on the live file. The check must leave the file byte-identical.

        Uses ``folder_path = "."`` so the old roundtrip actually reached PASSED
        here (the relative-folder_path defect is covered separately above) and
        the ciphertext churn is isolated as the failure."""
        env = _child_env(vault_endpoint, integration_pythonpath)
        secret_path = f"{vault_prefix}/byteexact-key"
        project, env_file = self._project_with_mapping(
            tmp_path, envdrift_cmd, env, vault_client, secret_path, "."
        )
        digest_before = _sha256(env_file)

        result = _run(
            envdrift_cmd,
            [
                "sync",
                "--force",
                "--check-decryption",
                "-p",
                "hashicorp",
                "--vault-url",
                vault_endpoint,
            ],
            project,
            env,
        )

        out = _norm(result)
        assert result.returncode == 0, f"sync failed:\n{result.stdout}\n{result.stderr}"
        assert "Passed: 1" in out
        assert _sha256(env_file) == digest_before, (
            "a PASSING sync --check-decryption rewrote the live encrypted file "
            "(fresh ciphertext) — a check must not modify files"
        )
        # No working-tree byproducts of the old in-place roundtrip.
        assert not env_file.with_suffix(".backup_decryption_test").exists()

    def test_failing_check_exits_nonzero_and_never_mutates(
        self,
        tmp_path: Path,
        vault_endpoint: str,
        vault_client,
        vault_prefix: str,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """A FAILED check must be a non-zero exit and must not touch the file.

        The issue's verifier reproduced overall exit 0 despite "Failed: 1"
        (without --ci). An explicitly requested check that fails must fail the
        run, and the live file must stay byte-identical (no decrypt/re-encrypt
        attempt against it)."""
        env = _child_env(vault_endpoint, integration_pythonpath)
        secret_path = f"{vault_prefix}/wrongsync-key"
        project, env_file = self._project_with_mapping(
            tmp_path, envdrift_cmd, env, vault_client, secret_path, "svc"
        )

        # Replace the vault copy with a real but UNRELATED key; --force sync
        # will install it locally and the decryption check must then fail.
        wrong_key, _ = _make_real_keypair(envdrift_cmd, env, tmp_path)
        _store_vault_value(vault_client, secret_path, f"DOTENV_PRIVATE_KEY_PRODUCTION={wrong_key}")
        digest_before = _sha256(env_file)

        result = _run(
            envdrift_cmd,
            [
                "sync",
                "--force",
                "--check-decryption",
                "-p",
                "hashicorp",
                "--vault-url",
                vault_endpoint,
            ],
            project,
            env,
        )

        out = _norm(result)
        assert "Failed: 1" in out, f"expected a failing decryption test:\n{result.stdout}"
        assert result.returncode == 1, (
            f"sync --check-decryption reported 'Failed: 1' but exited "
            f"{result.returncode} — a failed check must fail the run:\n{result.stdout}"
        )
        assert _sha256(env_file) == digest_before, (
            "a FAILING sync --check-decryption modified the live encrypted file"
        )
        assert not env_file.with_suffix(".backup_decryption_test").exists()
