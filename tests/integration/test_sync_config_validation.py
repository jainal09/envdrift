"""Regression tests for issue #488: sync config discovery and mapping validation.

The sync-family commands (``pull``, ``sync``, ``lock``, ``vault-push --all``)
validated neither the mapping's ``folder_path`` nor the files they read:

- a typo'd / nonexistent ``folder_path`` silently no-op'd as a benign "skipped"
  with exit 0 — ``sync --force --ci`` printed "All services synced
  successfully", ``pull`` even printed "[OK] Setup complete!", and
  ``vault-push --all`` reported "No .env file found" (the wrong reason) with
  "Errors: 0" — so a key-backup CI job went green having done nothing;
- ``pull`` and ``lock`` crashed with a raw ``UnicodeDecodeError`` traceback
  when a mapped env file was not valid UTF-8, and the remaining mappings in
  the run were never processed.

These tests drive the real ``envdrift`` CLI as a subprocess with the real
``dotenvx`` binary against the live HashiCorp Vault container
(``tests/docker-compose.test.yml``). Every vault path is namespaced under a
unique per-test prefix and cleaned up afterwards.
"""

from __future__ import annotations

import contextlib
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

# The typo'd service folder from the issue repro ("services/api" misspelled).
TYPO_FOLDER = "servces/api"

# Non-UTF-8 env-file content (Latin-1 "café"), written as raw bytes.
NON_UTF8_CONTENT = b"X=caf\xe9\n"


def _config_toml(mappings: list[tuple[str, str]]) -> str:
    """Minimal envdrift.toml with dotenvx-backed hashicorp sync mappings."""
    blocks = [
        """\
[encryption]
backend = "dotenvx"

[vault]
provider = "hashicorp"
"""
    ]
    blocks.extend(
        f"""
[[vault.sync.mappings]]
secret_name = "{secret_name}"
folder_path = "{folder_path}"
environment = "production"
"""
        for secret_name, folder_path in mappings
    )
    return "".join(blocks)


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


@pytest.fixture
def vault_prefix(vault_client) -> Generator[str, None, None]:
    """Unique KV v2 path prefix for this test; deletes everything under it after."""
    prefix = f"test/syncval488-{uuid.uuid4().hex[:12]}"
    created: list[str] = []

    yield prefix

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
    for key in [k for k in env if k.startswith("DOTENV_PRIVATE_KEY")]:
        env.pop(key)
    env.pop("DOTENV_KEY", None)
    return env


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


def _read_private_key(project: Path, folder: str) -> str:
    """Read the production private key from ``<project>/<folder>/.env.keys``."""
    from envdrift.sync.operations import EnvKeysFile

    key = EnvKeysFile(project / folder / ".env.keys").read_key("DOTENV_PRIVATE_KEY_PRODUCTION")
    assert key, f"no DOTENV_PRIVATE_KEY_PRODUCTION in {folder}/.env.keys"
    return key


class TestMissingMappingFolderIsLoud:
    """Item 1 of #488: a typo'd folder_path must be a per-mapping error, not a green skip."""

    def test_sync_force_ci_fails_on_typod_folder_path(
        self,
        tmp_path: Path,
        vault_endpoint: str,
        vault_client,
        vault_prefix: str,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """The CI repro from the issue: one mapping with a typo'd folder_path
        (and a secret name that does not exist in vault) plus one healthy
        mapping. ``sync --force --ci`` must exit 1, report the missing folder
        as an error on that mapping, and still sync the healthy mapping."""
        env = _child_env(vault_endpoint, integration_pythonpath)

        project = tmp_path / "project"
        (project / "svc").mkdir(parents=True)
        good_secret = f"{vault_prefix}/good-key"
        bad_secret = f"{vault_prefix}/does-not-exist"
        (project / "envdrift.toml").write_text(
            _config_toml([(bad_secret, TYPO_FOLDER), (good_secret, "svc")]),
            encoding="utf-8",
        )

        # Healthy mapping: real encrypted file, its real key stored in vault.
        _encrypt_in_project(envdrift_cmd, env, project, "svc/.env.production", ["DB=value1"])
        k_good = _read_private_key(project, "svc")
        (project / "svc" / ".env.keys").unlink()  # sync must re-create it from vault
        _store_vault_value(vault_client, good_secret, f"DOTENV_PRIVATE_KEY_PRODUCTION={k_good}")

        result = _run(
            envdrift_cmd,
            ["sync", "--force", "--ci", "-p", "hashicorp", "--vault-url", vault_endpoint],
            project,
            env,
        )

        out = _norm(result)
        assert result.returncode == 1, (
            f"sync --force --ci exited {result.returncode} for a typo'd folder_path "
            f"(silent no-op):\n{result.stdout}\n{result.stderr}"
        )
        assert "All services synced successfully" not in out
        # The row must state the REAL reason: the mapping folder does not exist.
        assert "does not exist" in out
        assert TYPO_FOLDER in out
        assert "Errors: 1" in out
        # The healthy mapping was still processed: its key was re-created from vault.
        assert (project / "svc" / ".env.keys").exists(), (
            "healthy mapping was not synced after the broken-mapping error"
        )

    def test_pull_force_fails_on_typod_folder_path(
        self,
        tmp_path: Path,
        vault_endpoint: str,
        vault_client,
        vault_prefix: str,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """``pull --force`` with only a typo'd mapping must exit 1 and must NOT
        print the green "Setup complete!" banner."""
        env = _child_env(vault_endpoint, integration_pythonpath)

        project = tmp_path / "project"
        project.mkdir()
        bad_secret = f"{vault_prefix}/does-not-exist"
        (project / "envdrift.toml").write_text(
            _config_toml([(bad_secret, TYPO_FOLDER)]), encoding="utf-8"
        )

        result = _run(
            envdrift_cmd,
            ["pull", "--force", "-p", "hashicorp", "--vault-url", vault_endpoint],
            project,
            env,
        )

        out = _norm(result)
        assert result.returncode == 1, (
            f"pull --force exited {result.returncode} for a typo'd folder_path "
            f"(silent no-op):\n{result.stdout}\n{result.stderr}"
        )
        assert "Setup complete" not in out
        assert "does not exist" in out
        assert TYPO_FOLDER in out

    def test_vault_push_all_errors_on_typod_folder_path(
        self,
        tmp_path: Path,
        vault_endpoint: str,
        vault_client,
        vault_prefix: str,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """``vault-push --all`` must report the missing mapping folder as an
        error (not the misleading "No .env file found" skip) and exit 1."""
        env = _child_env(vault_endpoint, integration_pythonpath)

        project = tmp_path / "project"
        project.mkdir()
        bad_secret = f"{vault_prefix}/does-not-exist"
        (project / "envdrift.toml").write_text(
            _config_toml([(bad_secret, TYPO_FOLDER)]), encoding="utf-8"
        )

        result = _run(
            envdrift_cmd,
            ["vault-push", "--all", "-p", "hashicorp", "--vault-url", vault_endpoint],
            project,
            env,
        )

        out = _norm(result)
        assert result.returncode == 1, (
            f"vault-push --all exited {result.returncode} for a typo'd folder_path "
            f"(silent no-op):\n{result.stdout}\n{result.stderr}"
        )
        assert "does not exist" in out
        assert "No .env file found" not in out, (
            "vault-push --all reported the wrong skip reason for a missing folder"
        )
        assert "Errors: 1" in out
        assert "Errors: 0" not in out


class TestNonUtf8EnvFileCleanError:
    """Item 2 of #488: a non-UTF-8 env file is a clean per-file error, not a traceback."""

    def test_pull_force_non_utf8_env_file_clean_error_and_continues(
        self,
        tmp_path: Path,
        vault_endpoint: str,
        vault_client,
        vault_prefix: str,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """The issue repro: a mapped ``.env.production`` holding non-UTF-8
        bytes crashed ``pull --force`` with a raw Rich UnicodeDecodeError
        traceback at the decrypt step and the remaining mappings were never
        processed. Expected: clean per-file error, exit 1, and the healthy
        mapping listed after it is still decrypted."""
        env = _child_env(vault_endpoint, integration_pythonpath)

        project = tmp_path / "project"
        (project / "bad").mkdir(parents=True)
        (project / "good").mkdir(parents=True)
        bad_secret = f"{vault_prefix}/bad-key"
        good_secret = f"{vault_prefix}/good-key"
        # bad mapping FIRST so the old crash would abort before the good one.
        (project / "envdrift.toml").write_text(
            _config_toml([(bad_secret, "bad"), (good_secret, "good")]), encoding="utf-8"
        )

        # bad: non-UTF-8 env file (written as bytes); its key exists in vault so
        # Step 1 (key sync) succeeds and the failure is isolated to the file read.
        (project / "bad" / ".env.production").write_bytes(NON_UTF8_CONTENT)
        _store_vault_value(vault_client, bad_secret, "DOTENV_PRIVATE_KEY_PRODUCTION=" + "ab" * 32)

        # good: real encrypted file with its real key in vault.
        good_file = _encrypt_in_project(
            envdrift_cmd, env, project, "good/.env.production", ["TOKEN=value2"]
        )
        k_good = _read_private_key(project, "good")
        _store_vault_value(vault_client, good_secret, f"DOTENV_PRIVATE_KEY_PRODUCTION={k_good}")

        result = _run(
            envdrift_cmd,
            ["pull", "--force", "-p", "hashicorp", "--vault-url", vault_endpoint],
            project,
            env,
        )

        out = _norm(result)
        assert "Traceback (most recent call last)" not in out, (
            f"pull crashed with a raw traceback on a non-UTF-8 env file:\n"
            f"{result.stdout}\n{result.stderr}"
        )
        assert result.returncode == 1, (
            f"pull exited {result.returncode} despite an unreadable mapped env file:\n"
            f"{result.stdout}\n{result.stderr}"
        )
        # Clean per-file error row for the bad file...
        assert "error" in out.lower()
        assert "Errors: 1" in out
        # ...and the run continued: the healthy mapping was still decrypted.
        assert "TOKEN=" in good_file.read_text(encoding="utf-8")
        assert "encrypted:" not in good_file.read_text(encoding="utf-8"), (
            "healthy mapping after the broken one was never decrypted"
        )

    def test_lock_force_non_utf8_env_file_clean_error_and_continues(
        self,
        tmp_path: Path,
        vault_endpoint: str,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """``lock --force`` with a non-UTF-8 mapped env file: clean per-file
        error and exit 1 (no traceback), remaining mappings still encrypted."""
        env = _child_env(vault_endpoint, integration_pythonpath)

        project = tmp_path / "project"
        (project / "bad").mkdir(parents=True)
        (project / "good").mkdir(parents=True)
        # lock without --verify-vault never talks to the vault; secret names
        # are arbitrary here, but the hashicorp provider needs a URL to build
        # its client during config loading.
        config = _config_toml([("unused/bad", "bad"), ("unused/good", "good")])
        config += f'\n[vault.hashicorp]\nurl = "{vault_endpoint}"\n'
        (project / "envdrift.toml").write_text(config, encoding="utf-8")

        (project / "bad" / ".env.production").write_bytes(NON_UTF8_CONTENT)
        good_file = project / "good" / ".env.production"
        good_file.write_text("API_KEY=plain" + "value3\n", encoding="utf-8")

        result = _run(envdrift_cmd, ["lock", "--force"], project, env)

        out = _norm(result)
        assert "Traceback (most recent call last)" not in out, (
            f"lock crashed with a raw traceback on a non-UTF-8 env file:\n"
            f"{result.stdout}\n{result.stderr}"
        )
        assert result.returncode == 1, (
            f"lock exited {result.returncode} despite an unreadable mapped env file:\n"
            f"{result.stdout}\n{result.stderr}"
        )
        assert "Errors: 1" in out
        # The run continued: the healthy plaintext file was still encrypted.
        assert "encrypted:" in good_file.read_text(encoding="utf-8"), (
            "healthy mapping after the broken one was never encrypted"
        )
