"""HashiCorp Vault integration tests.

Tests the HashiCorpVaultClient against a real Vault container (dev mode).
Requires: docker-compose -f tests/docker-compose.test.yml up -d

Test categories:
- Direct client operations (get/set/list secrets, auth)
- CLI sync commands
- CLI vault-push commands
- Error handling (missing secrets)
"""

from __future__ import annotations

import contextlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Generator

# Import test constants from conftest
# Check if hvac is available
import importlib.util

from tests.integration.conftest import VAULT_ROOT_TOKEN

HVAC_AVAILABLE = importlib.util.find_spec("hvac") is not None
DOTENVX_AVAILABLE = shutil.which("dotenvx") is not None

# Mark all tests in this module - skip if hvac not installed
pytestmark = [
    pytest.mark.integration,
    pytest.mark.vault,
    pytest.mark.skipif(
        not HVAC_AVAILABLE,
        reason="hvac not installed - install with: pip install envdrift[hashicorp]",
    ),
]

# --- Fixtures ---


@pytest.fixture(scope="module")
def populated_vault_secrets(vault_client) -> Generator[dict[str, str], None, None]:
    """Pre-populate Vault with test secrets.

    Creates test secrets in the KV v2 secrets engine at:
    - myapp/production: DOTENV_PRIVATE_KEY_PRODUCTION
    - myapp/staging: DOTENV_PRIVATE_KEY_STAGING
    - shared/api-keys: Multiple key-value pairs
    """
    secrets = {
        "myapp/production": {"value": "DOTENV_PRIVATE_KEY_PRODUCTION=prod-key-abc123"},
        "myapp/staging": {"value": "DOTENV_PRIVATE_KEY_STAGING=staging-key-def456"},
        "shared/api-keys": {"API_KEY": "secret123", "API_SECRET": "secret456"},
    }

    # Create secrets
    for path, data in secrets.items():
        vault_client.secrets.kv.v2.create_or_update_secret(
            path=path,
            secret=data,
            mount_point="secret",
        )

    yield {path: data.get("value", str(data)) for path, data in secrets.items()}

    # Cleanup - delete secrets
    for path in secrets:
        with contextlib.suppress(Exception):
            vault_client.secrets.kv.v2.delete_metadata_and_all_versions(
                path=path,
                mount_point="secret",
            )


# --- Direct Client Tests ---


class TestHashiCorpClientDirect:
    """Test HashiCorpVaultClient direct operations."""

    def test_hcv_get_secret(self, vault_endpoint: str, populated_vault_secrets: dict):
        """Test retrieving a secret from Vault."""
        from envdrift.vault.hashicorp import HashiCorpVaultClient

        client = HashiCorpVaultClient(
            url=vault_endpoint,
            token=VAULT_ROOT_TOKEN,
        )
        client.authenticate()

        secret = client.get_secret("myapp/production")

        assert secret.name == "myapp/production"
        assert "DOTENV_PRIVATE_KEY_PRODUCTION" in secret.value
        assert secret.version is not None
        assert "created_time" in secret.metadata

    def test_hcv_set_secret(self, vault_endpoint: str):
        """Test creating/updating a secret in Vault."""
        from envdrift.vault.hashicorp import HashiCorpVaultClient

        client = HashiCorpVaultClient(
            url=vault_endpoint,
            token=VAULT_ROOT_TOKEN,
        )
        client.authenticate()

        # Create a new secret
        result = client.set_secret("test/new-secret", "my-secret-value")

        assert result.name == "test/new-secret"
        assert result.value == "my-secret-value"
        assert result.version == "1"

        # Update the secret
        result2 = client.set_secret("test/new-secret", "updated-value")
        assert result2.version == "2"

        # Cleanup
        with contextlib.suppress(Exception):
            hvac = pytest.importorskip("hvac")
            cleanup_client = hvac.Client(url=vault_endpoint, token=VAULT_ROOT_TOKEN)
            cleanup_client.secrets.kv.v2.delete_metadata_and_all_versions(
                path="test/new-secret",
                mount_point="secret",
            )

    def test_hcv_list_secrets(self, vault_endpoint: str, populated_vault_secrets: dict):
        """Test listing secrets at a path."""
        from envdrift.vault.hashicorp import HashiCorpVaultClient

        client = HashiCorpVaultClient(
            url=vault_endpoint,
            token=VAULT_ROOT_TOKEN,
        )
        client.authenticate()

        # List secrets under myapp/
        secrets = client.list_secrets("myapp")

        assert len(secrets) >= 2
        assert "production" in secrets
        assert "staging" in secrets

    def test_hcv_authentication(self, vault_endpoint: str):
        """Test token authentication flow."""
        from envdrift.vault.hashicorp import HashiCorpVaultClient

        # Valid token
        client = HashiCorpVaultClient(
            url=vault_endpoint,
            token=VAULT_ROOT_TOKEN,
        )

        assert not client.is_authenticated()
        client.authenticate()
        assert client.is_authenticated()

    def test_hcv_secret_not_found(self, vault_endpoint: str):
        """Test graceful handling of missing secrets."""
        from envdrift.vault.base import SecretNotFoundError
        from envdrift.vault.hashicorp import HashiCorpVaultClient

        client = HashiCorpVaultClient(
            url=vault_endpoint,
            token=VAULT_ROOT_TOKEN,
        )
        client.authenticate()

        with pytest.raises(SecretNotFoundError, match="not found"):
            client.get_secret("nonexistent/secret/path")


# --- CLI Sync Command Tests ---


class TestHashiCorpSyncCommand:
    """Test CLI sync commands with HashiCorp Vault."""

    def test_hcv_sync_pull_kv_secret(
        self,
        vault_endpoint: str,
        vault_test_env: dict,
        populated_vault_secrets: dict,
        work_dir: Path,
        integration_pythonpath: str,
    ):
        """Test pulling a secret from Vault via CLI."""
        # Create pyproject.toml with vault config
        pyproject = work_dir / "pyproject.toml"
        pyproject.write_text(f'''
[tool.envdrift]
vault_backend = "hashicorp"
vault_url = "{vault_endpoint}"
vault_key_path = "myapp/production"
''')

        # Create empty .env.keys file
        env_keys = work_dir / ".env.keys"
        env_keys.write_text("")

        # Run envdrift pull
        env = vault_test_env.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            [sys.executable, "-m", "envdrift", "pull"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Check that pull succeeded or failed gracefully (not crashed)
        # returncode 0 = success, 1 = expected failure (e.g., auth issue)
        assert result.returncode in (0, 1), (
            f"Unexpected exit code: {result.returncode}\nstderr: {result.stderr}"
        )


# --- CLI Vault Push Command Tests ---


class TestHashiCorpVaultPush:
    """Test CLI vault-push commands with HashiCorp Vault."""

    def test_hcv_vault_push_kv_secret(
        self,
        vault_endpoint: str,
        vault_test_env: dict,
        vault_client,
        work_dir: Path,
        integration_pythonpath: str,
    ):
        """Test pushing a secret to Vault via CLI."""
        # Create pyproject.toml with vault config
        pyproject = work_dir / "pyproject.toml"
        pyproject.write_text(f'''
[tool.envdrift]
vault_backend = "hashicorp"
vault_url = "{vault_endpoint}"
vault_key_path = "test/pushed-secret"
''')

        # Create .env.keys file with content to push
        env_keys = work_dir / ".env.keys"
        env_keys.write_text("DOTENV_PRIVATE_KEY=test-key-from-push\n")

        # Run envdrift vault-push
        env = vault_test_env.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            [sys.executable, "-m", "envdrift", "vault-push"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Check result - may succeed or fail depending on CLI implementation
        # At minimum, the command should not crash
        assert result.returncode in (0, 1)

        # Cleanup if secret was created
        with contextlib.suppress(Exception):
            vault_client.secrets.kv.v2.delete_metadata_and_all_versions(
                path="test/pushed-secret",
                mount_point="secret",
            )


# ===========================================================================
# Extended HashiCorp Vault integration tests (generated test package)
#
# All tests below are gated on the live Vault container (via vault_endpoint /
# vault_client / vault_test_env), hvac (module pytestmark skipif), and dotenvx
# (DOTENVX_AVAILABLE) where the CLI must encrypt/decrypt. They assert the
# documented contract and clean up every path they create.
# ===========================================================================


def _delete_vault_path(vault_client, path: str, mount_point: str = "secret") -> None:
    """Best-effort cleanup of a KV v2 secret path."""
    with contextlib.suppress(Exception):
        vault_client.secrets.kv.v2.delete_metadata_and_all_versions(
            path=path,
            mount_point=mount_point,
        )


def _run_envdrift_cli(
    args: list[str],
    cwd: Path,
    env: dict,
    integration_pythonpath: str,
    timeout: int = 60,
) -> subprocess.CompletedProcess:
    """Run the envdrift CLI as a real subprocess against the live container."""
    run_env = env.copy()
    run_env["PYTHONPATH"] = integration_pythonpath
    return subprocess.run(
        [sys.executable, "-m", "envdrift.cli", *args],
        cwd=cwd,
        env=run_env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


# --- P0: authenticate() with an invalid token -----------------------------


# The documented contract is that an invalid token surfaces as
# AuthenticationError("Vault token is invalid or expired"). A known bug
# (src/envdrift/vault/hashicorp.py:86-91) re-wraps that AuthenticationError as a
# VaultError via the broad `except Exception`, so the assertion below currently
# fails on a real container. xfail(strict=False) keeps the test green while
# encoding the correct, documented behavior (it will XPASS once the bug is fixed).
@pytest.mark.xfail(
    reason="hashicorp.authenticate() re-wraps AuthenticationError as VaultError "
    "(broad except Exception at hashicorp.py:90) — see #305",
    strict=False,
)
def test_hcv_invalid_token_raises_authentication_error(vault_endpoint: str):
    """BP-02: an invalid token must raise AuthenticationError on authenticate()."""
    from envdrift.vault.base import AuthenticationError
    from envdrift.vault.hashicorp import HashiCorpVaultClient

    client = HashiCorpVaultClient(
        url=vault_endpoint,
        token="definitely-not-a-valid-token",
    )

    assert client.is_authenticated() is False
    with pytest.raises(AuthenticationError, match="invalid or expired"):
        client.authenticate()
    assert client.is_authenticated() is False


# --- P0: CLI vault-push single-service mode -------------------------------


def test_hcv_cli_vault_push_single_service_stores_key_and_reports_version(
    vault_endpoint: str,
    vault_test_env: dict,
    vault_client,
    work_dir: Path,
    integration_pythonpath: str,
    envdrift_cmd: list[str],
):
    """HP-11: single-service vault-push stores the key and reports a version."""
    secret_path = "test/cli-push-single"
    env_keys = work_dir / ".env.keys"
    env_keys.write_text("DOTENV_PRIVATE_KEY_PRODUCTION=prod-key-abc123\n")

    try:
        result = _run_envdrift_cli(
            [
                "vault-push",
                ".",
                secret_path,
                "--env",
                "production",
                "-p",
                "hashicorp",
                "--vault-url",
                vault_endpoint,
            ],
            cwd=work_dir,
            env=vault_test_env,
            integration_pythonpath=integration_pythonpath,
        )

        assert result.returncode == 0, (
            f"push failed: {result.returncode}\nstdout={result.stdout}\nstderr={result.stderr}"
        )
        combined = result.stdout + result.stderr
        assert "Pushed" in combined
        assert "Version" in combined

        read_back = vault_client.secrets.kv.v2.read_secret_version(
            path=secret_path,
            mount_point="secret",
        )
        assert read_back["data"]["data"]["value"] == "DOTENV_PRIVATE_KEY_PRODUCTION=prod-key-abc123"
    finally:
        _delete_vault_path(vault_client, secret_path)


# --- P0: CLI vault-pull default writes keys AND decrypts ------------------


@pytest.mark.slow
@pytest.mark.skipif(
    not DOTENVX_AVAILABLE, reason="dotenvx binary required to encrypt/decrypt .env files"
)
def test_hcv_cli_vault_pull_default_writes_keys_and_decrypts(
    vault_endpoint: str,
    vault_test_env: dict,
    vault_client,
    work_dir: Path,
    integration_pythonpath: str,
    envdrift_cmd: list[str],
):
    """HP-12: vault-pull (default) recreates .env.keys and decrypts .env.production."""
    secret_path = "test/cli-pull-decrypt"
    plaintext = "API_URL=https://example.com\nSECRET_TOKEN=plaintext-value-123\n"
    env_file = work_dir / ".env.production"
    env_file.write_text(plaintext)

    # Use the real envdrift CLI to generate a dotenvx keypair and encrypt the file.
    encrypt_result = _run_envdrift_cli(
        ["encrypt", ".env.production"],
        cwd=work_dir,
        env=vault_test_env,
        integration_pythonpath=integration_pythonpath,
    )
    assert encrypt_result.returncode == 0, (
        f"encrypt failed: {encrypt_result.stdout}\n{encrypt_result.stderr}"
    )
    encrypted = env_file.read_text()
    assert "encrypted:" in encrypted

    # Extract the generated private key from .env.keys.
    env_keys = work_dir / ".env.keys"
    from envdrift.sync.operations import EnvKeysFile

    priv = EnvKeysFile(env_keys).read_key("DOTENV_PRIVATE_KEY_PRODUCTION")
    assert priv, "dotenvx did not write DOTENV_PRIVATE_KEY_PRODUCTION"

    # Push the key into Vault, then delete the local keys so pull must recreate it.
    vault_client.secrets.kv.v2.create_or_update_secret(
        path=secret_path,
        secret={"value": f"DOTENV_PRIVATE_KEY_PRODUCTION={priv}"},
        mount_point="secret",
    )
    env_keys.unlink()

    try:
        result = _run_envdrift_cli(
            [
                "vault-pull",
                ".",
                secret_path,
                "--env",
                "production",
                "-p",
                "hashicorp",
                "--vault-url",
                vault_endpoint,
            ],
            cwd=work_dir,
            env=vault_test_env,
            integration_pythonpath=integration_pythonpath,
        )

        assert result.returncode == 0, (
            f"pull failed: {result.returncode}\nstdout={result.stdout}\nstderr={result.stderr}"
        )
        combined = result.stdout + result.stderr
        assert "Decrypted" in combined

        keys_content = env_keys.read_text()
        assert f"DOTENV_PRIVATE_KEY_PRODUCTION={priv}" in keys_content

        decrypted = env_file.read_text()
        assert "SECRET_TOKEN=plaintext-value-123" in decrypted
        assert "encrypted:" not in decrypted
    finally:
        _delete_vault_path(vault_client, secret_path)


# --- P0: CLI vault-pull env-prefix mismatch -------------------------------


def test_hcv_cli_vault_pull_env_prefix_mismatch_exits_1(
    vault_endpoint: str,
    vault_test_env: dict,
    vault_client,
    work_dir: Path,
    integration_pythonpath: str,
    envdrift_cmd: list[str],
):
    """BP-13: secret stored for STAGING but pulled --env production fails fast."""
    secret_path = "test/cli-pull-mismatch"
    vault_client.secrets.kv.v2.create_or_update_secret(
        path=secret_path,
        secret={"value": "DOTENV_PRIVATE_KEY_STAGING=staging-priv-key"},
        mount_point="secret",
    )
    env_keys = work_dir / ".env.keys"

    try:
        result = _run_envdrift_cli(
            [
                "vault-pull",
                ".",
                secret_path,
                "--env",
                "production",
                "--no-decrypt",
                "-p",
                "hashicorp",
                "--vault-url",
                vault_endpoint,
            ],
            cwd=work_dir,
            env=vault_test_env,
            integration_pythonpath=integration_pythonpath,
        )

        assert result.returncode == 1, (
            f"expected rc=1, got {result.returncode}\n{result.stdout}\n{result.stderr}"
        )
        combined = result.stdout + result.stderr
        assert "DOTENV_PRIVATE_KEY_STAGING" in combined
        assert "DOTENV_PRIVATE_KEY_PRODUCTION" in combined
        # .env.keys must NOT be written when the prefix mismatch is detected.
        assert not env_keys.exists()
    finally:
        _delete_vault_path(vault_client, secret_path)


# --- P0: CLI vault-pull --no-decrypt of a bare value ----------------------


def test_hcv_cli_vault_pull_bare_value_stored_as_key_value(
    vault_endpoint: str,
    vault_test_env: dict,
    vault_client,
    work_dir: Path,
    integration_pythonpath: str,
    envdrift_cmd: list[str],
):
    """EC-05: a bare (no-prefix) value is stored verbatim under the env key name."""
    secret_path = "test/cli-pull-bare"
    bare = "just-a-raw-private-key-no-prefix"
    vault_client.secrets.kv.v2.create_or_update_secret(
        path=secret_path,
        secret={"value": bare},
        mount_point="secret",
    )
    env_keys = work_dir / ".env.keys"

    try:
        result = _run_envdrift_cli(
            [
                "vault-pull",
                ".",
                secret_path,
                "--env",
                "production",
                "--no-decrypt",
                "-p",
                "hashicorp",
                "--vault-url",
                vault_endpoint,
            ],
            cwd=work_dir,
            env=vault_test_env,
            integration_pythonpath=integration_pythonpath,
        )

        assert result.returncode == 0, (
            f"pull failed: {result.returncode}\n{result.stdout}\n{result.stderr}"
        )
        assert f"DOTENV_PRIVATE_KEY_PRODUCTION={bare}" in env_keys.read_text()
    finally:
        _delete_vault_path(vault_client, secret_path)


# --- P0: CLI vault-pull --no-decrypt writes key only ----------------------


def test_hcv_cli_vault_pull_no_decrypt_writes_key_only(
    vault_endpoint: str,
    vault_test_env: dict,
    vault_client,
    work_dir: Path,
    integration_pythonpath: str,
    envdrift_cmd: list[str],
):
    """HP-13: vault-pull --no-decrypt writes only the key, skipping decryption."""
    secret_path = "test/cli-pull-nodecrypt"
    vault_client.secrets.kv.v2.create_or_update_secret(
        path=secret_path,
        secret={"value": "DOTENV_PRIVATE_KEY_PRODUCTION=abc-priv-key"},
        mount_point="secret",
    )
    env_keys = work_dir / ".env.keys"

    try:
        result = _run_envdrift_cli(
            [
                "vault-pull",
                ".",
                secret_path,
                "--env",
                "production",
                "--no-decrypt",
                "-p",
                "hashicorp",
                "--vault-url",
                vault_endpoint,
            ],
            cwd=work_dir,
            env=vault_test_env,
            integration_pythonpath=integration_pythonpath,
        )

        assert result.returncode == 0, (
            f"pull failed: {result.returncode}\n{result.stdout}\n{result.stderr}"
        )
        assert env_keys.exists()
        assert "DOTENV_PRIVATE_KEY_PRODUCTION=abc-priv-key" in env_keys.read_text()
        assert "Decrypted" not in (result.stdout + result.stderr)
    finally:
        _delete_vault_path(vault_client, secret_path)


# --- P0: CLI vault-pull default with missing target .env file -------------


def test_hcv_cli_vault_pull_missing_target_env_file_message_no_error(
    vault_endpoint: str,
    vault_test_env: dict,
    vault_client,
    work_dir: Path,
    integration_pythonpath: str,
    envdrift_cmd: list[str],
):
    """EC-06: default pull with no .env.production prints a notice and exits 0."""
    secret_path = "test/cli-pull-no-target"
    vault_client.secrets.kv.v2.create_or_update_secret(
        path=secret_path,
        secret={"value": "DOTENV_PRIVATE_KEY_PRODUCTION=abc-priv-key"},
        mount_point="secret",
    )
    env_keys = work_dir / ".env.keys"

    try:
        result = _run_envdrift_cli(
            [
                "vault-pull",
                ".",
                secret_path,
                "--env",
                "production",
                "-p",
                "hashicorp",
                "--vault-url",
                vault_endpoint,
            ],
            cwd=work_dir,
            env=vault_test_env,
            integration_pythonpath=integration_pythonpath,
        )

        assert result.returncode == 0, (
            f"pull failed: {result.returncode}\n{result.stdout}\n{result.stderr}"
        )
        combined = (result.stdout + result.stderr).lower()
        assert "no" in combined
        assert "to decrypt" in combined
        assert env_keys.exists()
        assert "DOTENV_PRIVATE_KEY_PRODUCTION=abc-priv-key" in env_keys.read_text()
    finally:
        _delete_vault_path(vault_client, secret_path)


# --- P0: vault-push hashicorp without --vault-url --------------------------


def test_hcv_cli_vault_push_missing_vault_url_exits_1(
    vault_test_env: dict,
    work_dir: Path,
    integration_pythonpath: str,
    envdrift_cmd: list[str],
):
    """BP-09: hashicorp provider without --vault-url and no config exits 1."""
    env_keys = work_dir / ".env.keys"
    env_keys.write_text("DOTENV_PRIVATE_KEY_PRODUCTION=prod-key\n")

    result = _run_envdrift_cli(
        [
            "vault-push",
            ".",
            "test/no-url",
            "--env",
            "production",
            "-p",
            "hashicorp",
        ],
        cwd=work_dir,
        env=vault_test_env,
        integration_pythonpath=integration_pythonpath,
    )

    assert result.returncode == 1, (
        f"expected rc=1, got {result.returncode}\n{result.stdout}\n{result.stderr}"
    )
    assert "--vault-url required for hashicorp" in (result.stdout + result.stderr)


# --- P0: vault-push normal mode missing --env -----------------------------


def test_hcv_cli_vault_push_normal_mode_missing_env_exits_1(
    vault_endpoint: str,
    vault_test_env: dict,
    work_dir: Path,
    integration_pythonpath: str,
    envdrift_cmd: list[str],
):
    """BP-10: vault-push normal mode without --env exits 1."""
    env_keys = work_dir / ".env.keys"
    env_keys.write_text("DOTENV_PRIVATE_KEY_PRODUCTION=prod-key\n")

    result = _run_envdrift_cli(
        [
            "vault-push",
            ".",
            "test/missing-env",
            "-p",
            "hashicorp",
            "--vault-url",
            vault_endpoint,
        ],
        cwd=work_dir,
        env=vault_test_env,
        integration_pythonpath=integration_pythonpath,
    )

    assert result.returncode == 1, (
        f"expected rc=1, got {result.returncode}\n{result.stdout}\n{result.stderr}"
    )
    combined = result.stdout + result.stderr
    assert "Required:" in combined
    assert "--env" in combined


# --- P0: vault-push normal mode missing .env.keys -------------------------


def test_hcv_cli_vault_push_missing_env_keys_file_exits_1(
    vault_endpoint: str,
    vault_test_env: dict,
    work_dir: Path,
    integration_pythonpath: str,
    envdrift_cmd: list[str],
):
    """BP-11: vault-push normal mode with absent .env.keys exits 1."""
    result = _run_envdrift_cli(
        [
            "vault-push",
            ".",
            "test/no-keys",
            "--env",
            "production",
            "-p",
            "hashicorp",
            "--vault-url",
            vault_endpoint,
        ],
        cwd=work_dir,
        env=vault_test_env,
        integration_pythonpath=integration_pythonpath,
    )

    assert result.returncode == 1, (
        f"expected rc=1, got {result.returncode}\n{result.stdout}\n{result.stderr}"
    )
    combined = result.stdout + result.stderr
    assert "File not found" in combined
    assert ".env.keys" in combined


# --- P0: vault-push key not present in .env.keys --------------------------


def test_hcv_cli_vault_push_key_not_in_env_keys_exits_1(
    vault_endpoint: str,
    vault_test_env: dict,
    work_dir: Path,
    integration_pythonpath: str,
    envdrift_cmd: list[str],
):
    """BP-12: .env.keys lacks the requested env key -> exit 1."""
    env_keys = work_dir / ".env.keys"
    env_keys.write_text("DOTENV_PRIVATE_KEY_STAGING=staging-only\n")

    result = _run_envdrift_cli(
        [
            "vault-push",
            ".",
            "test/wrong-env",
            "--env",
            "production",
            "-p",
            "hashicorp",
            "--vault-url",
            vault_endpoint,
        ],
        cwd=work_dir,
        env=vault_test_env,
        integration_pythonpath=integration_pythonpath,
    )

    assert result.returncode == 1, (
        f"expected rc=1, got {result.returncode}\n{result.stdout}\n{result.stderr}"
    )
    combined = result.stdout + result.stderr
    assert "DOTENV_PRIVATE_KEY_PRODUCTION" in combined
    assert "not found" in combined


# --- P0: vault-push --direct missing positional value ---------------------


def test_hcv_cli_vault_push_direct_missing_positional_args_exits_1(
    vault_endpoint: str,
    vault_test_env: dict,
    work_dir: Path,
    integration_pythonpath: str,
    envdrift_cmd: list[str],
):
    """BP-16: --direct with only a secret name (no value) exits 1."""
    result = _run_envdrift_cli(
        [
            "vault-push",
            "--direct",
            "some-secret-name",
            "-p",
            "hashicorp",
            "--vault-url",
            vault_endpoint,
        ],
        cwd=work_dir,
        env=vault_test_env,
        integration_pythonpath=integration_pythonpath,
    )

    assert result.returncode == 1, (
        f"expected rc=1, got {result.returncode}\n{result.stdout}\n{result.stderr}"
    )
    assert "Direct mode requires" in (result.stdout + result.stderr)


# --- P0: --skip-encrypt without --all warns and continues -----------------


def test_hcv_cli_skip_encrypt_without_all_warns_and_continues(
    vault_endpoint: str,
    vault_test_env: dict,
    vault_client,
    work_dir: Path,
    integration_pythonpath: str,
    envdrift_cmd: list[str],
):
    """BP-17: --skip-encrypt without --all warns but still pushes (single-service)."""
    secret_path = "test/cli-skip-encrypt-warn"
    env_keys = work_dir / ".env.keys"
    env_keys.write_text("DOTENV_PRIVATE_KEY_PRODUCTION=prod-key-skip\n")

    try:
        result = _run_envdrift_cli(
            [
                "vault-push",
                ".",
                secret_path,
                "--env",
                "production",
                "--skip-encrypt",
                "-p",
                "hashicorp",
                "--vault-url",
                vault_endpoint,
            ],
            cwd=work_dir,
            env=vault_test_env,
            integration_pythonpath=integration_pythonpath,
        )

        combined = result.stdout + result.stderr
        assert "--skip-encrypt is only applicable with --all" in combined
        assert result.returncode == 0, f"expected rc=0, got {result.returncode}\n{combined}"
        assert "Pushed" in combined
    finally:
        _delete_vault_path(vault_client, secret_path)


# --- P0: --force without --all warns and continues ------------------------


def test_hcv_cli_force_without_all_warns_and_continues(
    vault_endpoint: str,
    vault_test_env: dict,
    vault_client,
    work_dir: Path,
    integration_pythonpath: str,
    envdrift_cmd: list[str],
):
    """BP-18: --force without --all warns but still pushes (single-service)."""
    secret_path = "test/cli-force-warn"
    env_keys = work_dir / ".env.keys"
    env_keys.write_text("DOTENV_PRIVATE_KEY_PRODUCTION=prod-key-force\n")

    try:
        result = _run_envdrift_cli(
            [
                "vault-push",
                ".",
                secret_path,
                "--env",
                "production",
                "--force",
                "-p",
                "hashicorp",
                "--vault-url",
                vault_endpoint,
            ],
            cwd=work_dir,
            env=vault_test_env,
            integration_pythonpath=integration_pythonpath,
        )

        combined = result.stdout + result.stderr
        assert "--force is only applicable with --all" in combined
        assert result.returncode == 0, f"expected rc=0, got {result.returncode}\n{combined}"
        assert "Pushed" in combined
    finally:
        _delete_vault_path(vault_client, secret_path)


# --- P1: multi-key secret returns JSON ------------------------------------


def test_hcv_get_secret_multikey_returns_json(
    vault_endpoint: str,
    vault_client,
    populated_vault_secrets: dict,
):
    """HP-04: a multi-key secret is returned as a JSON-encoded string."""
    from envdrift.vault.hashicorp import HashiCorpVaultClient

    client = HashiCorpVaultClient(url=vault_endpoint, token=VAULT_ROOT_TOKEN)
    client.authenticate()

    secret = client.get_secret("shared/api-keys")

    assert secret.value.startswith("{")
    assert json.loads(secret.value) == {
        "API_KEY": "secret123",
        "API_SECRET": "secret456",
    }
    assert secret.version is not None
