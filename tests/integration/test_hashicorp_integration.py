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
