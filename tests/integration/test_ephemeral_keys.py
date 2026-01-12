"""Integration tests for ephemeral keys feature."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from envdrift.sync.config import ServiceMapping, SyncConfig
from envdrift.sync.engine import SyncEngine
from envdrift.sync.result import SyncAction
from envdrift.vault.base import SecretValue, VaultClient


class TestEphemeralKeysIntegration:
    """Integration tests for ephemeral keys feature."""

    @pytest.fixture
    def mock_vault_client(self) -> MagicMock:
        """Create a mock vault client."""
        client = MagicMock(spec=VaultClient)
        client.is_authenticated.return_value = True
        return client

    def test_ephemeral_pull_workflow(self, mock_vault_client: MagicMock, tmp_path: Path) -> None:
        """Test full ephemeral pull workflow - no .env.keys created."""
        # Setup: Create encrypted env file
        service_dir = tmp_path / "myapp"
        service_dir.mkdir()
        env_file = service_dir / ".env.production"
        env_file.write_text(
            "#/-------------------[DOTENV][Load][Setup]-----------------------/#\n"
            "#/------------------!DOTENV_PUBLIC_KEY!---------------------------/#\n"
            'DOTENV_PUBLIC_KEY="034a..."\n'
            "#/-------------------[DOTENV][Encryption]-----------------------/#\n"
            'SECRET="encrypted:abc123xyz..."\n'
        )

        # Setup: Mock vault returns key
        mock_vault_client.get_secret.return_value = SecretValue(
            name="myapp-key",
            value="ec0987654321fedcba...",
        )

        # Config with ephemeral mode
        config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="myapp-key",
                    folder_path=service_dir,
                ),
            ],
            ephemeral_keys=True,
        )

        # Execute sync
        engine = SyncEngine(config=config, vault_client=mock_vault_client)
        result = engine.sync_all()

        # Verify ephemeral behavior
        assert result.services[0].action == SyncAction.EPHEMERAL
        assert result.services[0].vault_key_value == "ec0987654321fedcba..."
        assert result.ephemeral_count == 1
        assert result.created_count == 0

        # Critical: No .env.keys file should be created
        env_keys_file = service_dir / ".env.keys"
        assert not env_keys_file.exists(), ".env.keys should NOT exist in ephemeral mode"

    def test_mixed_ephemeral_and_normal_mappings(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """Test mixing ephemeral and normal mappings."""
        # Setup: Create two service directories
        ephemeral_dir = tmp_path / "ephemeral-service"
        ephemeral_dir.mkdir()
        (ephemeral_dir / ".env.production").write_text("SECRET=encrypted:xyz\n")

        normal_dir = tmp_path / "normal-service"
        normal_dir.mkdir()
        (normal_dir / ".env.production").write_text("SECRET=encrypted:xyz\n")

        # Mock vault
        mock_vault_client.get_secret.return_value = SecretValue(name="key", value="secret123")

        # Config: one ephemeral, one normal
        config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="ephemeral-key",
                    folder_path=ephemeral_dir,
                    ephemeral_keys=True,  # Per-mapping ephemeral
                ),
                ServiceMapping(
                    secret_name="normal-key",
                    folder_path=normal_dir,
                    ephemeral_keys=False,  # Explicit normal
                ),
            ],
            ephemeral_keys=False,  # Central default
        )

        engine = SyncEngine(config=config, vault_client=mock_vault_client)
        result = engine.sync_all()

        # Verify mixed behavior
        assert result.ephemeral_count == 1
        assert result.created_count == 1

        # Ephemeral: no file
        assert not (ephemeral_dir / ".env.keys").exists()

        # Normal: file created
        assert (normal_dir / ".env.keys").exists()
        content = (normal_dir / ".env.keys").read_text()
        assert "DOTENV_PRIVATE_KEY_PRODUCTION=secret123" in content

    def test_ephemeral_with_all_vault_providers(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """Test ephemeral mode works with any vault provider (mocked)."""
        service_dir = tmp_path / "service"
        service_dir.mkdir()
        (service_dir / ".env.production").write_text("SECRET=encrypted:xyz\n")

        # Mock different vault response formats
        mock_vault_client.get_secret.return_value = SecretValue(
            name="key",
            value="DOTENV_PRIVATE_KEY_PRODUCTION=strippedvalue",  # Prefixed format
        )

        config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="key",
                    folder_path=service_dir,
                ),
            ],
            ephemeral_keys=True,
        )

        engine = SyncEngine(config=config, vault_client=mock_vault_client)
        result = engine.sync_all()

        # Verify key is stripped and returned
        assert result.services[0].action == SyncAction.EPHEMERAL
        assert result.services[0].vault_key_value == "strippedvalue"
        assert not (service_dir / ".env.keys").exists()
