"""Tests for sync engine."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from envdrift.sync.config import ServiceMapping, SyncConfig
from envdrift.sync.engine import SyncEngine, SyncMode
from envdrift.sync.result import DecryptionTestResult, SyncAction
from envdrift.vault.base import SecretNotFoundError, SecretValue, VaultClient, VaultError


@pytest.fixture
def mock_vault_client() -> MagicMock:
    """Create a mock vault client."""
    client = MagicMock(spec=VaultClient)
    client.is_authenticated.return_value = True
    return client


@pytest.fixture
def simple_config(tmp_path: Path) -> SyncConfig:
    """Create a simple sync config."""
    return SyncConfig(
        mappings=[
            ServiceMapping(
                secret_name="test-key",
                folder_path=tmp_path / "service1",
            ),
        ],
    )


class TestSyncEngineBasic:
    """Basic sync engine tests."""

    def test_sync_creates_new_file(self, mock_vault_client: MagicMock, tmp_path: Path) -> None:
        """Test syncing creates new .env.keys file."""
        mock_vault_client.get_secret.return_value = SecretValue(name="test-key", value="secret123")

        config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="test-key",
                    folder_path=tmp_path / "service1",
                ),
            ],
        )

        engine = SyncEngine(config=config, vault_client=mock_vault_client)
        result = engine.sync_all()

        assert len(result.services) == 1
        assert result.services[0].action == SyncAction.CREATED
        assert (tmp_path / "service1" / ".env.keys").exists()

    def test_sync_updates_mismatched_file(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """Test syncing updates when values don't match."""
        mock_vault_client.get_secret.return_value = SecretValue(name="test-key", value="new_secret")

        # Create existing file with different value
        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        (service_dir / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=old_secret\n")

        config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="test-key",
                    folder_path=service_dir,
                ),
            ],
        )

        engine = SyncEngine(
            config=config,
            vault_client=mock_vault_client,
            mode=SyncMode(force_update=True),
        )
        result = engine.sync_all()

        assert result.services[0].action == SyncAction.UPDATED
        content = (service_dir / ".env.keys").read_text()
        assert "new_secret" in content

    def test_sync_skips_when_values_match(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """Test syncing skips when values already match."""
        mock_vault_client.get_secret.return_value = SecretValue(
            name="test-key", value="same_secret"
        )

        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        (service_dir / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=same_secret\n")

        config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="test-key",
                    folder_path=service_dir,
                ),
            ],
        )

        engine = SyncEngine(config=config, vault_client=mock_vault_client)
        result = engine.sync_all()

        assert result.services[0].action == SyncAction.SKIPPED


class TestSyncEngineVerifyMode:
    """Tests for verify mode."""

    def test_verify_mode_no_modifications(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """Test verify mode doesn't modify files."""
        mock_vault_client.get_secret.return_value = SecretValue(name="test-key", value="secret123")

        config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="test-key",
                    folder_path=tmp_path / "service1",
                ),
            ],
        )

        engine = SyncEngine(
            config=config,
            vault_client=mock_vault_client,
            mode=SyncMode(verify_only=True),
        )
        result = engine.sync_all()

        # Should report error (file doesn't exist) but not create it
        assert result.services[0].action == SyncAction.ERROR
        assert not (tmp_path / "service1" / ".env.keys").exists()

    def test_verify_mode_reports_mismatch(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """Test verify mode reports mismatches as errors."""
        mock_vault_client.get_secret.return_value = SecretValue(name="test-key", value="new_secret")

        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        (service_dir / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=old_secret\n")

        config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="test-key",
                    folder_path=service_dir,
                ),
            ],
        )

        engine = SyncEngine(
            config=config,
            vault_client=mock_vault_client,
            mode=SyncMode(verify_only=True),
        )
        result = engine.sync_all()

        assert result.services[0].action == SyncAction.ERROR
        assert "mismatch" in result.services[0].message.lower()


class TestSyncEngineForceMode:
    """Tests for force mode."""

    def test_force_mode_updates_without_prompt(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """Test force mode updates without prompting."""
        mock_vault_client.get_secret.return_value = SecretValue(name="test-key", value="new_secret")

        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        (service_dir / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=old_secret\n")

        prompt_called = False

        def prompt_callback(msg: str) -> bool:
            nonlocal prompt_called
            prompt_called = True
            return True

        config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="test-key",
                    folder_path=service_dir,
                ),
            ],
        )

        engine = SyncEngine(
            config=config,
            vault_client=mock_vault_client,
            mode=SyncMode(force_update=True),
            prompt_callback=prompt_callback,
        )
        result = engine.sync_all()

        assert result.services[0].action == SyncAction.UPDATED
        assert not prompt_called  # Prompt should not be called in force mode


class TestSyncEngineErrorHandling:
    """Tests for error handling."""

    def test_handles_secret_not_found(self, mock_vault_client: MagicMock, tmp_path: Path) -> None:
        """Test handling when secret is not found in vault."""
        mock_vault_client.get_secret.side_effect = SecretNotFoundError("Secret not found")

        config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="missing-key",
                    folder_path=tmp_path / "service1",
                ),
            ],
        )

        engine = SyncEngine(config=config, vault_client=mock_vault_client)
        result = engine.sync_all()

        assert result.services[0].action == SyncAction.ERROR
        assert "not found" in result.services[0].message.lower()

    def test_handles_vault_error(self, mock_vault_client: MagicMock, tmp_path: Path) -> None:
        """Test handling generic vault errors."""
        mock_vault_client.get_secret.side_effect = VaultError("Connection failed")

        config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="test-key",
                    folder_path=tmp_path / "service1",
                ),
            ],
        )

        engine = SyncEngine(config=config, vault_client=mock_vault_client)
        result = engine.sync_all()

        assert result.services[0].action == SyncAction.ERROR


class TestSyncEngineMultipleServices:
    """Tests for multiple service handling."""

    def test_processes_multiple_services(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """Test processing multiple services."""
        mock_vault_client.get_secret.return_value = SecretValue(name="key", value="secret")

        config = SyncConfig(
            mappings=[
                ServiceMapping(secret_name="key1", folder_path=tmp_path / "service1"),
                ServiceMapping(secret_name="key2", folder_path=tmp_path / "service2"),
                ServiceMapping(secret_name="key3", folder_path=tmp_path / "service3"),
            ],
        )

        engine = SyncEngine(config=config, vault_client=mock_vault_client)
        result = engine.sync_all()

        assert len(result.services) == 3
        assert result.total_processed == 3
        assert result.created_count == 3


class TestSyncEngineDecryptionTest:
    """Tests for decryption verification."""

    def test_decryption_test_skipped_no_env_file(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """Test decryption test is skipped when no env file exists."""
        mock_vault_client.get_secret.return_value = SecretValue(name="test-key", value="secret123")

        config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="test-key",
                    folder_path=tmp_path / "service1",
                ),
            ],
        )

        engine = SyncEngine(
            config=config,
            vault_client=mock_vault_client,
            mode=SyncMode(check_decryption=True),
        )
        result = engine.sync_all()

        assert result.services[0].decryption_result == DecryptionTestResult.SKIPPED

    def test_decryption_test_skipped_not_encrypted(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """Test decryption test is skipped for non-encrypted files."""
        mock_vault_client.get_secret.return_value = SecretValue(name="test-key", value="secret123")

        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        (service_dir / ".env.production").write_text("DB_URL=localhost\n")

        config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="test-key",
                    folder_path=service_dir,
                ),
            ],
        )

        engine = SyncEngine(
            config=config,
            vault_client=mock_vault_client,
            mode=SyncMode(check_decryption=True),
        )
        result = engine.sync_all()

        assert result.services[0].decryption_result == DecryptionTestResult.SKIPPED


class TestSyncEngineFetchVaultSecret:
    """Tests for vault secret fetching."""

    def test_strips_key_prefix_from_value(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """Test that KEY= prefix is stripped from vault value."""
        # Some vaults store full line: KEY=value
        mock_vault_client.get_secret.return_value = SecretValue(
            name="test-key",
            value="DOTENV_PRIVATE_KEY_PRODUCTION=actual_secret",
        )

        config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="test-key",
                    folder_path=tmp_path / "service1",
                ),
            ],
        )

        engine = SyncEngine(config=config, vault_client=mock_vault_client)
        engine.sync_all()

        content = (tmp_path / "service1" / ".env.keys").read_text()
        # Should not have double KEY= prefix
        assert "DOTENV_PRIVATE_KEY_PRODUCTION=actual_secret" in content
        assert "DOTENV_PRIVATE_KEY_PRODUCTION=DOTENV_PRIVATE_KEY" not in content


class TestSyncResult:
    """Tests for SyncResult aggregation."""

    def test_exit_code_success(self, mock_vault_client: MagicMock, tmp_path: Path) -> None:
        """Test exit code is 0 on success."""
        mock_vault_client.get_secret.return_value = SecretValue(name="key", value="secret")

        config = SyncConfig(
            mappings=[
                ServiceMapping(secret_name="key", folder_path=tmp_path / "service"),
            ],
        )

        engine = SyncEngine(config=config, vault_client=mock_vault_client)
        result = engine.sync_all()

        assert result.exit_code == 0
        assert not result.has_errors

    def test_exit_code_error(self, mock_vault_client: MagicMock, tmp_path: Path) -> None:
        """Test exit code is 1 on error."""
        mock_vault_client.get_secret.side_effect = SecretNotFoundError("Not found")

        config = SyncConfig(
            mappings=[
                ServiceMapping(secret_name="key", folder_path=tmp_path / "service"),
            ],
        )

        engine = SyncEngine(config=config, vault_client=mock_vault_client)
        result = engine.sync_all()

        assert result.exit_code == 1
        assert result.has_errors
