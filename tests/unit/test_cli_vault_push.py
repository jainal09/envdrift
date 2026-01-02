"""Tests for vault-push command."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from envdrift.cli import app
from envdrift.sync.config import ServiceMapping, SyncConfig
from envdrift.vault.base import SecretNotFoundError, SecretValue

runner = CliRunner()


class TestVaultPushAll:
    """Tests for vault-push --all."""

    @patch("envdrift.cli_commands.sync.load_sync_config_and_client")
    @patch("envdrift.integrations.dotenvx.DotenvxWrapper")
    @patch("envdrift.sync.operations.EnvKeysFile")
    def test_push_all_success(
        self,
        mock_keys_file,
        mock_dotenvx_cls,
        mock_loader,
        tmp_path,
    ):
        """Test happy path for --all."""

        # Setup mocks
        mock_client = MagicMock()
        mock_sync_config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="my-secret",
                    folder_path=tmp_path / "service1",
                    environment="production",
                )
            ]
        )

        mock_loader.return_value = (mock_sync_config, mock_client, "azure", None, None)

        # Mock Dotenvx
        mock_dotenvx = MagicMock()
        mock_dotenvx_cls.return_value = mock_dotenvx

        # Create env file
        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        env_file = service_dir / ".env.production"
        env_file.write_text("encrypted: yes")  # appears encrypted

        # Create keys file
        keys_file = service_dir / ".env.keys"
        keys_file.write_text("DOTENV_PRIVATE_KEY_PRODUCTION=secret123")

        # Mock EnvKeysFile read_key
        mock_keys_instance = MagicMock()
        mock_keys_instance.read_key.return_value = "secret123"
        mock_keys_file.return_value = mock_keys_instance

        # Mock client.get_secret to raise SecretNotFoundError (simulating missing secret)
        mock_client.get_secret.side_effect = SecretNotFoundError("missing")

        # Run
        result = runner.invoke(app, ["vault-push", "--all"])

        assert result.exit_code == 0
        assert "Pushed my-secret" in result.output

        # Verify set_secret called
        mock_client.set_secret.assert_called_with(
            "my-secret", "DOTENV_PRIVATE_KEY_PRODUCTION=secret123"
        )

    @patch("envdrift.cli_commands.sync.load_sync_config_and_client")
    def test_push_all_skips_existing(
        self,
        mock_loader,
        tmp_path,
    ):
        """Test skipping existing secrets."""
        mock_client = MagicMock()
        mock_sync_config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="existing-secret",
                    folder_path=tmp_path / "service1",
                    environment="production",
                )
            ]
        )
        mock_loader.return_value = (mock_sync_config, mock_client, "azure", None, None)

        # Create env file
        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        env_file = service_dir / ".env.production"
        env_file.write_text("encrypted: yes")

        # Mock client.get_secret to return success
        mock_client.get_secret.return_value = SecretValue(name="existing-secret", value="val")

        result = runner.invoke(app, ["vault-push", "--all"])

        assert result.exit_code == 0
        assert "Skipped" in result.output
        assert "already" in result.output and "exists" in result.output
        mock_client.set_secret.assert_not_called()

    @patch("envdrift.cli_commands.sync.load_sync_config_and_client")
    @patch("envdrift.integrations.dotenvx.DotenvxWrapper")
    @patch("envdrift.sync.operations.EnvKeysFile")
    def test_push_all_encrypts_unencrypted(
        self,
        mock_keys_file,
        mock_dotenvx_cls,
        mock_loader,
        tmp_path,
    ):
        """Test auto-encryption."""
        mock_client = MagicMock()
        mock_sync_config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="new-secret",
                    folder_path=tmp_path / "service1",
                    environment="production",
                )
            ]
        )
        mock_loader.return_value = (mock_sync_config, mock_client, "azure", None, None)

        mock_dotenvx = MagicMock()
        mock_dotenvx_cls.return_value = mock_dotenvx

        # Create unencrypted env file
        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        env_file = service_dir / ".env.production"
        env_file.write_text("PLAIN=text")

        # Create keys file so it allows push processing
        (service_dir / ".env.keys").touch()
        mock_keys_instance = MagicMock()
        mock_keys_instance.read_key.return_value = "key123"
        mock_keys_file.return_value = mock_keys_instance

        # Setup mocks for push flow to continue
        mock_client.get_secret.side_effect = SecretNotFoundError("missing")

        # Run
        result = runner.invoke(app, ["vault-push", "--all"])

        assert result.exit_code == 0

        # Verify encryption called
        mock_dotenvx.encrypt.assert_called_once()
        args, _ = mock_dotenvx.encrypt.call_args
        assert args[0] == env_file
