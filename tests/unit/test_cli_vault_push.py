"""Tests for vault-push command."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from envdrift.cli import app
from envdrift.integrations.dotenvx import DotenvxError
from envdrift.sync.config import ServiceMapping, SyncConfig
from envdrift.vault.base import SecretNotFoundError, SecretValue, VaultError

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

        mock_loader.return_value = (mock_sync_config, mock_client, "azure", None, None, None)

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
        mock_loader.return_value = (mock_sync_config, mock_client, "azure", None, None, None)

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
        mock_loader.return_value = (mock_sync_config, mock_client, "azure", None, None, None)

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

    @patch("envdrift.cli_commands.sync.load_sync_config_and_client")
    @patch("envdrift.integrations.dotenvx.DotenvxWrapper")
    def test_push_all_error_handling(
        self,
        mock_dotenvx_cls,
        mock_loader,
        tmp_path,
    ):
        """Test various error conditions in push loop to ensure coverage."""
        mock_client = MagicMock()
        mock_dotenvx = MagicMock()
        mock_dotenvx_cls.return_value = mock_dotenvx

        # Scenarios:
        # 1. Missing .env file (Skipped)
        # 2. Encryption failure (Error)
        # 3. Vault API error (Error)
        # 4. Missing .env.keys file (Error)
        # 5. Missing key in .env.keys (Error)

        mappings = []
        for i in range(1, 6):
            mappings.append(
                ServiceMapping(
                    secret_name=f"s{i}",
                    folder_path=tmp_path / f"s{i}",
                    environment="prod",
                )
            )
            (tmp_path / f"s{i}").mkdir()

        mock_sync_config = SyncConfig(mappings=mappings)
        mock_loader.return_value = (mock_sync_config, mock_client, "azure", None, None, None)

        # Setup s1: No files.

        # Setup s2: Unencrypted .env, encrypt raises error
        (tmp_path / "s2" / ".env.prod").write_text("plain=text")
        mock_dotenvx.encrypt.side_effect = DotenvxError("encrypt failed")

        # Setup s3: Encrypted .env, Vault check raises VaultError
        (tmp_path / "s3" / ".env.prod").write_text("encrypted: yes")

        # Setup s4: Encrypted .env, Secret missing in vault, Missing .env.keys
        (tmp_path / "s4" / ".env.prod").write_text("encrypted: yes")

        # Setup s5: Encrypted .env, Secret missing, .env.keys exists but missing key
        (tmp_path / "s5" / ".env.prod").write_text("encrypted: yes")
        (tmp_path / "s5" / ".env.keys").write_text("OTHER_KEY=val")

        # Client side effects
        # s1: skipped before client call
        # s2: skipped before client call (encryption fail)
        # s3: calls get_secret -> raises VaultError
        # s4: calls get_secret -> raises SecretNotFoundError -> checks keys -> fail
        # s5: calls get_secret -> raises SecretNotFoundError -> checks keys -> reads -> None -> fail

        mock_client.get_secret.side_effect = [
            VaultError("api error"),  # s3
            SecretNotFoundError("miss"),  # s4
            SecretNotFoundError("miss"),  # s5
        ]

        result = runner.invoke(app, ["vault-push", "--all"])

        assert result.exit_code == 0

        output = result.output.replace("\n", " ").replace("  ", " ")

        # Verify counts
        assert "Skipped: 1" in output
        assert "Errors: 4" in output

        assert "No .env file found" in output
        assert "Failed to encrypt" in output
        assert "Vault error checking" in output
        assert ".env.keys not found" in output
        assert "not found in keys file" in output
