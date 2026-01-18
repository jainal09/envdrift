"""Unit tests for smart encryption integration in CLI commands."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from envdrift.cli import app

runner = CliRunner()


@patch("envdrift.cli_commands.encryption_helpers.should_skip_reencryption")
@patch("envdrift.cli_commands.encryption.get_encryption_backend")
def test_encrypt_command_skips_when_smart_encryption_says_so(
    mock_get_backend, mock_should_skip, tmp_path
):
    """Test encrypt command skips re-encryption when should_skip returns True."""
    # Setup mocks
    mock_should_skip.return_value = (True, "mock reason")

    mock_backend = MagicMock()
    mock_backend.is_installed.return_value = True
    mock_backend.name = "dotenvx"
    mock_get_backend.return_value = mock_backend

    env_file = tmp_path / ".env"
    env_file.write_text("SECRET=val")

    # Run command via runner (targeting the specific command function/app)
    # Note: envdrift.cli.app includes all commands.

    # We invoke 'encrypt' command.
    result = runner.invoke(app, ["encrypt", str(env_file), "--backend", "dotenvx"])

    assert result.exit_code == 0, f"Command failed with: {result.output}"
    # Normalize whitespace since terminal output may wrap lines
    stdout_normalized = " ".join(result.stdout.split())
    assert "Skipped" in stdout_normalized or "skipped" in stdout_normalized.lower()
    assert "mock reason" in stdout_normalized

    # Verify backend.encrypt was NOT called
    mock_backend.encrypt.assert_not_called()


@patch("envdrift.cli_commands.encryption_helpers.should_skip_reencryption")
@patch("envdrift.cli_commands.encryption_helpers.is_encrypted_content")
@patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
@patch("envdrift.cli_commands.sync.load_sync_config_and_client")
def test_lock_command_skips_when_smart_encryption_says_so(
    mock_load_sync_config, mock_resolve_backend, mock_is_encrypted, mock_should_skip, tmp_path
):
    """Test lock command skips re-encryption when smart encryption says so."""
    from envdrift.sync.config import ServiceMapping, SyncConfig

    # Setup mocks
    mock_should_skip.return_value = (True, "mock reason for lock")

    # Mock the encryption backend
    mock_backend = MagicMock()
    mock_backend.is_installed.return_value = True
    mock_backend.name = "dotenvx"
    mock_backend.has_encrypted_header.return_value = False
    from envdrift.encryption import EncryptionProvider

    mock_resolve_backend.return_value = (mock_backend, EncryptionProvider.DOTENVX, None)

    # Create temp env file
    env_file = tmp_path / ".env.production"
    env_file.write_text("SECRET=val")

    # Mock sync config to point to our temp directory
    sync_config = SyncConfig(
        mappings=[
            ServiceMapping(
                secret_name="test-secret",
                folder_path=tmp_path,
                environment="production",
            )
        ]
    )

    # Mock vault client
    mock_vault_client = MagicMock()

    mock_load_sync_config.return_value = (
        sync_config,
        mock_vault_client,
        "azure",
        "https://vault.azure.net",
        None,
        None,
    )

    # is_encrypted_content returns False so it proceeds to encryption step
    mock_is_encrypted.return_value = False

    # Run command with --force to skip interactive prompts
    result = runner.invoke(
        app,
        ["lock", "--provider", "azure", "--vault-url", "https://vault.azure.net", "--force"],
    )

    assert result.exit_code == 0
    # Normalize output to handle line wrapping from Rich console
    normalized_output = result.stdout.replace("\n", " ")
    assert "mock reason for lock" in normalized_output

    # Verify backend.encrypt was NOT called
    mock_backend.encrypt.assert_not_called()
