"""Unit tests for smart encryption integration in CLI commands."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from envdrift.cli import app
from envdrift.cli_commands.encryption import encrypt_cmd
from envdrift.cli_commands.sync import lock_cmd

runner = CliRunner()

@patch("envdrift.cli_commands.encryption.should_skip_reencryption")
@patch("envdrift.cli_commands.encryption.load_config")
@patch("envdrift.cli_commands.encryption.resolve_backend")
def test_encrypt_command_skips_when_smart_encryption_says_so(
    mock_resolve, mock_load_config, mock_should_skip, tmp_path
):
    """Test encrypt command skips re-encryption when should_skip returns True."""
    # Setup mocks
    mock_should_skip.return_value = (True, "mock reason")
    
    mock_backend = MagicMock()
    mock_resolve.return_value = mock_backend
    
    mock_config = MagicMock()
    mock_load_config.return_value = mock_config
    
    env_file = tmp_path / ".env"
    env_file.write_text("SECRET=val")

    # Run command via runner (targeting the specific command function/app)
    # Note: envdrift.cli.app includes all commands.
    
    # We invoke 'encrypt' command.
    result = runner.invoke(app, ["encrypt", str(env_file), "--backend", "dotenvx"])
    
    assert result.exit_code == 0
    assert "skipped (mock reason)" in result.stdout
    assert "Encrypted" not in result.stdout
    
    # Verify backend.encrypt was NOT called
    mock_backend.encrypt.assert_not_called()


@patch("envdrift.cli_commands.sync.should_skip_reencryption")
@patch("envdrift.cli_commands.sync.load_config")
@patch("envdrift.cli_commands.sync.resolve_backend")
@patch("envdrift.cli_commands.sync.load_envs_from_file")
@patch("envdrift.cli_commands.sync.is_encrypted_content")
def test_lock_command_skips_when_smart_encryption_says_so(
    mock_is_encrypted, mock_load_envs, mock_resolve, mock_load_config, mock_should_skip, tmp_path
):
    """Test lock command skips re-encryption when smart encryption says so."""
    # Setup mocks
    mock_should_skip.return_value = (True, "mock reason for lock")
    
    mock_backend = MagicMock()
    mock_resolve.return_value = mock_backend
    
    # lock iterates files found. We need to mock discovery or point to specific file?
    # lock command takes arguments for files or defaults to auto-discovery.
    # It calls 'get_env_files' internally if no files provided, or iterates args.
    # But lock command signature: `lock_cmd(files: list[Path]...)`
    
    # We'll pass file explicitly.
    env_file = tmp_path / ".env"
    env_file.write_text("SECRET=val")
    
    # is_encrypted_content needs to return False so it proceeds to encryption step
    # (if True, it skips as "already encrypted" unless force=True)
    mock_is_encrypted.return_value = False
    
    # Run command
    result = runner.invoke(app, ["lock", str(env_file), "--backend", "dotenvx", "--force"])
    
    assert result.exit_code == 0
    assert "skipped (mock reason for lock)" in result.stdout
    
    # Verify backend.encrypt was NOT called
    mock_backend.encrypt.assert_not_called()
