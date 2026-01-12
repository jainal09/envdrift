"""Tests for sync engine."""

from __future__ import annotations

import subprocess
from pathlib import Path
from textwrap import dedent
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

        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        (service_dir / ".env.production").write_text("DB_URL=encrypted:xyz\n")

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

        assert len(result.services) == 1
        assert result.services[0].action == SyncAction.CREATED
        assert (service_dir / ".env.keys").exists()

    def test_sync_skips_when_env_file_does_not_exist(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """Test syncing skips when .env.<environment> file doesn't exist."""
        mock_vault_client.get_secret.return_value = SecretValue(name="test-key", value="secret123")

        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        # No .env.production file created

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
        assert ".env.production" in result.services[0].message
        assert not (service_dir / ".env.keys").exists()

    def test_sync_updates_mismatched_file(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """Test syncing updates when values don't match."""
        mock_vault_client.get_secret.return_value = SecretValue(name="test-key", value="new_secret")

        # Create existing file with different value
        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        (service_dir / ".env.production").write_text("DB_URL=encrypted:xyz\n")
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
        (service_dir / ".env.production").write_text("DB_URL=encrypted:xyz\n")
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

        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        (service_dir / ".env.production").write_text("DB_URL=encrypted:xyz\n")

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

        # Should report error (key file doesn't exist) but not create it
        assert result.services[0].action == SyncAction.ERROR
        assert not (service_dir / ".env.keys").exists()

    def test_verify_mode_reports_mismatch(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """Test verify mode reports mismatches as errors."""
        mock_vault_client.get_secret.return_value = SecretValue(name="test-key", value="new_secret")

        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        (service_dir / ".env.production").write_text("DB_URL=encrypted:xyz\n")
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
        (service_dir / ".env.production").write_text("DB_URL=encrypted:xyz\n")
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

        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        (service_dir / ".env.production").write_text("DB_URL=encrypted:xyz\n")

        config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="missing-key",
                    folder_path=service_dir,
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

        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        (service_dir / ".env.production").write_text("DB_URL=encrypted:xyz\n")

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

        assert result.services[0].action == SyncAction.ERROR


class TestSyncEngineMultipleServices:
    """Tests for multiple service handling."""

    def test_processes_multiple_services(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """Test processing multiple services."""
        mock_vault_client.get_secret.return_value = SecretValue(name="key", value="secret")

        # Create all service directories with .env.production files
        for i in range(1, 4):
            service_dir = tmp_path / f"service{i}"
            service_dir.mkdir()
            (service_dir / ".env.production").write_text("DB_URL=encrypted:xyz\n")

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

    def test_decryption_test_passes(
        self, mock_vault_client: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test decryption test passes and cleans up backup."""
        mapping = ServiceMapping(
            secret_name="test-key", folder_path=tmp_path, environment="production"
        )
        env_file = tmp_path / ".env.production"
        env_file.write_text('DOTENV_PUBLIC_KEY="abc"\nSECRET="encrypted:xyz"\n')

        monkeypatch.setattr("envdrift.sync.engine.shutil.which", lambda _: "/usr/bin/dotenvx")
        monkeypatch.setattr("envdrift.sync.engine.shutil.copy2", lambda *a, **k: None)
        monkeypatch.setattr("envdrift.sync.engine.Path.unlink", lambda *a, **k: None)
        runner = MagicMock()
        runner.side_effect = [
            subprocess.CompletedProcess(["decrypt"], 0),
            subprocess.CompletedProcess(["encrypt"], 0),
        ]
        monkeypatch.setattr("envdrift.sync.engine.subprocess.run", runner)

        engine = SyncEngine(
            config=SyncConfig(mappings=[mapping]), vault_client=mock_vault_client, mode=SyncMode()
        )

        result = engine._test_decryption(mapping)

        assert runner.call_count == 2  # decrypt + encrypt
        assert result == DecryptionTestResult.PASSED
        assert not env_file.with_suffix(".backup_decryption_test").exists()

    def test_decryption_test_fails_on_subprocess_error(
        self, mock_vault_client: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test decryption test returns FAILED when subprocess fails."""
        mapping = ServiceMapping(
            secret_name="test-key", folder_path=tmp_path, environment="production"
        )
        env_file = tmp_path / ".env.production"
        env_file.write_text('DOTENV_PUBLIC_KEY="abc"\nSECRET="encrypted:xyz"\n')

        def fake_run(cmd, **kwargs):
            """
            Simulate subprocess.run by returning a completed process that indicates failure.

            Parameters:
                cmd: The command that would have been executed; accepted for signature compatibility and included in the returned CompletedProcess.
                **kwargs: Additional keyword arguments accepted for compatibility and ignored.

            Returns:
                subprocess.CompletedProcess: A CompletedProcess with the provided `cmd` and a `returncode` of 1.
            """
            return subprocess.CompletedProcess(cmd, 1)

        monkeypatch.setattr("envdrift.sync.engine.shutil.which", lambda _: "/usr/bin/dotenvx")
        monkeypatch.setattr("envdrift.sync.engine.subprocess.run", fake_run)

        engine = SyncEngine(
            config=SyncConfig(mappings=[mapping]), vault_client=mock_vault_client, mode=SyncMode()
        )
        result = engine._test_decryption(mapping)

        assert result == DecryptionTestResult.FAILED
        assert not env_file.with_suffix(".backup_decryption_test").exists()

    def test_decryption_test_timeout_restores_file(
        self, mock_vault_client: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Timeouts should be treated as FAILED and restore the original file."""
        mapping = ServiceMapping(
            secret_name="test-key", folder_path=tmp_path, environment="production"
        )
        env_file = tmp_path / ".env.production"
        original = 'DOTENV_PUBLIC_KEY="abc"\nSECRET="encrypted:xyz"\n'
        env_file.write_text(original)

        def fake_run(cmd, **kwargs):
            """
            Simulate a subprocess.run invocation that always raises a timeout.

            Parameters:
                cmd (Sequence[str] | str): The command that was attempted to run; included in the raised exception.
                **kwargs: Additional keyword arguments accepted by subprocess.run (ignored).

            Raises:
                subprocess.TimeoutExpired: Always raised with the provided `cmd` and a timeout value of 30 seconds.
            """
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=30)

        monkeypatch.setattr("envdrift.sync.engine.shutil.which", lambda _: "/usr/bin/dotenvx")
        monkeypatch.setattr("envdrift.sync.engine.subprocess.run", fake_run)

        engine = SyncEngine(
            config=SyncConfig(mappings=[mapping]), vault_client=mock_vault_client, mode=SyncMode()
        )
        result = engine._test_decryption(mapping)

        assert result == DecryptionTestResult.FAILED
        assert env_file.read_text() == original


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

        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        (service_dir / ".env.production").write_text("DB_URL=encrypted:xyz\n")

        config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="test-key",
                    folder_path=service_dir,
                ),
            ],
        )

        engine = SyncEngine(config=config, vault_client=mock_vault_client)
        engine.sync_all()

        content = (service_dir / ".env.keys").read_text()
        # Should not have double KEY= prefix
        assert "DOTENV_PRIVATE_KEY_PRODUCTION=actual_secret" in content
        assert "DOTENV_PRIVATE_KEY_PRODUCTION=DOTENV_PRIVATE_KEY" not in content

    def test_strips_any_key_prefix_from_value(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """Test that any DOTENV_PRIVATE_KEY_*= prefix is stripped from vault value."""
        # Vault stores key with different environment than config
        mock_vault_client.get_secret.return_value = SecretValue(
            name="test-key",
            value="DOTENV_PRIVATE_KEY_SOAK=actual_secret",
        )

        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        (service_dir / ".env.production").write_text("DB_URL=encrypted:xyz\n")

        config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="test-key",
                    folder_path=service_dir,
                    environment="production",
                ),
            ],
        )

        engine = SyncEngine(config=config, vault_client=mock_vault_client)
        engine.sync_all()

        content = (service_dir / ".env.keys").read_text()
        # Should strip the SOAK prefix and write with PRODUCTION key
        assert "DOTENV_PRIVATE_KEY_PRODUCTION=actual_secret" in content
        assert "DOTENV_PRIVATE_KEY_SOAK" not in content

    def test_strips_lowercase_key_prefix_from_value(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """Test that lowercase DOTENV_PRIVATE_KEY_*= prefix is stripped from vault value."""
        # Vault stores key with lowercase environment name like "soak", "local", "prod"
        mock_vault_client.get_secret.return_value = SecretValue(
            name="test-key",
            value="DOTENV_PRIVATE_KEY_soak=actual_secret",
        )

        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        (service_dir / ".env.soak").write_text("DB_URL=encrypted:xyz\n")

        config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="test-key",
                    folder_path=service_dir,
                    environment="soak",
                ),
            ],
        )

        engine = SyncEngine(config=config, vault_client=mock_vault_client)
        engine.sync_all()

        content = (service_dir / ".env.keys").read_text()
        # Should strip the soak prefix and write with SOAK key (uppercase in .env.keys)
        assert "DOTENV_PRIVATE_KEY_SOAK=actual_secret" in content
        assert "DOTENV_PRIVATE_KEY_soak=" not in content

    def test_strips_mixed_case_key_prefix_with_digits(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """Test that mixed case with digits DOTENV_PRIVATE_KEY_*= prefix is stripped."""
        # Vault stores key with mixed case and digits
        mock_vault_client.get_secret.return_value = SecretValue(
            name="test-key",
            value="DOTENV_PRIVATE_KEY_Prod2=actual_secret",
        )

        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        (service_dir / ".env.prod2").write_text("DB_URL=encrypted:xyz\n")

        config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="test-key",
                    folder_path=service_dir,
                    environment="prod2",
                ),
            ],
        )

        engine = SyncEngine(config=config, vault_client=mock_vault_client)
        engine.sync_all()

        content = (service_dir / ".env.keys").read_text()
        # Should strip the Prod2 prefix and write with PROD2 key
        assert "DOTENV_PRIVATE_KEY_PROD2=actual_secret" in content
        assert "DOTENV_PRIVATE_KEY_Prod2=" not in content


class TestSyncResult:
    """Tests for SyncResult aggregation."""

    def test_exit_code_success(self, mock_vault_client: MagicMock, tmp_path: Path) -> None:
        """Test exit code is 0 on success."""
        mock_vault_client.get_secret.return_value = SecretValue(name="key", value="secret")

        service_dir = tmp_path / "service"
        service_dir.mkdir()
        (service_dir / ".env.production").write_text("DB_URL=encrypted:xyz\n")

        config = SyncConfig(
            mappings=[
                ServiceMapping(secret_name="key", folder_path=service_dir),
            ],
        )

        engine = SyncEngine(config=config, vault_client=mock_vault_client)
        result = engine.sync_all()

        assert result.exit_code == 0
        assert not result.has_errors

    def test_exit_code_error(self, mock_vault_client: MagicMock, tmp_path: Path) -> None:
        """Test exit code is 1 on error."""
        mock_vault_client.get_secret.side_effect = SecretNotFoundError("Not found")

        service_dir = tmp_path / "service"
        service_dir.mkdir()
        (service_dir / ".env.production").write_text("DB_URL=encrypted:xyz\n")

        config = SyncConfig(
            mappings=[
                ServiceMapping(secret_name="key", folder_path=service_dir),
            ],
        )

        engine = SyncEngine(config=config, vault_client=mock_vault_client)
        result = engine.sync_all()

        assert result.exit_code == 1
        assert result.has_errors


class TestSyncEngineEphemeralKeys:
    """Tests for ephemeral keys mode."""

    def test_ephemeral_mode_fetches_key_but_does_not_write_file(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """Test ephemeral mode returns key but doesn't create .env.keys file."""
        mock_vault_client.get_secret.return_value = SecretValue(
            name="test-key", value="ephemeral_secret_123"
        )

        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        (service_dir / ".env.production").write_text("DB_URL=encrypted:xyz\n")

        config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="test-key",
                    folder_path=service_dir,
                ),
            ],
            ephemeral_keys=True,  # Central ephemeral mode
        )

        engine = SyncEngine(config=config, vault_client=mock_vault_client)
        result = engine.sync_all()

        assert result.services[0].action == SyncAction.EPHEMERAL
        assert result.services[0].vault_key_value == "ephemeral_secret_123"
        assert not (service_dir / ".env.keys").exists()

    def test_ephemeral_mode_per_mapping_override(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """Test per-mapping ephemeral override takes precedence over central."""
        mock_vault_client.get_secret.return_value = SecretValue(
            name="test-key", value="secret_value"
        )

        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        (service_dir / ".env.production").write_text("DB_URL=encrypted:xyz\n")

        config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="test-key",
                    folder_path=service_dir,
                    ephemeral_keys=True,  # Override: enable ephemeral for this mapping
                ),
            ],
            ephemeral_keys=False,  # Central: disabled
        )

        engine = SyncEngine(config=config, vault_client=mock_vault_client)
        result = engine.sync_all()

        # Per-mapping ephemeral=True should override central False
        assert result.services[0].action == SyncAction.EPHEMERAL
        assert not (service_dir / ".env.keys").exists()

    def test_ephemeral_count_in_result(self, mock_vault_client: MagicMock, tmp_path: Path) -> None:
        """Test ephemeral_count property in SyncResult."""
        mock_vault_client.get_secret.return_value = SecretValue(name="test-key", value="secret")

        for i in range(3):
            service_dir = tmp_path / f"service{i}"
            service_dir.mkdir()
            (service_dir / ".env.production").write_text("DB_URL=encrypted:xyz\n")

        config = SyncConfig(
            mappings=[
                ServiceMapping(secret_name="key1", folder_path=tmp_path / "service0"),
                ServiceMapping(secret_name="key2", folder_path=tmp_path / "service1"),
                ServiceMapping(secret_name="key3", folder_path=tmp_path / "service2"),
            ],
            ephemeral_keys=True,
        )

        engine = SyncEngine(config=config, vault_client=mock_vault_client)
        result = engine.sync_all()

        assert result.ephemeral_count == 3
        assert result.created_count == 0

    def test_ephemeral_mode_skips_decryption_test(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """Test that decryption test is skipped in ephemeral mode."""
        mock_vault_client.get_secret.return_value = SecretValue(
            name="test-key", value="ephemeral_secret"
        )

        service_dir = tmp_path / "service"
        service_dir.mkdir()
        (service_dir / ".env.production").write_text(
            'DOTENV_PUBLIC_KEY="xyz"\nSECRET="encrypted:abc"\n'
        )

        config = SyncConfig(
            mappings=[
                ServiceMapping(secret_name="test-key", folder_path=service_dir),
            ],
            ephemeral_keys=True,
        )

        engine = SyncEngine(
            config=config,
            vault_client=mock_vault_client,
            mode=SyncMode(check_decryption=True),  # Enable decryption test
        )
        result = engine.sync_all()

        # Should be ephemeral action with no decryption result (skipped)
        assert result.services[0].action == SyncAction.EPHEMERAL
        assert result.services[0].decryption_result is None


class TestSyncEngineSchemaValidation:
    """Schema validation behavior tests."""

    def test_validate_schema_uses_detected_env_file(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """Validation should use detected .env.* files when expected env is missing."""
        service_dir = tmp_path / "service"
        service_dir.mkdir()
        (service_dir / ".env.staging").write_text("NAME=envdrift\n")

        module_path = service_dir / "service_settings.py"
        module_path.write_text(
            dedent(
                """
                from pydantic_settings import BaseSettings

                class Settings(BaseSettings):
                    NAME: str
                """
            ).lstrip()
        )

        mapping = ServiceMapping(secret_name="test-key", folder_path=service_dir)
        config = SyncConfig(mappings=[mapping])

        engine = SyncEngine(
            config=config,
            vault_client=mock_vault_client,
            mode=SyncMode(schema_path="service_settings:Settings", service_dir=service_dir),
        )

        assert engine._validate_schema(mapping) is True

    def test_validate_schema_returns_true_without_env_file(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """Validation should skip when no env file exists."""
        service_dir = tmp_path / "service"
        service_dir.mkdir()

        mapping = ServiceMapping(secret_name="test-key", folder_path=service_dir)
        config = SyncConfig(mappings=[mapping])

        engine = SyncEngine(
            config=config,
            vault_client=mock_vault_client,
            mode=SyncMode(schema_path="service_settings:Settings"),
        )

        assert engine._validate_schema(mapping) is True
