"""Tests for vault-push command."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from envdrift.cli import app
from envdrift.encryption import EncryptionProvider
from envdrift.encryption.base import EncryptionBackendError
from envdrift.sync.config import ServiceMapping, SyncConfig
from envdrift.vault.base import SecretNotFoundError, SecretValue, VaultError
from tests.helpers import DummyEncryptionBackend

runner = CliRunner()


class TestVaultPushAll:
    """Tests for vault-push --all."""

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    @patch("envdrift.cli_commands.sync.load_sync_config_and_client")
    @patch("envdrift.sync.operations.EnvKeysFile")
    def test_push_all_success(
        self,
        mock_keys_file,
        mock_loader,
        mock_resolve_backend,
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

        dummy_backend = DummyEncryptionBackend()
        mock_resolve_backend.return_value = (
            dummy_backend,
            EncryptionProvider.DOTENVX,
            None,
        )

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

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    @patch("envdrift.cli_commands.sync.load_sync_config_and_client")
    def test_push_all_skips_existing(
        self,
        mock_loader,
        mock_resolve_backend,
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
        mock_resolve_backend.return_value = (
            DummyEncryptionBackend(),
            EncryptionProvider.DOTENVX,
            None,
        )

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

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    @patch("envdrift.cli_commands.sync.load_sync_config_and_client")
    @patch("envdrift.sync.operations.EnvKeysFile")
    def test_push_all_force_overwrites_existing(
        self,
        mock_keys_file,
        mock_loader,
        mock_resolve_backend,
        tmp_path,
    ):
        """Test --force overwrites existing secrets."""
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
        mock_resolve_backend.return_value = (
            DummyEncryptionBackend(),
            EncryptionProvider.DOTENVX,
            None,
        )

        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        (service_dir / ".env.production").write_text("encrypted: yes")
        (service_dir / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=secret123")

        mock_keys_instance = MagicMock()
        mock_keys_instance.read_key.return_value = "secret123"
        mock_keys_file.return_value = mock_keys_instance

        mock_client.get_secret.return_value = SecretValue(name="existing-secret", value="val")

        result = runner.invoke(app, ["vault-push", "--all", "--force"])

        assert result.exit_code == 0
        assert "Pushed existing-secret" in result.output
        mock_client.set_secret.assert_called_with(
            "existing-secret", "DOTENV_PRIVATE_KEY_PRODUCTION=secret123"
        )

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    @patch("envdrift.cli_commands.sync.load_sync_config_and_client")
    @patch("envdrift.sync.operations.EnvKeysFile")
    def test_push_all_encrypts_unencrypted(
        self,
        mock_keys_file,
        mock_loader,
        mock_resolve_backend,
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

        dummy_backend = DummyEncryptionBackend()
        mock_resolve_backend.return_value = (
            dummy_backend,
            EncryptionProvider.DOTENVX,
            None,
        )

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
        assert dummy_backend.encrypt_calls == [env_file]

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    @patch("envdrift.cli_commands.sync.load_sync_config_and_client")
    def test_push_all_skips_mismatched_provider(
        self,
        mock_loader,
        mock_resolve_backend,
        tmp_path,
    ):
        """vault-push --all should skip when file is encrypted with another provider."""
        mock_client = MagicMock()
        mock_sync_config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="mismatch-secret",
                    folder_path=tmp_path / "service1",
                    environment="production",
                )
            ]
        )
        mock_loader.return_value = (mock_sync_config, mock_client, "azure", None, None, None)

        dummy_backend = DummyEncryptionBackend(has_encrypted_header=lambda _content: False)
        mock_resolve_backend.return_value = (
            dummy_backend,
            EncryptionProvider.DOTENVX,
            None,
        )

        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        (service_dir / ".env.production").write_text("ENC[AES256_GCM,data:abc]")

        result = runner.invoke(app, ["vault-push", "--all"])

        assert result.exit_code == 0
        output = " ".join(result.output.lower().split())
        assert "encrypted with sops" in output
        assert "config uses dotenvx" in output

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    @patch("envdrift.cli_commands.sync.load_sync_config_and_client")
    def test_push_all_encrypt_failure_counts_error(
        self,
        mock_loader,
        mock_resolve_backend,
        tmp_path,
    ):
        """vault-push --all should count errors when encryption returns failure."""
        mock_client = MagicMock()
        mock_sync_config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="failing-secret",
                    folder_path=tmp_path / "service1",
                    environment="production",
                )
            ]
        )
        mock_loader.return_value = (mock_sync_config, mock_client, "azure", None, None, None)

        dummy_backend = DummyEncryptionBackend()
        original_encrypt = dummy_backend.encrypt

        def fail_encrypt(env_file, **kwargs):
            result = original_encrypt(env_file, **kwargs)
            result.success = False
            result.message = "encrypt failed"
            return result

        dummy_backend.encrypt = fail_encrypt  # type: ignore[method-assign]
        mock_resolve_backend.return_value = (
            dummy_backend,
            EncryptionProvider.DOTENVX,
            None,
        )

        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        (service_dir / ".env.production").write_text("PLAIN=text")

        result = runner.invoke(app, ["vault-push", "--all"])

        assert result.exit_code == 0
        output = result.output.lower()
        assert "encrypt failed" in output
        assert "errors: 1" in output

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    @patch("envdrift.cli_commands.sync.load_sync_config_and_client")
    @patch("envdrift.sync.operations.EnvKeysFile")
    def test_push_all_detects_env_file_and_environment(
        self,
        mock_keys_file,
        mock_loader,
        mock_resolve_backend,
        tmp_path,
    ):
        """vault-push --all should auto-detect env files and update environment."""
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

        dummy_backend = DummyEncryptionBackend()
        mock_resolve_backend.return_value = (
            dummy_backend,
            EncryptionProvider.DOTENVX,
            None,
        )

        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        env_file = service_dir / ".env.staging"
        env_file.write_text("PLAIN=text")
        (service_dir / ".env.keys").write_text("DOTENV_PRIVATE_KEY_STAGING=secret123")

        mock_keys_instance = MagicMock()
        mock_keys_instance.read_key.return_value = "secret123"
        mock_keys_file.return_value = mock_keys_instance

        mock_client.get_secret.side_effect = SecretNotFoundError("missing")

        result = runner.invoke(app, ["vault-push", "--all"])

        assert result.exit_code == 0
        assert dummy_backend.encrypt_calls == [env_file]
        mock_keys_instance.read_key.assert_called_with("DOTENV_PRIVATE_KEY_STAGING")
        mock_client.set_secret.assert_called_with(
            "my-secret", "DOTENV_PRIVATE_KEY_STAGING=secret123"
        )

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    @patch("envdrift.cli_commands.sync.load_sync_config_and_client")
    def test_push_all_error_handling(
        self,
        mock_loader,
        mock_resolve_backend,
        tmp_path,
    ):
        """Test various error conditions in push loop to ensure coverage."""
        mock_client = MagicMock()
        dummy_backend = DummyEncryptionBackend(
            encrypt_side_effect=EncryptionBackendError("encrypt failed")
        )
        mock_resolve_backend.return_value = (
            dummy_backend,
            EncryptionProvider.DOTENVX,
            None,
        )

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
        # Setup s3: Encrypted .env, Vault check raises VaultError
        (tmp_path / "s3" / ".env.prod").write_text("SECRET=encrypted:abc123")

        # Setup s4: Encrypted .env, Secret missing in vault, Missing .env.keys
        (tmp_path / "s4" / ".env.prod").write_text("SECRET=encrypted:abc123")

        # Setup s5: Encrypted .env, Secret missing, .env.keys exists but missing key
        (tmp_path / "s5" / ".env.prod").write_text("SECRET=encrypted:abc123")
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

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    @patch("envdrift.cli_commands.sync.load_sync_config_and_client")
    def test_push_all_backend_not_installed(
        self,
        mock_loader,
        mock_resolve_backend,
        tmp_path,
    ):
        """vault-push --all should exit when backend is missing."""
        mock_client = MagicMock()
        mock_sync_config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="missing-backend",
                    folder_path=tmp_path / "service1",
                    environment="production",
                )
            ]
        )
        mock_loader.return_value = (mock_sync_config, mock_client, "azure", None, None, None)
        mock_resolve_backend.return_value = (
            DummyEncryptionBackend(installed=False),
            EncryptionProvider.DOTENVX,
            None,
        )

        result = runner.invoke(app, ["vault-push", "--all"])

        assert result.exit_code == 1
        assert "not installed" in result.output.lower()

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    @patch("envdrift.cli_commands.sync.load_sync_config_and_client")
    def test_push_all_dotenvx_mismatch_errors(
        self,
        mock_loader,
        mock_resolve_backend,
        tmp_path,
    ):
        """vault-push --all should error when dotenvx files exist under sops config."""
        mock_client = MagicMock()
        mock_sync_config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="mismatch-secret",
                    folder_path=tmp_path / "service1",
                    environment="production",
                )
            ]
        )
        mock_loader.return_value = (mock_sync_config, mock_client, "azure", None, None, None)

        def sops_only_header(content: str) -> bool:
            return "ENC[AES256_GCM," in content or "sops:" in content

        mock_resolve_backend.return_value = (
            DummyEncryptionBackend(name="sops", has_encrypted_header=sops_only_header),
            EncryptionProvider.SOPS,
            None,
        )

        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        env_file = service_dir / ".env.production"
        env_file.write_text(
            "#/---BEGIN DOTENV ENCRYPTED---/\nDOTENV_PUBLIC_KEY=abc\nSECRET=encrypted:abc123\n"
        )

        result = runner.invoke(app, ["vault-push", "--all"])

        assert result.exit_code == 1
        output = " ".join(result.output.lower().split())
        assert "encrypted with dotenvx" in output

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    @patch("envdrift.cli_commands.sync.load_sync_config_and_client")
    @patch("envdrift.sync.operations.EnvKeysFile")
    def test_push_all_sops_encrypt_kwargs(
        self,
        mock_keys_file,
        mock_loader,
        mock_resolve_backend,
        tmp_path,
    ):
        """vault-push --all should pass SOPS encryption kwargs."""
        from envdrift.config import EncryptionConfig

        mock_client = MagicMock()
        mock_sync_config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="sops-secret",
                    folder_path=tmp_path / "service1",
                    environment="production",
                )
            ]
        )
        mock_loader.return_value = (mock_sync_config, mock_client, "azure", None, None, None)

        encryption_config = EncryptionConfig(
            backend="sops",
            sops_age_recipients="age1abc",
            sops_kms_arn="arn:aws:kms:us-east-1:123:key/abc",
            sops_gcp_kms="projects/p/locations/l/keyRings/r/cryptoKeys/k",
            sops_azure_kv="https://vault.vault.azure.net/keys/key/1",
        )

        def sops_only_header(content: str) -> bool:
            return "ENC[AES256_GCM," in content or "sops:" in content

        dummy_backend = DummyEncryptionBackend(name="sops", has_encrypted_header=sops_only_header)
        mock_resolve_backend.return_value = (
            dummy_backend,
            EncryptionProvider.SOPS,
            encryption_config,
        )

        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        env_file = service_dir / ".env.production"
        env_file.write_text("PLAIN=text")

        (service_dir / ".env.keys").touch()
        mock_keys_instance = MagicMock()
        mock_keys_instance.read_key.return_value = "secret123"
        mock_keys_file.return_value = mock_keys_instance
        mock_client.get_secret.side_effect = SecretNotFoundError("missing")

        result = runner.invoke(app, ["vault-push", "--all"])

        assert result.exit_code == 0
        assert dummy_backend.encrypt_calls == [env_file]
        assert dummy_backend.encrypt_kwargs == [
            {
                "age_recipients": "age1abc",
                "kms_arn": "arn:aws:kms:us-east-1:123:key/abc",
                "gcp_kms": "projects/p/locations/l/keyRings/r/cryptoKeys/k",
                "azure_kv": "https://vault.vault.azure.net/keys/key/1",
            }
        ]

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    @patch("envdrift.cli_commands.sync.load_sync_config_and_client")
    @patch("envdrift.sync.operations.EnvKeysFile")
    def test_push_all_skip_encrypt_skips_encryption(
        self,
        mock_keys_file,
        mock_loader,
        mock_resolve_backend,
        tmp_path,
    ):
        """Test --skip-encrypt skips encryption step."""
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

        dummy_backend = DummyEncryptionBackend()
        mock_resolve_backend.return_value = (
            dummy_backend,
            EncryptionProvider.DOTENVX,
            None,
        )

        # Create service dir with only .env.keys (no .env file)
        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        keys_file = service_dir / ".env.keys"
        keys_file.write_text("DOTENV_PRIVATE_KEY_PRODUCTION=secret123")

        mock_keys_instance = MagicMock()
        mock_keys_instance.read_key.return_value = "secret123"
        mock_keys_file.return_value = mock_keys_instance

        mock_client.get_secret.side_effect = SecretNotFoundError("missing")

        result = runner.invoke(app, ["vault-push", "--all", "--skip-encrypt"])

        assert result.exit_code == 0
        assert "Pushed my-secret" in result.output
        assert "skipped (--skip-encrypt)" in result.output.lower()
        # Verify encryption was NOT called
        assert dummy_backend.encrypt_calls == []
        mock_client.set_secret.assert_called_with(
            "my-secret", "DOTENV_PRIVATE_KEY_PRODUCTION=secret123"
        )

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    @patch("envdrift.cli_commands.sync.load_sync_config_and_client")
    @patch("envdrift.sync.operations.EnvKeysFile")
    def test_push_all_skip_encrypt_no_env_file_still_works(
        self,
        mock_keys_file,
        mock_loader,
        mock_resolve_backend,
        tmp_path,
    ):
        """Test --skip-encrypt allows pushing keys even without .env file."""
        mock_client = MagicMock()
        mock_sync_config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="my-secret",
                    folder_path=tmp_path / "service1",
                    environment="staging",
                )
            ]
        )
        mock_loader.return_value = (mock_sync_config, mock_client, "azure", None, None, None)

        dummy_backend = DummyEncryptionBackend()
        mock_resolve_backend.return_value = (
            dummy_backend,
            EncryptionProvider.DOTENVX,
            None,
        )

        # Create service dir with only .env.keys - NO .env file at all
        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        keys_file = service_dir / ".env.keys"
        keys_file.write_text("DOTENV_PRIVATE_KEY_STAGING=stagingkey")

        mock_keys_instance = MagicMock()
        mock_keys_instance.read_key.return_value = "stagingkey"
        mock_keys_file.return_value = mock_keys_instance

        mock_client.get_secret.side_effect = SecretNotFoundError("missing")

        result = runner.invoke(app, ["vault-push", "--all", "--skip-encrypt"])

        assert result.exit_code == 0
        assert "Pushed my-secret" in result.output
        # Without --skip-encrypt, this would have been skipped due to missing .env file
        mock_client.set_secret.assert_called_with(
            "my-secret", "DOTENV_PRIVATE_KEY_STAGING=stagingkey"
        )

    def test_skip_encrypt_without_all_warns(self, tmp_path):
        """Test --skip-encrypt without --all shows warning."""
        result = runner.invoke(
            app,
            [
                "vault-push",
                "--skip-encrypt",
                str(tmp_path),
                "secret-name",
                "--env",
                "prod",
                "-p",
                "azure",
                "--vault-url",
                "https://vault.vault.azure.net",
            ],
        )

        # Should show warning about --skip-encrypt only being for --all mode
        assert "--skip-encrypt is only applicable with --all mode" in result.output
