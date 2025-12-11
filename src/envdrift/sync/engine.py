"""Core sync orchestration engine."""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from envdrift.sync.config import ServiceMapping, SyncConfig
from envdrift.sync.operations import EnvKeysFile, ensure_directory, preview_value
from envdrift.sync.result import (
    DecryptionTestResult,
    ServiceSyncResult,
    SyncAction,
    SyncResult,
)
from envdrift.vault.base import SecretNotFoundError, VaultError

if TYPE_CHECKING:
    from envdrift.vault import VaultClient


@dataclass
class SyncMode:
    """Sync operation mode."""

    verify_only: bool = False
    force_update: bool = False
    check_decryption: bool = False
    validate_schema: bool = False
    schema_path: str | None = None
    service_dir: Path | None = None


@dataclass
class SyncEngine:
    """Orchestrates vault-to-local key synchronization."""

    config: SyncConfig
    vault_client: VaultClient
    mode: SyncMode = field(default_factory=SyncMode)
    prompt_callback: Callable[[str], bool] | None = None
    progress_callback: Callable[[str], None] | None = None

    def __post_init__(self) -> None:
        """Set default callbacks if not provided."""
        if self.prompt_callback is None:
            self.prompt_callback = self._default_prompt
        if self.progress_callback is None:
            self.progress_callback = lambda _: None

    def sync_all(self) -> SyncResult:
        """Sync all services defined in config."""
        result = SyncResult()

        self.vault_client.ensure_authenticated()

        for mapping in self.config.mappings:
            self._progress(f"Processing: {mapping.folder_path}")
            service_result = self._sync_service(mapping)
            result.services.append(service_result)

            # Decryption test if enabled and sync succeeded
            if self.mode.check_decryption and service_result.action != SyncAction.ERROR:
                self._progress(f"Testing decryption: {mapping.folder_path}")
                service_result.decryption_result = self._test_decryption(mapping)

            # Schema validation if enabled
            if self.mode.validate_schema and service_result.action != SyncAction.ERROR:
                self._progress(f"Validating schema: {mapping.folder_path}")
                service_result.schema_valid = self._validate_schema(mapping)

        return result

    def _sync_service(self, mapping: ServiceMapping) -> ServiceSyncResult:
        """Sync a single service."""
        try:
            # Fetch secret from vault
            vault_value = self._fetch_vault_secret(mapping)
            vault_preview = preview_value(vault_value)

            # Ensure folder exists
            if not mapping.folder_path.exists():
                if self.mode.verify_only:
                    return ServiceSyncResult(
                        secret_name=mapping.secret_name,
                        folder_path=mapping.folder_path,
                        action=SyncAction.ERROR,
                        message="Folder does not exist",
                        error=f"Folder does not exist: {mapping.folder_path}",
                    )
                ensure_directory(mapping.folder_path)

            # Read local file
            env_keys_path = mapping.folder_path / self.config.env_keys_filename
            env_keys_file = EnvKeysFile(env_keys_path)
            local_value = env_keys_file.read_key(mapping.env_key_name)
            local_preview = preview_value(local_value) if local_value else None

            # Compare values
            if local_value is None:
                # Key doesn't exist - create
                if self.mode.verify_only:
                    return ServiceSyncResult(
                        secret_name=mapping.secret_name,
                        folder_path=mapping.folder_path,
                        action=SyncAction.ERROR,
                        message="Key file does not exist",
                        vault_value_preview=vault_preview,
                    )

                env_keys_file.write_key(mapping.env_key_name, vault_value, mapping.environment)
                return ServiceSyncResult(
                    secret_name=mapping.secret_name,
                    folder_path=mapping.folder_path,
                    action=SyncAction.CREATED,
                    message="Created new .env.keys file",
                    vault_value_preview=vault_preview,
                )

            elif local_value == vault_value:
                # Values match - skip
                return ServiceSyncResult(
                    secret_name=mapping.secret_name,
                    folder_path=mapping.folder_path,
                    action=SyncAction.SKIPPED,
                    message="Values match - no update needed",
                    vault_value_preview=vault_preview,
                    local_value_preview=local_preview,
                )

            else:
                # Mismatch - update
                if self.mode.verify_only:
                    return ServiceSyncResult(
                        secret_name=mapping.secret_name,
                        folder_path=mapping.folder_path,
                        action=SyncAction.ERROR,
                        message="Value mismatch detected",
                        vault_value_preview=vault_preview,
                        local_value_preview=local_preview,
                        error="Local value differs from vault",
                    )

                # Check if we should update
                should_update = self.mode.force_update
                if not should_update and self.prompt_callback:
                    prompt_msg = (
                        f"Value mismatch for {mapping.secret_name}:\n"
                        f"  Local:  {local_preview}\n"
                        f"  Vault:  {vault_preview}\n"
                        "Update local file with vault value?"
                    )
                    should_update = self.prompt_callback(prompt_msg)

                if should_update:
                    # Create backup before updating
                    backup_path = env_keys_file.create_backup()
                    env_keys_file.write_key(mapping.env_key_name, vault_value, mapping.environment)
                    return ServiceSyncResult(
                        secret_name=mapping.secret_name,
                        folder_path=mapping.folder_path,
                        action=SyncAction.UPDATED,
                        message="Updated with vault value",
                        vault_value_preview=vault_preview,
                        local_value_preview=local_preview,
                        backup_path=backup_path,
                    )
                else:
                    return ServiceSyncResult(
                        secret_name=mapping.secret_name,
                        folder_path=mapping.folder_path,
                        action=SyncAction.SKIPPED,
                        message="Update skipped by user",
                        vault_value_preview=vault_preview,
                        local_value_preview=local_preview,
                    )

        except SecretNotFoundError as e:
            return ServiceSyncResult(
                secret_name=mapping.secret_name,
                folder_path=mapping.folder_path,
                action=SyncAction.ERROR,
                message="Secret not found in vault",
                error=str(e),
            )
        except VaultError as e:
            return ServiceSyncResult(
                secret_name=mapping.secret_name,
                folder_path=mapping.folder_path,
                action=SyncAction.ERROR,
                message="Vault error",
                error=str(e),
            )
        except Exception as e:
            return ServiceSyncResult(
                secret_name=mapping.secret_name,
                folder_path=mapping.folder_path,
                action=SyncAction.ERROR,
                message="Unexpected error",
                error=str(e),
            )

    def _fetch_vault_secret(self, mapping: ServiceMapping) -> str:
        """Fetch secret from vault."""
        secret = self.vault_client.get_secret(mapping.secret_name)
        value = secret.value

        # Handle case where vault stores full line (KEY=value)
        if value.startswith(f"{mapping.env_key_name}="):
            value = value[len(f"{mapping.env_key_name}=") :]

        return value

    def _test_decryption(self, mapping: ServiceMapping) -> DecryptionTestResult:
        """Test that the synced key can decrypt .env files."""
        # Find .env file to test (prefer .env.production)
        env_files = [
            mapping.folder_path / f".env.{mapping.environment}",
            mapping.folder_path / ".env.production",
            mapping.folder_path / ".env.staging",
            mapping.folder_path / ".env.development",
        ]

        target_file = next((f for f in env_files if f.exists()), None)
        if not target_file:
            return DecryptionTestResult.SKIPPED

        # Check if file is encrypted (contains dotenvx markers)
        content = target_file.read_text()
        if "encrypted:" not in content.lower():
            return DecryptionTestResult.SKIPPED

        dotenvx_path = shutil.which("dotenvx")
        if not dotenvx_path:
            return DecryptionTestResult.SKIPPED

        backup_path = target_file.with_suffix(".backup_decryption_test")

        try:
            shutil.copy2(target_file, backup_path)

            # Try to decrypt using dotenvx
            result = subprocess.run(
                [dotenvx_path, "decrypt", "-f", str(target_file)],
                cwd=str(mapping.folder_path),
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                # Restore from backup
                shutil.copy2(backup_path, target_file)
                return DecryptionTestResult.FAILED

            # Re-encrypt to not leave file decrypted
            encrypt_result = subprocess.run(
                [dotenvx_path, "encrypt", "-f", str(target_file)],
                cwd=str(mapping.folder_path),
                capture_output=True,
                text=True,
                timeout=30,
            )

            if encrypt_result.returncode != 0:
                shutil.copy2(backup_path, target_file)
                return DecryptionTestResult.FAILED

            return DecryptionTestResult.PASSED

        except FileNotFoundError:
            # dotenvx not installed
            return DecryptionTestResult.SKIPPED
        except subprocess.TimeoutExpired:
            shutil.copy2(backup_path, target_file)
            return DecryptionTestResult.FAILED
        except Exception:
            shutil.copy2(backup_path, target_file)
            return DecryptionTestResult.FAILED
        finally:
            # Clean up backup
            backup_path.unlink(missing_ok=True)

    def _validate_schema(self, mapping: ServiceMapping) -> bool:
        """Run schema validation for the service."""
        if not self.mode.schema_path:
            return True

        try:
            from envdrift.core.schema import SchemaLoader
            from envdrift.core.validator import EnvValidator

            # Find env file
            env_file = mapping.folder_path / f".env.{mapping.environment}"
            if not env_file.exists():
                env_file = mapping.folder_path / ".env"
            if not env_file.exists():
                return True  # No file to validate

            # Load schema
            service_dir = self.mode.service_dir or mapping.folder_path
            loader = SchemaLoader()
            settings_cls = loader.load(self.mode.schema_path, service_dir=service_dir)
            schema = loader.extract_metadata(settings_cls)

            # Validate
            validator = EnvValidator(schema)
            result = validator.validate(env_file)

            return result.valid

        except Exception:
            return False

    def _progress(self, message: str) -> None:
        """Report progress."""
        if self.progress_callback:
            self.progress_callback(message)

    @staticmethod
    def _default_prompt(message: str) -> bool:
        """Default interactive prompt."""
        response = input(f"{message} (y/N): ").strip().lower()
        return response in ("y", "yes")
