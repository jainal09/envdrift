"""Core sync orchestration engine."""

from __future__ import annotations

import re
import shutil
import subprocess  # nosec B404
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from envdrift.env_files import detect_env_file
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

            # Decryption test if enabled and sync succeeded (skip for ephemeral mode)
            if (
                self.mode.check_decryption
                and service_result.action != SyncAction.ERROR
                and service_result.action != SyncAction.EPHEMERAL
            ):
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
            # Check if corresponding .env.<environment> file exists
            env_file = mapping.folder_path / f".env.{mapping.effective_environment}"
            effective_environment = mapping.effective_environment

            if not env_file.exists():
                # Try to auto-detect: find any .env.* file or plain .env in the folder
                detected = self._detect_env_file(mapping.folder_path)
                if detected:
                    env_file, effective_environment = detected
                else:
                    return ServiceSyncResult(
                        secret_name=mapping.secret_name,
                        folder_path=mapping.folder_path,
                        action=SyncAction.SKIPPED,
                        message=f"No .env.{mapping.effective_environment} file found - skipping",
                    )

            # Use effective environment for key name
            effective_key_name = f"DOTENV_PRIVATE_KEY_{effective_environment.upper()}"

            # Fetch secret from vault
            vault_value = self._fetch_vault_secret(mapping)
            vault_preview = preview_value(vault_value)

            # Check for ephemeral mode - skip local file operations
            is_ephemeral = self.config.get_effective_ephemeral(mapping)
            if is_ephemeral:
                # In ephemeral mode, we don't store keys locally
                # Just return the key for downstream use
                return ServiceSyncResult(
                    secret_name=mapping.secret_name,
                    folder_path=mapping.folder_path,
                    action=SyncAction.EPHEMERAL,
                    message="Ephemeral mode: key fetched from vault (not stored locally)",
                    vault_value_preview=vault_preview,
                    vault_key_value=vault_value,  # Pass actual key for downstream use
                )

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
            local_value = env_keys_file.read_key(effective_key_name)
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

                env_keys_file.write_key(effective_key_name, vault_value, effective_environment)
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
                    env_keys_file.write_key(effective_key_name, vault_value, effective_environment)
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
        # Strip any DOTENV_PRIVATE_KEY_*= prefix, not just the current environment's
        # Support uppercase, lowercase, digits in environment names (e.g., soak, local, prod)
        pattern = r"^DOTENV_PRIVATE_KEY_[A-Za-z0-9_]+=(.+)$"
        match = re.match(pattern, value)
        if match:
            value = match.group(1)

        return value

    def _detect_env_file(self, folder_path: Path) -> tuple[Path, str] | None:
        """
        Auto-detect .env file in a folder.

        Checks for:
        1. Plain .env file (returns default environment)
        2. Single .env.* file (returns environment from suffix)

        Returns (env_file_path, environment_name) or None.
        """
        detection = detect_env_file(folder_path)
        if (
            detection.status == "found"
            and detection.path is not None
            and detection.environment is not None
        ):
            return (detection.path, detection.environment)

        return None

    def _test_decryption(self, mapping: ServiceMapping) -> DecryptionTestResult:
        """
        Attempt to verify that the synchronized key can decrypt an environment file for the service.

        The method locates an environment file for the mapping (preferring .env.<environment>, then .env.production, .env.staging, .env.development), checks whether the file appears encrypted, and uses the `dotenvx` utility to decrypt and then re-encrypt the file to confirm the key works. If decryption or re-encryption fails the file is restored to its original state before returning.

        Returns:
            DecryptionTestResult.PASSED if decryption and re-encryption both succeed.
            DecryptionTestResult.FAILED if decryption or re-encryption fails (the original file is restored).
            DecryptionTestResult.SKIPPED if no suitable env file exists, the file does not appear encrypted, or the `dotenvx` utility is not available.
        """
        # Find .env file to test (prefer .env.<effective_environment>)
        env_files = [
            mapping.folder_path / f".env.{mapping.effective_environment}",
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
            result = subprocess.run(  # nosec B603
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
            encrypt_result = subprocess.run(  # nosec B603
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
            from envdrift.core.parser import EnvParser
            from envdrift.core.schema import SchemaLoader
            from envdrift.core.validator import Validator

            # Find env file (mirror _sync_service's detection behavior)
            env_file_path = mapping.folder_path / f".env.{mapping.effective_environment}"
            if not env_file_path.exists():
                detected = self._detect_env_file(mapping.folder_path)
                if detected:
                    env_file_path, _effective_environment = detected
                else:
                    return True  # No file to validate

            # Load schema
            service_dir = self.mode.service_dir or mapping.folder_path
            loader = SchemaLoader()
            settings_cls = loader.load(self.mode.schema_path, service_dir=service_dir)
            schema = loader.extract_metadata(settings_cls)

            # Parse env file and validate
            parser = EnvParser()
            env_file = parser.parse(env_file_path)
            validator = Validator()
            result = validator.validate(env_file, schema)

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
