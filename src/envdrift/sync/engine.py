"""Core sync orchestration engine."""

from __future__ import annotations

import logging
import re
import shutil
import subprocess  # nosec B404
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from envdrift.env_files import detect_env_file, resolve_mapping_env_file
from envdrift.sync.config import ServiceMapping, SyncConfig
from envdrift.sync.operations import EnvKeysFile, ensure_directory, redact_value
from envdrift.sync.result import (
    DecryptionTestResult,
    ServiceSyncResult,
    SyncAction,
    SyncResult,
)
from envdrift.vault.base import SecretNotFoundError, VaultError

if TYPE_CHECKING:
    from envdrift.vault import VaultClient

logger = logging.getLogger(__name__)


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
            detection = resolve_mapping_env_file(mapping)
            if (
                detection.status != "found"
                or detection.path is None
                or detection.environment is None
            ):
                if detection.path is not None:
                    expected = detection.path
                elif mapping.env_file is not None:
                    expected = mapping.folder_path / mapping.env_file
                else:
                    expected = mapping.folder_path / f".env.{mapping.effective_environment}"
                return ServiceSyncResult(
                    secret_name=mapping.secret_name,
                    folder_path=mapping.folder_path,
                    action=SyncAction.SKIPPED,
                    message=f"No {expected.name} file found - skipping",
                )

            effective_environment = detection.environment

            # Use effective environment for key name
            effective_key_name = f"DOTENV_PRIVATE_KEY_{effective_environment.upper()}"

            # Fetch secret from vault
            vault_value = self._fetch_vault_secret(mapping, effective_environment)
            vault_preview = redact_value(vault_value)

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
            local_preview = redact_value(local_value) if local_value is not None else None

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

    def _fetch_vault_secret(self, mapping: ServiceMapping, effective_environment: str) -> str:
        """Fetch secret from vault.

        ``effective_environment`` is the environment the value will be installed
        as (derived from the detected ``.env.<env>`` file). When the vault value
        is a full ``DOTENV_PRIVATE_KEY_<SUFFIX>=...`` line we strip the prefix so
        it converges with the locally-stored value (#356) — but only after
        confirming ``<SUFFIX>`` matches the target environment. A mismatch means
        a key labeled for one environment would be silently relabeled and
        installed as another (e.g. staging key written as production), so we
        raise instead of stripping (#348).
        """
        secret = self.vault_client.get_secret(mapping.secret_name)
        value = secret.value

        # Normalize the same way read_key() (operations.py) does so a vault value
        # and the local file value converge instead of mismatching forever (#356).
        # Order matters: surrounding whitespace, THEN a single layer of surrounding
        # quotes, THEN any DOTENV_PRIVATE_KEY_*= prefix — quotes must come off
        # before the prefix so a quoted full `KEY=value` line
        # (e.g. `"DOTENV_PRIVATE_KEY_PROD=abc"`) still has its prefix stripped.
        value = value.strip()
        if len(value) >= 2 and (
            (value[0] == '"' and value[-1] == '"') or (value[0] == "'" and value[-1] == "'")
        ):
            value = value[1:-1]
        match = re.match(r"^DOTENV_PRIVATE_KEY_([A-Za-z0-9_]+)=(.+)$", value)
        if match:
            suffix = match.group(1)
            if suffix.upper() != effective_environment.upper():
                raise VaultError(
                    f"vault key labeled for environment {suffix.upper()} cannot be "
                    f"installed as environment {effective_environment.upper()} "
                    f"(secret {mapping.secret_name!r})"
                )
            value = match.group(2)

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

    @staticmethod
    def _safe_restore(backup_path: Path, target_file: Path) -> bool:
        """
        Restore ``target_file`` from ``backup_path`` without ever raising.

        The restore is only attempted when ``backup_path`` exists, and the copy
        itself is wrapped so that a restore failure (for example because the
        initial backup copy never completed, or the target is no longer
        writable) cannot escape and mask the original error. The caller is
        already on a failure path and will return DecryptionTestResult.FAILED
        regardless.

        Returns:
            ``True`` when the file is in a known-good state — the backup did not
            exist (nothing to restore) or the restore copy succeeded. ``False``
            when a restore was attempted but failed, meaning the target may be
            left modified and the backup must be preserved as the recovery copy.
        """
        if not backup_path.exists():
            return True
        try:
            shutil.copy2(backup_path, target_file)
        except Exception:
            return False
        return True

    def _test_decryption(self, mapping: ServiceMapping) -> DecryptionTestResult:
        """
        Attempt to verify that the synchronized key can decrypt an environment file for the service.

        The method locates an environment file for the mapping (preferring .env.<environment>, then .env.production, .env.staging, .env.development), checks whether the file appears encrypted, and uses the `dotenvx` utility to decrypt and then re-encrypt the file to confirm the key works. If decryption or re-encryption fails the file is restored to its original state (when a backup exists) before returning. Any unexpected error, including a failure to create the backup, results in DecryptionTestResult.FAILED rather than an escaping exception.

        Returns:
            DecryptionTestResult.PASSED if decryption and re-encryption both succeed.
            DecryptionTestResult.FAILED if decryption or re-encryption fails (the original file is restored when a backup exists).
            DecryptionTestResult.SKIPPED if no suitable env file exists, the file does not appear encrypted, or the `dotenvx` utility is not available.
        """
        detection = resolve_mapping_env_file(mapping)
        if detection.status != "found" or detection.path is None:
            return DecryptionTestResult.SKIPPED
        target_file = detection.path

        # Reading the env file can raise for a non-UTF-8 file
        # (UnicodeDecodeError) or an unreadable one (OSError). Neither must escape
        # as a traceback: a file we cannot even decode/open is not a key we can
        # verify, so treat it as a FAILED decryption test rather than crashing the
        # whole sync run (see #413).
        try:
            content = target_file.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return DecryptionTestResult.FAILED

        # Check if file is encrypted (contains dotenvx markers)
        if "encrypted:" not in content.lower():
            return DecryptionTestResult.SKIPPED

        dotenvx_path = shutil.which("dotenvx")
        if not dotenvx_path:
            return DecryptionTestResult.SKIPPED

        backup_path = target_file.with_suffix(".backup_decryption_test")

        # Create the backup up front and outside the main try block. If this
        # copy fails (permission/disk error, missing parent dir), there is no
        # backup to restore from, so the run is a failed decryption test rather
        # than a dotenvx-not-installed SKIP — and we must not fall through to a
        # restore that would raise a secondary FileNotFoundError (see #317).
        try:
            shutil.copy2(target_file, backup_path)
        except Exception:
            return DecryptionTestResult.FAILED

        result, backup_safe_to_delete = self._dotenvx_roundtrip(
            dotenvx_path, target_file, backup_path, mapping
        )

        # Only delete the backup when the file is in a known-good state. If a
        # restore was attempted and failed, KEEP the backup as the recovery copy
        # and warn the user that the file may be left decrypted.
        if backup_safe_to_delete:
            backup_path.unlink(missing_ok=True)
        else:
            logger.warning(
                "Failed to restore %s after a decryption-test failure; the file "
                "may be left decrypted. The backup has been preserved at %s — "
                "restore it manually to recover the original encrypted file.",
                target_file,
                backup_path,
            )

        return result

    def _dotenvx_roundtrip(
        self,
        dotenvx_path: str,
        target_file: Path,
        backup_path: Path,
        mapping: ServiceMapping,
    ) -> tuple[DecryptionTestResult, bool]:
        """
        Decrypt then re-encrypt ``target_file`` with dotenvx to verify the key.

        A backup already exists at ``backup_path``; this helper never deletes it.

        Returns:
            ``(result, backup_safe_to_delete)``. ``backup_safe_to_delete`` is
            ``False`` only when the on-disk file was decrypted and a subsequent
            restore failed — the backup is then the only encrypted copy and the
            caller must preserve it (see cubic P1 on #317).
        """
        # Tracks whether the live target file has been rewritten to plaintext on
        # disk by `dotenvx decrypt`. Once True, any subsequent failure (a missing
        # dotenvx binary at the encrypt stage, a timeout, a vanished cwd, …) must
        # NOT be treated as "dotenvx not installed / file untouched": the file is
        # decrypted and we must restore + preserve the backup, never delete it.
        file_modified = False

        try:
            # Wrap ONLY the first `decrypt` subprocess so a FileNotFoundError
            # here (dotenvx genuinely missing) maps to SKIPPED with the file
            # untouched. A FileNotFoundError raised later (the encrypt stage,
            # after the file is already plaintext) flows through the outer
            # failure/restore handlers below instead, so the backup is never
            # deleted while the file is left decrypted.
            try:
                result = subprocess.run(  # nosec B603
                    [dotenvx_path, "decrypt", "-f", str(target_file)],
                    cwd=str(mapping.folder_path),
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
            except FileNotFoundError:
                # dotenvx not installed; the decrypt never ran and the file was
                # never modified, so the backup is safe to delete.
                return DecryptionTestResult.SKIPPED, True

            if result.returncode != 0:
                # Decrypt failed: dotenvx may or may not have modified the file,
                # so restore from backup to be conservative.
                safe = self._safe_restore(backup_path, target_file)
                return DecryptionTestResult.FAILED, safe

            # Decrypt returned 0: the live file is now plaintext on disk. From
            # this point on the backup is the ONLY encrypted copy, so no failure
            # path may delete it without first restoring/re-encrypting the file.
            file_modified = True

            # Re-encrypt to not leave file decrypted
            encrypt_result = subprocess.run(  # nosec B603
                [dotenvx_path, "encrypt", "-f", str(target_file)],
                cwd=str(mapping.folder_path),
                capture_output=True,
                text=True,
                timeout=30,
            )

            if encrypt_result.returncode != 0:
                safe = self._safe_restore(backup_path, target_file)
                return DecryptionTestResult.FAILED, safe

            # Happy path: the file is correctly re-encrypted, backup is disposable.
            return DecryptionTestResult.PASSED, True

        except FileNotFoundError:
            # dotenvx vanished mid-run (e.g. at the encrypt stage). If the file
            # was never decrypted, it is untouched and this is a SKIP. Once
            # `file_modified` is True the file is already plaintext on disk, so
            # this is a real FAILURE, not a SKIP: restore from backup and
            # preserve it if the restore fails so the plaintext file can be
            # recovered (never delete the only encrypted copy).
            if not file_modified:
                return DecryptionTestResult.SKIPPED, True
            safe = self._safe_restore(backup_path, target_file)
            return DecryptionTestResult.FAILED, safe
        except subprocess.TimeoutExpired:
            safe = self._safe_restore(backup_path, target_file)
            return DecryptionTestResult.FAILED, safe
        except Exception:
            # Any other failure is a failed decryption test; restore only when a
            # backup actually exists so the restore cannot itself raise.
            safe = self._safe_restore(backup_path, target_file)
            return DecryptionTestResult.FAILED, safe

    def _validate_schema(self, mapping: ServiceMapping) -> bool:
        """Run schema validation for the service."""
        if not self.mode.schema_path:
            return True

        try:
            from envdrift.core.parser import EnvParser
            from envdrift.core.schema import SchemaLoader
            from envdrift.core.validator import Validator

            detection = resolve_mapping_env_file(mapping)
            if detection.status != "found" or detection.path is None:
                return True  # No file to validate
            env_file_path = detection.path

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
