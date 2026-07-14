"""Core sync orchestration engine."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess  # nosec B404
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple

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

# Re-exported: the canonical vault key-material parser lives in
# envdrift.vault.keymaterial (#480) but historical importers (tests, sync CLI)
# reach it through this module.
from envdrift.vault.keymaterial import (
    extract_key_material,
)
from envdrift.vault.keymaterial import (
    normalize_vault_key_value as normalize_vault_key_value,
)

if TYPE_CHECKING:
    from envdrift.env_files import EnvFileDetection
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
    # Sync-capable workflows can promise verification without becoming read-only.
    verify_skipped_secrets: bool = False


class _ServiceSyncContext(NamedTuple):
    """Per-service fetch-resolved values shared by the ``_sync_service`` phase helpers."""

    mapping: ServiceMapping
    effective_key_name: str
    effective_environment: str
    vault_value: str
    vault_preview: str | None


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
            # Name the mapping, not just the folder: two mappings can share a
            # folder_path (per-environment secrets for one service), and bare
            # "Processing: <folder>" lines are indistinguishable (#441).
            self._progress(
                f"Processing: {mapping.folder_path} "
                f"({mapping.secret_name}, env: {mapping.effective_environment})"
            )
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
            resolved = self._resolve_sync_env_file(mapping)
            if isinstance(resolved, ServiceSyncResult):
                return resolved
            effective_environment = resolved

            # Use effective environment for key name
            effective_key_name = f"DOTENV_PRIVATE_KEY_{effective_environment.upper()}"

            # Fetch secret from vault
            vault_value = self._fetch_vault_secret(mapping, effective_environment)
            vault_preview = redact_value(vault_value)
            ctx = _ServiceSyncContext(
                mapping=mapping,
                effective_key_name=effective_key_name,
                effective_environment=effective_environment,
                vault_value=vault_value,
                vault_preview=vault_preview,
            )

            # Check for ephemeral mode - skip local file operations
            is_ephemeral = self.config.get_effective_ephemeral(mapping)
            if is_ephemeral:
                return self._ephemeral_result(ctx)

            # Ensure folder exists
            folder_error = self._ensure_service_folder(mapping)
            if folder_error is not None:
                return folder_error

            return self._sync_local_key(ctx)

        except SecretNotFoundError as e:
            return ServiceSyncResult(
                secret_name=mapping.secret_name,
                folder_path=mapping.folder_path,
                environment=mapping.effective_environment,
                action=SyncAction.ERROR,
                message="Secret not found in vault",
                error=str(e),
            )
        except VaultError as e:
            return ServiceSyncResult(
                secret_name=mapping.secret_name,
                folder_path=mapping.folder_path,
                environment=mapping.effective_environment,
                action=SyncAction.ERROR,
                message="Vault error",
                error=str(e),
            )
        except Exception as e:
            return ServiceSyncResult(
                secret_name=mapping.secret_name,
                folder_path=mapping.folder_path,
                environment=mapping.effective_environment,
                action=SyncAction.ERROR,
                message="Unexpected error",
                error=str(e),
            )

    def _resolve_sync_env_file(self, mapping: ServiceMapping) -> ServiceSyncResult | str:
        """Resolve the mapping's env file to the effective environment name.

        Returns the detected environment on success, or a terminal
        ``ServiceSyncResult`` (broken-config ERROR / benign skip) when the
        mapping has no usable env file.
        """
        detection = resolve_mapping_env_file(mapping)
        if detection.status == "folder_not_found":
            # A mapping whose folder does not exist is a broken config (a
            # typo'd folder_path), not a benign "env file not created yet"
            # skip. Reporting it as SKIPPED let `sync --ci` / `pull` exit 0
            # ("All services synced successfully") while doing nothing (#488).
            return ServiceSyncResult(
                secret_name=mapping.secret_name,
                folder_path=mapping.folder_path,
                environment=mapping.effective_environment,
                action=SyncAction.ERROR,
                message="Mapping folder does not exist or is not a directory",
                error=(
                    f"Mapping folder does not exist or is not a directory: "
                    f"{mapping.folder_path} (check folder_path in your sync config)"
                ),
            )
        if detection.status != "found" or detection.path is None or detection.environment is None:
            return self._env_file_not_found_result(mapping, detection)
        return detection.environment

    def _env_file_not_found_result(
        self, mapping: ServiceMapping, detection: EnvFileDetection
    ) -> ServiceSyncResult:
        """Build the skip result for a mapping whose env file was not resolved.

        Verify-labeled modes probe the vault secret first; the probe raises
        (``SecretNotFoundError``/``VaultError``) for a missing or unusable
        secret, which ``_sync_service`` turns into an ERROR row.
        """
        # ``lock --sync-keys`` still creates/updates local keys, but its
        # verification-labeled phase must validate mappings it skips.
        if self.mode.verify_only or self.mode.verify_skipped_secrets:
            self._verify_secret_usable(mapping)
        if detection.status == "multiple_found":
            # Distinct, truthful skip reason: the folder has several
            # candidate env files and the mapping is ambiguous (#488).
            return ServiceSyncResult(
                secret_name=mapping.secret_name,
                folder_path=mapping.folder_path,
                environment=mapping.effective_environment,
                action=SyncAction.SKIPPED,
                message=(
                    "Multiple env files found - skipping "
                    "(set environment or env_file in the mapping)"
                ),
            )
        if detection.path is not None:
            expected = detection.path
        elif mapping.env_file is not None:
            expected = mapping.folder_path / mapping.env_file
        else:
            expected = mapping.folder_path / f".env.{mapping.effective_environment}"
        return ServiceSyncResult(
            secret_name=mapping.secret_name,
            folder_path=mapping.folder_path,
            environment=mapping.effective_environment,
            action=SyncAction.SKIPPED,
            message=f"No {expected.name} file found - skipping",
        )

    def _ephemeral_result(self, ctx: _ServiceSyncContext) -> ServiceSyncResult:
        """Build the ephemeral-mode result carrying the fetched key."""
        # In ephemeral mode, we don't store keys locally
        # Just return the key for downstream use
        return ServiceSyncResult(
            secret_name=ctx.mapping.secret_name,
            folder_path=ctx.mapping.folder_path,
            environment=ctx.mapping.effective_environment,
            action=SyncAction.EPHEMERAL,
            message="Ephemeral mode: key fetched from vault (not stored locally)",
            vault_value_preview=ctx.vault_preview,
            vault_key_value=ctx.vault_value,  # Pass actual key for downstream use
        )

    def _ensure_service_folder(self, mapping: ServiceMapping) -> ServiceSyncResult | None:
        """Ensure the mapping folder exists, creating it outside verify mode.

        Returns an ERROR result in verify mode (which must not create
        anything); ``None`` once the folder exists.
        """
        if not mapping.folder_path.exists():
            if self.mode.verify_only:
                return ServiceSyncResult(
                    secret_name=mapping.secret_name,
                    folder_path=mapping.folder_path,
                    environment=mapping.effective_environment,
                    action=SyncAction.ERROR,
                    message="Folder does not exist",
                    error=f"Folder does not exist: {mapping.folder_path}",
                )
            ensure_directory(mapping.folder_path)
        return None

    def _sync_local_key(self, ctx: _ServiceSyncContext) -> ServiceSyncResult:
        """Compare the local key against the vault value and apply the outcome."""
        # Read local file
        env_keys_path = ctx.mapping.folder_path / self.config.env_keys_filename
        env_keys_file = EnvKeysFile(env_keys_path)
        local_value = env_keys_file.read_key(ctx.effective_key_name)
        local_preview = redact_value(local_value) if local_value is not None else None

        # Compare values
        if local_value is None:
            # Key doesn't exist - create
            return self._create_missing_key(ctx, env_keys_file, env_keys_path)
        elif local_value == ctx.vault_value:
            # Values match - skip
            return ServiceSyncResult(
                secret_name=ctx.mapping.secret_name,
                folder_path=ctx.mapping.folder_path,
                environment=ctx.mapping.effective_environment,
                action=SyncAction.SKIPPED,
                message="Values match - no update needed",
                vault_value_preview=ctx.vault_preview,
                local_value_preview=local_preview,
            )
        else:
            # Mismatch - update
            return self._update_mismatched_key(ctx, env_keys_file, local_preview)

    def _create_missing_key(
        self, ctx: _ServiceSyncContext, env_keys_file: EnvKeysFile, env_keys_path: Path
    ) -> ServiceSyncResult:
        """Write the missing local key, or report why verify-only cannot."""
        if self.mode.verify_only:
            # Populate ``error`` with a diagnosable reason (#487): the
            # renderer prints ``error``, and a file that exists but
            # lacks the key is a different problem than a missing file.
            if env_keys_file.exists():
                reason = f"{ctx.effective_key_name} missing from {env_keys_path}"
            else:
                reason = f"Key file does not exist: {env_keys_path}"
            return ServiceSyncResult(
                secret_name=ctx.mapping.secret_name,
                folder_path=ctx.mapping.folder_path,
                environment=ctx.mapping.effective_environment,
                action=SyncAction.ERROR,
                message=reason,
                vault_value_preview=ctx.vault_preview,
                error=reason,
            )

        env_keys_file.write_key(ctx.effective_key_name, ctx.vault_value, ctx.effective_environment)
        return ServiceSyncResult(
            secret_name=ctx.mapping.secret_name,
            folder_path=ctx.mapping.folder_path,
            environment=ctx.mapping.effective_environment,
            action=SyncAction.CREATED,
            message="Created new .env.keys file",
            vault_value_preview=ctx.vault_preview,
        )

    def _update_mismatched_key(
        self, ctx: _ServiceSyncContext, env_keys_file: EnvKeysFile, local_preview: str | None
    ) -> ServiceSyncResult:
        """Update a mismatched local key (verify errors; prompt unless forced)."""
        if self.mode.verify_only:
            return ServiceSyncResult(
                secret_name=ctx.mapping.secret_name,
                folder_path=ctx.mapping.folder_path,
                environment=ctx.mapping.effective_environment,
                action=SyncAction.ERROR,
                message="Value mismatch detected",
                vault_value_preview=ctx.vault_preview,
                local_value_preview=local_preview,
                error="Local value differs from vault",
            )

        # Check if we should update
        should_update = self.mode.force_update
        if not should_update and self.prompt_callback:
            prompt_msg = (
                f"Value mismatch for {ctx.mapping.secret_name}:\n"
                f"  Local:  {local_preview}\n"
                f"  Vault:  {ctx.vault_preview}\n"
                "Update local file with vault value?"
            )
            should_update = self.prompt_callback(prompt_msg)

        if should_update:
            # Create backup before updating
            backup_path = env_keys_file.create_backup()
            env_keys_file.write_key(
                ctx.effective_key_name, ctx.vault_value, ctx.effective_environment
            )
            return ServiceSyncResult(
                secret_name=ctx.mapping.secret_name,
                folder_path=ctx.mapping.folder_path,
                environment=ctx.mapping.effective_environment,
                action=SyncAction.UPDATED,
                message="Updated with vault value",
                vault_value_preview=ctx.vault_preview,
                local_value_preview=local_preview,
                backup_path=backup_path,
            )
        else:
            return ServiceSyncResult(
                secret_name=ctx.mapping.secret_name,
                folder_path=ctx.mapping.folder_path,
                environment=ctx.mapping.effective_environment,
                action=SyncAction.SKIPPED,
                message="Update skipped by user",
                vault_value_preview=ctx.vault_preview,
                local_value_preview=local_preview,
            )

    def _verify_secret_usable(self, mapping: ServiceMapping) -> None:
        """Verify the configured secret exists in the vault and is usable.

        Called on the verify-mode skip paths (no env file yet / ambiguous
        mapping), where the value-consuming fetch is never reached: a deleted
        vault secret used to pass ``sync --verify`` (and ``--verify --ci``)
        as "skipped" with "All services synced successfully" (#441). Applies
        the same normalization/shape validation as the consuming path (see
        ``_fetch_vault_secret``), so a secret that exists but could never
        sync — unusable key material, an env label that mismatches the
        mapping — fails verify exactly like it would fail a real sync (#661
        review). A missing or unusable secret raises
        ``SecretNotFoundError``/``VaultError``, which ``_sync_service`` turns
        into an ERROR row; when the secret is usable the mapping stays a
        benign skip ("env file not created yet").
        """
        self._fetch_vault_secret(mapping, mapping.effective_environment)

    def _fetch_vault_secret(self, mapping: ServiceMapping, effective_environment: str) -> str:
        """Fetch secret from vault.

        ``effective_environment`` is the environment the value will be installed
        as (derived from the detected ``.env.<env>`` file). When the vault value
        is a full ``DOTENV_PRIVATE_KEY_<SUFFIX>=...`` line we strip the prefix so
        it converges with the locally-stored value (#356) — but only after
        confirming ``<SUFFIX>`` matches the target environment. A mismatch means
        a key labeled for one environment would be silently relabeled and
        installed as another (e.g. staging key written as production), so we
        raise instead of stripping (#348). Binary payloads, JSON documents
        without a usable key field, and multi-line blobs without a key line
        raise ``KeyMaterialError`` (a ``VaultError``) instead of being installed
        verbatim under a success action (#480).
        """
        secret = self.vault_client.get_secret(mapping.secret_name)

        # Normalize + shape-validate the same way read_key() (operations.py) and
        # vault-pull do, so a vault value and the local file value converge
        # instead of mismatching forever (#356, #480).
        value, suffix = extract_key_material(secret, effective_environment)
        if suffix is not None and suffix.upper() != effective_environment.upper():
            # A prefix labeled for a different env would silently relabel and
            # install a key as the wrong environment, so raise instead (#348).
            raise VaultError(
                f"vault key labeled for environment {suffix.upper()} cannot be "
                f"installed as environment {effective_environment.upper()} "
                f"(secret {mapping.secret_name!r})"
            )

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
        Verify that the synchronized key can decrypt the service's env file.

        Locates the mapping's environment file, checks whether it appears
        encrypted, and runs ``dotenvx decrypt`` against a copy in an isolated
        temporary directory (together with a copy of the local keys file).
        The live working-tree file is NEVER decrypted, rewritten, or touched
        in any way — a check must not modify files (#473). The previous
        implementation decrypted and re-encrypted the live file in place,
        which churned the ciphertext on every PASSING run (dotenvx ECIES is
        non-deterministic) and left the file plaintext if interrupted.

        Returns:
            DecryptionTestResult.PASSED if the temp copy decrypts successfully.
            DecryptionTestResult.FAILED if decryption fails, the file cannot be
            read, or an unexpected error occurs.
            DecryptionTestResult.SKIPPED if no suitable env file exists, the
            file does not appear encrypted, or ``dotenvx`` is not available.
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

        return self._verify_decryption_on_copy(dotenvx_path, target_file, mapping)

    def _verify_decryption_on_copy(
        self,
        dotenvx_path: str,
        target_file: Path,
        mapping: ServiceMapping,
    ) -> DecryptionTestResult:
        """
        Run ``dotenvx decrypt`` against a temp-dir copy of ``target_file``.

        The env file and the mapping's local keys file are copied into an
        isolated ``TemporaryDirectory`` (the keys copy is always named
        ``.env.keys`` so dotenvx finds it regardless of a custom
        ``env_keys_filename``), and dotenvx runs with ``cwd`` set to that
        directory and only the file *name* on the command line. This fixes the
        relative-``folder_path`` false FAILURE of the old in-place roundtrip,
        which ran ``dotenvx decrypt -f <folder>/<file>`` with ``cwd=<folder>``
        — a doubled relative path (#473).

        Stray ``DOTENV_PRIVATE_KEY*`` / ``DOTENV_KEY`` variables are scrubbed
        from the child environment so the verdict reflects the synced keys
        file, not whatever key happens to be exported in the parent shell.

        The temp directory (and its transient plaintext) is always discarded;
        the live file is never written to.
        """
        env_keys_path = mapping.folder_path / (self.config.env_keys_filename or ".env.keys")
        child_env = {k: v for k, v in os.environ.items() if not k.startswith("DOTENV_PRIVATE_KEY")}
        child_env.pop("DOTENV_KEY", None)

        try:
            with tempfile.TemporaryDirectory(prefix=".envdrift-check-decryption-") as temp_dir:
                temp_dir_path = Path(temp_dir)
                # Preserve the file name: dotenvx derives the expected
                # DOTENV_PRIVATE_KEY_<ENV> name from it.
                temp_copy = temp_dir_path / target_file.name
                shutil.copy2(target_file, temp_copy)
                if env_keys_path.exists():
                    shutil.copy2(env_keys_path, temp_dir_path / ".env.keys")

                try:
                    result = subprocess.run(  # nosec B603
                        [dotenvx_path, "decrypt", "-f", temp_copy.name],
                        cwd=str(temp_dir_path),
                        env=child_env,
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )
                except FileNotFoundError:
                    # dotenvx vanished between which() and run(). Nothing was
                    # verified — and nothing in the working tree was touched.
                    return DecryptionTestResult.SKIPPED

                if result.returncode == 0:
                    return DecryptionTestResult.PASSED
                logger.debug(
                    "Decryption test failed for %s: %s",
                    target_file,
                    (result.stderr or result.stdout or "").strip(),
                )
                return DecryptionTestResult.FAILED
        except Exception:
            # Timeout, copy failure, vanished temp dir, … — the check could not
            # prove the key works, so it is a failed test; the live file was
            # never modified, so there is nothing to restore. Log the cause so
            # an infrastructure failure is distinguishable from a wrong key.
            logger.warning(
                "Decryption check for %s failed unexpectedly", target_file, exc_info=True
            )
            return DecryptionTestResult.FAILED

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
