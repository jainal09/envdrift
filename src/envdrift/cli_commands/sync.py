"""Vault sync-related commands for envdrift."""

from __future__ import annotations

import shutil
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Lock
from typing import TYPE_CHECKING, Annotated, Any

import typer

from envdrift.output.rich import console, print_warning
from envdrift.sync.operations import atomic_write
from envdrift.utils import normalize_max_workers

if TYPE_CHECKING:
    from envdrift.encryption import EncryptionProvider
    from envdrift.sync.config import ServiceMapping, SyncConfig


def _maybe_activate_profile(mapping: ServiceMapping, env_file: Path, profile: str | None) -> str:
    """Copy a decrypted profile env file to its ``activate_to`` path (#413).

    Returns ``"activated"`` on success, ``"error"`` on an invalid path or copy
    failure, or ``"noop"`` when there is nothing to activate (not the active
    profile, or no ``activate_to``). Run from BOTH the post-decrypt path and the
    "already decrypted" skip path so ``pull --profile`` is idempotent: a file
    that was committed decrypted, or decrypted by an earlier run, is still
    activated instead of being silently skipped.
    """
    if not (profile and mapping.profile == profile and mapping.activate_to):
        return "noop"

    activate_path = (mapping.folder_path / mapping.activate_to).resolve()
    # Validate the target stays within folder_path to prevent directory traversal.
    try:
        activate_path.relative_to(mapping.folder_path.resolve())
    except ValueError:
        console.print(
            f"  [red]![/red] {mapping.activate_to} [red]- invalid path (escapes folder)[/red]"
        )
        return "error"

    try:
        shutil.copy2(env_file, activate_path)
        console.print(
            f"  [cyan]→[/cyan] {activate_path} [dim]- activated from {env_file.name}[/dim]"
        )
        return "activated"
    except OSError as e:
        console.print(f"  [red]![/red] {activate_path} [red]- activation failed: {e}[/red]")
        return "error"


def load_sync_config_and_client(
    config_file: Path | None,
    provider: str | None,
    vault_url: str | None,
    region: str | None,
    project_id: str | None,
) -> tuple[SyncConfig, Any, str, str | None, str | None, str | None]:
    """Load sync mappings and construct their provider-specific vault client."""

    from envdrift.cli_commands.sync_config_helpers import (
        SyncLoadRequest,
        load_sync_connection,
    )

    return load_sync_connection(
        SyncLoadRequest(
            config_file=config_file,
            provider=provider,
            vault_url=vault_url,
            region=region,
            project_id=project_id,
        )
    )


def _normalize_max_workers(max_workers: int | None) -> int | None:
    return normalize_max_workers(max_workers, warn=print_warning)


def _normalize_mapped_dotenvx_metadata(
    env_file: Path,
    env_keys_file: Path,
    effective_environment: str,
    backend_provider: Any,
    check_only: bool = False,
) -> None:
    from envdrift.encryption import EncryptionProvider
    from envdrift.integrations.dotenvx import (
        dotenvx_filename_needs_normalization,
        normalize_dotenvx_metadata,
    )

    if backend_provider != EncryptionProvider.DOTENVX:
        return
    # Normalize whenever the resolved filename is non-canonical — configured via
    # env_file or auto-detected (e.g. postgresql.env) — since dotenvx derives its
    # key name from the filename and would otherwise write a non-canonical key.
    if not dotenvx_filename_needs_normalization(env_file, effective_environment):
        return

    # `lock --check` is a documented read-only dry run (see #303): the file's
    # non-canonical key name is still surfaced downstream (re-key detection
    # reports "would re-key"), but we must NOT rewrite .env.keys / the header
    # here. normalize_dotenvx_metadata() write_text()s both files.
    if check_only:
        return

    normalize_dotenvx_metadata(env_file, env_keys_file, effective_environment)


def _find_config_path(config_file: Path | None) -> Path | None:
    """Find the config path from explicit file or auto-discovery."""
    from envdrift.config import find_config

    if config_file is not None and config_file.suffix.lower() == ".toml":
        return config_file
    elif config_file is None:
        return find_config()
    return None


def _load_partial_encryption_paths(
    config_file: Path | None,
) -> tuple[set[Path], set[Path], set[Path]]:
    from envdrift.config import ConfigLoadError, ConfigNotFoundError, load_config

    config_path = _find_config_path(config_file)

    if not config_path:
        return set(), set(), set()

    try:
        config = load_config(config_path)
    except ConfigNotFoundError:
        return set(), set(), set()
    except ConfigLoadError as exc:
        # load_config converts every OSError into ConfigLoadError (#491).
        print_warning(f"Unable to read config for partial encryption: {exc}")
        return set(), set(), set()

    if not config.partial_encryption.enabled:
        return set(), set(), set()

    clear_files: set[Path] = set()
    secret_files: set[Path] = set()
    combined_files: set[Path] = set()
    for env_config in config.partial_encryption.environments:
        if env_config.secrets_only:
            # Secrets-only environments encrypt files in place within secrets_dir
            # and have no clear/secret/combined files. Their clear_file/secret_file/
            # combined_file are empty strings, and Path("") resolves to the current
            # directory, so they must be skipped to avoid polluting these sets.
            continue
        clear_files.add(Path(env_config.clear_file).resolve())
        secret_files.add(Path(env_config.secret_file).resolve())
        combined_files.add(Path(env_config.combined_file).resolve())

    return clear_files, secret_files, combined_files


def _should_use_executor(max_workers: int | None, task_count: int) -> bool:
    if task_count < 2:
        return False
    if max_workers is None:
        return True
    return max_workers > 1


def _run_tasks(tasks: list[Any], worker, max_workers: int | None):
    if not _should_use_executor(max_workers, len(tasks)):
        return [worker(task) for task in tasks]
    if max_workers is None:
        with ThreadPoolExecutor() as executor:
            return list(executor.map(worker, tasks))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        return list(executor.map(worker, tasks))


def _write_merged_combined_file(clear_file: Path, secret_file: Path, combined_file: Path) -> None:
    """Write ``combined_file`` from the clear file plus the decrypted secret file.

    The dotenvx header comments (``#/---`` banner and ``DOTENV_PUBLIC_KEY``) are
    stripped from the secret content so the merged file is a clean .env. The
    resulting file holds DECRYPTED secrets and must already be gitignored by the
    caller (see ``_ensure_combined_gitignore``).
    """
    combined_lines: list[str] = []

    if clear_file.exists():
        combined_lines.extend(clear_file.read_text(encoding="utf-8").splitlines())
        combined_lines.append("")

    if secret_file.exists():
        combined_lines.extend(
            line
            for line in secret_file.read_text(encoding="utf-8").splitlines()
            if not line.strip().startswith("#/---")
            and not line.strip().startswith("DOTENV_PUBLIC_KEY")
        )

    # The merged file holds DECRYPTED secret values, so write it exactly like
    # the .env.keys private key: 0600 for a fresh file, fchmod on the fd,
    # atomic rename — never a bare write_text at the process umask (#471). The
    # 0o600 cap also tightens combined files a pre-fix write_text left 0o644.
    atomic_write(combined_file, "\n".join(combined_lines) + "\n", max_permissions=0o600)


_SyncConfigOption = Annotated[
    Path | None,
    typer.Option(
        "--config",
        "-c",
        help="Path to sync config file (TOML or legacy pair.txt format)",
    ),
]
_ProviderOption = Annotated[
    str | None,
    typer.Option("--provider", "-p", help="Vault provider: azure, aws, hashicorp, gcp"),
]
_VaultUrlOption = Annotated[
    str | None,
    typer.Option("--vault-url", help="Vault URL (Azure Key Vault or HashiCorp Vault)"),
]
_RegionOption = Annotated[
    str | None,
    typer.Option("--region", help="AWS region (default: us-east-1)"),
]
_ProjectIdOption = Annotated[
    str | None,
    typer.Option("--project-id", help="GCP project ID (Secret Manager)"),
]
_PullForceOption = Annotated[
    bool,
    typer.Option("--force", "-f", help="Update all mismatches without prompting"),
]
_ProfileOption = Annotated[
    str | None,
    typer.Option("--profile", help="Only process mappings for this profile"),
]
_SkipSyncOption = Annotated[
    bool,
    typer.Option("--skip-sync", help="Skip syncing keys from vault, only decrypt files"),
]
_MergeOption = Annotated[
    bool,
    typer.Option(
        "--merge",
        "-m",
        help="For partial encryption: create combined decrypted .env file from .clear + .secret",
    ),
]
_LockForceOption = Annotated[
    bool,
    typer.Option("--force", "-f", help="Force encryption without prompting"),
]
_VerifyVaultOption = Annotated[
    bool,
    typer.Option("--verify-vault", help="Verify local keys match vault before encrypting"),
]
_SyncKeysOption = Annotated[
    bool,
    typer.Option(
        "--sync-keys", help="Sync keys from vault before encrypting (implies --verify-vault)"
    ),
]
_CheckOnlyOption = Annotated[
    bool,
    typer.Option("--check", help="Only check encryption status, don't encrypt"),
]
_AllFilesOption = Annotated[
    bool,
    typer.Option(
        "--all",
        help="Include partial encryption files: encrypt .secret files and delete combined files",
    ),
]
_SyncVerifyOption = Annotated[
    bool,
    typer.Option("--verify", help="Check only, don't modify files"),
]
_SyncForceOption = Annotated[
    bool,
    typer.Option("--force", "-f", help="Update all mismatches without prompting"),
]
_CheckDecryptionOption = Annotated[
    bool,
    typer.Option("--check-decryption", help="Verify keys can decrypt .env files"),
]
_ValidateSchemaOption = Annotated[
    bool,
    typer.Option("--validate-schema", help="Run schema validation after sync"),
]
_SchemaOption = Annotated[
    str | None,
    typer.Option("--schema", "-s", help="Schema path for validation"),
]
_ServiceDirOption = Annotated[
    Path | None,
    typer.Option("--service-dir", "-d", help="Service directory for schema imports"),
]
_CiOption = Annotated[
    bool,
    typer.Option("--ci", help="CI mode: exit with code 1 on errors"),
]


def sync(
    config_file: _SyncConfigOption = None,
    provider: _ProviderOption = None,
    vault_url: _VaultUrlOption = None,
    region: _RegionOption = None,
    project_id: _ProjectIdOption = None,
    verify: _SyncVerifyOption = False,
    force: _SyncForceOption = False,
    profile: _ProfileOption = None,
    check_decryption: _CheckDecryptionOption = False,
    validate_schema: _ValidateSchemaOption = False,
    schema: _SchemaOption = None,
    service_dir: _ServiceDirOption = None,
    ci: _CiOption = False,
) -> None:
    """
    Sync encryption keys from a configured vault to local .env.keys files for each service.

    Loads sync configuration and a vault client, fetches DOTENV_PRIVATE_KEY_* secrets for configured mappings, and writes/updates local key files; optionally verifies keys, forces updates, checks decryption, and runs schema validation after sync. In interactive mode the command may prompt before updating individual services; --force, --verify, and --ci disable prompts.

    Exits with code 1 on vault or sync configuration errors, when run with --ci if any sync
    errors occurred, whenever a --check-decryption test fails (even without --ci), and when
    --check-decryption is requested but dotenvx is not installed (nothing can be verified).
    """

    from envdrift.cli_commands.sync_run_helpers import SyncRequest, SyncRuntime, execute_sync

    execute_sync(
        SyncRequest(
            config_file=config_file,
            provider=provider,
            vault_url=vault_url,
            region=region,
            project_id=project_id,
            verify=verify,
            force=force,
            profile=profile,
            check_decryption=check_decryption,
            validate_schema=validate_schema,
            schema=schema,
            service_dir=service_dir,
            ci=ci,
        ),
        SyncRuntime(
            load_sync=load_sync_config_and_client,
            find_binary=shutil.which,
        ),
    )


PULL_HELP = """Pull keys from vault and decrypt all env files (one-command developer setup).

Reads your TOML configuration, fetches encryption keys from your cloud vault,
writes them to local .env.keys files, and decrypts all corresponding .env files.

This is the recommended command for onboarding new developers - just run
`envdrift pull` and all encrypted environment files are ready to use.

Use --profile to filter mappings and activate a specific environment:
- Without --profile: processes all mappings without a profile tag
- With --profile: processes regular mappings + the matching profile,
  and copies the decrypted file to the activate_to path if configured

Configuration is read from:
- pyproject.toml [tool.envdrift.vault.sync] section
- envdrift.toml [vault.sync] section
- Explicit --config file

Examples:
    # Auto-discover config and pull everything (non-profile mappings only)
    envdrift pull

    # Pull with a specific profile (regular mappings + profile, activates env)
    envdrift pull --profile local

    # Use explicit config file
    envdrift pull -c envdrift.toml

    # Override provider settings
    envdrift pull -p azure --vault-url https://myvault.vault.azure.net/

    # Force update without prompts
    envdrift pull --force

    # Skip vault sync, only decrypt files (useful when keys are already local)
    envdrift pull --skip-sync

    # For partial encryption: decrypt and create combined .env file for local use
    envdrift pull --merge
"""

LOCK_HELP = """Verify keys and encrypt all env files (opposite of pull - prepares for commit).

The lock command ensures your environment files are properly encrypted before
committing. It can optionally verify that local keys match vault keys to prevent
key drift, and then encrypts all decrypted .env files.

This is the recommended command before committing changes to ensure:
1. Local encryption keys are in sync with the team's vault keys
2. All .env files are properly encrypted
3. No plaintext secrets are accidentally committed

Workflow:
- With --verify-vault: Check if local .env.keys match vault secrets.
  Any mapping that cannot be verified (missing .env.keys, missing key
  entry, missing/empty vault secret, vault error) or that mismatches is
  a hard failure: nothing is encrypted and the exit code is 1, even with
  --force. Use --sync-keys to repair, or drop --verify-vault to skip.
- With --sync-keys: Fetch keys from vault to ensure consistency
- With --all: Also encrypt partial encryption .secret files and delete combined files
- Then: Encrypt all .env files that are currently decrypted

Use --profile to filter mappings for a specific environment.

Configuration is read from:
- pyproject.toml [tool.envdrift.vault.sync] section
- envdrift.toml [vault.sync] section
- Explicit --config file

Examples:
    # Encrypt all env files (basic usage)
    envdrift lock

    # Verify keys match vault, then encrypt
    envdrift lock --verify-vault

    # Sync keys from vault first, then encrypt
    envdrift lock --sync-keys

    # Check encryption status only (dry run)
    envdrift lock --check

    # Lock with a specific profile
    envdrift lock --profile local

    # Force encryption without prompts
    envdrift lock --force

    # Include partial encryption files (encrypt .secret, delete combined)
    envdrift lock --all
"""


def pull(
    config_file: _SyncConfigOption = None,
    provider: _ProviderOption = None,
    vault_url: _VaultUrlOption = None,
    region: _RegionOption = None,
    project_id: _ProjectIdOption = None,
    force: _PullForceOption = False,
    profile: _ProfileOption = None,
    skip_sync: _SkipSyncOption = False,
    merge: _MergeOption = False,
) -> None:
    """Pull vault keys and decrypt the configured environment files."""
    from envdrift.cli_commands.sync_helpers import PullRequest, PullRuntime, execute_pull

    execute_pull(
        PullRequest(
            config_file=config_file,
            provider=provider,
            vault_url=vault_url,
            region=region,
            project_id=project_id,
            force=force,
            profile=profile,
            skip_sync=skip_sync,
            merge=merge,
        ),
        PullRuntime(
            load_sync=load_sync_config_and_client,
            run_tasks=_run_tasks,
            normalize_metadata=_normalize_mapped_dotenvx_metadata,
            load_partial_paths=_load_partial_encryption_paths,
            maybe_activate_profile=_maybe_activate_profile,
            find_config_path=_find_config_path,
            write_merged_file=_write_merged_combined_file,
        ),
    )


def _find_stale_private_key_name(env_keys_file: Path, expected_key_name: str) -> str | None:
    """Return the old ``DOTENV_PRIVATE_KEY_*`` name when it mismatches the env.

    Handles the renamed-file case (e.g. ``.env.local`` -> ``.env.localenv``)
    where ``.env.keys`` still carries the key under the old name: the expected
    key is absent but another private key is present. Returns ``None`` when the
    expected key exists (or the keys file is missing/empty).
    """
    if not env_keys_file.exists():
        return None
    from envdrift.sync.operations import EnvKeysFile

    if EnvKeysFile(env_keys_file).read_key(expected_key_name):
        return None
    # UTF-8 like dotenvx itself: the .env.keys header contains a non-ASCII
    # character, so the locale codec (cp1252, LC_ALL=C) cannot decode it (#474).
    for line in env_keys_file.read_text(encoding="utf-8").splitlines():
        if line.startswith("DOTENV_PRIVATE_KEY_") and "=" in line:
            old_key_name = line.split("=")[0].strip()
            if old_key_name != expected_key_name:
                return old_key_name
    return None


def _rekey_dotenvx_file(
    env_file: Path,
    encryption_backend: Any,
    sops_encrypt_kwargs: dict[str, Any],
) -> tuple[bool, str]:
    """Decrypt + re-encrypt ``env_file`` so dotenvx generates the expected key.

    Returns ``(ok, error_message)``; ``error_message`` is empty on success.
    """
    from envdrift.encryption import EncryptionBackendError, EncryptionNotFoundError

    try:
        decrypt_result = encryption_backend.decrypt(env_file.resolve(), **sops_encrypt_kwargs)
        if not decrypt_result.success:
            return False, f"decrypt failed: {decrypt_result.message}"
        result = encryption_backend.encrypt(env_file.resolve(), **sops_encrypt_kwargs)
        if not result.success:
            return False, f"re-encrypt failed: {result.message}"
    except (EncryptionNotFoundError, EncryptionBackendError) as e:
        return False, f"rekey error: {e}"
    return True, ""


def _verify_issue_summary(failed: int, unusable: int) -> str:
    """Summary line for the ``lock --verify-vault`` fail-fast gate.

    Failed and unusable keys get named separately with their own remedy:
    ``--sync-keys`` fixes a mismatched or missing/cannot-verify local key,
    while an unusable (malformed) vault secret must be fixed in the vault
    itself — the sync engine raises the same ``KeyMaterialError`` — so
    labeling both the same steered users toward syncing keys that could never
    install (#480 review follow-up). Every variant states that nothing was
    encrypted: the gate hard-stops before Step 2, even with ``--force``,
    because encrypting past a failed verification could mint a fresh
    local-only key or commit a file the team's vault key cannot decrypt
    (#473).
    """
    found: list[str] = []
    if failed:
        found.append(f"{failed} failed key verification(s)")
    if unusable:
        found.append(f"{unusable} unusable vault key(s)")
    if not unusable:
        remedy = (
            "Run 'envdrift lock --sync-keys' to sync keys from vault, or rerun "
            "without --verify-vault to skip verification."
        )
    elif failed:
        remedy = (
            "Fix the vault secret shapes named above, then run "
            "'envdrift lock --sync-keys' to sync the remaining keys from vault."
        )
    else:
        remedy = (
            "Fix the vault secret shapes named above (--sync-keys cannot install an unusable key)."
        )
    return f"Found {' and '.join(found)}. Nothing was encrypted. {remedy}"


def _sops_missing_recipients(
    encryption_backend: Any,
    backend_provider: EncryptionProvider,
    sops_encrypt_kwargs: dict[str, Any],
    content: str,
) -> list[str]:
    """Recipients configured in envdrift.toml but absent from ``content``'s metadata.

    A fully-encrypted SOPS file skips ``backend.encrypt()`` in ``lock``, so the
    recipient check inside it never runs — this helper lets lock's
    already-encrypted branch verify the configured recipients anyway (#475).
    Returns an empty list for non-SOPS providers, an empty recipient config, or
    a backend that does not expose the check.
    """
    from envdrift.encryption import EncryptionProvider

    if backend_provider != EncryptionProvider.SOPS or not sops_encrypt_kwargs:
        return []
    from envdrift.encryption.sops import SOPSEncryptionBackend

    if not isinstance(encryption_backend, SOPSEncryptionBackend):
        return []
    return encryption_backend.missing_recipients(content, **sops_encrypt_kwargs)


def lock(
    config_file: _SyncConfigOption = None,
    provider: _ProviderOption = None,
    vault_url: _VaultUrlOption = None,
    region: _RegionOption = None,
    project_id: _ProjectIdOption = None,
    force: _LockForceOption = False,
    profile: _ProfileOption = None,
    verify_vault: _VerifyVaultOption = False,
    sync_keys: _SyncKeysOption = False,
    check_only: _CheckOnlyOption = False,
    all_files: _AllFilesOption = False,
) -> None:
    """Verify keys and encrypt the configured environment files."""
    from envdrift.cli_commands.sync_lock_helpers import LockRequest, LockRuntime, execute_lock

    execute_lock(
        LockRequest(
            config_file=config_file,
            provider=provider,
            vault_url=vault_url,
            region=region,
            project_id=project_id,
            force=force,
            profile=profile,
            verify_vault=verify_vault or sync_keys,
            sync_keys=sync_keys,
            check_only=check_only,
            all_files=all_files,
        ),
        LockRuntime(
            load_sync=load_sync_config_and_client,
            run_tasks=_run_tasks,
            normalize_metadata=_normalize_mapped_dotenvx_metadata,
            load_partial_paths=_load_partial_encryption_paths,
            find_config_path=_find_config_path,
            find_stale_key=_find_stale_private_key_name,
            rekey_file=_rekey_dotenvx_file,
            verify_summary=_verify_issue_summary,
            sops_missing_recipients=_sops_missing_recipients,
            lock_factory=Lock,
        ),
    )
