"""Vault sync-related commands for envdrift."""

from __future__ import annotations

import shutil
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import TYPE_CHECKING, Annotated, Any

import typer
from rich.panel import Panel

from envdrift.env_files import resolve_mapping_env_file
from envdrift.output.rich import console, print_error, print_success, print_warning
from envdrift.utils import normalize_max_workers
from envdrift.vault.base import SecretNotFoundError, VaultError

if TYPE_CHECKING:
    from envdrift.sync.config import ServiceMapping, SyncConfig


@dataclass(frozen=True)
class _DecryptTask:
    mapping: ServiceMapping
    env_file: Path
    ephemeral_key: str | None = None  # Key value for ephemeral mode
    ephemeral_key_name: str | None = None  # Key name (e.g., DOTENV_PRIVATE_KEY_PRODUCTION)


@dataclass(frozen=True)
class _EncryptTask:
    mapping: ServiceMapping
    env_file: Path
    env_keys_file: Path
    effective_environment: str


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
    """
    Load sync configuration and instantiate a vault client using CLI arguments, discovered project config, or an explicit config file.

    This resolves effective provider, vault URL, and region by preferring CLI arguments over project defaults (from a provided TOML file, discovered envdrift.toml/pyproject.toml, or an explicit legacy config), constructs a SyncConfig (from a TOML, legacy pair file, or project sync mappings), validates required provider-specific options, and returns the SyncConfig along with a ready-to-use vault client and the resolved provider/URL/region.

    Parameters:
        config_file (Path | None): Path provided via --config. If a TOML file is given, it is used for defaults and/or as the sync config source; other extensions may be treated as legacy pair files.
        provider (str | None): CLI provider override (e.g., "azure", "aws", "hashicorp", "gcp"). If omitted, the provider from project config is used when available.
        vault_url (str | None): CLI vault URL override for providers that require it (Azure, HashiCorp). If omitted, the value from project config is used when present.
        region (str | None): CLI region override for AWS. If omitted, the value from project config is used when present.
        project_id (str | None): CLI project ID override for GCP Secret Manager. If omitted, the value from project config is used when present.

    Returns:
        tuple[SyncConfig, Any, str, str | None, str | None]: A tuple containing:
            - SyncConfig: the resolved synchronization configuration with mappings.
            - vault_client: an instantiated vault client for the resolved provider.
            - effective_provider: the resolved provider string.
            - effective_vault_url: the resolved vault URL when applicable, otherwise None.
            - effective_region: the resolved region when applicable, otherwise None.
            - effective_project_id: the resolved GCP project ID when applicable, otherwise None.

    Raises:
        typer.Exit: Exits with a non-zero code if no valid sync configuration can be found, required provider options are missing, the config file is invalid or unreadable, or the vault client cannot be created.
    """
    import tomllib

    from envdrift.config import ConfigNotFoundError, find_config, load_config
    from envdrift.sync.config import ServiceMapping, SyncConfig, SyncConfigError
    from envdrift.vault import get_vault_client

    # Determine config source for defaults:
    # 1. If --config points to a TOML file, use it for defaults
    # 2. Otherwise, use auto-discovery (find_config)
    # Note: discovery only runs when --config is not provided. If --config points
    # to a non-TOML file (e.g., pair.txt), we skip discovery to avoid pulling
    # defaults from unrelated projects.
    envdrift_config = None
    config_path = None

    if config_file is not None and config_file.suffix.lower() == ".toml":
        # Use the explicitly provided TOML file for defaults
        config_path = config_file
        try:
            envdrift_config = load_config(config_path)
        except tomllib.TOMLDecodeError as e:
            print_error(f"TOML syntax error in {config_path}: {e}")
            raise typer.Exit(code=1) from None
        except ValueError as e:
            # A malformed section (e.g. a sync mapping missing secret_name) now
            # raises a clean ValueError from load_config instead of a raw
            # KeyError traceback (#443 #32).
            print_error(f"Invalid config in {config_path}: {e}")
            raise typer.Exit(code=1) from None
        except ConfigNotFoundError:
            pass
    elif config_file is None:
        # Auto-discover config from envdrift.toml or pyproject.toml
        config_path = find_config()
        if config_path:
            try:
                envdrift_config = load_config(config_path)
            except ConfigNotFoundError:
                pass
            except tomllib.TOMLDecodeError as e:
                print_warning(f"TOML syntax error in {config_path}: {e}")

    vault_config = getattr(envdrift_config, "vault", None)

    # Determine effective provider (CLI overrides config)
    effective_provider = provider or getattr(vault_config, "provider", None)

    # Determine effective vault URL (CLI overrides config)
    effective_vault_url = vault_url
    if effective_vault_url is None and vault_config:
        if effective_provider == "azure":
            effective_vault_url = getattr(vault_config, "azure_vault_url", None)
        elif effective_provider == "hashicorp":
            effective_vault_url = getattr(vault_config, "hashicorp_url", None)

    # Determine effective region (CLI overrides config)
    effective_region = region
    if effective_region is None and vault_config:
        effective_region = getattr(vault_config, "aws_region", None)

    effective_project_id = project_id
    if effective_project_id is None and vault_config:
        effective_project_id = getattr(vault_config, "gcp_project_id", None)

    vault_sync = getattr(vault_config, "sync", None)

    # Load sync config from file or project config
    sync_config: SyncConfig | None = None

    if config_file is not None:
        # Explicit config file provided
        if not config_file.exists():
            print_error(f"Config file not found: {config_file}")
            raise typer.Exit(code=1)

        try:
            # Detect format by extension
            if config_file.suffix.lower() == ".toml":
                sync_config = SyncConfig.from_toml_file(config_file)
            else:
                # Legacy pair.txt format
                sync_config = SyncConfig.from_file(config_file)
        except SyncConfigError as e:
            print_error(f"Invalid config file: {e}")
            raise typer.Exit(code=1) from None
    elif vault_sync and vault_sync.mappings:
        # Use mappings from project config
        sync_config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name=m.secret_name,
                    folder_path=Path(m.folder_path),
                    vault_name=m.vault_name,
                    environment=m.environment,
                    env_file=Path(m.env_file) if m.env_file else None,
                    profile=m.profile,
                    activate_to=Path(m.activate_to) if m.activate_to else None,
                    ephemeral_keys=m.ephemeral_keys,
                )
                for m in vault_sync.mappings
            ],
            default_vault_name=vault_sync.default_vault_name,
            env_keys_filename=vault_sync.env_keys_filename,
            max_workers=vault_sync.max_workers,
            ephemeral_keys=vault_sync.ephemeral_keys,
        )
    elif config_path and config_path.suffix.lower() == ".toml":
        # Try to load sync config from discovered TOML
        try:
            sync_config = SyncConfig.from_toml_file(config_path)
        except SyncConfigError as e:
            print_warning(f"Could not load sync config from {config_path}: {e}")

    if sync_config is None or not sync_config.mappings:
        print_error(
            "No sync configuration found. Provide one of:\n"
            "  --config <file.toml>  TOML config with [vault.sync] section\n"
            "  --config <pair.txt>   Legacy format: secret=folder\n"
            "  [tool.envdrift.vault.sync] section in pyproject.toml"
        )
        raise typer.Exit(code=1)

    # Validate provider is set
    if effective_provider is None:
        print_error(
            "--provider is required (or set [vault] provider in config). "
            "Options: azure, aws, hashicorp, gcp"
        )
        raise typer.Exit(code=1)

    # Validate provider-specific options
    if effective_provider == "azure" and not effective_vault_url:
        print_error("Azure provider requires --vault-url (or [vault.azure] vault_url in config)")
        raise typer.Exit(code=1)

    if effective_provider == "hashicorp" and not effective_vault_url:
        print_error("HashiCorp provider requires --vault-url (or [vault.hashicorp] url in config)")
        raise typer.Exit(code=1)

    if effective_provider == "gcp" and not effective_project_id:
        print_error("GCP provider requires --project-id (or [vault.gcp] project_id in config)")
        raise typer.Exit(code=1)

    # Create vault client
    try:
        vault_kwargs: dict = {}
        if effective_provider == "azure":
            vault_kwargs["vault_url"] = effective_vault_url
        elif effective_provider == "aws":
            vault_kwargs["region"] = effective_region or "us-east-1"
        elif effective_provider == "hashicorp":
            vault_kwargs["url"] = effective_vault_url
        elif effective_provider == "gcp":
            vault_kwargs["project_id"] = effective_project_id

        vault_client = get_vault_client(effective_provider, **vault_kwargs)
    except ImportError as e:
        print_error(str(e))
        raise typer.Exit(code=1) from None
    except ValueError as e:
        print_error(str(e))
        raise typer.Exit(code=1) from None

    return (
        sync_config,
        vault_client,
        effective_provider,
        effective_vault_url,
        effective_region,
        effective_project_id,
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
    from envdrift.config import ConfigNotFoundError, load_config

    config_path = _find_config_path(config_file)

    if not config_path:
        return set(), set(), set()

    try:
        config = load_config(config_path)
    except ConfigNotFoundError:
        return set(), set(), set()
    except (OSError, AttributeError, KeyError) as exc:
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

    combined_file.write_text("\n".join(combined_lines) + "\n", encoding="utf-8")


def sync(
    config_file: Annotated[
        Path | None,
        typer.Option(
            "--config",
            "-c",
            help="Path to sync config file (TOML or legacy pair.txt format)",
        ),
    ] = None,
    provider: Annotated[
        str | None,
        typer.Option("--provider", "-p", help="Vault provider: azure, aws, hashicorp, gcp"),
    ] = None,
    vault_url: Annotated[
        str | None,
        typer.Option("--vault-url", help="Vault URL (Azure Key Vault or HashiCorp Vault)"),
    ] = None,
    region: Annotated[
        str | None,
        typer.Option("--region", help="AWS region (default: us-east-1)"),
    ] = None,
    project_id: Annotated[
        str | None,
        typer.Option("--project-id", help="GCP project ID (Secret Manager)"),
    ] = None,
    verify: Annotated[
        bool,
        typer.Option("--verify", help="Check only, don't modify files"),
    ] = False,
    force: Annotated[
        bool,
        typer.Option("--force", "-f", help="Update all mismatches without prompting"),
    ] = False,
    check_decryption: Annotated[
        bool,
        typer.Option("--check-decryption", help="Verify keys can decrypt .env files"),
    ] = False,
    validate_schema: Annotated[
        bool,
        typer.Option("--validate-schema", help="Run schema validation after sync"),
    ] = False,
    schema: Annotated[
        str | None,
        typer.Option("--schema", "-s", help="Schema path for validation"),
    ] = None,
    service_dir: Annotated[
        Path | None,
        typer.Option("--service-dir", "-d", help="Service directory for schema imports"),
    ] = None,
    ci: Annotated[
        bool,
        typer.Option("--ci", help="CI mode: exit with code 1 on errors"),
    ] = False,
) -> None:
    """
    Sync encryption keys from a configured vault to local .env.keys files for each service.

    Loads sync configuration and a vault client, fetches DOTENV_PRIVATE_KEY_* secrets for configured mappings, and writes/updates local key files; optionally verifies keys, forces updates, checks decryption, and runs schema validation after sync. In interactive mode the command may prompt before updating individual services; --force, --verify, and --ci disable prompts.

    Exits with code 1 on vault or sync configuration errors, and when run with --ci if any sync errors occurred.
    """
    from envdrift.output.rich import print_service_sync_status, print_sync_result
    from envdrift.sync.config import SyncConfigError

    sync_config, vault_client, effective_provider, _, _, _ = load_sync_config_and_client(
        config_file=config_file,
        provider=provider,
        vault_url=vault_url,
        region=region,
        project_id=project_id,
    )
    from envdrift.integrations.hook_check import ensure_git_hook_setup

    hook_errors = ensure_git_hook_setup(config_file=config_file)
    if hook_errors:
        for error in hook_errors:
            print_error(error)
        raise typer.Exit(code=1)

    # Create sync engine
    from envdrift.sync.engine import SyncEngine, SyncMode

    mode = SyncMode(
        verify_only=verify,
        force_update=force,
        check_decryption=check_decryption,
        validate_schema=validate_schema,
        schema_path=schema,
        service_dir=service_dir,
    )

    # Progress callback for non-CI mode
    def progress_callback(msg: str) -> None:
        if not ci:
            console.print(f"[dim]{msg}[/dim]")

    # Prompt callback (disabled in force/verify/ci modes)
    def prompt_callback(msg: str) -> bool:
        if force or verify or ci:
            return force
        response = console.input(f"{msg} (y/N): ").strip().lower()
        return response in ("y", "yes")

    engine = SyncEngine(
        config=sync_config,
        vault_client=vault_client,
        mode=mode,
        prompt_callback=prompt_callback,
        progress_callback=progress_callback,
    )

    # Print header
    console.print()
    mode_str = "VERIFY" if verify else ("FORCE" if force else "Interactive")
    console.print(f"[bold]Vault Sync[/bold] - Mode: {mode_str}")
    console.print(
        f"[dim]Provider: {effective_provider} | Services: {len(sync_config.mappings)}[/dim]"
    )
    console.print()

    # Run sync
    try:
        result = engine.sync_all()
    except (VaultError, SyncConfigError, SecretNotFoundError, OSError, UnicodeDecodeError) as e:
        print_error(f"Sync failed: {e}")
        raise typer.Exit(code=1) from None

    # Print results
    for service_result in result.services:
        print_service_sync_status(service_result)

    print_sync_result(result)

    # Exit with appropriate code
    if ci and result.has_errors:
        raise typer.Exit(code=1)


def pull(
    config_file: Annotated[
        Path | None,
        typer.Option(
            "--config",
            "-c",
            help="Path to sync config file (TOML or legacy pair.txt format)",
        ),
    ] = None,
    provider: Annotated[
        str | None,
        typer.Option("--provider", "-p", help="Vault provider: azure, aws, hashicorp, gcp"),
    ] = None,
    vault_url: Annotated[
        str | None,
        typer.Option("--vault-url", help="Vault URL (Azure Key Vault or HashiCorp Vault)"),
    ] = None,
    region: Annotated[
        str | None,
        typer.Option("--region", help="AWS region (default: us-east-1)"),
    ] = None,
    project_id: Annotated[
        str | None,
        typer.Option("--project-id", help="GCP project ID (Secret Manager)"),
    ] = None,
    force: Annotated[
        bool,
        typer.Option("--force", "-f", help="Update all mismatches without prompting"),
    ] = False,
    profile: Annotated[
        str | None,
        typer.Option("--profile", help="Only process mappings for this profile"),
    ] = None,
    skip_sync: Annotated[
        bool,
        typer.Option("--skip-sync", help="Skip syncing keys from vault, only decrypt files"),
    ] = False,
    merge: Annotated[
        bool,
        typer.Option(
            "--merge",
            "-m",
            help="For partial encryption: create combined decrypted .env file from .clear + .secret",
        ),
    ] = False,
) -> None:
    """
    Pull keys from vault and decrypt all env files (one-command developer setup).

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
    from envdrift.output.rich import print_service_sync_status, print_sync_result
    from envdrift.sync.config import SyncConfigError

    sync_config, vault_client, effective_provider, _, _, _ = load_sync_config_and_client(
        config_file=config_file,
        provider=provider,
        vault_url=vault_url,
        region=region,
        project_id=project_id,
    )
    from envdrift.integrations.hook_check import ensure_git_hook_setup

    hook_errors = ensure_git_hook_setup(config_file=config_file)
    if hook_errors:
        for error in hook_errors:
            print_error(error)
        raise typer.Exit(code=1)

    # === FILTER MAPPINGS BY PROFILE ===
    from envdrift.sync.engine import SyncEngine, SyncMode

    filtered_mappings = sync_config.filter_by_profile(profile)

    if not filtered_mappings:
        if profile:
            print_error(f"No mappings found for profile '{profile}'")
        else:
            print_warning("No non-profile mappings found. Use --profile to specify one.")
        raise typer.Exit(code=1)

    # Create a filtered config for the sync engine
    from envdrift.sync.config import SyncConfig as SyncConfigClass

    filtered_config = SyncConfigClass(
        mappings=filtered_mappings,
        default_vault_name=sync_config.default_vault_name,
        env_keys_filename=sync_config.env_keys_filename,
        max_workers=sync_config.max_workers,
        ephemeral_keys=sync_config.ephemeral_keys,
    )

    # === STEP 1: SYNC KEYS FROM VAULT ===
    mode = SyncMode(force_update=force)

    def progress_callback(msg: str) -> None:
        console.print(f"[dim]{msg}[/dim]")

    def prompt_callback(msg: str) -> bool:
        if force:
            return True
        response = console.input(f"{msg} (y/N): ").strip().lower()
        return response in ("y", "yes")

    engine = SyncEngine(
        config=filtered_config,
        vault_client=vault_client,
        mode=mode,
        prompt_callback=prompt_callback,
        progress_callback=progress_callback,
    )

    console.print()
    profile_info = f" (profile: {profile})" if profile else ""
    action = "Decrypting env files" if skip_sync else "Syncing keys and decrypting env files"
    console.print(f"[bold]Pull[/bold] - {action}{profile_info}")
    console.print(f"[dim]Provider: {effective_provider} | Services: {len(filtered_mappings)}[/dim]")
    console.print()

    # === STEP 1: SYNC KEYS FROM VAULT (unless --skip-sync) ===
    # Build ephemeral keys map for decryption (folder_path -> (key_name, key_value))
    ephemeral_keys_map: dict[Path, tuple[str, str]] = {}

    if skip_sync:
        console.print("[dim]Step 1: Skipped (--skip-sync)[/dim]")
    else:
        console.print("[bold cyan]Step 1:[/bold cyan] Syncing keys from vault...")
        console.print()

        try:
            sync_result = engine.sync_all()
        except (VaultError, SyncConfigError, SecretNotFoundError) as e:
            print_error(f"Sync failed: {e}")
            raise typer.Exit(code=1) from None

        for service_result in sync_result.services:
            print_service_sync_status(service_result)

        print_sync_result(sync_result)

        if sync_result.has_errors:
            print_error("Setup incomplete due to sync errors")
            raise typer.Exit(code=1)

        # Build ephemeral keys map from sync results
        from envdrift.sync.result import SyncAction

        # Index mappings by resolved folder path so ephemeral key names are
        # derived from the mapping's ENVIRONMENT (the source of truth), not the
        # folder basename, and the match is robust to relative/absolute paths
        # (#325). setdefault keeps the FIRST mapping when two share a folder,
        # preserving the original break-on-first semantics deterministically.
        mappings_by_folder: dict[Path, ServiceMapping] = {}
        for m in filtered_mappings:
            mappings_by_folder.setdefault(m.folder_path.resolve(), m)

        for service_result in sync_result.services:
            action = getattr(service_result, "action", None)
            vault_key_value = getattr(service_result, "vault_key_value", None)
            if action == SyncAction.EPHEMERAL and vault_key_value:
                matched = mappings_by_folder.get(service_result.folder_path.resolve())
                if matched is not None:
                    key_name = f"DOTENV_PRIVATE_KEY_{matched.effective_environment.upper()}"
                else:
                    # No mapping matched (should not happen) — last-resort fallback.
                    key_name = f"DOTENV_PRIVATE_KEY_{service_result.folder_path.name.upper()}"
                # Key the map on the RESOLVED folder_path so Step 2's lookup
                # (also resolved) matches even when the result's folder_path is a
                # different Path value than the mapping's but points at the same
                # directory (#325 — e.g. a relative result vs an absolute mapping).
                ephemeral_keys_map[service_result.folder_path.resolve()] = (
                    key_name,
                    vault_key_value,
                )

    # === STEP 2: DECRYPT ENV FILES ===
    console.print()
    console.print("[bold cyan]Step 2:[/bold cyan] Decrypting environment files...")
    console.print()

    try:
        from envdrift.cli_commands import encryption_helpers
        from envdrift.encryption import (
            EncryptionBackendError,
            EncryptionNotFoundError,
            EncryptionProvider,
            detect_encryption_provider,
        )

        encryption_backend, backend_provider, _ = encryption_helpers.resolve_encryption_backend(
            config_file
        )
        if not encryption_backend.is_installed():
            print_error(f"{encryption_backend.name} is not installed")
            console.print(encryption_backend.install_instructions())
            raise typer.Exit(code=1)
    except ValueError as e:
        print_error(f"Unsupported encryption backend: {e}")
        raise typer.Exit(code=1) from None

    decrypted_count = 0
    skipped_count = 0
    error_count = 0
    activated_count = 0
    activation_error_count = 0
    decrypt_tasks: list[_DecryptTask] = []
    partial_clear, _, partial_combined = _load_partial_encryption_paths(config_file)

    for mapping in filtered_mappings:
        try:
            detection = resolve_mapping_env_file(mapping)
        except ValueError as e:
            console.print(
                f"  [red]![/red] {mapping.folder_path} [red]- invalid env_file: {e}[/red]"
            )
            error_count += 1
            continue
        effective_env = detection.environment or mapping.effective_environment
        env_file = (
            detection.path
            if detection.path is not None
            else mapping.folder_path / f".env.{effective_env}"
        )

        if detection.status != "found" or detection.path is None:
            if detection.status == "multiple_found":
                console.print(
                    f"  [yellow]?[/yellow] {mapping.folder_path} "
                    f"[yellow]- skipped (multiple .env.* files, specify environment)[/yellow]"
                )
            else:
                console.print(f"  [dim]=[/dim] {env_file} [dim]- skipped (not found)[/dim]")
            skipped_count += 1
            continue

        resolved_env_file = env_file.resolve()
        if resolved_env_file in partial_combined:
            console.print(
                f"  [dim]=[/dim] {env_file} [dim]- skipped (partial encryption combined file)[/dim]"
            )
            skipped_count += 1
            continue
        if resolved_env_file in partial_clear:
            console.print(
                f"  [dim]=[/dim] {env_file} [dim]- skipped (partial encryption clear file)[/dim]"
            )
            skipped_count += 1
            continue

        _normalize_mapped_dotenvx_metadata(
            env_file,
            mapping.folder_path / (sync_config.env_keys_filename or ".env.keys"),
            effective_env,
            backend_provider,
        )

        # Check if the file carries this backend's ciphertext. Decrypt direction,
        # so use the lenient predicate (#475): a mixed SOPS file (metadata block
        # + surviving plaintext value) must still be handed to sops for a loud
        # outcome, not silently skipped as "not encrypted" (and even
        # profile-activated) while its values are still ciphertext.
        content = env_file.read_text()
        if not encryption_helpers.should_attempt_decryption(
            backend_provider, encryption_backend, content
        ):
            detected_provider = detect_encryption_provider(env_file)
            if detected_provider and detected_provider != backend_provider:
                if (
                    detected_provider == EncryptionProvider.DOTENVX
                    and backend_provider != EncryptionProvider.DOTENVX
                ):
                    console.print(
                        f"  [red]![/red] {env_file} "
                        f"[red]- encrypted with dotenvx, but config uses "
                        f"{backend_provider.value}[/red]"
                    )
                    error_count += 1
                    continue
                console.print(
                    f"  [dim]=[/dim] {env_file} "
                    f"[dim]- skipped (encrypted with {detected_provider.value}, "
                    f"config uses {backend_provider.value})[/dim]"
                )
                skipped_count += 1
                continue
            console.print(f"  [dim]=[/dim] {env_file} [dim]- skipped (not encrypted)[/dim]")
            skipped_count += 1
            # An already-decrypted profile file must still be activated so
            # `pull --profile` is idempotent (#413): a file committed decrypted
            # or decrypted by an earlier run isn't silently left un-activated.
            outcome = _maybe_activate_profile(mapping, env_file, profile)
            if outcome == "activated":
                activated_count += 1
            elif outcome == "error":
                activation_error_count += 1
            continue

        decrypt_tasks.append(
            _DecryptTask(
                mapping=mapping,
                env_file=env_file,
                ephemeral_key=ephemeral_keys_map.get(mapping.folder_path.resolve(), (None, None))[
                    1
                ],
                ephemeral_key_name=ephemeral_keys_map.get(
                    mapping.folder_path.resolve(), (None, None)
                )[0],
            )
        )

    max_workers = _normalize_max_workers(sync_config.max_workers)

    def _decrypt_task(task: _DecryptTask):
        try:
            # Build env dict with ephemeral key if available
            env_override = None
            if task.ephemeral_key and task.ephemeral_key_name:
                import os

                env_override = dict(os.environ)
                env_override[task.ephemeral_key_name] = task.ephemeral_key

            result = encryption_backend.decrypt(
                task.env_file.resolve(),
                env=env_override,
            )
            return task, result, None
        except (EncryptionNotFoundError, EncryptionBackendError) as e:
            return task, None, e

    for task, result, error in _run_tasks(decrypt_tasks, _decrypt_task, max_workers):
        env_file = task.env_file
        mapping = task.mapping
        if error is not None:
            console.print(f"  [red]![/red] {env_file} [red]- error: {error}[/red]")
            error_count += 1
            continue
        if result is None or not result.success:
            message = result.message if result else "unknown error"
            console.print(f"  [red]![/red] {env_file} [red]- error: {message}[/red]")
            error_count += 1
            continue

        console.print(f"  [green]+[/green] {env_file} [dim]- decrypted[/dim]")
        decrypted_count += 1

        outcome = _maybe_activate_profile(mapping, env_file, profile)
        if outcome == "activated":
            activated_count += 1
        elif outcome == "error":
            activation_error_count += 1

    # === SUMMARY ===
    console.print()
    summary_lines = [
        f"Decrypted: {decrypted_count}",
        f"Skipped: {skipped_count}",
        f"Errors: {error_count}",
    ]
    if activated_count > 0:
        summary_lines.append(f"Activated: {activated_count}")
    if activation_error_count > 0:
        summary_lines.append(f"Activation errors: {activation_error_count}")
    console.print(
        Panel(
            "\n".join(summary_lines),
            title="Decrypt Summary",
            expand=False,
        )
    )

    # Decryption and activation are distinct failures — keep the messages
    # accurate so an activation failure on an already-plaintext file isn't
    # reported as "could not be decrypted" (#413).
    if error_count > 0:
        print_warning("Some files could not be decrypted")
    if activation_error_count > 0:
        print_warning("Some profile files could not be activated")
    if error_count > 0 or activation_error_count > 0:
        raise typer.Exit(code=1)

    # === STEP 3: PARTIAL ENCRYPTION (decrypt .secret files + optional merge) ===
    partial_decrypted = 0
    partial_merged = 0
    partial_skipped = 0
    partial_errors: list[str] = []

    config_path = _find_config_path(config_file)
    partial_config = None
    if config_path:
        from envdrift.config import ConfigNotFoundError
        from envdrift.config import load_config as load_envdrift_config

        try:
            partial_config = load_envdrift_config(config_path)
        except ConfigNotFoundError:
            partial_config = None
        except (OSError, AttributeError, KeyError) as exc:
            print_warning(f"Unable to read config for partial encryption: {exc}")
            partial_config = None

    if partial_config and partial_config.partial_encryption.enabled:
        console.print()
        console.print("[bold cyan]Step 3:[/bold cyan] Processing partial encryption files...")
        console.print()

        from envdrift.core.partial_encryption import (
            PartialEncryptionError,
            pull_partial_encryption,
            pull_secrets_only,
        )

        # When --merge writes combined files with DECRYPTED secrets, they must be
        # gitignored just like `push` does — otherwise a routine `git add .` stages
        # plaintext secrets. Mirror push's _ensure_combined_gitignore (which also
        # protects the dotenvx .env.keys file) before writing anything (see #413).
        if merge:
            from envdrift.cli_commands.partial import _ensure_combined_gitignore

            _ensure_combined_gitignore(partial_config.partial_encryption.environments)

        for env_config in partial_config.partial_encryption.environments:
            if env_config.secrets_only:
                try:
                    result = pull_secrets_only(env_config)
                except PartialEncryptionError as e:
                    console.print(
                        f"  [red]![/red] {env_config.secrets_dir} [red]- error: {e}[/red]"
                    )
                    partial_errors.append(f"{env_config.name}: {e}")
                    continue
                if result["decrypted"]:
                    console.print(
                        f"  [green]+[/green] {env_config.secrets_dir} "
                        f"[dim]- {result['decrypted']} file(s) decrypted[/dim]"
                    )
                    partial_decrypted += result["decrypted"]
                else:
                    console.print(
                        f"  [dim]=[/dim] {env_config.secrets_dir} "
                        f"[dim]- skipped (already decrypted)[/dim]"
                    )
                partial_skipped += result["already_decrypted"]
                continue

            secret_file = Path(env_config.secret_file)

            if not secret_file.exists():
                console.print(f"  [dim]=[/dim] {secret_file} [dim]- skipped (not found)[/dim]")
                partial_skipped += 1
                continue

            try:
                was_decrypted, _ = pull_partial_encryption(env_config)

                if was_decrypted:
                    console.print(f"  [green]+[/green] {secret_file} [dim]- decrypted[/dim]")
                    partial_decrypted += 1
                else:
                    console.print(
                        f"  [dim]=[/dim] {secret_file} [dim]- skipped (already decrypted)[/dim]"
                    )
                    partial_skipped += 1

                # Merge if requested
                if merge:
                    combined_file = Path(env_config.combined_file)
                    try:
                        _write_merged_combined_file(
                            Path(env_config.clear_file), secret_file, combined_file
                        )
                    except (OSError, UnicodeDecodeError) as e:
                        console.print(
                            f"  [red]![/red] {combined_file} [red]- merge failed: {e}[/red]"
                        )
                        partial_errors.append(f"{env_config.name}: {e}")
                        continue
                    console.print(
                        f"  [cyan]→[/cyan] {combined_file} [dim]- merged (decrypted)[/dim]"
                    )
                    partial_merged += 1

            except PartialEncryptionError as e:
                console.print(f"  [red]![/red] {secret_file} [red]- error: {e}[/red]")
                partial_errors.append(f"{env_config.name}: {e}")

        # Partial encryption summary
        console.print()
        partial_summary = [
            f"Decrypted: {partial_decrypted}",
            f"Skipped: {partial_skipped}",
        ]
        if merge:
            partial_summary.append(f"Merged: {partial_merged}")
        if partial_errors:
            partial_summary.append(f"Errors: {len(partial_errors)}")

        console.print(
            Panel(
                "\n".join(partial_summary),
                title="Partial Encryption Summary",
                expand=False,
            )
        )

        if partial_errors:
            print_warning("Some partial encryption files had errors")
            for err in partial_errors:
                console.print(f"  • {err}")
            raise typer.Exit(code=1)

    console.print()
    print_success("Setup complete! Your environment files are ready to use.")


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
    for line in env_keys_file.read_text().splitlines():
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


def lock(
    config_file: Annotated[
        Path | None,
        typer.Option(
            "--config",
            "-c",
            help="Path to sync config file (TOML or legacy pair.txt format)",
        ),
    ] = None,
    provider: Annotated[
        str | None,
        typer.Option("--provider", "-p", help="Vault provider: azure, aws, hashicorp, gcp"),
    ] = None,
    vault_url: Annotated[
        str | None,
        typer.Option("--vault-url", help="Vault URL (Azure Key Vault or HashiCorp Vault)"),
    ] = None,
    region: Annotated[
        str | None,
        typer.Option("--region", help="AWS region (default: us-east-1)"),
    ] = None,
    project_id: Annotated[
        str | None,
        typer.Option("--project-id", help="GCP project ID (Secret Manager)"),
    ] = None,
    force: Annotated[
        bool,
        typer.Option("--force", "-f", help="Force encryption without prompting"),
    ] = False,
    profile: Annotated[
        str | None,
        typer.Option("--profile", help="Only process mappings for this profile"),
    ] = None,
    verify_vault: Annotated[
        bool,
        typer.Option("--verify-vault", help="Verify local keys match vault before encrypting"),
    ] = False,
    sync_keys: Annotated[
        bool,
        typer.Option(
            "--sync-keys", help="Sync keys from vault before encrypting (implies --verify-vault)"
        ),
    ] = False,
    check_only: Annotated[
        bool,
        typer.Option("--check", help="Only check encryption status, don't encrypt"),
    ] = False,
    all_files: Annotated[
        bool,
        typer.Option(
            "--all",
            help="Include partial encryption files: encrypt .secret files and delete combined files",
        ),
    ] = False,
) -> None:
    """
    Verify keys and encrypt all env files (opposite of pull - prepares for commit).

    The lock command ensures your environment files are properly encrypted before
    committing. It can optionally verify that local keys match vault keys to prevent
    key drift, and then encrypts all decrypted .env files.

    This is the recommended command before committing changes to ensure:
    1. Local encryption keys are in sync with the team's vault keys
    2. All .env files are properly encrypted
    3. No plaintext secrets are accidentally committed

    Workflow:
    - With --verify-vault: Check if local .env.keys match vault secrets
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
    from envdrift.output.rich import print_service_sync_status, print_sync_result
    from envdrift.sync.config import SyncConfigError

    # If sync_keys is requested, it implies verify_vault
    if sync_keys:
        verify_vault = True

    sync_config, vault_client, effective_provider, _, _, _ = load_sync_config_and_client(
        config_file=config_file,
        provider=provider,
        vault_url=vault_url,
        region=region,
        project_id=project_id,
    )
    from envdrift.integrations.hook_check import ensure_git_hook_setup

    hook_errors = ensure_git_hook_setup(config_file=config_file)
    if hook_errors:
        for error in hook_errors:
            print_error(error)
        raise typer.Exit(code=1)

    # === FILTER MAPPINGS BY PROFILE ===
    from envdrift.sync.config import SyncConfig as SyncConfigClass
    from envdrift.sync.engine import SyncEngine, SyncMode, normalize_vault_key_value

    filtered_mappings = sync_config.filter_by_profile(profile)

    if not filtered_mappings:
        if profile:
            print_error(f"No mappings found for profile '{profile}'")
        else:
            print_warning("No non-profile mappings found. Use --profile to specify one.")
        raise typer.Exit(code=1)

    # Create a filtered config for the sync engine
    filtered_config = SyncConfigClass(
        mappings=filtered_mappings,
        default_vault_name=sync_config.default_vault_name,
        env_keys_filename=sync_config.env_keys_filename,
        max_workers=sync_config.max_workers,
        ephemeral_keys=sync_config.ephemeral_keys,
    )

    console.print()
    profile_info = f" (profile: {profile})" if profile else ""
    mode_str = "CHECK" if check_only else ("FORCE" if force else "Interactive")
    all_info = " | Including partial encryption" if all_files else ""
    console.print(f"[bold]Lock[/bold] - Verifying keys and encrypting env files{profile_info}")
    console.print(
        f"[dim]Provider: {effective_provider} | Mode: {mode_str} | Services: {len(filtered_mappings)}{all_info}[/dim]"
    )
    console.print()

    # Tracking for summary
    warnings: list[str] = []
    errors: list[str] = []
    partial_clear, _, partial_combined = _load_partial_encryption_paths(config_file)

    # === STEP 1: VERIFY/SYNC KEYS (OPTIONAL) ===
    if verify_vault:
        console.print("[bold cyan]Step 1:[/bold cyan] Verifying keys with vault...")
        console.print()

        if sync_keys:
            # Actually sync keys from vault
            mode = SyncMode(force_update=force)

            def progress_callback(msg: str) -> None:
                console.print(f"[dim]{msg}[/dim]")

            def prompt_callback(msg: str) -> bool:
                if force:
                    return True
                response = console.input(f"{msg} (y/N): ").strip().lower()
                return response in ("y", "yes")

            engine = SyncEngine(
                config=filtered_config,
                vault_client=vault_client,
                mode=mode,
                prompt_callback=prompt_callback,
                progress_callback=progress_callback,
            )

            try:
                sync_result = engine.sync_all()
            except (VaultError, SyncConfigError, SecretNotFoundError) as e:
                print_error(f"Key sync failed: {e}")
                raise typer.Exit(code=1) from None

            for service_result in sync_result.services:
                print_service_sync_status(service_result)

            print_sync_result(sync_result)

            if sync_result.has_errors:
                errors.append("Key synchronization had errors")
                if not force:
                    print_error("Cannot proceed with encryption due to key sync errors")
                    raise typer.Exit(code=1)
        else:
            # Just verify (compare local keys with vault)
            from envdrift.sync.operations import EnvKeysFile

            verification_issues = 0

            for mapping in filtered_mappings:
                effective_env = mapping.effective_environment
                env_keys_file = mapping.folder_path / (sync_config.env_keys_filename or ".env.keys")
                key_name = f"DOTENV_PRIVATE_KEY_{effective_env.upper()}"

                # Check if local key exists
                if not env_keys_file.exists():
                    console.print(
                        f"  [yellow]![/yellow] {mapping.folder_path} "
                        f"[yellow]- warning: .env.keys not found[/yellow]"
                    )
                    warnings.append(f"{mapping.folder_path}: .env.keys file missing")
                    continue

                local_keys = EnvKeysFile(env_keys_file)
                local_key = local_keys.read_key(key_name)

                if not local_key:
                    console.print(
                        f"  [yellow]![/yellow] {mapping.folder_path} "
                        f"[yellow]- warning: {key_name} not found in .env.keys[/yellow]"
                    )
                    warnings.append(f"{mapping.folder_path}: {key_name} missing from .env.keys")
                    continue

                # Fetch key from vault for comparison
                try:
                    vault_client.ensure_authenticated()
                    vault_secret = vault_client.get_secret(mapping.secret_name)

                    if not vault_secret or not vault_secret.value:
                        console.print(
                            f"  [yellow]![/yellow] {mapping.folder_path} "
                            f"[yellow]- warning: vault secret '{mapping.secret_name}' is empty[/yellow]"
                        )
                        warnings.append(f"{mapping.folder_path}: vault secret is empty")
                        continue

                    vault_value = vault_secret.value

                    # Parse the vault value identically to the sync engine /
                    # read_key (strip whitespace + surrounding quotes + a
                    # DOTENV_PRIVATE_KEY_*= prefix) so a quoted or prefixed vault
                    # value isn't reported as a false KEY MISMATCH (#413).
                    vault_key, vault_suffix = normalize_vault_key_value(vault_value)
                    # A key labeled for a different environment is a genuine
                    # mismatch, not a parse artifact.
                    suffix_ok = (
                        vault_suffix is None or vault_suffix.upper() == effective_env.upper()
                    )

                    # Compare keys
                    if suffix_ok and local_key == vault_key:
                        console.print(
                            f"  [green]✓[/green] {mapping.folder_path} "
                            f"[dim]- keys match vault[/dim]"
                        )
                    else:
                        console.print(
                            f"  [red]✗[/red] {mapping.folder_path} "
                            f"[red]- KEY MISMATCH: local key differs from vault![/red]"
                        )
                        errors.append(
                            f"{mapping.folder_path}: local key does not match vault "
                            f"(run 'envdrift lock --sync-keys' to fix)"
                        )
                        verification_issues += 1

                except SecretNotFoundError:
                    console.print(
                        f"  [yellow]![/yellow] {mapping.folder_path} "
                        f"[yellow]- warning: vault secret '{mapping.secret_name}' not found[/yellow]"
                    )
                    warnings.append(f"{mapping.folder_path}: vault secret not found")
                except VaultError as e:
                    console.print(
                        f"  [red]![/red] {mapping.folder_path} "
                        f"[red]- error: vault access failed: {e}[/red]"
                    )
                    errors.append(f"{mapping.folder_path}: vault error - {e}")

            console.print()

            if verification_issues > 0 and not force:
                print_error(
                    f"Found {verification_issues} key mismatch(es). "
                    "Run with --sync-keys to update local keys, or --force to encrypt anyway."
                )
                raise typer.Exit(code=1)

    # === STEP 2: ENCRYPT ENV FILES ===
    step_num = "Step 2" if verify_vault else "Step 1"
    console.print(f"[bold cyan]{step_num}:[/bold cyan] Encrypting environment files...")
    console.print()

    try:
        from envdrift.cli_commands import encryption_helpers
        from envdrift.encryption import (
            EncryptionBackendError,
            EncryptionNotFoundError,
            EncryptionProvider,
            detect_encryption_provider,
        )

        encryption_backend, backend_provider, encryption_config = (
            encryption_helpers.resolve_encryption_backend(config_file)
        )
        if not encryption_backend.is_installed():
            print_error(f"{encryption_backend.name} is not installed")
            console.print(encryption_backend.install_instructions())
            raise typer.Exit(code=1)
    except ValueError as e:
        print_error(f"Unsupported encryption backend: {e}")
        raise typer.Exit(code=1) from None

    # Canonical encryption-state predicate, shared with the push paths (#470).
    from envdrift.core.partial_encryption import has_plaintext_secret_value

    sops_encrypt_kwargs = {}
    if backend_provider == EncryptionProvider.SOPS:
        sops_encrypt_kwargs = encryption_helpers.build_sops_encrypt_kwargs(encryption_config)

    encrypted_count = 0
    skipped_count = 0
    error_count = 0
    already_encrypted_count = 0
    encrypt_tasks: list[_EncryptTask] = []
    dotenvx_locks: dict[Path, Lock] = {}

    for mapping in filtered_mappings:
        try:
            detection = resolve_mapping_env_file(mapping)
        except ValueError as e:
            console.print(
                f"  [red]![/red] {mapping.folder_path} [red]- invalid env_file: {e}[/red]"
            )
            errors.append(f"{mapping.folder_path}: invalid env_file - {e}")
            error_count += 1
            continue
        effective_env = detection.environment or mapping.effective_environment
        env_file = (
            detection.path
            if detection.path is not None
            else mapping.folder_path / f".env.{effective_env}"
        )

        # Check if env file exists
        if detection.status != "found" or detection.path is None:
            if detection.status == "multiple_found":
                console.print(
                    f"  [yellow]?[/yellow] {mapping.folder_path} "
                    f"[yellow]- skipped (multiple .env.* files, specify environment)[/yellow]"
                )
                warnings.append(f"{mapping.folder_path}: multiple .env files found")
            else:
                console.print(f"  [dim]=[/dim] {env_file} [dim]- skipped (not found)[/dim]")
                warnings.append(f"{env_file}: file not found")
            skipped_count += 1
            continue

        resolved_env_file = env_file.resolve()
        if resolved_env_file in partial_combined and not all_files:
            console.print(
                f"  [dim]=[/dim] {env_file} "
                "[dim]- skipped (partial encryption combined file, use --all to include)[/dim]"
            )
            warnings.append(
                f"{env_file}: use envdrift lock --all or envdrift push for partial encryption"
            )
            skipped_count += 1
            continue
        if resolved_env_file in partial_clear and not all_files:
            console.print(
                f"  [dim]=[/dim] {env_file} [dim]- skipped (partial encryption clear file)[/dim]"
            )
            warnings.append(
                f"{env_file}: use envdrift lock --all or envdrift push for partial encryption"
            )
            skipped_count += 1
            continue

        # Check if .env.keys file exists (needed for encryption)
        env_keys_file = mapping.folder_path / (sync_config.env_keys_filename or ".env.keys")
        if backend_provider == EncryptionProvider.DOTENVX and not env_keys_file.exists():
            console.print(
                f"  [yellow]![/yellow] {env_file} "
                f"[yellow]- warning: no .env.keys file, will generate new key[/yellow]"
            )
            warnings.append(f"{env_file}: no .env.keys file found, new key will be generated")

        _normalize_mapped_dotenvx_metadata(
            env_file,
            env_keys_file,
            effective_env,
            backend_provider,
            check_only=check_only,
        )

        # Check if file is already encrypted
        content = env_file.read_text()
        if not encryption_helpers.is_encrypted_content(
            backend_provider, encryption_backend, content
        ):
            detected_provider = detect_encryption_provider(env_file)
            if detected_provider and detected_provider != backend_provider:
                if (
                    detected_provider == EncryptionProvider.DOTENVX
                    and backend_provider != EncryptionProvider.DOTENVX
                ):
                    console.print(
                        f"  [red]![/red] {env_file} "
                        f"[red]- encrypted with dotenvx, but config uses "
                        f"{backend_provider.value}[/red]"
                    )
                    errors.append(
                        f"{env_file}: encrypted with dotenvx, but config uses "
                        f"{backend_provider.value}"
                    )
                    error_count += 1
                    continue
                console.print(
                    f"  [dim]=[/dim] {env_file} "
                    f"[dim]- skipped (encrypted with {detected_provider.value}, "
                    f"config uses {backend_provider.value})[/dim]"
                )
                warnings.append(
                    f"{env_file}: encrypted with {detected_provider.value}, "
                    f"config uses {backend_provider.value}"
                )
                skipped_count += 1
                continue
        else:
            # Canonical encryption-state predicate (#470), backend-agnostic: the
            # file is fully encrypted only when no plaintext secret value
            # remains. has_plaintext_secret_value ignores comments, the
            # plaintext DOTENV_PUBLIC_KEY_* header and SOPS's sops_* metadata
            # trailer, so a small fully-encrypted file is no longer mis-flagged
            # as partial (the old N/(N+1) ratio), and a mixed file holding one
            # freshly added plaintext secret is never blessed "already
            # encrypted" (the old >=90% ratio) — for dotenvx AND SOPS alike.
            if has_plaintext_secret_value(env_file):
                warnings.append(f"{env_file}: partially encrypted, plaintext values remain")
                if check_only:
                    # Dry run (--check): report only — never the active voice.
                    console.print(
                        f"  [cyan]?[/cyan] {env_file} "
                        "[dim]- would re-encrypt (plaintext values remain)[/dim]"
                    )
                    encrypted_count += 1
                    continue
                # Mixed state: ciphertext present but at least one plaintext
                # secret remains - re-encrypt to cover the new values.
                console.print(
                    f"  [yellow]~[/yellow] {env_file} "
                    "[dim]- partially encrypted (plaintext values remain), "
                    "re-encrypting...[/dim]"
                )
            else:
                if backend_provider == EncryptionProvider.DOTENVX:
                    # Fully encrypted. Check if the key name matches the
                    # expected environment - this handles the case where a file
                    # was renamed (e.g., .env.local -> .env.localenv) but the
                    # .env.keys still has the old key name.
                    expected_key_name = f"DOTENV_PRIVATE_KEY_{effective_env.upper()}"
                    old_key_name = _find_stale_private_key_name(env_keys_file, expected_key_name)

                    if old_key_name:
                        if check_only:
                            # Dry run: report the intended re-key without
                            # touching the env file or .env.keys on disk (#303).
                            console.print(
                                f"  [cyan]?[/cyan] {env_file} "
                                f"[dim]- would re-key ({old_key_name} -> "
                                f"{expected_key_name})[/dim]"
                            )
                            warnings.append(
                                f"{env_file}: key name mismatch, would re-encrypt to "
                                f"generate {expected_key_name}"
                            )
                            encrypted_count += 1
                            continue
                        console.print(
                            f"  [yellow]~[/yellow] {env_file} "
                            f"[dim]- key name mismatch ({old_key_name} -> {expected_key_name}), "
                            "re-encrypting...[/dim]"
                        )
                        warnings.append(
                            f"{env_file}: key name mismatch, re-encrypting to generate "
                            f"{expected_key_name}"
                        )
                        # Decrypt first, then re-encrypt (generates the new key)
                        rekey_ok, rekey_error = _rekey_dotenvx_file(
                            env_file, encryption_backend, sops_encrypt_kwargs
                        )
                        if not rekey_ok:
                            console.print(f"  [red]![/red] {env_file} [red]- {rekey_error}[/red]")
                            errors.append(f"{env_file}: {rekey_error}")
                            error_count += 1
                            continue
                        _normalize_mapped_dotenvx_metadata(
                            env_file,
                            env_keys_file,
                            effective_env,
                            backend_provider,
                        )
                        console.print(
                            f"  [green]+[/green] {env_file} [dim]- re-encrypted with new key[/dim]"
                        )
                        encrypted_count += 1
                        continue

                # A fully-encrypted SOPS file skips backend.encrypt(), so the
                # recipient check inside it never runs — verify here that every
                # recipient configured in envdrift.toml is recorded in the
                # file's metadata. Otherwise `lock` would print "ready to
                # commit" while a newly added teammate silently never got
                # access (#475) — and disagree with `envdrift encrypt`, which
                # fails loudly on the same file + config.
                if backend_provider == EncryptionProvider.SOPS and sops_encrypt_kwargs:
                    from envdrift.encryption.sops import SOPSEncryptionBackend

                    missing = (
                        encryption_backend.missing_recipients(content, **sops_encrypt_kwargs)
                        if isinstance(encryption_backend, SOPSEncryptionBackend)
                        else []
                    )
                    if missing:
                        recipients = ", ".join(missing)
                        console.print(
                            f"  [red]![/red] {env_file} "
                            f"[red]- encrypted, but SOPS metadata is missing requested "
                            f"recipient(s): {recipients}[/red]"
                        )
                        errors.append(
                            f"{env_file}: SOPS metadata is missing requested "
                            f"recipient(s): {recipients} - re-running encrypt cannot add "
                            f"recipients; use `sops rotate --add-age <recipient>` or "
                            f"`sops updatekeys`, or decrypt and re-encrypt"
                        )
                        error_count += 1
                        continue

                console.print(f"  [dim]=[/dim] {env_file} [dim]- skipped (already encrypted)[/dim]")
                already_encrypted_count += 1
                continue

        if check_only:
            # Just report what would be encrypted
            console.print(f"  [cyan]?[/cyan] {env_file} [dim]- would be encrypted[/dim]")
            encrypted_count += 1
            continue

        # === SMART ENCRYPTION: Skip re-encryption if content unchanged ===
        # This addresses dotenvx's non-deterministic encryption (ECIES) which
        # produces different ciphertext each time, even for identical plaintext.
        # We compare the current file with the decrypted version from git;
        # if unchanged, restore the original encrypted file to avoid git noise.
        smart_enabled = encryption_config.smart_encryption if encryption_config else False
        should_skip, skip_reason = encryption_helpers.should_skip_reencryption(
            env_file, encryption_backend, enabled=smart_enabled
        )
        if should_skip:
            console.print(f"  [dim]=[/dim] {env_file} [dim]- skipped ({skip_reason})[/dim]")
            already_encrypted_count += 1
            continue

        # Prompt before encrypting (unless force mode)
        if not force:
            response = console.input(f"  Encrypt {env_file}? (y/N): ").strip().lower()
            if response not in ("y", "yes"):
                console.print(f"  [dim]=[/dim] {env_file} [dim]- skipped (user declined)[/dim]")
                skipped_count += 1
                continue

        if force:
            encrypt_tasks.append(
                _EncryptTask(
                    mapping=mapping,
                    env_file=env_file,
                    env_keys_file=env_keys_file,
                    effective_environment=effective_env,
                )
            )
            if backend_provider == EncryptionProvider.DOTENVX:
                lock_key = env_keys_file.resolve()
                if lock_key not in dotenvx_locks:
                    dotenvx_locks[lock_key] = Lock()
            continue

        # Perform encryption
        try:
            result = encryption_backend.encrypt(env_file.resolve(), **sops_encrypt_kwargs)
            if not result.success:
                console.print(f"  [red]![/red] {env_file} [red]- error: {result.message}[/red]")
                errors.append(f"{env_file}: encryption failed - {result.message}")
                error_count += 1
                continue
            _normalize_mapped_dotenvx_metadata(
                env_file,
                env_keys_file,
                effective_env,
                backend_provider,
            )
            console.print(f"  [green]+[/green] {env_file} [dim]- encrypted[/dim]")
            encrypted_count += 1

        except (EncryptionNotFoundError, EncryptionBackendError) as e:
            console.print(f"  [red]![/red] {env_file} [red]- error: {e}[/red]")
            errors.append(f"{env_file}: encryption failed - {e}")
            error_count += 1

    if force and encrypt_tasks:
        max_workers = _normalize_max_workers(sync_config.max_workers)

        def _encrypt_task(task: _EncryptTask):
            try:
                if backend_provider == EncryptionProvider.DOTENVX:
                    lock_key = task.env_keys_file.resolve()
                    lock = dotenvx_locks.get(lock_key)
                    if lock:
                        with lock:
                            result = encryption_backend.encrypt(
                                task.env_file.resolve(), **sops_encrypt_kwargs
                            )
                    else:
                        result = encryption_backend.encrypt(
                            task.env_file.resolve(), **sops_encrypt_kwargs
                        )
                else:
                    result = encryption_backend.encrypt(
                        task.env_file.resolve(), **sops_encrypt_kwargs
                    )
                return task, result, None
            except (EncryptionNotFoundError, EncryptionBackendError) as e:
                return task, None, e

        for task, result, error in _run_tasks(encrypt_tasks, _encrypt_task, max_workers):
            env_file = task.env_file
            if error is not None:
                console.print(f"  [red]![/red] {env_file} [red]- error: {error}[/red]")
                errors.append(f"{env_file}: encryption failed - {error}")
                error_count += 1
                continue
            if result is None or not result.success:
                message = result.message if result else "unknown error"
                console.print(f"  [red]![/red] {env_file} [red]- error: {message}[/red]")
                errors.append(f"{env_file}: encryption failed - {message}")
                error_count += 1
                continue
            _normalize_mapped_dotenvx_metadata(
                task.env_file,
                task.env_keys_file,
                task.effective_environment,
                backend_provider,
            )
            console.print(f"  [green]+[/green] {env_file} [dim]- encrypted[/dim]")
            encrypted_count += 1

    # === STEP 3: PROCESS PARTIAL ENCRYPTION FILES (OPTIONAL) ===
    partial_encrypted_count = 0
    combined_deleted_count = 0
    secrets_only_skipped = 0
    # (env name, pending file count) for skipped secrets-only environments that
    # still hold plaintext - the final banner/exit must not overclaim (#470).
    secrets_only_pending: list[tuple[str, int]] = []

    if all_files:
        step_num = "Step 3" if verify_vault else "Step 2"
        console.print()
        console.print(f"[bold cyan]{step_num}:[/bold cyan] Processing partial encryption files...")
        console.print()

        # Load partial encryption config using shared helper
        from envdrift.config import ConfigNotFoundError
        from envdrift.config import load_config as load_envdrift_config
        from envdrift.core.partial_encryption import (
            PartialEncryptionError,
            encrypt_secret_file,
            is_fully_encrypted,
            push_secrets_only,
        )

        config_path = _find_config_path(config_file)

        if config_path:
            try:
                envdrift_cfg = load_envdrift_config(config_path)
                if envdrift_cfg.partial_encryption.enabled:
                    for env_config in envdrift_cfg.partial_encryption.environments:
                        if env_config.secrets_only:
                            # Secrets-only environments are encrypted in place with
                            # dotenvx via `envdrift push` and have no combined file.
                            # Skip them here so Path("") does not collapse to the
                            # current directory and get encrypted/deleted.
                            console.print(
                                f"  [dim]=[/dim] {env_config.secrets_dir} "
                                "[dim]- skipped (secrets-only, managed by 'envdrift push')[/dim]"
                            )
                            secrets_only_skipped += 1
                            # The skip is by design, but the final "ready to
                            # commit" banner/exit 0 must not paper over plaintext
                            # knowingly left on disk (#470). Reuse push's dry run
                            # (check=True touches nothing) to count the files a
                            # real push would still need to encrypt.
                            try:
                                stats = push_secrets_only(env_config, check=True)
                            except PartialEncryptionError as e:
                                warnings.append(
                                    f"{env_config.name}: skipped secrets-only environment "
                                    f"could not be checked - {e}"
                                )
                                continue
                            pending = int(stats["encrypted"])
                            if pending:
                                secrets_only_pending.append((env_config.name, pending))
                            continue
                        secret_file = Path(env_config.secret_file)
                        combined_file = Path(env_config.combined_file)

                        # Encrypt the .secret file unless it is FULLY encrypted.
                        # is_fully_encrypted is the same predicate `envdrift push`
                        # uses: ciphertext present AND no leftover plaintext secret
                        # value. The old any-ciphertext check skipped a MIXED
                        # .secret (one encrypted value + one fresh plaintext) and
                        # shipped the new secret in cleartext (#470).
                        # enc_state gates the combined-file deletion below:
                        # only a successful / already-encrypted .secret may have
                        # its combined artifact removed (#507 review). Routing
                        # the encrypt through encrypt_secret_file() keeps the
                        # canonical partial-encryption lifecycle: read-back
                        # verification and clearing the skip-worktree bit a
                        # pull-partial left behind, exactly like `envdrift push`.
                        enc_state = "missing"
                        if secret_file.exists():
                            if not is_fully_encrypted(secret_file):
                                if check_only:
                                    console.print(
                                        f"  [cyan]?[/cyan] {secret_file} "
                                        "[dim]- would be encrypted[/dim]"
                                    )
                                    partial_encrypted_count += 1
                                    enc_state = "encrypted"
                                else:
                                    try:
                                        encrypt_secret_file(env_config)
                                        console.print(
                                            f"  [green]+[/green] {secret_file} "
                                            "[dim]- encrypted[/dim]"
                                        )
                                        partial_encrypted_count += 1
                                        enc_state = "encrypted"
                                    except PartialEncryptionError as e:
                                        console.print(
                                            f"  [red]![/red] {secret_file} [red]- error: {e}[/red]"
                                        )
                                        errors.append(f"{secret_file}: encryption failed - {e}")
                                        error_count += 1
                                        enc_state = "failed"
                            else:
                                if not check_only:
                                    # Already fully encrypted: still run the
                                    # canonical no-op path so a stale
                                    # skip-worktree bit is lifted (#507 review).
                                    encrypt_secret_file(env_config)
                                console.print(
                                    f"  [dim]=[/dim] {secret_file} "
                                    "[dim]- skipped (already encrypted)[/dim]"
                                )
                                already_encrypted_count += 1
                                enc_state = "already"
                        else:
                            console.print(
                                f"  [dim]=[/dim] {secret_file} [dim]- skipped (not found)[/dim]"
                            )

                        # Delete the combined file ONLY when the .secret is in a
                        # good state: deleting it after a failed encryption (or
                        # with no .secret source at all) would destroy the one
                        # remaining runtime artifact while plaintext lingers
                        # (#507 review; same data-loss class as #471).
                        if combined_file.exists():
                            if enc_state in ("encrypted", "already"):
                                if check_only:
                                    console.print(
                                        f"  [cyan]?[/cyan] {combined_file} "
                                        "[dim]- would be deleted[/dim]"
                                    )
                                    combined_deleted_count += 1
                                else:
                                    try:
                                        combined_file.unlink()
                                        console.print(
                                            f"  [yellow]-[/yellow] {combined_file} "
                                            "[dim]- deleted (combined file)[/dim]"
                                        )
                                        combined_deleted_count += 1
                                    except OSError as e:
                                        console.print(
                                            f"  [red]![/red] {combined_file} "
                                            f"[red]- delete failed: {e}[/red]"
                                        )
                                        errors.append(f"{combined_file}: delete failed - {e}")
                                        error_count += 1
                            else:
                                reason = (
                                    "encryption failed"
                                    if enc_state == "failed"
                                    else "no .secret source"
                                )
                                console.print(
                                    f"  [yellow]![/yellow] {combined_file} "
                                    f"[dim]- kept ({reason})[/dim]"
                                )
                else:
                    console.print("  [dim]Partial encryption not enabled in config[/dim]")
            except ConfigNotFoundError:
                print_warning("Could not find partial encryption config")
            except (OSError, AttributeError, KeyError) as e:
                # A failure ANYWHERE in the partial step (unreadable .secret,
                # broken config types, ...) must not melt into a warning under
                # the green "ready to commit" banner with exit 0 — the partial
                # environments were NOT processed (#507 review follow-up).
                print_warning(f"Partial encryption step failed: {e}")
                errors.append(f"partial encryption step failed: {e}")
                error_count += 1

    # === SUMMARY ===
    console.print()
    summary_lines = []

    if check_only:
        summary_lines.append(f"Would encrypt: {encrypted_count}")
    else:
        summary_lines.append(f"Encrypted: {encrypted_count}")

    summary_lines.append(f"Already encrypted: {already_encrypted_count}")
    summary_lines.append(f"Skipped: {skipped_count}")
    summary_lines.append(f"Errors: {error_count}")

    if all_files:
        if check_only:
            summary_lines.append(f"Partial secrets to encrypt: {partial_encrypted_count}")
            summary_lines.append(f"Combined files to delete: {combined_deleted_count}")
        else:
            summary_lines.append(f"Partial secrets encrypted: {partial_encrypted_count}")
            summary_lines.append(f"Combined files deleted: {combined_deleted_count}")
        if secrets_only_skipped:
            summary_lines.append(f"Secrets-only environments skipped: {secrets_only_skipped}")

    console.print(
        Panel(
            "\n".join(summary_lines),
            title="Lock Summary",
            expand=False,
        )
    )

    # Print warnings
    if warnings:
        console.print()
        console.print("[bold yellow]Warnings:[/bold yellow]")
        for warning in warnings:
            console.print(f"  [yellow]•[/yellow] {warning}")

    # Print errors
    if errors:
        console.print()
        console.print("[bold red]Errors:[/bold red]")
        for error in errors:
            console.print(f"  [red]•[/red] {error}")

    if error_count > 0 or errors:
        print_warning("Some files could not be encrypted or had issues")
        raise typer.Exit(code=1)

    console.print()
    if secrets_only_pending:
        # Truthful result (#470): these environments were knowingly skipped
        # (they are managed by 'envdrift push'), but they still hold plaintext
        # secrets - no green "ready to commit" banner, no exit 0.
        pending_total = sum(count for _, count in secrets_only_pending)
        pending_names = ", ".join(name for name, _ in secrets_only_pending)
        print_warning(
            f"Skipped secrets-only environment(s) ({pending_names}) still have "
            f"{pending_total} file(s) needing encryption. "
            "Run 'envdrift push' to encrypt them."
        )
        raise typer.Exit(code=1)
    if check_only:
        # Partial-encryption secrets pending under --all count too: a dry run
        # that reports "would be encrypted" must not exit 0 (#470).
        pending_check = encrypted_count + partial_encrypted_count
        if pending_check > 0:
            # In check mode, if files would be encrypted, this is a failure
            # (useful for CI/pre-commit hooks to ensure all files are encrypted)
            rerun_cmd = "envdrift lock --all" if all_files else "envdrift lock"
            print_warning(
                f"Found {pending_check} file(s) that need encryption. "
                f"Run '{rerun_cmd}' to encrypt them."
            )
            raise typer.Exit(code=1)
        else:
            print_success("Check complete! All files are already encrypted.")
    else:
        print_success("Lock complete! Your environment files are encrypted and ready to commit.")
