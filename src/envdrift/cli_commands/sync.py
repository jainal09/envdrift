"""Vault sync-related commands for envdrift."""

from __future__ import annotations

import shutil
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Lock
from typing import TYPE_CHECKING, Annotated, Any

import typer

from envdrift.output.rich import console, print_error, print_warning
from envdrift.sync.operations import atomic_write
from envdrift.utils import normalize_max_workers
from envdrift.vault.base import SecretNotFoundError, VaultError

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
    from envdrift.config import ConfigLoadError, ConfigNotFoundError, find_config, load_config
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
        except ConfigLoadError as e:
            # The loader's message is already the clean one-liner (TOML syntax
            # error / unreadable file / invalid section) (#443 #32, #491).
            print_error(str(e))
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
            except ConfigLoadError as e:
                # A discovered-but-broken config used to be a mere warning and
                # the command continued with defaults, silently changing
                # behavior; fail loudly instead (#491). The config WAS found,
                # so falling through to "No sync configuration found" would
                # hide the real problem (#488). load_config already folds TOML
                # syntax errors, unreadable files, and malformed sections into
                # one clean ConfigLoadError message.
                print_error(str(e))
                raise typer.Exit(code=1) from None

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
        # envdrift.toml is the PRIMARY documented config mechanism (README /
        # quickstart lead with it) — omitting it here steered users debugging a
        # missing config away from the recommended setup (#488).
        print_error(
            "No sync configuration found. Provide one of:\n"
            "  [vault.sync] section in envdrift.toml (auto-discovered)\n"
            "  [tool.envdrift.vault.sync] section in pyproject.toml\n"
            "  --config <file.toml>  TOML config with [vault.sync] section\n"
            "  --config <pair.txt>   Legacy format: secret=folder"
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

    Exits with code 1 on vault or sync configuration errors, when run with --ci if any sync
    errors occurred, whenever a --check-decryption test fails (even without --ci), and when
    --check-decryption is requested but dotenvx is not installed (nothing can be verified).
    """
    from envdrift.output.rich import print_service_sync_status, print_sync_result
    from envdrift.sync.config import SyncConfigError

    # An explicitly requested decryption check must be able to actually run.
    # Without dotenvx the engine degrades every per-service test to SKIPPED,
    # so the run would exit 0 having verified nothing — the same
    # cannot-verify-downgraded-to-success class as #473. Mirror
    # `decrypt --verify-vault`, which fails loudly for the identical state.
    if check_decryption and shutil.which("dotenvx") is None:
        print_error("dotenvx is not installed - cannot verify decryption")
        raise typer.Exit(code=1)

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
    # An explicitly requested decryption check that failed must fail the run
    # even without --ci: printing "Decryption: FAILED" and exiting 0 is an
    # untruthful verdict that scripts and pre-commit hooks silently miss (#473).
    if check_decryption and result.decryption_failed > 0:
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
    from envdrift.cli_commands.sync_helpers import LockRequest, LockRuntime, execute_lock

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
