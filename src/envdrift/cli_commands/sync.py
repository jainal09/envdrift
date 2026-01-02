"""Vault sync-related commands for envdrift."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any

import typer
from rich.panel import Panel

from envdrift.env_files import detect_env_file
from envdrift.output.rich import console, print_error, print_success, print_warning
from envdrift.vault.base import SecretNotFoundError, VaultError

if TYPE_CHECKING:
    from envdrift.sync.config import SyncConfig


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
                    profile=m.profile,
                    activate_to=Path(m.activate_to) if m.activate_to else None,
                )
                for m in vault_sync.mappings
            ],
            default_vault_name=vault_sync.default_vault_name,
            env_keys_filename=vault_sync.env_keys_filename,
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


def _get_dotenvx_auto_install(config_file: Path | None) -> bool:
    import tomllib

    from envdrift.config import ConfigNotFoundError, find_config, load_config

    config_path = None
    if config_file is not None and config_file.suffix.lower() == ".toml":
        config_path = config_file
    elif config_file is None:
        config_path = find_config()

    if not config_path:
        return False

    try:
        envdrift_config = load_config(config_path)
    except (ConfigNotFoundError, tomllib.TOMLDecodeError):
        return False

    encryption_config = getattr(envdrift_config, "encryption", None)
    if not encryption_config:
        return False

    return encryption_config.dotenvx_auto_install


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
    except (VaultError, SyncConfigError, SecretNotFoundError) as e:
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
    console.print(f"[bold]Pull[/bold] - Syncing keys and decrypting env files{profile_info}")
    console.print(f"[dim]Provider: {effective_provider} | Services: {len(filtered_mappings)}[/dim]")
    console.print()

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

    # === STEP 2: DECRYPT ENV FILES ===
    console.print()
    console.print("[bold cyan]Step 2:[/bold cyan] Decrypting environment files...")
    console.print()

    try:
        from envdrift.cli_commands.encryption_helpers import (
            is_encrypted_content,
            resolve_encryption_backend,
        )
        from envdrift.encryption import (
            EncryptionBackendError,
            EncryptionNotFoundError,
            EncryptionProvider,
            detect_encryption_provider,
        )

        encryption_backend, backend_provider, _ = resolve_encryption_backend(config_file)
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

    for mapping in filtered_mappings:
        effective_env = mapping.effective_environment
        env_file = mapping.folder_path / f".env.{effective_env}"

        if not env_file.exists():
            # Try to auto-detect .env.* file
            detection = detect_env_file(mapping.folder_path)
            if detection.status == "found" and detection.path is not None:
                env_file = detection.path
            elif detection.status == "multiple_found":
                console.print(
                    f"  [yellow]?[/yellow] {mapping.folder_path} "
                    f"[yellow]- skipped (multiple .env.* files, specify environment)[/yellow]"
                )
                skipped_count += 1
                continue
            else:
                console.print(f"  [dim]=[/dim] {env_file} [dim]- skipped (not found)[/dim]")
                skipped_count += 1
                continue

        # Check if file is encrypted
        content = env_file.read_text()
        if not is_encrypted_content(backend_provider, encryption_backend, content):
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
            continue

        try:
            result = encryption_backend.decrypt(env_file.resolve())
            if not result.success:
                console.print(f"  [red]![/red] {env_file} [red]- error: {result.message}[/red]")
                error_count += 1
                continue

            console.print(f"  [green]+[/green] {env_file} [dim]- decrypted[/dim]")
            decrypted_count += 1

            # Activate profile: copy decrypted file to activate_to path if configured
            if profile and mapping.profile == profile and mapping.activate_to:
                activate_path = (mapping.folder_path / mapping.activate_to).resolve()
                # Validate path is within folder_path to prevent directory traversal
                try:
                    activate_path.relative_to(mapping.folder_path.resolve())
                except ValueError:
                    console.print(
                        f"  [red]![/red] {mapping.activate_to} [red]- invalid path (escapes folder)[/red]"
                    )
                    error_count += 1
                    continue

                try:
                    shutil.copy2(env_file, activate_path)
                    console.print(
                        f"  [cyan]→[/cyan] {activate_path} [dim]- activated from {env_file.name}[/dim]"
                    )
                    activated_count += 1
                except OSError as e:
                    console.print(
                        f"  [red]![/red] {activate_path} [red]- activation failed: {e}[/red]"
                    )
                    error_count += 1

        except (EncryptionNotFoundError, EncryptionBackendError) as e:
            console.print(f"  [red]![/red] {env_file} [red]- error: {e}[/red]")
            error_count += 1

    # === SUMMARY ===
    console.print()
    summary_lines = [
        f"Decrypted: {decrypted_count}",
        f"Skipped: {skipped_count}",
        f"Errors: {error_count}",
    ]
    if activated_count > 0:
        summary_lines.append(f"Activated: {activated_count}")
    console.print(
        Panel(
            "\n".join(summary_lines),
            title="Decrypt Summary",
            expand=False,
        )
    )

    if error_count > 0:
        print_warning("Some files could not be decrypted")
        raise typer.Exit(code=1)

    console.print()
    print_success("Setup complete! Your environment files are ready to use.")


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

    # === FILTER MAPPINGS BY PROFILE ===
    from envdrift.sync.config import SyncConfig as SyncConfigClass
    from envdrift.sync.engine import SyncEngine, SyncMode

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
    )

    console.print()
    profile_info = f" (profile: {profile})" if profile else ""
    mode_str = "CHECK" if check_only else ("FORCE" if force else "Interactive")
    console.print(f"[bold]Lock[/bold] - Verifying keys and encrypting env files{profile_info}")
    console.print(
        f"[dim]Provider: {effective_provider} | Mode: {mode_str} | Services: {len(filtered_mappings)}[/dim]"
    )
    console.print()

    # Tracking for summary
    warnings: list[str] = []
    errors: list[str] = []

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

                    # Parse vault value (format: KEY_NAME=value)
                    if "=" in vault_value and vault_value.startswith("DOTENV_PRIVATE_KEY"):
                        vault_key = vault_value.split("=", 1)[1]
                    else:
                        vault_key = vault_value

                    # Compare keys
                    if local_key == vault_key:
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
        from envdrift.integrations.dotenvx import DotenvxError, DotenvxWrapper

        dotenvx_auto_install = _get_dotenvx_auto_install(config_file)
        dotenvx = DotenvxWrapper(auto_install=dotenvx_auto_install)

        if not dotenvx.is_installed():
            print_error("dotenvx is not installed")
            console.print(dotenvx.install_instructions())
            raise typer.Exit(code=1)
    except ImportError:
        print_error("dotenvx integration not available")
        raise typer.Exit(code=1) from None

    encrypted_count = 0
    skipped_count = 0
    error_count = 0
    already_encrypted_count = 0

    for mapping in filtered_mappings:
        effective_env = mapping.effective_environment
        env_file = mapping.folder_path / f".env.{effective_env}"

        # Check if env file exists
        if not env_file.exists():
            # Try to auto-detect .env.* file
            detection = detect_env_file(mapping.folder_path)
            if detection.status == "found" and detection.path is not None:
                env_file = detection.path
            elif detection.status == "multiple_found":
                console.print(
                    f"  [yellow]?[/yellow] {mapping.folder_path} "
                    f"[yellow]- skipped (multiple .env.* files, specify environment)[/yellow]"
                )
                warnings.append(f"{mapping.folder_path}: multiple .env files found")
                skipped_count += 1
                continue
            else:
                console.print(f"  [dim]=[/dim] {env_file} [dim]- skipped (not found)[/dim]")
                warnings.append(f"{env_file}: file not found")
                skipped_count += 1
                continue

        # Check if .env.keys file exists (needed for encryption)
        env_keys_file = mapping.folder_path / (sync_config.env_keys_filename or ".env.keys")
        if not env_keys_file.exists():
            console.print(
                f"  [yellow]![/yellow] {env_file} "
                f"[yellow]- warning: no .env.keys file, will generate new key[/yellow]"
            )
            warnings.append(f"{env_file}: no .env.keys file found, new key will be generated")

        # Check if file is already encrypted
        content = env_file.read_text()
        if "encrypted:" in content.lower():
            # Check encryption ratio
            encrypted_lines = sum(
                1 for line in content.splitlines() if "encrypted:" in line.lower()
            )
            total_value_lines = sum(
                1
                for line in content.splitlines()
                if line.strip() and not line.strip().startswith("#") and "=" in line
            )

            if total_value_lines > 0:
                ratio = encrypted_lines / total_value_lines
                if ratio >= 0.9:  # 90%+ encrypted = fully encrypted
                    console.print(
                        f"  [dim]=[/dim] {env_file} [dim]- skipped (already encrypted)[/dim]"
                    )
                    already_encrypted_count += 1
                    continue
                else:
                    # Partially encrypted - re-encrypt to catch new values
                    console.print(
                        f"  [yellow]~[/yellow] {env_file} "
                        f"[dim]- partially encrypted ({int(ratio*100)}%), re-encrypting...[/dim]"
                    )
                    warnings.append(f"{env_file}: was only {int(ratio*100)}% encrypted")

        if check_only:
            # Just report what would be encrypted
            console.print(f"  [cyan]?[/cyan] {env_file} [dim]- would be encrypted[/dim]")
            encrypted_count += 1
            continue

        # Prompt before encrypting (unless force mode)
        if not force:
            response = console.input(f"  Encrypt {env_file}? (y/N): ").strip().lower()
            if response not in ("y", "yes"):
                console.print(f"  [dim]=[/dim] {env_file} [dim]- skipped (user declined)[/dim]")
                skipped_count += 1
                continue

        # Perform encryption
        try:
            dotenvx.encrypt(env_file.resolve())
            console.print(f"  [green]+[/green] {env_file} [dim]- encrypted[/dim]")
            encrypted_count += 1

        except DotenvxError as e:
            console.print(f"  [red]![/red] {env_file} [red]- error: {e}[/red]")
            errors.append(f"{env_file}: encryption failed - {e}")
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
    if check_only:
        if encrypted_count > 0:
            # In check mode, if files would be encrypted, this is a failure
            # (useful for CI/pre-commit hooks to ensure all files are encrypted)
            print_warning(
                f"Found {encrypted_count} file(s) that need encryption. "
                "Run 'envdrift lock' to encrypt them."
            )
            raise typer.Exit(code=1)
        else:
            print_success("Check complete! All files are already encrypted.")
    else:
        print_success("Lock complete! Your environment files are encrypted and ready to commit.")
