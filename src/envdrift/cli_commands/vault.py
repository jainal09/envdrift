"""Vault operations for envdrift."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from envdrift.env_files import detect_env_file
from envdrift.output.rich import console, print_error, print_success, print_warning


def vault_push(
    folder: Annotated[
        Path | None,
        typer.Argument(help="Service folder containing .env.keys file"),
    ] = None,
    secret_name: Annotated[
        str | None,
        typer.Argument(help="Name of the secret in the vault"),
    ] = None,
    env: Annotated[
        str | None,
        typer.Option(
            "--env", "-e", help="Environment suffix (e.g., 'soak' for DOTENV_PRIVATE_KEY_SOAK)"
        ),
    ] = None,
    direct: Annotated[
        bool,
        typer.Option(
            "--direct",
            help="Push a direct key-value pair (use with positional args: secret-name value)",
        ),
    ] = False,
    all_services: Annotated[
        bool,
        typer.Option(
            "--all",
            help="Push all secrets defined in sync config (skipping existing unless --force)",
        ),
    ] = False,
    force: Annotated[
        bool,
        typer.Option("--force", "-f", help="Push all secrets even if they already exist"),
    ] = False,
    skip_encrypt: Annotated[
        bool,
        typer.Option("--skip-encrypt", help="Skip encryption step, only push keys to vault"),
    ] = False,
    config: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Path to sync config file"),
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
) -> None:
    """
    Push encryption keys from local .env.keys files to cloud vaults.

    This is the reverse of `envdrift sync` - uploads local keys to vault.

    Three modes:

    1. From .env.keys file (Single Service):
       envdrift vault-push ./services/soak soak-machine --env soak

    2. Direct value:
       envdrift vault-push --direct soak-machine "DOTENV_PRIVATE_KEY_SOAK=abc123..."

    3. All Services (from config):
       envdrift vault-push --all

    Examples:
        # Push from .env.keys (reads DOTENV_PRIVATE_KEY_SOAK)
        envdrift vault-push ./services/soak soak-machine --env soak -p azure --vault-url https://myvault.vault.azure.net/

        # Push direct value
        envdrift vault-push --direct soak-machine "DOTENV_PRIVATE_KEY_SOAK=abc..." -p azure --vault-url https://myvault.vault.azure.net/

        # Push all missing secrets defined in config
        envdrift vault-push --all

        # Push all secrets, overwriting existing ones
        envdrift vault-push --all --force

        # Push all without encrypting (when files are already encrypted)
        envdrift vault-push --all --skip-encrypt
    """
    import contextlib
    import tomllib

    from envdrift.config import ConfigNotFoundError, find_config, load_config
    from envdrift.sync.operations import EnvKeysFile
    from envdrift.vault import VaultError, get_vault_client
    from envdrift.vault.base import SecretNotFoundError

    # Validate --skip-encrypt is only used with --all
    if skip_encrypt and not all_services:
        print_warning("--skip-encrypt is only applicable with --all mode, ignoring")

    # Validate --force is only used with --all
    if force and not all_services:
        print_warning("--force is only applicable with --all mode, ignoring")

    # --all mode implementation
    if all_services:
        from envdrift.cli_commands.encryption_helpers import (
            build_sops_encrypt_kwargs,
            is_encrypted_content,
            resolve_encryption_backend,
        )
        from envdrift.cli_commands.sync import load_sync_config_and_client
        from envdrift.encryption import (
            EncryptionBackendError,
            EncryptionNotFoundError,
            EncryptionProvider,
            detect_encryption_provider,
        )

        # Load sync config and client
        sync_config, client, effective_provider, _, _, _ = load_sync_config_and_client(
            config_file=config,
            provider=provider,
            vault_url=vault_url,
            region=region,
            project_id=project_id,
        )

        # Authenticate the vault client
        try:
            client.authenticate()
        except VaultError as e:
            print_error(str(e))
            raise typer.Exit(code=1) from None

        try:
            encryption_backend, backend_provider, encryption_config = resolve_encryption_backend(
                config
            )
        except ValueError as e:
            print_error(f"Unsupported encryption backend: {e}")
            raise typer.Exit(code=1) from None

        if not encryption_backend.is_installed():
            print_error(f"{encryption_backend.name} is not installed")
            console.print(encryption_backend.install_instructions())
            raise typer.Exit(code=1)

        sops_encrypt_kwargs = {}
        if backend_provider == EncryptionProvider.SOPS:
            sops_encrypt_kwargs = build_sops_encrypt_kwargs(encryption_config)

        console.print("[bold]Vault Push All[/bold]")
        console.print(f"Provider: {effective_provider}")
        console.print(f"Services: {len(sync_config.mappings)}")
        if force:
            console.print("[dim]Force: overwrite existing secrets (--force)[/dim]")
        if skip_encrypt:
            console.print("[dim]Encryption: skipped (--skip-encrypt)[/dim]")
        console.print()

        pushed_count = 0
        skipped_count = 0
        error_count = 0
        dotenvx_mismatch = False

        for mapping in sync_config.mappings:
            try:
                # Check/Detect .env file (unless --skip-encrypt, where we only need .env.keys)
                env_file = mapping.folder_path / f".env.{mapping.effective_environment}"
                effective_environment = mapping.effective_environment

                if not skip_encrypt:
                    if not env_file.exists():
                        # Auto-detect logic similar to sync
                        detected = detect_env_file(mapping.folder_path)
                        if detected.status == "found" and detected.path:
                            env_file = detected.path
                            if detected.environment:
                                effective_environment = detected.environment

                    if not env_file.exists():
                        console.print(
                            f"[dim]Skipped[/dim] {mapping.folder_path}: No .env file found"
                        )
                        skipped_count += 1
                        continue

                # Check encryption (unless --skip-encrypt)
                if not skip_encrypt:
                    content = env_file.read_text()
                    if not is_encrypted_content(backend_provider, encryption_backend, content):
                        detected_provider = detect_encryption_provider(env_file)
                        if detected_provider and detected_provider != backend_provider:
                            if (
                                detected_provider == EncryptionProvider.DOTENVX
                                and backend_provider != EncryptionProvider.DOTENVX
                            ):
                                print_error(
                                    f"{env_file}: encrypted with dotenvx, "
                                    f"but config uses {backend_provider.value}"
                                )
                                error_count += 1
                                dotenvx_mismatch = True
                                continue
                            console.print(
                                f"[dim]Skipped[/dim] {mapping.folder_path}: "
                                f"Encrypted with {detected_provider.value}, "
                                f"config uses {backend_provider.value}"
                            )
                            skipped_count += 1
                            continue

                        console.print(f"Encrypting {env_file} with {encryption_backend.name}...")
                        try:
                            result = encryption_backend.encrypt(env_file, **sops_encrypt_kwargs)
                            if not result.success:
                                print_error(result.message)
                                error_count += 1
                                continue
                        except (EncryptionNotFoundError, EncryptionBackendError) as e:
                            print_error(f"Failed to encrypt {env_file}: {e}")
                            error_count += 1
                            continue

                # Check if secret exists in vault
                if not force:
                    try:
                        client.get_secret(mapping.secret_name)
                        # If successful, secret exists
                        console.print(
                            f"[dim]Skipped[/dim] {mapping.folder_path}: "
                            f"Secret '{mapping.secret_name}' already exists"
                        )
                        skipped_count += 1
                        continue
                    except SecretNotFoundError:
                        # Secret missing, proceed to push
                        pass
                    except VaultError as e:
                        print_error(f"Vault error checking {mapping.secret_name}: {e}")
                        error_count += 1
                        continue

                # Read key to push
                env_keys_path = mapping.folder_path / sync_config.env_keys_filename
                if not env_keys_path.exists():
                    print_error(f"Skipped {mapping.folder_path}: .env.keys not found")
                    error_count += 1
                    continue

                env_keys = EnvKeysFile(env_keys_path)
                key_name = f"DOTENV_PRIVATE_KEY_{effective_environment.upper()}"
                key_value = env_keys.read_key(key_name)

                if not key_value:
                    print_error(f"Skipped {mapping.folder_path}: {key_name} not found in keys file")
                    error_count += 1
                    continue

                actual_value = f"{key_name}={key_value}"

                # Push
                client.set_secret(mapping.secret_name, actual_value)
                print_success(f"Pushed {mapping.secret_name}")
                pushed_count += 1

            except (VaultError, OSError, ValueError) as e:
                print_error(f"Error processing {mapping.folder_path}: {e}")
                error_count += 1

        console.print()
        console.print(
            f"Done. Pushed: {pushed_count}, Skipped: {skipped_count}, Errors: {error_count}"
        )
        if dotenvx_mismatch:
            raise typer.Exit(code=1)
        return

    # Normal/Direct mode preamble
    envdrift_config = None
    if config:
        with contextlib.suppress(ConfigNotFoundError, tomllib.TOMLDecodeError):
            envdrift_config = load_config(config)
    else:
        config_path = find_config()
        if config_path:
            with contextlib.suppress(ConfigNotFoundError, tomllib.TOMLDecodeError):
                envdrift_config = load_config(config_path)

    vault_config = getattr(envdrift_config, "vault", None)

    # Determine effective provider
    effective_provider = provider or getattr(vault_config, "provider", None)
    if not effective_provider:
        print_error("Vault provider required. Use --provider or configure in envdrift.toml")
        raise typer.Exit(code=1)

    # Determine effective vault URL
    effective_vault_url = vault_url
    if effective_vault_url is None and vault_config:
        if effective_provider == "azure":
            effective_vault_url = getattr(vault_config, "azure_vault_url", None)
        elif effective_provider == "hashicorp":
            effective_vault_url = getattr(vault_config, "hashicorp_url", None)

    # Determine effective region
    effective_region = region
    if effective_region is None and vault_config:
        effective_region = getattr(vault_config, "aws_region", None)

    effective_project_id = project_id
    if effective_project_id is None and vault_config:
        effective_project_id = getattr(vault_config, "gcp_project_id", None)

    # Validate provider-specific requirements
    if effective_provider in ("azure", "hashicorp") and not effective_vault_url:
        print_error(f"--vault-url required for {effective_provider}")
        raise typer.Exit(code=1)
    if effective_provider == "gcp" and not effective_project_id:
        print_error("--project-id required for gcp")
        raise typer.Exit(code=1)

    # Handle direct mode
    if direct:
        if not folder or not secret_name:
            print_error("Direct mode requires: envdrift vault-push --direct <secret-name> <value>")
            raise typer.Exit(code=1)
        # In direct mode, folder is actually the secret name, secret_name is the value
        actual_secret_name = str(folder)
        actual_value = secret_name
    else:
        # Normal mode: read from .env.keys
        if not folder or not secret_name or not env:
            print_error(
                "Required: envdrift vault-push <folder> <secret-name> --env <environment> (or use --all)"
            )
            raise typer.Exit(code=1)

        # Read the key from .env.keys
        env_keys_path = folder / ".env.keys"
        if not env_keys_path.exists():
            print_error(f"File not found: {env_keys_path}")
            raise typer.Exit(code=1)

        env_keys = EnvKeysFile(env_keys_path)
        key_name = f"DOTENV_PRIVATE_KEY_{env.upper()}"
        key_value = env_keys.read_key(key_name)

        if not key_value:
            print_error(f"Key '{key_name}' not found in {env_keys_path}")
            raise typer.Exit(code=1)

        actual_secret_name = secret_name
        actual_value = f"{key_name}={key_value}"

    # Create vault client
    try:
        vault_client_config = {}
        if effective_provider == "azure":
            vault_client_config["vault_url"] = effective_vault_url
        elif effective_provider == "aws":
            vault_client_config["region"] = effective_region or "us-east-1"
        elif effective_provider == "hashicorp":
            vault_client_config["url"] = effective_vault_url
        elif effective_provider == "gcp":
            vault_client_config["project_id"] = effective_project_id

        client = get_vault_client(effective_provider, **vault_client_config)
        client.authenticate()
    except ImportError as e:
        print_error(str(e))
        raise typer.Exit(code=1) from None
    except VaultError as e:
        print_error(f"Vault authentication failed: {e}")
        raise typer.Exit(code=1) from None

    # Push the secret
    try:
        result = client.set_secret(actual_secret_name, actual_value)
        print_success(f"Pushed secret '{actual_secret_name}' to {effective_provider} vault")
        if result.version:
            console.print(f"  Version: {result.version}")
    except VaultError as e:
        print_error(f"Failed to push secret: {e}")
        raise typer.Exit(code=1) from None
