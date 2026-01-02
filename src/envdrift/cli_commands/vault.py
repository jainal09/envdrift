"""Vault operations for envdrift."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from envdrift.output.rich import console, print_error, print_success


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
    provider: Annotated[
        str | None,
        typer.Option("--provider", "-p", help="Vault provider: azure, aws, hashicorp"),
    ] = None,
    vault_url: Annotated[
        str | None,
        typer.Option("--vault-url", help="Vault URL (Azure Key Vault or HashiCorp Vault)"),
    ] = None,
    region: Annotated[
        str | None,
        typer.Option("--region", help="AWS region (default: us-east-1)"),
    ] = None,
) -> None:
    """
    Push encryption keys from local .env.keys files to cloud vaults.

    This is the reverse of `envdrift sync` - uploads local keys to vault.

    Two modes:

    1. From .env.keys file:
       envdrift vault-push ./services/soak soak-machine --env soak

    2. Direct value:
       envdrift vault-push --direct soak-machine "DOTENV_PRIVATE_KEY_SOAK=abc123..."

    Examples:
        # Push from .env.keys (reads DOTENV_PRIVATE_KEY_SOAK)
        envdrift vault-push ./services/soak soak-machine --env soak -p azure --vault-url https://myvault.vault.azure.net/

        # Push direct value
        envdrift vault-push --direct soak-machine "DOTENV_PRIVATE_KEY_SOAK=abc..." -p azure --vault-url https://myvault.vault.azure.net/

        # Using config from envdrift.toml
        envdrift vault-push ./services/soak soak-machine --env soak
    """
    import contextlib
    import tomllib

    from envdrift.config import ConfigNotFoundError, find_config, load_config
    from envdrift.sync.operations import EnvKeysFile
    from envdrift.vault import VaultError, get_vault_client

    # Load config for defaults
    envdrift_config = None
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

    # Validate provider-specific requirements
    if effective_provider in ("azure", "hashicorp") and not effective_vault_url:
        print_error(f"--vault-url required for {effective_provider}")
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
            print_error("Required: envdrift vault-push <folder> <secret-name> --env <environment>")
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
