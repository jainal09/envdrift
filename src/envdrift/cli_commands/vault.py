"""Vault CLI command definitions."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from envdrift.cli_commands.vault_helpers import (
    VaultPullRequest,
    VaultPushRequest,
    execute_vault_pull,
    execute_vault_push,
)

VAULT_PUSH_HELP = """Push encryption keys from local .env.keys files to cloud vaults.

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

VAULT_PULL_HELP = """Pull a single encryption key from a cloud vault into a local .env.keys file.

This is the config-free inverse of `envdrift vault-push` (single-service mode):
it fetches one secret, writes the DOTENV_PRIVATE_KEY_<ENV> key into
`<folder>/.env.keys`, and (by default) decrypts the matching `.env.<env>` file
so a single command onboards a developer with no TOML required.

Modes:

1. Pull key and decrypt (default):
   envdrift vault-pull ./services/soak soak-machine --env soak -p azure --vault-url https://myvault.vault.azure.net/

2. Pull key only (skip decryption):
   envdrift vault-pull ./services/soak soak-machine --env soak --no-decrypt -p azure --vault-url https://myvault.vault.azure.net/

Provider/URL/region/project-id may be omitted when they are configured in the
`[vault]` section of an envdrift.toml/pyproject.toml.

Examples:
    # Azure
    envdrift vault-pull . my-app-key --env production -p azure --vault-url https://myvault.vault.azure.net/

    # AWS
    envdrift vault-pull . my-app-key --env production -p aws --region us-east-1

    # GCP
    envdrift vault-pull . my-app-key --env production -p gcp --project-id my-gcp-project

    # HashiCorp
    envdrift vault-pull . my-app-key --env production -p hashicorp --vault-url https://vault.example.com:8200
"""

_PushFolder = Annotated[
    Path | None,
    typer.Argument(help="Service folder containing .env.keys file"),
]
_PushSecretName = Annotated[
    str | None,
    typer.Argument(help="Name of the secret in the vault"),
]
_PushEnvironment = Annotated[
    str | None,
    typer.Option(
        "--env",
        "-e",
        help=(
            "Required (single-service mode): environment suffix that selects which "
            "DOTENV_PRIVATE_KEY_<ENV> key is read from .env.keys "
            "(e.g., 'soak' -> DOTENV_PRIVATE_KEY_SOAK)"
        ),
    ),
]
_DirectOption = Annotated[
    bool,
    typer.Option(
        "--direct",
        help="Push a direct key-value pair (use with positional args: secret-name value)",
    ),
]
_AllServicesOption = Annotated[
    bool,
    typer.Option(
        "--all",
        help="Push all secrets defined in sync config (skipping existing unless --force)",
    ),
]
_ForceOption = Annotated[
    bool,
    typer.Option("--force", "-f", help="Push all secrets even if they already exist"),
]
_SkipEncryptOption = Annotated[
    bool,
    typer.Option("--skip-encrypt", help="Skip encryption step, only push keys to vault"),
]
_ConfigOption = Annotated[
    Path | None,
    typer.Option("--config", "-c", help="Path to sync config file"),
]
_PullConfigOption = Annotated[
    Path | None,
    typer.Option("--config", "-c", help="Path to envdrift.toml config file"),
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
_PullFolder = Annotated[
    Path,
    typer.Argument(help="Service folder to write the fetched .env.keys file into"),
]
_PullSecretName = Annotated[str, typer.Argument(help="Name of the secret in the vault")]
_PullEnvironment = Annotated[
    str,
    typer.Option(
        "--env",
        "-e",
        help=(
            "Required: environment suffix that names the key written to .env.keys "
            "(e.g., 'soak' -> DOTENV_PRIVATE_KEY_SOAK). Also selects which "
            ".env.<env> file is decrypted unless --no-decrypt is used."
        ),
    ),
]
_NoDecryptOption = Annotated[
    bool,
    typer.Option(
        "--no-decrypt",
        help="Only write the key to .env.keys; do not decrypt the .env.<env> file",
    ),
]
_EnvFileOption = Annotated[
    Path | None,
    typer.Option("--env-file", help="Custom env filename to decrypt, relative to FOLDER"),
]


def vault_push(
    folder: _PushFolder = None,
    secret_name: _PushSecretName = None,
    env: _PushEnvironment = None,
    direct: _DirectOption = False,
    all_services: _AllServicesOption = False,
    force: _ForceOption = False,
    skip_encrypt: _SkipEncryptOption = False,
    config: _ConfigOption = None,
    provider: _ProviderOption = None,
    vault_url: _VaultUrlOption = None,
    region: _RegionOption = None,
    project_id: _ProjectIdOption = None,
) -> None:
    """Push encryption keys from local files to a configured cloud vault."""
    execute_vault_push(
        VaultPushRequest(
            folder=folder,
            secret_name=secret_name,
            environment=env,
            direct=direct,
            all_services=all_services,
            force=force,
            skip_encrypt=skip_encrypt,
            config=config,
            provider=provider,
            vault_url=vault_url,
            region=region,
            project_id=project_id,
        )
    )


def vault_pull(
    folder: _PullFolder,
    secret_name: _PullSecretName,
    env: _PullEnvironment,
    config: _PullConfigOption = None,
    provider: _ProviderOption = None,
    vault_url: _VaultUrlOption = None,
    region: _RegionOption = None,
    project_id: _ProjectIdOption = None,
    no_decrypt: _NoDecryptOption = False,
    env_file: _EnvFileOption = None,
) -> None:
    """Pull an encryption key from a cloud vault and optionally decrypt its env file."""
    execute_vault_pull(
        VaultPullRequest(
            folder=folder,
            secret_name=secret_name,
            environment=env,
            config=config,
            provider=provider,
            vault_url=vault_url,
            region=region,
            project_id=project_id,
            no_decrypt=no_decrypt,
            env_file=env_file,
        )
    )
