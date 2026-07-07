"""Vault operations for envdrift."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from envdrift.env_files import resolve_custom_env_file, resolve_mapping_env_file
from envdrift.output.rich import console, print_error, print_success, print_warning


def _resolve_vault_settings(
    config: Path | None,
    provider: str | None,
    vault_url: str | None,
    region: str | None,
    project_id: str | None,
) -> tuple[str, str | None, str | None, str | None]:
    """Resolve the effective vault provider/url/region/project-id.

    Merges explicit CLI flags with the ``[vault]`` section of an
    ``envdrift.toml``/``pyproject.toml`` (flags win). Exits the CLI with a
    user-facing error when the provider is missing or a provider-specific
    requirement is unmet (azure/hashicorp need ``--vault-url``; gcp needs
    ``--project-id``).

    Shared by ``vault-push`` (single-service mode) and ``vault-pull`` so the two
    commands stay byte-for-byte consistent.
    """
    import contextlib
    import tomllib

    from envdrift.config import ConfigNotFoundError, find_config, load_config

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

    effective_provider = provider or getattr(vault_config, "provider", None)
    if not effective_provider:
        print_error("Vault provider required. Use --provider or configure in envdrift.toml")
        raise typer.Exit(code=1)

    effective_vault_url = vault_url
    if effective_vault_url is None and vault_config:
        if effective_provider == "azure":
            effective_vault_url = getattr(vault_config, "azure_vault_url", None)
        elif effective_provider == "hashicorp":
            effective_vault_url = getattr(vault_config, "hashicorp_url", None)

    effective_region = region
    if effective_region is None and vault_config:
        effective_region = getattr(vault_config, "aws_region", None)

    effective_project_id = project_id
    if effective_project_id is None and vault_config:
        effective_project_id = getattr(vault_config, "gcp_project_id", None)

    if effective_provider in ("azure", "hashicorp") and not effective_vault_url:
        print_error(f"--vault-url required for {effective_provider}")
        raise typer.Exit(code=1)
    if effective_provider == "gcp" and not effective_project_id:
        print_error("--project-id required for gcp")
        raise typer.Exit(code=1)

    return effective_provider, effective_vault_url, effective_region, effective_project_id


def _build_authenticated_client(
    provider: str,
    vault_url: str | None,
    region: str | None,
    project_id: str | None,
):
    """Create and authenticate a vault client for the given effective settings.

    Exits the CLI with a user-facing error on a missing optional dependency
    (``ImportError``), an unsupported provider or bad configuration
    (``ValueError``), or an authentication failure (``VaultError``).
    """
    from envdrift.vault import VaultError, get_vault_client

    try:
        vault_client_config: dict[str, str | None] = {}
        if provider == "azure":
            vault_client_config["vault_url"] = vault_url
        elif provider == "aws":
            vault_client_config["region"] = region or "us-east-1"
        elif provider == "hashicorp":
            vault_client_config["url"] = vault_url
        elif provider == "gcp":
            vault_client_config["project_id"] = project_id

        client = get_vault_client(provider, **vault_client_config)
        client.authenticate()
    except ImportError as e:
        print_error(str(e))
        raise typer.Exit(code=1) from None
    except ValueError as e:
        print_error(f"Invalid vault configuration: {e}")
        raise typer.Exit(code=1) from None
    except VaultError as e:
        print_error(f"Vault authentication failed: {e}")
        raise typer.Exit(code=1) from None

    return client


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
            "--env",
            "-e",
            help=(
                "Required (single-service mode): environment suffix that selects which "
                "DOTENV_PRIVATE_KEY_<ENV> key is read from .env.keys "
                "(e.g., 'soak' -> DOTENV_PRIVATE_KEY_SOAK)"
            ),
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
    from envdrift.sync.operations import EnvKeysFile
    from envdrift.vault import VaultError
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
        from envdrift.integrations.dotenvx import dotenvx_filename_needs_normalization

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
                detection = resolve_mapping_env_file(mapping)
                if detection.status == "folder_not_found":
                    # A missing mapping folder is a broken config (typo'd
                    # folder_path), not a "No .env file found" skip: reporting
                    # it as a skip with Errors: 0 let a key-backup CI job go
                    # green having pushed nothing (#488).
                    print_error(
                        f"Error processing {mapping.folder_path}: folder does not "
                        "exist (check folder_path in your sync config)"
                    )
                    error_count += 1
                    continue
                env_file = (
                    detection.path
                    if detection.path is not None
                    else mapping.folder_path / f".env.{mapping.effective_environment}"
                )
                effective_environment = detection.environment or mapping.effective_environment

                # Check if the secret exists in vault BEFORE any file mutation
                # (encrypt/normalize), so a skipped push leaves the working tree
                # untouched (#347). This needs only `force` and the secret name,
                # both independent of the encrypt/normalize block below.
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

                if not skip_encrypt:
                    if detection.status != "found" or detection.path is None:
                        missing_description = (
                            f"{env_file.name} file" if mapping.env_file is not None else ".env file"
                        )
                        console.print(
                            f"[dim]Skipped[/dim] {mapping.folder_path}: "
                            f"No {missing_description} found"
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

                    # Normalize dotenvx metadata for custom filenames so the vault
                    # key name stays canonical (DOTENV_*_<environment>). This runs
                    # whether we just encrypted the file or it was already encrypted
                    # by a prior run, so the canonical key always exists below. It
                    # applies to any non-canonical filename — configured (env_file)
                    # or auto-detected (e.g. postgresql.env) — since dotenvx derives
                    # its key name from the filename.
                    if (
                        backend_provider == EncryptionProvider.DOTENVX
                        and dotenvx_filename_needs_normalization(env_file, effective_environment)
                    ):
                        from envdrift.integrations.dotenvx import normalize_dotenvx_metadata

                        normalize_dotenvx_metadata(
                            env_file,
                            mapping.folder_path / (sync_config.env_keys_filename or ".env.keys"),
                            effective_environment,
                        )

                # Read key to push
                env_keys_path = mapping.folder_path / (sync_config.env_keys_filename or ".env.keys")
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
        # Exit non-zero on any per-mapping failure (not just dotenvx mismatch) so
        # CI/automation can detect a partially-failed bulk push (#353).
        if dotenvx_mismatch or error_count > 0:
            raise typer.Exit(code=1)
        return

    # Normal/Direct mode preamble: resolve effective provider settings (shared
    # with vault-pull).
    (
        effective_provider,
        effective_vault_url,
        effective_region,
        effective_project_id,
    ) = _resolve_vault_settings(config, provider, vault_url, region, project_id)

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
        # Same OSError/ValueError boundary as --all mode: .env.keys may be a
        # directory (IsADirectoryError) or hold non-UTF-8 bytes
        # (UnicodeDecodeError); both must surface as a clean one-line error,
        # not a raw Rich traceback (#487).
        try:
            key_value = env_keys.read_key(key_name)
        except (OSError, ValueError) as e:
            print_error(f"Cannot read {env_keys_path}: {e}")
            raise typer.Exit(code=1) from None

        if not key_value:
            print_error(f"Key '{key_name}' not found in {env_keys_path}")
            raise typer.Exit(code=1)

        actual_secret_name = secret_name
        actual_value = f"{key_name}={key_value}"

    # Create vault client (shared with vault-pull)
    client = _build_authenticated_client(
        effective_provider, effective_vault_url, effective_region, effective_project_id
    )

    # Push the secret
    try:
        result = client.set_secret(actual_secret_name, actual_value)
        print_success(f"Pushed secret '{actual_secret_name}' to {effective_provider} vault")
        if result.version:
            console.print(f"  Version: {result.version}")
    except VaultError as e:
        print_error(f"Failed to push secret: {e}")
        raise typer.Exit(code=1) from None


def vault_pull(
    folder: Annotated[
        Path,
        typer.Argument(help="Service folder to write the fetched .env.keys file into"),
    ],
    secret_name: Annotated[
        str,
        typer.Argument(help="Name of the secret in the vault"),
    ],
    env: Annotated[
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
    ],
    config: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Path to envdrift.toml config file"),
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
    no_decrypt: Annotated[
        bool,
        typer.Option(
            "--no-decrypt",
            help="Only write the key to .env.keys; do not decrypt the .env.<env> file",
        ),
    ] = False,
    env_file: Annotated[
        Path | None,
        typer.Option(
            "--env-file",
            help="Custom env filename to decrypt, relative to FOLDER",
        ),
    ] = None,
) -> None:
    """
    Pull a single encryption key from a cloud vault into a local .env.keys file.

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
    from envdrift.sync.operations import EnvKeysFile
    from envdrift.vault import VaultError
    from envdrift.vault.base import SecretNotFoundError
    from envdrift.vault.keymaterial import KeyMaterialError, extract_key_material

    # Validate the target folder before any vault round-trip (#487): a typo'd
    # or non-directory FOLDER must fail fast with a clean error instead of
    # being silently created (or crashing with a raw OSError traceback) after
    # the secret was already fetched.
    if not folder.exists():
        print_error(f"Folder not found: {folder}")
        raise typer.Exit(code=1)
    if not folder.is_dir():
        print_error(f"Not a directory: {folder}")
        raise typer.Exit(code=1)

    # Resolve effective provider settings + build an authenticated client
    # (shared with vault-push single-service mode).
    (
        effective_provider,
        effective_vault_url,
        effective_region,
        effective_project_id,
    ) = _resolve_vault_settings(config, provider, vault_url, region, project_id)
    client = _build_authenticated_client(
        effective_provider, effective_vault_url, effective_region, effective_project_id
    )

    # Fetch the secret
    try:
        secret = client.get_secret(secret_name)
    except SecretNotFoundError:
        # Name the AWS region that was searched (#487): with --region omitted
        # the CLI silently defaults to us-east-1, making the classic
        # wrong-region mistake undiagnosable from a region-free message.
        region_note = ""
        if effective_provider == "aws":
            client_region = getattr(client, "region", None)
            if client_region:
                region_note = f" (region {client_region})"
        print_error(f"Secret '{secret_name}' not found in {effective_provider} vault{region_note}")
        raise typer.Exit(code=1) from None
    except VaultError as e:
        print_error(f"Failed to fetch secret: {e}")
        raise typer.Exit(code=1) from None

    key_name = f"DOTENV_PRIVATE_KEY_{env.upper()}"

    # Normalize + shape-validate the stored value through the shared parser used
    # by the sync engine and lock --verify-vault (#356, #480): quoted/whitespace-
    # wrapped values, JSON key/value documents, and multi-line .env.keys blobs
    # are reduced to the bare key; binary payloads and unusable shapes fail
    # loudly here instead of corrupting .env.keys under a success banner.
    try:
        key_value, stored_suffix = extract_key_material(secret, env)
    except KeyMaterialError as e:
        print_error(f"Cannot install secret as a dotenvx key: {e}")
        raise typer.Exit(code=1) from None

    # Fail fast on env-prefix mismatch: e.g. pulling --env production a secret
    # that was pushed --env staging would otherwise silently store the staging
    # key under the production name and fail later with an opaque crypto error.
    if stored_suffix is not None and stored_suffix.upper() != env.upper():
        print_error(
            f"Secret holds 'DOTENV_PRIVATE_KEY_{stored_suffix.upper()}' but --env {env} "
            f"expects '{key_name}'. "
            f"Re-run with --env matching the environment the secret was pushed for "
            f"(or push the secret under the correct environment)."
        )
        raise typer.Exit(code=1)

    # Write the key into <folder>/.env.keys. Same OSError/ValueError boundary
    # as vault-push (#487): the destination may be unwritable
    # (PermissionError), a directory (IsADirectoryError), or an existing
    # non-UTF-8 file (UnicodeDecodeError on the preserve-content read).
    env_keys_path = folder / ".env.keys"
    env_keys = EnvKeysFile(env_keys_path)
    try:
        env_keys.write_key(key_name, key_value, environment=env)
    except (OSError, ValueError) as e:
        print_error(f"Cannot write {env_keys_path}: {e}")
        raise typer.Exit(code=1) from None

    print_success(f"Pulled '{secret_name}' -> {key_name} written to {env_keys_path}")

    # Optionally decrypt the matching .env.<env> file (true one-command onboarding)
    if no_decrypt:
        return

    try:
        target_env_file = (
            resolve_custom_env_file(folder, env_file)
            if env_file is not None
            else folder / f".env.{env}"
        )
    except ValueError as e:
        print_error(f"Invalid --env-file: {e}")
        raise typer.Exit(code=1) from None
    if not target_env_file.exists():
        console.print(f"[dim]Key written; no {target_env_file} found to decrypt.[/dim]")
        return

    from envdrift.cli_commands.encryption_helpers import resolve_encryption_backend
    from envdrift.encryption import (
        EncryptionBackendError,
        EncryptionNotFoundError,
        EncryptionProvider,
    )

    # resolve_encryption_backend only honours `config` when it has a `.toml`
    # suffix; a config path without that suffix is silently ignored here (falls
    # back to auto-discovery) even though the vault settings above did load it.
    # Warn so the inconsistency isn't silent.
    if config is not None and config.suffix.lower() != ".toml":
        print_warning(
            f"--config {config} has no .toml suffix; it is used for vault settings "
            f"but ignored when selecting the encryption backend (auto-detected instead)."
        )

    try:
        encryption_backend, backend_provider, _ = resolve_encryption_backend(config)
    except ValueError as e:
        print_error(f"Unsupported encryption backend: {e}")
        raise typer.Exit(code=1) from None

    if not encryption_backend.is_installed():
        print_error(f"{encryption_backend.name} is not installed")
        console.print(encryption_backend.install_instructions())
        raise typer.Exit(code=1)

    if backend_provider == EncryptionProvider.DOTENVX and env_file is not None:
        from envdrift.integrations.dotenvx import normalize_dotenvx_metadata

        normalize_dotenvx_metadata(target_env_file, env_keys_path, env)

    try:
        # Point the backend at the .env.keys we just wrote so decryption works
        # even when FOLDER is not the current working directory (monorepo usage).
        result = encryption_backend.decrypt(
            target_env_file.resolve(),
            keys_file=env_keys_path.resolve(),
        )
    except (EncryptionNotFoundError, EncryptionBackendError) as e:
        print_error(f"Failed to decrypt {target_env_file}: {e}")
        raise typer.Exit(code=1) from None

    if not result.success:
        print_error(f"Failed to decrypt {target_env_file}: {result.message}")
        raise typer.Exit(code=1)

    print_success(f"Decrypted {target_env_file}")
