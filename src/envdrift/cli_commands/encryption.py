"""Encryption and decryption commands for envdrift.

Supports multiple encryption backends:
- dotenvx (default): Uses dotenvx CLI for encryption
- sops: Uses Mozilla SOPS for encryption
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from envdrift.core.encryption import EncryptionDetector
from envdrift.core.parser import EnvParser
from envdrift.core.schema import SchemaLoader, SchemaLoadError
from envdrift.encryption import EncryptionProvider, get_encryption_backend
from envdrift.encryption.base import EncryptionBackendError, EncryptionNotFoundError
from envdrift.output.rich import (
    console,
    print_encryption_report,
    print_error,
    print_success,
    print_warning,
)
from envdrift.vault.base import SecretNotFoundError, VaultError


def _load_encryption_config():
    import tomllib

    from envdrift.config import ConfigNotFoundError, EnvdriftConfig, find_config, load_config

    config_path = find_config()
    if not config_path:
        return EnvdriftConfig(), None

    try:
        return load_config(config_path), config_path
    except tomllib.TOMLDecodeError as e:
        print_warning(f"TOML syntax error in {config_path}: {e}")
    except ConfigNotFoundError as e:
        print_warning(str(e))

    return EnvdriftConfig(), None


def _resolve_config_path(config_path: Path | None, value: Path | str | None) -> Path | None:
    if not value:
        return None

    path = Path(value)
    if config_path and not path.is_absolute():
        return (config_path.parent / path).resolve()
    return path


def encrypt_cmd(
    env_file: Annotated[Path, typer.Argument(help="Path to .env file")] = Path(".env"),
    check: Annotated[
        bool, typer.Option("--check", help="Only check encryption status, don't encrypt")
    ] = False,
    backend: Annotated[
        str | None,
        typer.Option(
            "--backend",
            "-b",
            help="Encryption backend to use: dotenvx or sops (defaults to config or dotenvx)",
        ),
    ] = None,
    schema: Annotated[
        str | None,
        typer.Option("--schema", "-s", help="Schema for sensitive field detection"),
    ] = None,
    service_dir: Annotated[
        Path | None,
        typer.Option("--service-dir", "-d", help="Service directory for imports"),
    ] = None,
    # SOPS-specific options
    age_recipients: Annotated[
        str | None,
        typer.Option("--age", help="Age public key(s) for SOPS encryption"),
    ] = None,
    kms_arn: Annotated[
        str | None,
        typer.Option("--kms", help="AWS KMS key ARN for SOPS encryption"),
    ] = None,
    gcp_kms: Annotated[
        str | None,
        typer.Option("--gcp-kms", help="GCP KMS resource ID for SOPS encryption"),
    ] = None,
    azure_kv: Annotated[
        str | None,
        typer.Option("--azure-kv", help="Azure Key Vault key URL for SOPS encryption"),
    ] = None,
    sops_config_file: Annotated[
        Path | None,
        typer.Option("--sops-config", help="Path to .sops.yaml config for SOPS"),
    ] = None,
    age_key_file: Annotated[
        Path | None,
        typer.Option("--age-key-file", help="Path to age private key file for SOPS"),
    ] = None,
    # Deprecated vault options
    verify_vault: Annotated[
        bool,
        typer.Option(
            "--verify-vault",
            help="(Deprecated) Use `envdrift decrypt --verify-vault` instead",
            hidden=True,
        ),
    ] = False,
    vault_provider: Annotated[
        str | None,
        typer.Option(
            "--provider", "-p", help="(Deprecated) Use with decrypt --verify-vault", hidden=True
        ),
    ] = None,
    vault_url: Annotated[
        str | None,
        typer.Option(
            "--vault-url", help="(Deprecated) Use with decrypt --verify-vault", hidden=True
        ),
    ] = None,
    vault_region: Annotated[
        str | None,
        typer.Option("--region", help="(Deprecated) Use with decrypt --verify-vault", hidden=True),
    ] = None,
    vault_secret: Annotated[
        str | None,
        typer.Option("--secret", help="(Deprecated) Use with decrypt --verify-vault", hidden=True),
    ] = None,
) -> None:
    """
    Check encryption status of an .env file or encrypt it.

    Supports multiple encryption backends:
    - dotenvx (default or config): Uses dotenvx CLI for encryption
    - sops: Uses Mozilla SOPS for encryption

    If --backend is not provided, envdrift uses the backend from config
    (envdrift.toml/pyproject.toml) or falls back to dotenvx.

    When run with --check, prints an encryption report and exits with code 1
    if the detector recommends blocking a commit.

    When run without --check, attempts to perform encryption using the
    specified backend; if the tool is not available, prints installation
    instructions and exits.

    Examples:
        envdrift encrypt                     # Encrypt with dotenvx (default)
        envdrift encrypt --backend sops      # Encrypt with SOPS
        envdrift encrypt --check             # Check encryption status only
        envdrift encrypt -b sops --age AGE_PUBLIC_KEY  # SOPS with age key
        envdrift encrypt --sops-config .sops.yaml  # SOPS with explicit config
    """
    if not env_file.exists():
        print_error(f"ENV file not found: {env_file}")
        raise typer.Exit(code=1)

    if verify_vault or vault_provider or vault_url or vault_region or vault_secret:
        print_error("Vault verification moved to `envdrift decrypt --verify-vault ...`")
        raise typer.Exit(code=1)

    envdrift_config, config_path = _load_encryption_config()
    encryption_config = getattr(envdrift_config, "encryption", None)

    from envdrift.integrations.hook_check import ensure_git_hook_setup

    hook_errors = ensure_git_hook_setup(config=envdrift_config, config_path=config_path)
    if hook_errors:
        for error in hook_errors:
            print_error(error)
        raise typer.Exit(code=1)

    if backend is None:
        backend = encryption_config.backend if encryption_config else "dotenvx"

    # Validate backend
    try:
        backend_enum = EncryptionProvider(backend.lower())
    except ValueError:
        print_error(f"Unknown encryption backend: {backend}")
        print_error("Supported backends: dotenvx, sops")
        raise typer.Exit(code=1) from None

    if encryption_config and backend_enum == EncryptionProvider.SOPS:
        if age_recipients is None:
            age_recipients = encryption_config.sops_age_recipients
        if kms_arn is None:
            kms_arn = encryption_config.sops_kms_arn
        if gcp_kms is None:
            gcp_kms = encryption_config.sops_gcp_kms
        if azure_kv is None:
            azure_kv = encryption_config.sops_azure_kv

        if sops_config_file is None:
            sops_config_file = _resolve_config_path(
                config_path,
                encryption_config.sops_config_file,
            )
        if age_key_file is None:
            age_key_file = _resolve_config_path(
                config_path,
                encryption_config.sops_age_key_file,
            )

    # Load schema if provided
    schema_meta = None
    if schema:
        loader = SchemaLoader()
        try:
            settings_cls = loader.load(schema, service_dir)
            schema_meta = loader.extract_metadata(settings_cls)
        except SchemaLoadError as e:
            print_warning(f"Could not load schema: {e}")

    # Parse env file
    parser = EnvParser()
    env = parser.parse(env_file)

    # Analyze encryption
    detector = EncryptionDetector()
    report = detector.analyze(env, schema_meta)
    detected_backend = detector.detect_backend_for_file(env_file)
    if detected_backend:
        report.detected_backend = detected_backend
    elif report.detected_backend is None:
        report.detected_backend = backend_enum.value

    if check:
        # Just report status
        print_encryption_report(report)

        if detector.should_block_commit(report):
            raise typer.Exit(code=1)
    else:
        # Attempt encryption using the selected backend
        try:
            backend_config: dict[str, object] = {}
            if encryption_config and backend_enum == EncryptionProvider.DOTENVX:
                backend_config["auto_install"] = encryption_config.dotenvx_auto_install
            if backend_enum == EncryptionProvider.SOPS:
                if encryption_config:
                    backend_config["auto_install"] = encryption_config.sops_auto_install
                if sops_config_file:
                    backend_config["config_file"] = sops_config_file
                if age_key_file:
                    backend_config["age_key_file"] = age_key_file

            encryption_backend = get_encryption_backend(backend_enum, **backend_config)

            if not encryption_backend.is_installed():
                print_error(f"{encryption_backend.name} is not installed")
                console.print(encryption_backend.install_instructions())
                raise typer.Exit(code=1)

            # Build kwargs for SOPS-specific options
            encrypt_kwargs = {}
            if backend_enum == EncryptionProvider.SOPS:
                if age_recipients:
                    encrypt_kwargs["age_recipients"] = age_recipients
                if kms_arn:
                    encrypt_kwargs["kms_arn"] = kms_arn
                if gcp_kms:
                    encrypt_kwargs["gcp_kms"] = gcp_kms
                if azure_kv:
                    encrypt_kwargs["azure_kv"] = azure_kv

            # === SMART ENCRYPTION: Skip re-encryption if content unchanged ===
            # This addresses dotenvx's non-deterministic encryption (ECIES) which
            # produces different ciphertext each time, causing unnecessary git noise.
            from envdrift.cli_commands.encryption_helpers import should_skip_reencryption

            smart_enabled = encryption_config.smart_encryption if encryption_config else False
            should_skip, skip_reason = should_skip_reencryption(
                env_file, encryption_backend, enabled=smart_enabled
            )
            if should_skip:
                print_success(f"Skipped re-encryption of {env_file} ({skip_reason})")
                return

            result = encryption_backend.encrypt(env_file, **encrypt_kwargs)
            if result.success:
                print_success(f"Encrypted {env_file} using {encryption_backend.name}")
            else:
                print_error(result.message)
                raise typer.Exit(code=1)

        except EncryptionNotFoundError as e:
            print_error(str(e))
            raise typer.Exit(code=1) from None
        except EncryptionBackendError as e:
            print_error(f"Encryption failed: {e}")
            raise typer.Exit(code=1) from None


def _verify_decryption_with_vault(
    env_file: Path,
    provider: str,
    vault_url: str | None,
    region: str | None,
    project_id: str | None,
    secret_name: str,
    ci: bool = False,
    auto_install: bool = False,
) -> bool:
    """
    Verify that a vault-stored private key can decrypt the given .env file.

    Performs a non-destructive check by fetching the secret named `secret_name` from the specified vault provider, injecting the retrieved key into an isolated environment, and attempting to decrypt a temporary copy of `env_file` using the dotenvx integration. Prints user-facing status and remediation guidance; does not modify the original file.

    Parameters:
        env_file (Path): Path to the .env file to test decryption for.
        provider (str): Vault provider identifier (e.g., "azure", "aws", "hashicorp", "gcp").
        vault_url (str | None): Vault endpoint URL when required by the provider (e.g., Azure or HashiCorp); may be None for providers that do not require it.
        region (str | None): Region identifier for providers that require it (e.g., AWS); may be None.
        project_id (str | None): GCP project ID for Secret Manager.
        secret_name (str): Name of the secret in the vault that contains the private key (or an environment-style value like "DOTENV_PRIVATE_KEY_ENV=key").

    Returns:
        bool: `True` if the vault key successfully decrypts a temporary copy of `env_file`, `False` otherwise.
    """
    import os
    import tempfile

    from envdrift.vault import get_vault_client

    if not ci:
        console.print()
        console.print("[bold]Vault Key Verification[/bold]")
        console.print(f"[dim]Provider: {provider} | Secret: {secret_name}[/dim]")

    try:
        # Create vault client
        vault_kwargs: dict = {}
        if provider == "azure":
            vault_kwargs["vault_url"] = vault_url
        elif provider == "aws":
            vault_kwargs["region"] = region or "us-east-1"
        elif provider == "hashicorp":
            vault_kwargs["url"] = vault_url
        elif provider == "gcp":
            vault_kwargs["project_id"] = project_id

        vault_client = get_vault_client(provider, **vault_kwargs)
        vault_client.ensure_authenticated()

        # Fetch private key from vault
        if not ci:
            console.print("[dim]Fetching private key from vault...[/dim]")
        private_key = vault_client.get_secret(secret_name)

        # SecretValue can be truthy even if value is empty; check both
        if not private_key or (hasattr(private_key, "value") and not private_key.value):
            print_error(f"Secret '{secret_name}' is empty in vault")
            return False

        # Extract the actual value from SecretValue object
        # The vault client returns a SecretValue with .value attribute
        if hasattr(private_key, "value"):
            private_key_str = private_key.value
        elif isinstance(private_key, str):
            private_key_str = private_key
        else:
            private_key_str = str(private_key)

        if not ci:
            console.print("[dim]Private key retrieved successfully[/dim]")

        # Try to decrypt using the vault key
        if not ci:
            console.print("[dim]Testing decryption with vault key...[/dim]")

        from envdrift.integrations.dotenvx import DotenvxError, DotenvxWrapper

        dotenvx = DotenvxWrapper(auto_install=auto_install)
        if not dotenvx.is_installed():
            print_error("dotenvx is not installed - cannot verify decryption")
            return False

        # The vault stores secrets in "DOTENV_PRIVATE_KEY_ENV=key" format
        # Parse out the actual key value if it's in that format
        actual_private_key = private_key_str
        if "=" in private_key_str and private_key_str.startswith("DOTENV_PRIVATE_KEY"):
            # Extract just the key value after the =
            actual_private_key = private_key_str.split("=", 1)[1]
            # Get the variable name from the vault value
            key_var_name = private_key_str.split("=", 1)[0]
        else:
            # Key is just the raw value, construct variable name from env file
            env_name = env_file.stem.replace(".env", "").replace(".", "_").upper()
            if env_name.startswith("_"):
                env_name = env_name[1:]
            if not env_name:
                env_name = "PRODUCTION"  # Default
            key_var_name = f"DOTENV_PRIVATE_KEY_{env_name}"

        # Build a clean environment so dotenvx cannot fall back to stray keys
        dotenvx_env = {
            k: v for k, v in os.environ.items() if not k.startswith("DOTENV_PRIVATE_KEY")
        }
        dotenvx_env.pop("DOTENV_KEY", None)
        dotenvx_env[key_var_name] = actual_private_key

        # Work inside an isolated temp directory with only the vault key
        with tempfile.TemporaryDirectory(prefix=".envdrift-verify-") as temp_dir:
            temp_dir_path = Path(temp_dir)
            tmp_path = temp_dir_path / env_file.name  # Preserve filename for key naming

            # Copy env file into isolated directory; inject vault key via environment
            tmp_path.write_text(env_file.read_text())

            try:
                dotenvx.decrypt(
                    tmp_path,
                    env_keys_file=None,
                    env=dotenvx_env,
                    cwd=temp_dir_path,
                )
                print_success("✓ Vault key can decrypt this file - keys are in sync!")
                return True
            except DotenvxError as e:
                print_error("✗ Vault key CANNOT decrypt this file!")
                console.print(f"[red]Error: {e}[/red]")
                console.print()
                console.print(
                    "[yellow]This means the file was encrypted with a DIFFERENT key.[/yellow]"
                )
                console.print("[yellow]The team's shared vault key won't work![/yellow]")
                console.print()
                console.print("[bold]To fix:[/bold]")
                console.print(f"  1. Restore the encrypted file: git restore {env_file}")

                # Construct sync command with the same provider options
                sync_cmd = f"envdrift sync --force -c pair.txt -p {provider}"
                if vault_url:
                    sync_cmd += f" --vault-url {vault_url}"
                if region:
                    sync_cmd += f" --region {region}"
                if project_id:
                    sync_cmd += f" --project-id {project_id}"
                console.print(f"  2. Restore vault key locally: {sync_cmd}")

                console.print(f"  3. Re-encrypt with the vault key: envdrift encrypt {env_file}")
                return False

    except SecretNotFoundError:
        print_error(f"Secret '{secret_name}' not found in vault")
        return False
    except VaultError as e:
        print_error(f"Vault error: {e}")
        return False
    except ImportError as e:
        print_error(f"Import error: {e}")
        return False
    except Exception as e:
        import logging
        import traceback

        logging.debug("Unexpected vault verification error:\n%s", traceback.format_exc())
        print_error(f"Unexpected error during vault verification: {e}")
        return False


def decrypt_cmd(
    env_file: Annotated[Path, typer.Argument(help="Path to encrypted .env file")] = Path(".env"),
    backend: Annotated[
        str | None,
        typer.Option(
            "--backend",
            "-b",
            help="Encryption backend: dotenvx, sops (auto-detects or uses config if not specified)",
        ),
    ] = None,
    sops_config_file: Annotated[
        Path | None,
        typer.Option("--sops-config", help="Path to .sops.yaml config for SOPS"),
    ] = None,
    age_key_file: Annotated[
        Path | None,
        typer.Option("--age-key-file", help="Path to age private key file for SOPS"),
    ] = None,
    verify_vault: Annotated[
        bool,
        typer.Option(
            "--verify-vault", help="Verify vault key can decrypt without modifying the file"
        ),
    ] = False,
    ci: Annotated[
        bool,
        typer.Option("--ci", help="CI mode: non-interactive; exits non-zero on errors"),
    ] = False,
    vault_provider: Annotated[
        str | None,
        typer.Option("--provider", "-p", help="Vault provider: azure, aws, hashicorp, gcp"),
    ] = None,
    vault_url: Annotated[
        str | None,
        typer.Option("--vault-url", help="Vault URL (Azure/HashiCorp)"),
    ] = None,
    vault_region: Annotated[
        str | None,
        typer.Option("--region", help="AWS region"),
    ] = None,
    vault_project_id: Annotated[
        str | None,
        typer.Option("--project-id", help="GCP project ID (Secret Manager)"),
    ] = None,
    vault_secret: Annotated[
        str | None,
        typer.Option("--secret", help="Vault secret name for the private key"),
    ] = None,
) -> None:
    """
    Decrypt an encrypted .env file.

    Supports multiple encryption backends:
    - dotenvx: Uses dotenvx CLI for decryption
    - sops: Uses Mozilla SOPS for decryption

    If --backend is not specified, the backend will be auto-detected based on
    the file content. When auto-detection fails, envdrift falls back to the
    configured backend or dotenvx.

    Examples:
        envdrift decrypt                     # Auto-detect backend
        envdrift decrypt --backend sops      # Force SOPS decryption
        envdrift decrypt --verify-vault ...  # Verify vault key (dotenvx only)

    Parameters:
        env_file (Path): Path to the encrypted .env file to operate on.
        backend (str | None): Encryption backend to use (dotenvx or sops).
        sops_config_file (Path | None): Path to .sops.yaml when using SOPS.
        age_key_file (Path | None): Path to age private key file for SOPS.
        verify_vault (bool): If true, perform a vault-based verification instead of local decryption.
        ci (bool): CI mode (non-interactive); affects exit behavior for errors.
        vault_provider (str | None): Vault provider identifier; supported values include "azure", "aws", "hashicorp", and "gcp". Required when --verify-vault is used.
        vault_url (str | None): Vault URL required for providers that need it (Azure and HashiCorp) when verifying with a vault key.
        vault_region (str | None): AWS region when using the AWS provider for vault verification.
        vault_project_id (str | None): GCP project ID when using the GCP provider for vault verification.
        vault_secret (str | None): Name of the vault secret that holds the private key; required when --verify-vault is used.
    """
    if not env_file.exists():
        print_error(f"ENV file not found: {env_file}")
        raise typer.Exit(code=1)

    envdrift_config, config_path = _load_encryption_config()
    encryption_config = getattr(envdrift_config, "encryption", None)

    from envdrift.integrations.hook_check import ensure_git_hook_setup

    hook_errors = ensure_git_hook_setup(config=envdrift_config, config_path=config_path)
    if hook_errors:
        for error in hook_errors:
            print_error(error)
        raise typer.Exit(code=1)

    # Auto-detect backend if not specified
    if backend is None:
        detector = EncryptionDetector()
        detected = detector.detect_backend_for_file(env_file)
        if detected:
            backend = detected
            console.print(f"[dim]Auto-detected encryption backend: {backend}[/dim]")
        else:
            backend = encryption_config.backend if encryption_config else "dotenvx"

    # Validate backend
    try:
        backend_enum = EncryptionProvider(backend.lower())
    except ValueError:
        print_error(f"Unknown encryption backend: {backend}")
        print_error("Supported backends: dotenvx, sops")
        raise typer.Exit(code=1) from None

    if encryption_config and backend_enum == EncryptionProvider.SOPS:
        if sops_config_file is None:
            sops_config_file = _resolve_config_path(
                config_path,
                encryption_config.sops_config_file,
            )
        if age_key_file is None:
            age_key_file = _resolve_config_path(
                config_path,
                encryption_config.sops_age_key_file,
            )

    if verify_vault:
        # Vault verification currently only works with dotenvx
        if backend_enum != EncryptionProvider.DOTENVX:
            print_error("Vault verification is only supported with dotenvx backend")
            raise typer.Exit(code=1)

        if not vault_provider:
            print_error("--verify-vault requires --provider")
            raise typer.Exit(code=1)
        if not vault_secret:
            print_error("--verify-vault requires --secret (vault secret name)")
            raise typer.Exit(code=1)
        if vault_provider in ("azure", "hashicorp") and not vault_url:
            print_error(f"--verify-vault with {vault_provider} requires --vault-url")
            raise typer.Exit(code=1)
        if vault_provider == "gcp" and not vault_project_id:
            print_error("--verify-vault with gcp requires --project-id")
            raise typer.Exit(code=1)

        vault_check_passed = _verify_decryption_with_vault(
            env_file=env_file,
            provider=vault_provider,
            vault_url=vault_url,
            region=vault_region,
            project_id=vault_project_id,
            secret_name=vault_secret,
            ci=ci,
            auto_install=encryption_config.dotenvx_auto_install if encryption_config else False,
        )
        if not vault_check_passed:
            raise typer.Exit(code=1)

        console.print("[dim]Vault verification completed. Original file was not decrypted.[/dim]")
        console.print("[dim]Run without --verify-vault to decrypt the file locally.[/dim]")
        return

    # Decrypt using the selected backend
    try:
        backend_config: dict[str, object] = {}
        if encryption_config and backend_enum == EncryptionProvider.DOTENVX:
            backend_config["auto_install"] = encryption_config.dotenvx_auto_install
        if backend_enum == EncryptionProvider.SOPS:
            if encryption_config:
                backend_config["auto_install"] = encryption_config.sops_auto_install
            if sops_config_file:
                backend_config["config_file"] = sops_config_file
            if age_key_file:
                backend_config["age_key_file"] = age_key_file

        encryption_backend = get_encryption_backend(backend_enum, **backend_config)

        if not encryption_backend.is_installed():
            print_error(f"{encryption_backend.name} is not installed")
            console.print(encryption_backend.install_instructions())
            raise typer.Exit(code=1)

        result = encryption_backend.decrypt(env_file)
        if result.success:
            print_success(f"Decrypted {env_file} using {encryption_backend.name}")
        else:
            print_error(result.message)
            raise typer.Exit(code=1)

    except EncryptionNotFoundError as e:
        print_error(str(e))
        raise typer.Exit(code=1) from None
    except EncryptionBackendError as e:
        print_error(f"Decryption failed: {e}")
        raise typer.Exit(code=1) from None
