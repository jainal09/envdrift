"""Encryption and decryption commands for envdrift."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from envdrift.core.encryption import EncryptionDetector
from envdrift.core.parser import EnvParser
from envdrift.core.schema import SchemaLoader, SchemaLoadError
from envdrift.output.rich import (
    console,
    print_encryption_report,
    print_error,
    print_success,
    print_warning,
)
from envdrift.vault.base import SecretNotFoundError, VaultError


def encrypt_cmd(
    env_file: Annotated[Path, typer.Argument(help="Path to .env file")] = Path(".env"),
    check: Annotated[
        bool, typer.Option("--check", help="Only check encryption status, don't encrypt")
    ] = False,
    schema: Annotated[
        str | None,
        typer.Option("--schema", "-s", help="Schema for sensitive field detection"),
    ] = None,
    service_dir: Annotated[
        Path | None,
        typer.Option("--service-dir", "-d", help="Service directory for imports"),
    ] = None,
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
    Check encryption status of an .env file or encrypt it using dotenvx.

    When run with --check, prints an encryption report and exits with code 1 if the detector recommends blocking a commit.
    When run without --check, attempts to perform encryption via the dotenvx integration; if dotenvx is not available, prints installation instructions and exits.

    Parameters:
        env_file (Path): Path to the .env file to inspect or encrypt.
        check (bool): If True, only analyze and report encryption status; do not modify the file.
        schema (str | None): Optional dotted path to a Settings schema used to detect sensitive fields.
        service_dir (Path | None): Optional directory to add to import resolution when loading the schema.
    """
    if not env_file.exists():
        print_error(f"ENV file not found: {env_file}")
        raise typer.Exit(code=1)

    if verify_vault or vault_provider or vault_url or vault_region or vault_secret:
        print_error("Vault verification moved to `envdrift decrypt --verify-vault ...`")
        raise typer.Exit(code=1)

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

    if check:
        # Just report status
        print_encryption_report(report)

        if detector.should_block_commit(report):
            raise typer.Exit(code=1)
    else:
        # Attempt encryption using dotenvx
        try:
            from envdrift.integrations.dotenvx import DotenvxWrapper

            dotenvx = DotenvxWrapper()

            if not dotenvx.is_installed():
                print_error("dotenvx is not installed")
                console.print(dotenvx.install_instructions())
                raise typer.Exit(code=1)

            dotenvx.encrypt(env_file)
            print_success(f"Encrypted {env_file}")
        except ImportError:
            print_error("dotenvx integration not available")
            console.print("Run: envdrift encrypt --check to check encryption status")
            raise typer.Exit(code=1) from None


def _verify_decryption_with_vault(
    env_file: Path,
    provider: str,
    vault_url: str | None,
    region: str | None,
    secret_name: str,
    ci: bool = False,
) -> bool:
    """
    Verify that a vault-stored private key can decrypt the given .env file.

    Performs a non-destructive check by fetching the secret named `secret_name` from the specified vault provider, injecting the retrieved key into an isolated environment, and attempting to decrypt a temporary copy of `env_file` using the dotenvx integration. Prints user-facing status and remediation guidance; does not modify the original file.

    Parameters:
        env_file (Path): Path to the .env file to test decryption for.
        provider (str): Vault provider identifier (e.g., "azure", "aws", "hashicorp").
        vault_url (str | None): Vault endpoint URL when required by the provider (e.g., Azure or HashiCorp); may be None for providers that do not require it.
        region (str | None): Region identifier for providers that require it (e.g., AWS); may be None.
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

        dotenvx = DotenvxWrapper()
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
        typer.Option("--provider", "-p", help="Vault provider: azure, aws, hashicorp"),
    ] = None,
    vault_url: Annotated[
        str | None,
        typer.Option("--vault-url", help="Vault URL (Azure/HashiCorp)"),
    ] = None,
    vault_region: Annotated[
        str | None,
        typer.Option("--region", help="AWS region"),
    ] = None,
    vault_secret: Annotated[
        str | None,
        typer.Option("--secret", help="Vault secret name for the private key"),
    ] = None,
) -> None:
    """
    Decrypt an encrypted .env file or verify that a vault-provided key can decrypt it without modifying the file.

    When run normally, decrypts the given env file using the dotenvx integration and reports success; if dotenvx is not available, prints installation instructions and exits. When run with --verify-vault, checks that the specified vault provider and secret contain a key capable of decrypting the file without changing the file on disk; on a successful check the function prints confirmation and does not decrypt the file.

    Parameters:
        env_file (Path): Path to the encrypted .env file to operate on.
        verify_vault (bool): If true, perform a vault-based verification instead of local decryption.
        ci (bool): CI mode (non-interactive); affects exit behavior for errors.
        vault_provider (str | None): Vault provider identifier; supported values include "azure", "aws", and "hashicorp". Required when --verify-vault is used.
        vault_url (str | None): Vault URL required for providers that need it (Azure and HashiCorp) when verifying with a vault key.
        vault_region (str | None): AWS region when using the AWS provider for vault verification.
        vault_secret (str | None): Name of the vault secret that holds the private key; required when --verify-vault is used.
    """
    if not env_file.exists():
        print_error(f"ENV file not found: {env_file}")
        raise typer.Exit(code=1)

    if verify_vault:
        if not vault_provider:
            print_error("--verify-vault requires --provider")
            raise typer.Exit(code=1)
        if not vault_secret:
            print_error("--verify-vault requires --secret (vault secret name)")
            raise typer.Exit(code=1)
        if vault_provider in ("azure", "hashicorp") and not vault_url:
            print_error(f"--verify-vault with {vault_provider} requires --vault-url")
            raise typer.Exit(code=1)

        vault_check_passed = _verify_decryption_with_vault(
            env_file=env_file,
            provider=vault_provider,
            vault_url=vault_url,
            region=vault_region,
            secret_name=vault_secret,
            ci=ci,
        )
        if not vault_check_passed:
            raise typer.Exit(code=1)

        console.print("[dim]Vault verification completed. Original file was not decrypted.[/dim]")
        console.print("[dim]Run without --verify-vault to decrypt the file locally.[/dim]")
        return

    try:
        from envdrift.integrations.dotenvx import DotenvxWrapper

        dotenvx = DotenvxWrapper()

        if not dotenvx.is_installed():
            print_error("dotenvx is not installed")
            console.print(dotenvx.install_instructions())
            raise typer.Exit(code=1)

        dotenvx.decrypt(env_file)
        print_success(f"Decrypted {env_file}")
    except ImportError:
        print_error("dotenvx integration not available")
        raise typer.Exit(code=1) from None
