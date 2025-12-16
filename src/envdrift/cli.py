"""Command-line interface for envdrift."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from envdrift import __version__
from envdrift.core.diff import DiffEngine
from envdrift.core.encryption import EncryptionDetector
from envdrift.core.parser import EnvParser
from envdrift.core.schema import SchemaLoader, SchemaLoadError
from envdrift.core.validator import Validator
from envdrift.output.rich import (
    console,
    print_diff_result,
    print_encryption_report,
    print_error,
    print_success,
    print_validation_result,
    print_warning,
)
from envdrift.vault.base import SecretNotFoundError, VaultError

app = typer.Typer(
    name="envdrift",
    help="Prevent environment variable drift with Pydantic schema validation.",
    no_args_is_help=True,
)


@app.command()
def validate(
    env_file: Annotated[Path, typer.Argument(help="Path to .env file to validate")] = Path(".env"),
    schema: Annotated[
        str | None,
        typer.Option("--schema", "-s", help="Dotted path to Settings class"),
    ] = None,
    service_dir: Annotated[
        Path | None,
        typer.Option("--service-dir", "-d", help="Service directory for imports"),
    ] = None,
    ci: Annotated[bool, typer.Option("--ci", help="CI mode: exit with code 1 on failure")] = False,
    check_encryption: Annotated[
        bool,
        typer.Option("--check-encryption/--no-check-encryption", help="Check encryption"),
    ] = True,
    fix: Annotated[
        bool, typer.Option("--fix", help="Output template for missing variables")
    ] = False,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Show additional details")
    ] = False,
) -> None:
    """
    Validate an .env file against a Pydantic Settings schema and display results.

    Loads the specified Settings class, parses the given .env file, runs validation
    (including optional encryption checks and extra-key checks), and prints a
    human-readable validation report. If --fix is provided and validation fails,
    prints a generated template for missing values. Exits with code 1 on invalid
    schema or missing env file; when --ci is set, also exits with code 1 if the
    validation result is invalid.

    Parameters:
        schema (str | None): Dotted import path to the Pydantic Settings class
            (for example: "app.config:Settings"). Required; the command exits with
            code 1 if not provided or if loading fails.
        service_dir (Path | None): Optional directory to add to imports when
            resolving the schema.
        ci (bool): When true, exit with code 1 if validation fails.
        check_encryption (bool): When true, validate encryption-related metadata
            on sensitive fields.
        fix (bool): When true and validation fails, print a fix template with
            missing variables and defaults when available.
        verbose (bool): When true, include additional details in the validation
            output.
    """
    if schema is None:
        print_error("--schema is required. Example: --schema 'app.config:Settings'")
        raise typer.Exit(code=1)

    # Check env file exists
    if not env_file.exists():
        print_error(f"ENV file not found: {env_file}")
        raise typer.Exit(code=1)

    # Load schema
    loader = SchemaLoader()
    try:
        settings_cls = loader.load(schema, service_dir)
        schema_meta = loader.extract_metadata(settings_cls)
    except SchemaLoadError as e:
        print_error(str(e))
        raise typer.Exit(code=1) from None

    # Parse env file
    parser = EnvParser()
    try:
        env = parser.parse(env_file)
    except FileNotFoundError as e:
        print_error(str(e))
        raise typer.Exit(code=1) from None

    # Validate
    validator = Validator()
    result = validator.validate(
        env,
        schema_meta,
        check_encryption=check_encryption,
        check_extra=True,
    )

    # Print result
    print_validation_result(result, env_file, schema_meta, verbose=verbose)

    # Generate fix template if requested
    if fix and not result.valid:
        template = validator.generate_fix_template(result, schema_meta)
        if template:
            console.print("[bold]Fix template:[/bold]")
            console.print(template)

    # Exit with appropriate code
    if ci and not result.valid:
        raise typer.Exit(code=1)


@app.command()
def diff(
    env1: Annotated[Path, typer.Argument(help="First .env file (e.g., .env.dev)")],
    env2: Annotated[Path, typer.Argument(help="Second .env file (e.g., .env.prod)")],
    schema: Annotated[
        str | None,
        typer.Option("--schema", "-s", help="Schema for sensitive field detection"),
    ] = None,
    service_dir: Annotated[
        Path | None,
        typer.Option("--service-dir", "-d", help="Service directory for imports"),
    ] = None,
    show_values: Annotated[
        bool, typer.Option("--show-values", help="Don't mask sensitive values")
    ] = False,
    format_: Annotated[
        str, typer.Option("--format", "-f", help="Output format: table (default), json")
    ] = "table",
    include_unchanged: Annotated[
        bool, typer.Option("--include-unchanged", help="Include unchanged variables")
    ] = False,
) -> None:
    """
    Compare two .env files and display their differences.

    Parameters:
        env1 (Path): Path to the first .env file (e.g., .env.dev).
        env2 (Path): Path to the second .env file (e.g., .env.prod).
        schema (str | None): Optional dotted path to a Pydantic Settings class used to detect sensitive fields; if provided, the schema will be loaded for masking decisions.
        service_dir (Path | None): Optional directory to add to import resolution when loading the schema.
        show_values (bool): If True, do not mask sensitive values in the output.
        format_ (str): Output format, either "table" (default) for human-readable output or "json" for machine-readable output.
        include_unchanged (bool): If True, include variables that are unchanged between the two files in the output.
    """
    # Check files exist
    if not env1.exists():
        print_error(f"ENV file not found: {env1}")
        raise typer.Exit(code=1)
    if not env2.exists():
        print_error(f"ENV file not found: {env2}")
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

    # Parse env files
    parser = EnvParser()
    try:
        env_file1 = parser.parse(env1)
        env_file2 = parser.parse(env2)
    except FileNotFoundError as e:
        print_error(str(e))
        raise typer.Exit(code=1) from None

    # Diff
    engine = DiffEngine()
    result = engine.diff(
        env_file1,
        env_file2,
        schema=schema_meta,
        mask_values=not show_values,
        include_unchanged=include_unchanged,
    )

    # Output
    if format_ == "json":
        console.print_json(json.dumps(engine.to_dict(result), indent=2))
    else:
        print_diff_result(result, show_unchanged=include_unchanged)


@app.command("encrypt")
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


@app.command("decrypt")
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


@app.command()
def init(
    env_file: Annotated[
        Path, typer.Argument(help="Path to .env file to generate schema from")
    ] = Path(".env"),
    output: Annotated[
        Path, typer.Option("--output", "-o", help="Output file for Settings class")
    ] = Path("settings.py"),
    class_name: Annotated[
        str, typer.Option("--class-name", "-c", help="Name for the Settings class")
    ] = "Settings",
    detect_sensitive: Annotated[
        bool, typer.Option("--detect-sensitive", help="Auto-detect sensitive variables")
    ] = True,
) -> None:
    """
    Generate a Pydantic BaseSettings subclass from variables in an .env file.

    Writes a Python module containing a Pydantic `BaseSettings` subclass with fields
    inferred from the .env variables. Detected sensitive variables are annotated
    with `json_schema_extra={"sensitive": True}` and fields without a sensible
    default are left required.

    Parameters:
        env_file (Path): Path to the source .env file.
        output (Path): Path to write the generated Python module (e.g., settings.py).
        class_name (str): Name to use for the generated `BaseSettings` subclass.
        detect_sensitive (bool): If true, attempt to auto-detect sensitive variables
            (by name and value) and mark them in the generated fields.
    """
    if not env_file.exists():
        print_error(f"ENV file not found: {env_file}")
        raise typer.Exit(code=1)

    # Parse env file
    parser = EnvParser()
    env = parser.parse(env_file)

    # Detect sensitive variables if requested
    detector = EncryptionDetector()
    sensitive_vars = set()
    if detect_sensitive:
        for var_name, env_var in env.variables.items():
            is_name_sens = detector.is_name_sensitive(var_name)
            is_val_susp = detector.is_value_suspicious(env_var.value)
            if is_name_sens or is_val_susp:
                sensitive_vars.add(var_name)

    # Generate settings class
    lines = [
        '"""Auto-generated Pydantic Settings class."""',
        "",
        "from pydantic import Field",
        "from pydantic_settings import BaseSettings, SettingsConfigDict",
        "",
        "",
        f"class {class_name}(BaseSettings):",
        f'    """Settings generated from {env_file}."""',
        "",
        "    model_config = SettingsConfigDict(",
        f'        env_file="{env_file}",',
        '        extra="forbid",',
        "    )",
        "",
    ]

    for var_name, env_var in sorted(env.variables.items()):
        is_sensitive = var_name in sensitive_vars

        # Try to infer type from value
        value = env_var.value
        if value.lower() in ("true", "false"):
            type_hint = "bool"
            default_val = value.lower() == "true"
        elif value.isdigit():
            type_hint = "int"
            default_val = int(value)
        else:
            type_hint = "str"
            default_val = None  # Will be required

        # Build field
        if is_sensitive:
            extra = 'json_schema_extra={"sensitive": True}'
            if default_val is not None:
                lines.append(
                    f"    {var_name}: {type_hint} = Field(default={default_val!r}, {extra})"
                )
            else:
                lines.append(f"    {var_name}: {type_hint} = Field({extra})")
        else:
            if default_val is not None:
                lines.append(f"    {var_name}: {type_hint} = {default_val!r}")
            else:
                lines.append(f"    {var_name}: {type_hint}")

    lines.append("")

    # Write output
    output.write_text("\n".join(lines))
    print_success(f"Generated {output}")

    if sensitive_vars:
        console.print(f"[dim]Detected {len(sensitive_vars)} sensitive variable(s)[/dim]")


@app.command()
def hook(
    install: Annotated[
        bool, typer.Option("--install", "-i", help="Install pre-commit hook")
    ] = False,
    show_config: Annotated[
        bool, typer.Option("--config", help="Show pre-commit config snippet")
    ] = False,
) -> None:
    """
    Manage the pre-commit hook integration by showing a sample config or installing hooks.

    When invoked with --config or without --install, prints a pre-commit configuration snippet for envdrift hooks.
    When invoked with --install, attempts to install the hooks using the pre-commit integration and prints success on completion.

    Parameters:
        install (bool): If True, install the pre-commit hooks into the project (--install / -i).
        show_config (bool): If True, print the sample pre-commit configuration snippet (--config).

    Raises:
        typer.Exit: If installation is requested but the pre-commit integration is unavailable.
    """
    if show_config or (not install):
        hook_config = """# Add to .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: envdrift-validate
        name: Validate env files
        entry: envdrift validate --ci
        language: system
        files: ^\\.env\\.(production|staging|development)$
        pass_filenames: true

      - id: envdrift-encryption
        name: Check env encryption
        entry: envdrift encrypt --check
        language: system
        files: ^\\.env\\.(production|staging)$
        pass_filenames: true

      # Optional: Verify encryption keys match vault (prevents key drift)
      # - id: envdrift-vault-verify
      #   name: Verify vault key can decrypt
      #   entry: envdrift decrypt --verify-vault -p azure --vault-url https://myvault.vault.azure.net --secret myapp-dotenvx-key --ci
      #   language: system
      #   files: ^\\.env\\.production$
      #   pass_filenames: true
"""
        console.print(hook_config)

        if not install:
            console.print("[dim]Use --install to add hooks to .pre-commit-config.yaml[/dim]")
            return

    if install:
        try:
            from envdrift.integrations.precommit import install_hooks

            install_hooks()
            print_success("Pre-commit hooks installed")
        except ImportError:
            print_error("Pre-commit integration not available")
            console.print("Copy the config above to .pre-commit-config.yaml manually")
            raise typer.Exit(code=1) from None


@app.command()
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
    Sync encryption keys from vault to local .env.keys files.

    Fetches DOTENV_PRIVATE_KEY_* secrets from cloud vaults (Azure Key Vault,
    AWS Secrets Manager, HashiCorp Vault) and syncs them to local service
    directories for dotenvx decryption.

    Configuration can be provided via:
    - TOML: pyproject.toml [tool.envdrift.vault.sync] or envdrift.toml [vault.sync]
    - Legacy: pair.txt file with secret=folder format

    Examples:
        # Auto-discover config from pyproject.toml or envdrift.toml
        envdrift sync

        # TOML config file
        envdrift sync -c envdrift.toml

        # Legacy pair.txt format
        envdrift sync -c pair.txt -p azure --vault-url https://myvault.vault.azure.net/

        # Verify mode (CI)
        envdrift sync --verify --ci
    """
    import tomllib

    from envdrift.config import ConfigNotFoundError, find_config, load_config
    from envdrift.output.rich import print_service_sync_status, print_sync_result
    from envdrift.sync.config import SyncConfig, SyncConfigError

    # Determine config source for defaults:
    # 1. If --config points to a TOML file, use it for defaults
    # 2. Otherwise, use auto-discovery (find_config)
    # Note: skip discovery when --config is provided (e.g., pair.txt) to avoid
    # pulling defaults from unrelated projects.
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
        from envdrift.sync.config import ServiceMapping

        sync_config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name=m.secret_name,
                    folder_path=Path(m.folder_path),
                    vault_name=m.vault_name,
                    environment=m.environment,
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
            "Options: azure, aws, hashicorp"
        )
        raise typer.Exit(code=1)

    # Validate provider-specific options
    if effective_provider == "azure" and not effective_vault_url:
        print_error("Azure provider requires --vault-url " "(or [vault.azure] vault_url in config)")
        raise typer.Exit(code=1)

    if effective_provider == "hashicorp" and not effective_vault_url:
        print_error(
            "HashiCorp provider requires --vault-url " "(or [vault.hashicorp] url in config)"
        )
        raise typer.Exit(code=1)

    # Create vault client
    try:
        from envdrift.vault import get_vault_client

        vault_kwargs: dict = {}
        if effective_provider == "azure":
            vault_kwargs["vault_url"] = effective_vault_url
        elif effective_provider == "aws":
            vault_kwargs["region"] = effective_region or "us-east-1"
        elif effective_provider == "hashicorp":
            vault_kwargs["url"] = effective_vault_url

        vault_client = get_vault_client(effective_provider, **vault_kwargs)
    except ImportError as e:
        print_error(str(e))
        raise typer.Exit(code=1) from None
    except ValueError as e:
        print_error(str(e))
        raise typer.Exit(code=1) from None

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


@app.command()
def version() -> None:
    """
    Display the installed envdrift version in the console.

    Prints the current package version using the application's styled console output.
    """
    console.print(f"envdrift [bold green]{__version__}[/bold green]")


if __name__ == "__main__":
    app()
