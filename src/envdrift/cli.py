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


@app.command("decrypt")
def decrypt_cmd(
    env_file: Annotated[Path, typer.Argument(help="Path to encrypted .env file")] = Path(".env"),
) -> None:
    """Decrypt an encrypted .env file using dotenvx."""
    if not env_file.exists():
        print_error(f"ENV file not found: {env_file}")
        raise typer.Exit(code=1)

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
        typer.Option("--config", "-c", help="Path to sync config file (pair.txt format)"),
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

    Examples:
        # Azure Key Vault
        envdrift sync -c pair.txt -p azure --vault-url https://myvault.vault.azure.net/

        # AWS Secrets Manager
        envdrift sync -c pair.txt -p aws --region us-west-2

        # HashiCorp Vault
        envdrift sync -c pair.txt -p hashicorp --vault-url http://localhost:8200

        # Verify mode (CI)
        envdrift sync -c pair.txt -p azure --vault-url $URL --verify --ci
    """
    from envdrift.output.rich import print_service_sync_status, print_sync_result

    # Validate required options
    if config_file is None:
        print_error("--config is required. Example: --config pair.txt")
        raise typer.Exit(code=1)

    if provider is None:
        print_error("--provider is required. Options: azure, aws, hashicorp")
        raise typer.Exit(code=1)

    if not config_file.exists():
        print_error(f"Config file not found: {config_file}")
        raise typer.Exit(code=1)

    # Validate provider-specific options
    if provider == "azure" and not vault_url:
        print_error("Azure provider requires --vault-url")
        raise typer.Exit(code=1)

    if provider == "hashicorp" and not vault_url:
        print_error("HashiCorp provider requires --vault-url")
        raise typer.Exit(code=1)

    # Load sync config
    try:
        from envdrift.sync.config import SyncConfig, SyncConfigError

        sync_config = SyncConfig.from_file(config_file)
    except SyncConfigError as e:
        print_error(f"Invalid config file: {e}")
        raise typer.Exit(code=1) from None

    if not sync_config.mappings:
        print_warning("No service mappings found in config file")
        return

    # Create vault client
    try:
        from envdrift.vault import get_vault_client

        vault_kwargs: dict = {}
        if provider == "azure":
            vault_kwargs["vault_url"] = vault_url
        elif provider == "aws":
            vault_kwargs["region"] = region or "us-east-1"
        elif provider == "hashicorp":
            vault_kwargs["url"] = vault_url

        vault_client = get_vault_client(provider, **vault_kwargs)
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
    console.print(f"[dim]Provider: {provider} | Services: {len(sync_config.mappings)}[/dim]")
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
