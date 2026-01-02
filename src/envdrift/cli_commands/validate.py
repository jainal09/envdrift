"""Validation command for envdrift."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from envdrift.core.parser import EnvParser
from envdrift.core.schema import SchemaLoader, SchemaLoadError
from envdrift.core.validator import Validator
from envdrift.output.rich import console, print_error, print_validation_result


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
