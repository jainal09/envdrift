"""Validation command for envdrift."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Annotated

import typer

from envdrift.config import ConfigNotFoundError, ValidationConfig, find_config, load_config
from envdrift.core.parser import EnvParser
from envdrift.core.schema import SchemaLoader, SchemaLoadError
from envdrift.core.validator import Validator
from envdrift.output.rich import console, print_error, print_validation_result


def _resolve_validation_settings(check_encryption_flag: bool | None) -> tuple[bool, bool]:
    """Resolve effective ``(check_encryption, check_extra)`` from the CLI flag
    and ``[validation]`` config.

    ``--check-encryption/--no-check-encryption`` overrides config when passed
    explicitly; otherwise ``[validation].check_encryption`` is the default.
    ``check_extra`` comes from ``[validation].strict_extra``. A config that
    cannot be loaded raises ``typer.Exit(1)`` with a clean error.
    """
    validation_cfg = ValidationConfig()
    config_path = find_config()
    if config_path is not None:
        try:
            validation_cfg = load_config(config_path).validation
        except (OSError, ValueError, tomllib.TOMLDecodeError, ConfigNotFoundError) as exc:
            print_error(f"Failed to load envdrift config ({config_path}): {exc}")
            raise typer.Exit(code=1) from None

    effective_check_encryption = (
        check_encryption_flag
        if check_encryption_flag is not None
        else validation_cfg.check_encryption
    )
    return effective_check_encryption, validation_cfg.strict_extra


def validate(
    env_files: Annotated[
        list[Path] | None,
        typer.Argument(help="Path(s) to .env file(s) to validate (default: .env)"),
    ] = None,
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
        bool | None,
        typer.Option(
            "--check-encryption/--no-check-encryption",
            help="Check that sensitive vars are encrypted "
            "(default: [validation].check_encryption from envdrift.toml, else on)",
        ),
    ] = None,
    fix: Annotated[
        bool, typer.Option("--fix", help="Output template for missing variables")
    ] = False,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Show additional details")
    ] = False,
) -> None:
    """
    Validate one or more .env files against a Pydantic Settings schema and display results.

    Loads the specified Settings class, parses each given .env file, runs validation
    (including optional encryption checks and extra-key checks), and prints a
    human-readable validation report per file. Accepting multiple files keeps the
    command usable as a pre-commit ``pass_filenames: true`` hook entry, where every
    matched staged file is appended to one invocation (#493). If --fix is provided,
    prints a generated template for each failing file. Exits with code 1 on invalid
    schema or missing env file; when --ci is set, also exits with code 1 if any
    validation result is invalid.

    Parameters:
        env_files (list[Path] | None): Paths of the .env files to validate;
            defaults to ``.env`` when omitted.
        schema (str | None): Dotted import path to the Pydantic Settings class
            (for example: "app.config:Settings"). Required; the command exits with
            code 1 if not provided or if loading fails.
        service_dir (Path | None): Optional directory to add to imports when
            resolving the schema.
        ci (bool): When true, exit with code 1 if validation fails.
        check_encryption (bool | None): Tri-state. When explicitly set via
            ``--check-encryption``/``--no-check-encryption`` it overrides config;
            when left unset (None) it falls back to ``[validation].check_encryption``
            from envdrift.toml (default on). Controls validation of
            encryption-related metadata on sensitive fields.
        fix (bool): When true and validation fails, print a fix template with
            missing variables and defaults when available.
        verbose (bool): When true, include additional details in the validation
            output.
    """
    files = list(env_files) if env_files else [Path(".env")]

    if schema is None:
        print_error("--schema is required. Example: --schema 'app.config:Settings'")
        raise typer.Exit(code=1)

    # Check all env files exist before doing any work
    missing_files = [env_file for env_file in files if not env_file.exists()]
    if missing_files:
        for env_file in missing_files:
            print_error(f"ENV file not found: {env_file}")
        raise typer.Exit(code=1)

    # Load schema. Default --service-dir to the cwd so a schema generated by
    # `envdrift init` in the project root (e.g. settings.py) imports without the
    # user having to discover `--service-dir .`.
    effective_service_dir = service_dir if service_dir is not None else Path.cwd()
    loader = SchemaLoader()
    try:
        settings_cls = loader.load(schema, effective_service_dir)
        schema_meta = loader.extract_metadata(settings_cls)
    except SchemaLoadError as e:
        print_error(str(e))
        raise typer.Exit(code=1) from None

    # Resolve [validation] config: CLI flag overrides check_encryption; strict_extra
    # drives check_extra (False skips the extra-variable check entirely).
    effective_check_encryption, check_extra = _resolve_validation_settings(check_encryption)

    parser = EnvParser()
    validator = Validator()
    any_invalid = False

    for env_file in files:
        # Parse env file. lenient=True so non-identifier / non-ASCII keys (which
        # init emits as alias-backed schema fields) are present and can be matched
        # against the schema by alias — keeping the init→validate round-trip intact.
        try:
            env = parser.parse(env_file, lenient=True)
        except (FileNotFoundError, IsADirectoryError, ValueError) as e:
            # IsADirectoryError: a directory passed where a file is expected;
            # ValueError: a non-UTF-8 / binary file. Surface both cleanly (#24, #25).
            print_error(str(e))
            raise typer.Exit(code=1) from None

        result = validator.validate(
            env,
            schema_meta,
            check_encryption=effective_check_encryption,
            check_extra=check_extra,
        )

        # Print result
        print_validation_result(result, env_file, schema_meta, verbose=verbose)

        # Generate fix template if requested
        if fix and not result.valid:
            template = validator.generate_fix_template(result, schema_meta)
            if template:
                console.print("[bold]Fix template:[/bold]")
                console.print(template)

        if not result.valid:
            any_invalid = True

    # Exit with appropriate code
    if ci and any_invalid:
        raise typer.Exit(code=1)
