"""Diff command for envdrift."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from envdrift.core.diff import DiffEngine
from envdrift.core.parser import EnvParser
from envdrift.core.schema import SchemaLoader, SchemaLoadError
from envdrift.output.rich import console, print_diff_result, print_error, print_warning


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
