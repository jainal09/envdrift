"""Diff command for envdrift."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated

import typer

from envdrift.core.diff import DiffEngine
from envdrift.core.parser import EnvParser
from envdrift.core.schema import SchemaLoader, SchemaLoadError, SchemaMetadata
from envdrift.output.rich import print_diff_result, print_error, print_warning


def _load_schema_meta(schema: str, service_dir: Path | None, format_: str) -> SchemaMetadata | None:
    """Load schema metadata for masking, surfacing a load failure as a warning.

    In ``json`` mode the warning is routed to stderr so stdout stays pure JSON
    and a documented ``--format json > drift.json`` capture still parses (#413).
    Returns ``None`` when the schema can't be loaded.
    """
    loader = SchemaLoader()
    try:
        settings_cls = loader.load(schema, service_dir)
        return loader.extract_metadata(settings_cls)
    except SchemaLoadError as e:
        if format_ == "json":
            print(f"[WARN] Could not load schema: {e}", file=sys.stderr)
        else:
            print_warning(f"Could not load schema: {e}")
        return None


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
    normalize: Annotated[
        bool,
        typer.Option(
            "--normalize/--strict",
            help=(
                "Normalize values (whitespace, bool casing, JSON quote style) and "
                "use --schema types for comparison. Disable with --strict for "
                "raw string compare."
            ),
        ),
    ] = True,
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
        normalize (bool): If True (default), normalize values before comparing — strips leading/trailing whitespace, treats `true/True/TRUE` (and similar bool aliases) as equal, and parses JSON-style lists/dicts so quote-style differences don't read as drift. When a `--schema` is provided, values are also coerced through the corresponding Pydantic type before comparison. Pass `--strict` to disable and fall back to raw string compare.
    """
    # Validate output format up-front (mirrors guard's --fail-on validation).
    # Lowercase first so "JSON"/"Table" are accepted, but reject anything else
    # instead of silently falling back to a Rich table (which would corrupt a
    # CI pipeline that captured stdout expecting JSON).
    format_ = format_.lower()
    if format_ not in {"table", "json"}:
        print_error(f"Invalid --format '{format_}'. Valid options: table, json")
        raise typer.Exit(code=1)

    # Check files exist
    if not env1.exists():
        print_error(f"ENV file not found: {env1}")
        raise typer.Exit(code=1)
    if not env2.exists():
        print_error(f"ENV file not found: {env2}")
        raise typer.Exit(code=1)

    # Load schema if provided
    schema_meta = _load_schema_meta(schema, service_dir, format_) if schema else None

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
        normalize=normalize,
    )

    # Output
    if format_ == "json":
        # Emit plain JSON via stdlib print so forced color / TTY (FORCE_COLOR)
        # never injects ANSI into machine-readable output (#333).
        print(json.dumps(engine.to_dict(result), indent=2))
    else:
        print_diff_result(result, show_unchanged=include_unchanged)
