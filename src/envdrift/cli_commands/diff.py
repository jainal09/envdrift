"""Diff command for envdrift."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated, NoReturn

import typer

from envdrift.core.diff import DiffEngine
from envdrift.core.parser import EnvFile, EnvParser
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


def _emit_error(message: str, format_: str) -> NoReturn:
    """Emit an error honoring the output format, then exit nonzero.

    In ``json`` mode a clean ``{"error": ...}`` object is written to stdout via
    stdlib ``json`` (no ANSI, always parseable) so a ``--format json`` consumer
    is never handed Rich prose mid-stream; otherwise a Rich ``[ERROR]`` line is
    printed. Used for every error path so binary/directory/not-found inputs fail
    cleanly instead of leaking a traceback or colorized prose (#443).
    """
    if format_ == "json":
        print(json.dumps({"error": message}))
    else:
        print_error(message)
    raise typer.Exit(code=1)


def _read_env(path: Path, format_: str) -> EnvFile:
    """Validate and parse one .env file, surfacing every failure as a clean error.

    Guards the cases the adversarial sweep crashed on: a directory passed where a
    file is expected (``IsADirectoryError``) and a binary / non-UTF-8 file
    (``UnicodeDecodeError``) both produced an uncaught traceback. Returns the
    parsed file or exits nonzero with an actionable message.
    """
    # Typer's Path argument already rejects an unreadable file (Click exits 2
    # with a clean "is not readable" message), so the remaining cases to guard
    # are a missing path, a directory, and a readable-but-binary file.
    if not path.exists():
        _emit_error(f"ENV file not found: {path}", format_)
    if not path.is_file():
        _emit_error(f"Not a file: {path}", format_)
    try:
        return EnvParser().parse(path)
    except ValueError:
        # EnvParser converts a non-UTF-8 read into a ValueError (UnicodeDecodeError
        # is itself a ValueError subclass), so this one arm covers both.
        _emit_error(f"Could not read {path} as UTF-8 text (not a valid .env file)", format_)


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
    exit_on_drift: Annotated[
        bool,
        typer.Option(
            "--exit-on-drift",
            "--ci",
            help="Exit with code 1 when drift is detected",
        ),
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
        exit_on_drift (bool): If True, exit with code 1 after displaying output when drift is detected. Defaults to False.
        normalize (bool): If True (default), normalize values before comparing — strips leading/trailing whitespace, treats `true/True/TRUE` (and similar bool aliases) as equal, and parses JSON-style lists/dicts so quote-style differences don't read as drift. When a `--schema` is provided, values are also coerced through the corresponding Pydantic type before comparison. Pass `--strict` to disable and fall back to raw string compare.
    """
    # Validate output format up-front (mirrors guard's --fail-on validation).
    # Lowercase first so "JSON"/"Table" are accepted, but reject anything else
    # instead of silently falling back to a Rich table (which would corrupt a
    # CI pipeline that captured stdout expecting JSON).
    format_ = format_.lower()
    if format_ not in {"table", "json"}:
        _emit_error(f"Invalid --format '{format_}'. Valid options: table, json", format_)

    # Validate + parse both files. Clean, format-aware errors for missing,
    # directory, and binary/non-UTF-8 inputs instead of an uncaught traceback.
    env_file1 = _read_env(env1, format_)
    env_file2 = _read_env(env2, format_)

    # Load schema if provided
    schema_meta = _load_schema_meta(schema, service_dir, format_) if schema else None

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

    if exit_on_drift and result.has_drift:
        raise typer.Exit(code=1)
