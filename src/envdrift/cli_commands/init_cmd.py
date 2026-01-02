"""Schema generation command for envdrift."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from envdrift.core.encryption import EncryptionDetector
from envdrift.core.parser import EnvParser
from envdrift.output.rich import console, print_error, print_success


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
