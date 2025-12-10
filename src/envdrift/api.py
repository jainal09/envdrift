"""Core functionality for envdrift - high-level API functions."""

from __future__ import annotations

from pathlib import Path

from envdrift.core.diff import DiffEngine, DiffResult
from envdrift.core.parser import EnvParser
from envdrift.core.schema import SchemaLoader
from envdrift.core.validator import ValidationResult, Validator


def validate(
    env_file: Path | str = ".env",
    schema: str | None = None,
    service_dir: Path | str | None = None,
    check_encryption: bool = True,
) -> ValidationResult:
    """
    Validate an .env file against a Pydantic Settings class schema.

    Parameters:
        env_file: Path or string to the .env file to validate.
        schema: Dotted path to the Pydantic Settings class (e.g., "app.config:Settings"); required.
        service_dir: Optional directory to add to sys.path to assist importing the schema.
        check_encryption: If true, perform additional checks for encrypted or sensitive values.

    Returns:
        ValidationResult: Result containing validation status and any issues found.

    Raises:
        ValueError: If `schema` is not provided.
        FileNotFoundError: If the env file does not exist or cannot be read.
        SchemaLoadError: If the specified schema cannot be imported or loaded.
    """
    if schema is None:
        raise ValueError("schema is required. Example: 'app.config:Settings'")

    env_file = Path(env_file)

    # Parse env file
    parser = EnvParser()
    env = parser.parse(env_file)

    # Load schema
    loader = SchemaLoader()
    settings_cls = loader.load(schema, service_dir)
    schema_meta = loader.extract_metadata(settings_cls)

    # Validate
    validator = Validator()
    return validator.validate(env, schema_meta, check_encryption=check_encryption)


def diff(
    env1: Path | str,
    env2: Path | str,
    schema: str | None = None,
    service_dir: Path | str | None = None,
    mask_values: bool = True,
) -> DiffResult:
    """
    Compute differences between two .env files.

    Parameters:
        env1 (Path | str): Path to the first .env file.
        env2 (Path | str): Path to the second .env file.
        schema (str | None): Optional dotted path to a Pydantic Settings class used to identify sensitive fields.
        service_dir (Path | str | None): Optional directory to add to imports when loading the schema.
        mask_values (bool): If true, mask sensitive values in the resulting diff.

    Returns:
        DiffResult: Differences between the files, including added, removed, and changed variables. Sensitive values are masked when requested.

    Raises:
        FileNotFoundError: If either env1 or env2 does not exist.
    """
    env1 = Path(env1)
    env2 = Path(env2)

    # Parse env files
    parser = EnvParser()
    env_file1 = parser.parse(env1)
    env_file2 = parser.parse(env2)

    # Load schema if provided
    schema_meta = None
    if schema:
        loader = SchemaLoader()
        settings_cls = loader.load(schema, service_dir)
        schema_meta = loader.extract_metadata(settings_cls)

    # Diff
    engine = DiffEngine()
    return engine.diff(env_file1, env_file2, schema=schema_meta, mask_values=mask_values)


def init(
    env_file: Path | str = ".env",
    output: Path | str = "settings.py",
    class_name: str = "Settings",
    detect_sensitive: bool = True,
) -> Path:
    """
    Generate a Pydantic BaseSettings subclass file from an existing .env file.

    Parses the provided env file, optionally detects variables that appear sensitive, and writes a Python module defining a Pydantic Settings class with inferred type hints and defaults. Sensitive fields are marked with `json_schema_extra={"sensitive": True}`.

    Parameters:
        env_file (Path | str): Path to the source .env file.
        output (Path | str): Path where the generated Python module will be written.
        class_name (str): Name to use for the generated Settings class.
        detect_sensitive (bool): If True, attempt to detect sensitive variables and mark them in the generated fields.

    Returns:
        Path: The path to the written settings file.

    Raises:
        FileNotFoundError: If the specified env_file does not exist or cannot be read.
    """
    from envdrift.core.encryption import EncryptionDetector

    env_file = Path(env_file)
    output = Path(output)

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
            default_val = None

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
    return output
