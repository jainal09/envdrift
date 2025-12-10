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
    """Validate an .env file against a Pydantic schema.

    Args:
        env_file: Path to the .env file to validate
        schema: Dotted path to the Pydantic Settings class (e.g., 'app.config:Settings')
        service_dir: Optional directory to add to sys.path for imports
        check_encryption: Whether to check if sensitive vars are encrypted

    Returns:
        ValidationResult with validation status and any issues found

    Raises:
        FileNotFoundError: If env file doesn't exist
        SchemaLoadError: If schema cannot be loaded
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
    """Compare two .env files and return differences.

    Args:
        env1: Path to first .env file
        env2: Path to second .env file
        schema: Optional schema for sensitive field detection
        service_dir: Optional directory to add to sys.path for imports
        mask_values: Whether to mask sensitive values in output

    Returns:
        DiffResult with all differences between the files

    Raises:
        FileNotFoundError: If either env file doesn't exist
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
    """Generate a Pydantic Settings class from an existing .env file.

    Args:
        env_file: Path to the .env file to read
        output: Path where to write the generated Settings class
        class_name: Name for the Settings class
        detect_sensitive: Auto-detect sensitive variables

    Returns:
        Path to the generated file

    Raises:
        FileNotFoundError: If env file doesn't exist
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
            if detector.is_name_sensitive(var_name) or detector.is_value_suspicious(env_var.value):
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
            if default_val is not None:
                lines.append(f'    {var_name}: {type_hint} = Field(default={default_val!r}, json_schema_extra={{"sensitive": True}})')
            else:
                lines.append(f'    {var_name}: {type_hint} = Field(json_schema_extra={{"sensitive": True}})')
        else:
            if default_val is not None:
                lines.append(f"    {var_name}: {type_hint} = {default_val!r}")
            else:
                lines.append(f"    {var_name}: {type_hint}")

    lines.append("")

    # Write output
    output.write_text("\n".join(lines))
    return output
