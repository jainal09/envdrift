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

    Non-identifier .env keys (leading digits, dashes) are skipped by the strict
    parser; keys that are valid identifiers but Python keywords (`class`,
    `import`) are emitted with a sanitized attribute name plus a Pydantic
    ``alias`` so the generated module always imports cleanly.

    Returns:
        Path: The path to the written settings file.

    Raises:
        FileNotFoundError: If the specified env_file does not exist or cannot be read.
        ValueError: If ``class_name`` is not a valid Python identifier.
    """
    from envdrift.cli_commands.init_cmd import generate_settings_module

    env_file = Path(env_file)
    output = Path(output)

    result = generate_settings_module(env_file, class_name, detect_sensitive)
    output.write_text(result.source)
    return output
