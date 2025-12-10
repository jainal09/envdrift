"""Configuration loader for envdrift.toml."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class VaultConfig:
    """Vault-specific configuration."""

    provider: str = "azure"  # azure, aws, hashicorp
    azure_vault_url: str | None = None
    aws_region: str = "us-east-1"
    hashicorp_url: str | None = None
    mappings: dict[str, str] = field(default_factory=dict)


@dataclass
class ValidationConfig:
    """Validation settings."""

    check_encryption: bool = True
    strict_extra: bool = True
    secret_patterns: list[str] = field(default_factory=list)


@dataclass
class PrecommitConfig:
    """Pre-commit hook settings."""

    files: list[str] = field(default_factory=list)
    schemas: dict[str, str] = field(default_factory=dict)


@dataclass
class EnvdriftConfig:
    """Complete envdrift configuration."""

    # Core settings
    schema: str | None = None
    environments: list[str] = field(
        default_factory=lambda: ["development", "staging", "production"]
    )
    env_file_pattern: str = ".env.{environment}"

    # Sub-configs
    validation: ValidationConfig = field(default_factory=ValidationConfig)
    vault: VaultConfig = field(default_factory=VaultConfig)
    precommit: PrecommitConfig = field(default_factory=PrecommitConfig)

    # Raw config for access to custom fields
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EnvdriftConfig:
        """
        Builds an EnvdriftConfig from a configuration dictionary.

        Parses top-level sections (expected keys: "envdrift", "validation", "vault", "precommit"), applies sensible defaults for missing fields, and returns a populated EnvdriftConfig with the original dictionary stored in `raw`.

        Parameters:
            data (dict[str, Any]): Parsed TOML/pyproject data containing configuration sections.

        Returns:
            EnvdriftConfig: Configuration object populated from `data`.
        """
        envdrift_section = data.get("envdrift", {})
        validation_section = data.get("validation", {})
        vault_section = data.get("vault", {})
        precommit_section = data.get("precommit", {})

        # Build validation config
        validation = ValidationConfig(
            check_encryption=validation_section.get("check_encryption", True),
            strict_extra=validation_section.get("strict_extra", True),
            secret_patterns=validation_section.get("secret_patterns", []),
        )

        # Build vault config
        vault = VaultConfig(
            provider=vault_section.get("provider", "azure"),
            azure_vault_url=vault_section.get("azure", {}).get("vault_url"),
            aws_region=vault_section.get("aws", {}).get("region", "us-east-1"),
            hashicorp_url=vault_section.get("hashicorp", {}).get("url"),
            mappings=vault_section.get("mappings", {}),
        )

        # Build precommit config
        precommit = PrecommitConfig(
            files=precommit_section.get("files", []),
            schemas=precommit_section.get("schemas", {}),
        )

        return cls(
            schema=envdrift_section.get("schema"),
            environments=envdrift_section.get(
                "environments", ["development", "staging", "production"]
            ),
            env_file_pattern=envdrift_section.get("env_file_pattern", ".env.{environment}"),
            validation=validation,
            vault=vault,
            precommit=precommit,
            raw=data,
        )


class ConfigNotFoundError(Exception):
    """Configuration file not found."""

    pass


def find_config(start_dir: Path | None = None, filename: str = "envdrift.toml") -> Path | None:
    """
    Locate an envdrift configuration file by searching the given directory and its parents.

    Searches each directory from start_dir (defaults to the current working directory) up to the filesystem root for a file named by `filename`. If no such file is found, also checks each directory's pyproject.toml for a top-level [tool.envdrift] section and returns that pyproject path when present.

    Parameters:
        start_dir (Path | None): Directory to start searching from; defaults to the current working directory.
        filename (str): Configuration filename to look for (default "envdrift.toml").

    Returns:
        Path | None: Path to the first matching configuration file or pyproject.toml containing [tool.envdrift], or `None` if none is found.
    """
    if start_dir is None:
        start_dir = Path.cwd()

    current = start_dir.resolve()

    while current != current.parent:
        config_path = current / filename
        if config_path.exists():
            return config_path

        # Also check pyproject.toml for [tool.envdrift] section
        pyproject = current / "pyproject.toml"
        if pyproject.exists():
            try:
                with open(pyproject, "rb") as f:
                    data = tomllib.load(f)
                if "tool" in data and "envdrift" in data["tool"]:
                    return pyproject
            except (OSError, tomllib.TOMLDecodeError):
                # Skip malformed or unreadable pyproject.toml files
                pass

        current = current.parent

    return None


def load_config(path: Path | str | None = None) -> EnvdriftConfig:
    """Load configuration from envdrift.toml or pyproject.toml.

    Args:
        path: Path to config file (auto-detected if None)

    Returns:
        EnvdriftConfig instance

    Raises:
        ConfigNotFoundError: If config file not found and path was specified
    """
    if path is not None:
        path = Path(path)
        if not path.exists():
            raise ConfigNotFoundError(f"Configuration file not found: {path}")
    else:
        path = find_config()
        if path is None:
            # Return default config if no file found
            return EnvdriftConfig()

    with open(path, "rb") as f:
        data = tomllib.load(f)

    # Check if this is pyproject.toml with [tool.envdrift]
    if path.name == "pyproject.toml":
        tool_config = data.get("tool", {}).get("envdrift", {})
        if tool_config:
            # Restructure to expected format (copy to avoid mutating original)
            envdrift_section = dict(tool_config)
            data = {"envdrift": envdrift_section}
            if "validation" in envdrift_section:
                data["validation"] = envdrift_section.get("validation")
                del envdrift_section["validation"]
            if "vault" in envdrift_section:
                data["vault"] = envdrift_section.get("vault")
                del envdrift_section["vault"]
            if "precommit" in envdrift_section:
                data["precommit"] = envdrift_section.get("precommit")
                del envdrift_section["precommit"]

    return EnvdriftConfig.from_dict(data)


def get_env_file_path(config: EnvdriftConfig, environment: str) -> Path:
    """
    Build the Path to the .env file for the given environment using the configuration's env_file_pattern.

    Parameters:
        config (EnvdriftConfig): Configuration whose env_file_pattern will be formatted.
        environment (str): Environment name inserted into the pattern (replaces `{environment}`).

    Returns:
        Path: Path to the computed .env file.
    """
    filename = config.env_file_pattern.format(environment=environment)
    return Path(filename)


def get_schema_for_environment(config: EnvdriftConfig, environment: str) -> str | None:
    """
    Resolve the schema path to use for a given environment.

    Prefers an environment-specific precommit schema when configured; otherwise returns the default schema from the config.

    Returns:
        The schema path for `environment`, or `None` if no schema is configured.
    """
    # Check for environment-specific schema
    env_schema = config.precommit.schemas.get(environment)
    if env_schema:
        return env_schema

    # Fall back to default schema
    return config.schema


# Example config file content
EXAMPLE_CONFIG = """# envdrift.toml - Project configuration

[envdrift]
# Default schema for validation
schema = "config.settings:ProductionSettings"

# Environments to manage
environments = ["development", "staging", "production"]

# Path pattern for env files
env_file_pattern = ".env.{environment}"

[validation]
# Check encryption by default
check_encryption = true

# Treat extra vars as errors (matches Pydantic extra="forbid")
strict_extra = true

# Additional secret detection patterns
secret_patterns = [
    "^STRIPE_",
    "^TWILIO_",
]

[vault]
# Vault provider: azure, aws, hashicorp
provider = "azure"

[vault.azure]
vault_url = "https://my-vault.vault.azure.net/"

[vault.aws]
region = "us-east-1"

[vault.hashicorp]
url = "https://vault.example.com:8200"
# token from VAULT_TOKEN env var

# Key mappings: vault_secret_name -> local_path
[vault.mappings]
"myapp-dotenvx-key" = "."
"service2-dotenvx-key" = "services/service2"

[precommit]
# Files to validate on commit
files = [
    ".env.production",
    ".env.staging",
]

# Schema per environment (optional override)
[precommit.schemas]
production = "config.settings:ProductionSettings"
staging = "config.settings:StagingSettings"
"""


def create_example_config(path: Path | None = None) -> Path:
    """
    Create an example envdrift.toml configuration file at the given path.

    Parameters:
        path (Path | None): Destination path for the example config. If None, defaults to "./envdrift.toml".

    Returns:
        Path: The path to the created configuration file.

    Raises:
        FileExistsError: If a file already exists at the target path.
    """
    if path is None:
        path = Path("envdrift.toml")

    if path.exists():
        raise FileExistsError(f"Configuration file already exists: {path}")

    path.write_text(EXAMPLE_CONFIG)
    return path
