"""Configuration loader for envdrift.toml."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from envdrift.utils import normalize_max_workers

_GUARDIAN_IDLE_TIMEOUT_PATTERN = re.compile(r"^\d+(s|m|h|d)$")


def _validate_guardian_idle_timeout(value: Any) -> str:
    """Validate guardian idle_timeout format (e.g., 5m, 1h, 30s)."""
    if not isinstance(value, str):
        raise ValueError("guardian.idle_timeout must be a string like '5m'")

    normalized = value.strip().lower()
    if not _GUARDIAN_IDLE_TIMEOUT_PATTERN.match(normalized):
        raise ValueError("guardian.idle_timeout must match '<number><s|m|h|d>', e.g. '5m' or '30s'")

    return normalized


@dataclass
class SyncMappingConfig:
    """Sync mapping configuration for vault key synchronization."""

    secret_name: str
    folder_path: str
    vault_name: str | None = None
    environment: str | None = None  # None = derive from profile or default to "production"
    profile: str | None = None  # Profile name for filtering (e.g., "local", "prod")
    activate_to: str | None = None  # Path to copy decrypted file when profile is activated
    ephemeral_keys: bool | None = None  # None = inherit from central SyncConfig


@dataclass
class SyncConfig:
    """Sync-specific configuration."""

    mappings: list[SyncMappingConfig] = field(default_factory=list)
    default_vault_name: str | None = None
    env_keys_filename: str = ".env.keys"
    max_workers: int | None = None
    ephemeral_keys: bool = False  # When True, never store .env.keys locally


@dataclass
class VaultConfig:
    """Vault-specific configuration."""

    provider: str = "azure"  # azure, aws, hashicorp, gcp
    azure_vault_url: str | None = None
    aws_region: str = "us-east-1"
    hashicorp_url: str | None = None
    gcp_project_id: str | None = None
    mappings: dict[str, str] = field(default_factory=dict)
    sync: SyncConfig = field(default_factory=SyncConfig)


@dataclass
class EncryptionConfig:
    """Encryption backend settings."""

    # Encryption backend: dotenvx (default) or sops
    backend: str = "dotenvx"

    # Smart encryption: skip re-encryption if content unchanged (opt-in)
    smart_encryption: bool = False

    # dotenvx-specific settings
    dotenvx_auto_install: bool = False

    # SOPS-specific settings
    sops_auto_install: bool = False
    sops_config_file: str | None = None  # Path to .sops.yaml
    sops_age_key_file: str | None = None  # Path to age key file
    sops_age_recipients: str | None = None  # Age public key(s) for encryption
    sops_kms_arn: str | None = None  # AWS KMS key ARN
    sops_gcp_kms: str | None = None  # GCP KMS resource ID
    sops_azure_kv: str | None = None  # Azure Key Vault key URL


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
class GitHookCheckConfig:
    """Git hook check settings."""

    method: str | None = None
    precommit_config: str | None = None


@dataclass
class GuardConfig:
    """Guard command configuration for secret scanning.

    Example envdrift.toml:
        [guard]
        scanners = ["native", "gitleaks"]
        auto_install = true
        include_history = false
        check_entropy = false
        entropy_threshold = 4.5
        fail_on_severity = "high"
        skip_clear_files = false  # Set to true to skip .clear files
        skip_duplicate = false  # Set to true to show only unique secrets
        ignore_paths = ["*.test.py", "tests/**"]

        [guard.ignore_rules]
        "high-entropy-string" = ["**/*.clear"]
    """

    scanners: list[str] = field(default_factory=lambda: ["native", "gitleaks"])
    auto_install: bool = True
    include_history: bool = False
    check_entropy: bool = False
    entropy_threshold: float = 4.5
    fail_on_severity: str = "high"
    skip_clear_files: bool = False  # Skip .clear files from scanning
    skip_encrypted_files: bool = True  # Skip findings from encrypted files (dotenvx/SOPS)
    skip_duplicate: bool = False  # Show only unique findings by secret value
    skip_gitignored: bool = False  # Skip findings from gitignored files
    ignore_paths: list[str] = field(default_factory=list)
    ignore_rules: dict[str, list[str]] = field(default_factory=dict)
    verify_secrets: bool = False  # For trufflehog verification


@dataclass
class PartialEncryptionEnvironmentConfig:
    """Partial encryption configuration for a single environment."""

    name: str
    clear_file: str
    secret_file: str
    combined_file: str


@dataclass
class GuardianWatchConfig:
    """Guardian background agent watch configuration.

    This is the per-project configuration that tells the agent how to watch
    and auto-encrypt .env files in this project.

    Example envdrift.toml:
        [guardian]
        enabled = true
        idle_timeout = "5m"
        patterns = [".env*"]
        exclude = [".env.example", ".env.sample", ".env.keys"]
        notify = true
    """

    enabled: bool = False  # When True, register this project with the agent
    idle_timeout: str = "5m"  # Encrypt after idle for this duration
    patterns: list[str] = field(default_factory=lambda: [".env*"])
    exclude: list[str] = field(default_factory=lambda: [".env.example", ".env.sample", ".env.keys"])
    notify: bool = True  # Desktop notifications when encrypting


@dataclass
class PartialEncryptionConfig:
    """Partial encryption settings."""

    enabled: bool = False
    environments: list[PartialEncryptionEnvironmentConfig] = field(default_factory=list)


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
    encryption: EncryptionConfig = field(default_factory=EncryptionConfig)
    precommit: PrecommitConfig = field(default_factory=PrecommitConfig)
    git_hook_check: GitHookCheckConfig = field(default_factory=GitHookCheckConfig)
    partial_encryption: PartialEncryptionConfig = field(default_factory=PartialEncryptionConfig)
    guard: GuardConfig = field(default_factory=GuardConfig)
    guardian: GuardianWatchConfig = field(default_factory=GuardianWatchConfig)

    # Raw config for access to custom fields
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EnvdriftConfig:
        """
        Builds an EnvdriftConfig from a configuration dictionary.

        Parses top-level sections (expected keys: "envdrift", "validation", "vault", "encryption", "precommit", "git_hook_check"), applies sensible defaults for missing fields, and returns a populated EnvdriftConfig with the original dictionary stored in `raw`.

        Parameters:
            data (dict[str, Any]): Parsed TOML/pyproject data containing configuration sections.

        Returns:
            EnvdriftConfig: Configuration object populated from `data`.
        """
        envdrift_section = data.get("envdrift", {})
        validation_section = data.get("validation", {})
        vault_section = data.get("vault", {})
        encryption_section = data.get("encryption", {})
        precommit_section = data.get("precommit", {})
        git_hook_check_section = data.get("git_hook_check", {})

        # Build validation config
        validation = ValidationConfig(
            check_encryption=validation_section.get("check_encryption", True),
            strict_extra=validation_section.get("strict_extra", True),
            secret_patterns=validation_section.get("secret_patterns", []),
        )

        # Build sync config from vault.sync section
        sync_section = vault_section.get("sync", {})
        max_workers = normalize_max_workers(sync_section.get("max_workers"))
        sync_mappings = [
            SyncMappingConfig(
                secret_name=m["secret_name"],
                folder_path=m["folder_path"],
                vault_name=m.get("vault_name"),
                environment=m.get("environment"),  # None = derive from profile
                profile=m.get("profile"),
                activate_to=m.get("activate_to"),
                ephemeral_keys=m.get("ephemeral_keys"),  # None = inherit from central
            )
            for m in sync_section.get("mappings", [])
        ]
        sync_config = SyncConfig(
            mappings=sync_mappings,
            default_vault_name=sync_section.get("default_vault_name"),
            env_keys_filename=sync_section.get("env_keys_filename", ".env.keys"),
            max_workers=max_workers,
            ephemeral_keys=sync_section.get("ephemeral_keys", False),
        )

        # Build vault config
        vault = VaultConfig(
            provider=vault_section.get("provider", "azure"),
            azure_vault_url=vault_section.get("azure", {}).get("vault_url"),
            aws_region=vault_section.get("aws", {}).get("region", "us-east-1"),
            hashicorp_url=vault_section.get("hashicorp", {}).get("url"),
            gcp_project_id=vault_section.get("gcp", {}).get("project_id"),
            mappings=vault_section.get("mappings", {}),
            sync=sync_config,
        )

        # Build precommit config
        precommit = PrecommitConfig(
            files=precommit_section.get("files", []),
            schemas=precommit_section.get("schemas", {}),
        )

        git_hook_check = GitHookCheckConfig(
            method=git_hook_check_section.get("method"),
            precommit_config=git_hook_check_section.get("precommit_config"),
        )

        # Build partial_encryption config
        partial_encryption_section = data.get("partial_encryption", {})
        partial_encryption_envs = [
            PartialEncryptionEnvironmentConfig(
                name=env["name"],
                clear_file=env["clear_file"],
                secret_file=env["secret_file"],
                combined_file=env["combined_file"],
            )
            for env in partial_encryption_section.get("environments", [])
        ]
        partial_encryption = PartialEncryptionConfig(
            enabled=partial_encryption_section.get("enabled", False),
            environments=partial_encryption_envs,
        )

        # Build encryption config
        sops_section = encryption_section.get("sops", {})
        dotenvx_section = encryption_section.get("dotenvx", {})
        encryption = EncryptionConfig(
            backend=encryption_section.get("backend", "dotenvx"),
            smart_encryption=encryption_section.get("smart_encryption", False),
            dotenvx_auto_install=dotenvx_section.get("auto_install", False),
            sops_auto_install=sops_section.get("auto_install", False),
            sops_config_file=sops_section.get("config_file"),
            sops_age_key_file=sops_section.get("age_key_file"),
            sops_age_recipients=sops_section.get("age_recipients"),
            sops_kms_arn=sops_section.get("kms_arn"),
            sops_gcp_kms=sops_section.get("gcp_kms"),
            sops_azure_kv=sops_section.get("azure_kv"),
        )

        # Build guard config
        guard_section = data.get("guard", {})
        scanners = guard_section.get("scanners", ["native", "gitleaks"])
        if isinstance(scanners, str):
            scanners = [scanners]
        guard = GuardConfig(
            scanners=scanners,
            auto_install=guard_section.get("auto_install", True),
            include_history=guard_section.get("include_history", False),
            check_entropy=guard_section.get("check_entropy", False),
            entropy_threshold=guard_section.get("entropy_threshold", 4.5),
            fail_on_severity=guard_section.get("fail_on_severity", "high"),
            skip_clear_files=guard_section.get("skip_clear_files", False),
            skip_encrypted_files=guard_section.get("skip_encrypted_files", True),
            skip_duplicate=guard_section.get("skip_duplicate", False),
            skip_gitignored=guard_section.get("skip_gitignored", False),
            ignore_paths=guard_section.get("ignore_paths", []),
            ignore_rules=guard_section.get("ignore_rules", {}),
            verify_secrets=guard_section.get("verify_secrets", False),
        )

        # Build guardian config (for background agent)
        guardian_section = data.get("guardian", {})
        guardian = GuardianWatchConfig(
            enabled=guardian_section.get("enabled", False),
            idle_timeout=_validate_guardian_idle_timeout(
                guardian_section.get("idle_timeout", "5m")
            ),
            patterns=guardian_section.get("patterns", [".env*"]),
            exclude=guardian_section.get("exclude", [".env.example", ".env.sample", ".env.keys"]),
            notify=guardian_section.get("notify", True),
        )

        return cls(
            schema=envdrift_section.get("schema"),
            environments=envdrift_section.get(
                "environments", ["development", "staging", "production"]
            ),
            env_file_pattern=envdrift_section.get("env_file_pattern", ".env.{environment}"),
            validation=validation,
            vault=vault,
            encryption=encryption,
            precommit=precommit,
            git_hook_check=git_hook_check,
            partial_encryption=partial_encryption,
            guard=guard,
            guardian=guardian,
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
        ValueError: If configuration values are invalid
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
                data["validation"] = envdrift_section.pop("validation")
            if "vault" in envdrift_section:
                data["vault"] = envdrift_section.pop("vault")
            if "encryption" in envdrift_section:
                data["encryption"] = envdrift_section.pop("encryption")
            if "precommit" in envdrift_section:
                data["precommit"] = envdrift_section.pop("precommit")
            if "git_hook_check" in envdrift_section:
                data["git_hook_check"] = envdrift_section.pop("git_hook_check")
            if "partial_encryption" in envdrift_section:
                data["partial_encryption"] = envdrift_section.pop("partial_encryption")
            if "guard" in envdrift_section:
                data["guard"] = envdrift_section.pop("guard")
            if "guardian" in envdrift_section:
                data["guardian"] = envdrift_section.pop("guardian")

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

[encryption]
# Encryption backend: dotenvx (default) or sops
backend = "dotenvx"

# Smart encryption: skip re-encryption if content unchanged (reduces git noise)
# smart_encryption = true

# dotenvx-specific settings
[encryption.dotenvx]
auto_install = false

# SOPS-specific settings (only used when backend = "sops")
[encryption.sops]
auto_install = false
# config_file = ".sops.yaml"  # Path to SOPS configuration
# age_key_file = "key.txt"    # Path to age private key file
# age_recipients = "age1..."  # Age public key(s) for encryption
# kms_arn = "arn:aws:kms:..."  # AWS KMS key ARN
# gcp_kms = "projects/..."    # GCP KMS resource ID
# azure_kv = "https://..."    # Azure Key Vault key URL

[vault]
# Vault provider: azure, aws, hashicorp, gcp
provider = "azure"

[vault.azure]
vault_url = "https://my-vault.vault.azure.net/"

[vault.aws]
region = "us-east-1"

[vault.hashicorp]
url = "https://vault.example.com:8200"

[vault.gcp]
project_id = "my-gcp-project"
# token from VAULT_TOKEN env var

# Sync configuration for `envdrift sync` command
[vault.sync]
default_vault_name = "my-keyvault"
env_keys_filename = ".env.keys"
# max_workers = 4  # Optional: parallelize env file decrypt/encrypt

# Map vault secrets to local service directories
[[vault.sync.mappings]]
secret_name = "myapp-dotenvx-key"
folder_path = "."
environment = "production"

[[vault.sync.mappings]]
secret_name = "service2-dotenvx-key"
folder_path = "services/service2"
vault_name = "other-vault"  # Optional: override default vault
environment = "staging"

# Profile mappings - use with `envdrift pull --profile local`
[[vault.sync.mappings]]
secret_name = "local-key"
folder_path = "."
profile = "local"           # Tag for --profile filtering
activate_to = ".env"        # Copy decrypted .env.local to .env

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

# Git hook verification (optional)
[git_hook_check]
# method = "precommit.yaml"  # or "direct git hook"
# precommit_config = ".pre-commit-config.yaml"

# Partial encryption configuration (optional)
[partial_encryption]
enabled = false

# Configure environments for partial encryption
# [[partial_encryption.environments]]
# name = "production"
# clear_file = ".env.production.clear"
# secret_file = ".env.production.secret"
# combined_file = ".env.production"

# Background agent configuration (optional)
# When enabled, registers this project with the envdrift-agent daemon
[guardian]
enabled = false              # Set to true to register with agent
idle_timeout = "5m"          # Encrypt after 5 minutes idle
patterns = [".env*"]         # File patterns to watch
exclude = [".env.example", ".env.sample", ".env.keys"]  # Files to skip
notify = true                # Desktop notifications when encrypting
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
