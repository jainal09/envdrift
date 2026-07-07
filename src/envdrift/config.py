"""Configuration loader for envdrift.toml."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from envdrift.utils import normalize_max_workers

_GUARDIAN_IDLE_TIMEOUT_PATTERN = re.compile(r"^\d+(s|m|h|d)$")


class ConfigValidationError(ValueError):
    """A config section that a command consumes is invalid.

    Subclasses ``ValueError`` so existing ``except ValueError`` handlers keep
    working, while letting deferred validators (guardian/partial_encryption)
    raise a typed error that consuming commands can convert to a clean message
    (see #413).
    """


def _validate_guardian_idle_timeout(value: Any) -> str:
    """Validate guardian idle_timeout format (e.g., 5m, 1h, 30s)."""
    if not isinstance(value, str):
        raise ConfigValidationError("guardian.idle_timeout must be a string like '5m'")

    normalized = value.strip().lower()
    if not _GUARDIAN_IDLE_TIMEOUT_PATTERN.match(normalized):
        raise ConfigValidationError(
            "guardian.idle_timeout must match '<number><s|m|h|d>', e.g. '5m' or '30s'"
        )

    return normalized


@dataclass
class SyncMappingConfig:
    """Sync mapping configuration for vault key synchronization."""

    secret_name: str
    folder_path: str
    vault_name: str | None = None
    environment: str | None = None  # None = derive from profile or default to "production"
    env_file: str | None = None  # Optional custom env filename relative to folder_path
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
    """Validation settings consumed by ``envdrift validate``.

    ``check_encryption`` seeds the default for the
    ``--check-encryption/--no-check-encryption`` flag (an explicit flag
    overrides it). ``strict_extra`` controls whether variables absent from the
    schema are checked at all (``False`` skips the extra-variable check).
    """

    check_encryption: bool = True
    strict_extra: bool = True


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
    # Combine mode fields (required when secrets_only=False)
    clear_file: str = ""
    secret_file: str = ""
    combined_file: str = ""
    # Secrets-only mode: encrypt/decrypt secrets_dir in place, no combine step,
    # no awareness of any configs directory
    secrets_only: bool = False
    secrets_dir: str = ""
    pattern: str = ".env*"


def validate_partial_encryption_environments(
    environments: list[PartialEncryptionEnvironmentConfig],
) -> None:
    """Check each partial-encryption environment has the fields its mode needs.

    Deferred until the partial-encryption commands actually consume the section
    so an unrelated ``[[partial_encryption.environments]]`` typo can't crash
    commands that never read it (encrypt/decrypt/guard/pull/sync) (#413). Raises
    ``ConfigValidationError`` (a ``ValueError`` subclass).
    """
    for env in environments:
        if not env.name:
            raise ConfigValidationError(
                "partial_encryption environment is missing the required 'name' field"
            )
        if env.secrets_only:
            if not env.secrets_dir:
                raise ConfigValidationError(
                    f"partial_encryption environment '{env.name}': secrets_dir is "
                    "required when secrets_only=true"
                )
        else:
            missing = [
                k for k in ("clear_file", "secret_file", "combined_file") if not getattr(env, k)
            ]
            if missing:
                raise ConfigValidationError(
                    f"partial_encryption environment '{env.name}': "
                    f"missing required field(s) for combine mode: {', '.join(missing)}"
                )


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

    def validate(self) -> str:
        """Validate and return the normalized ``idle_timeout``.

        Deferred until the agent commands consume the ``[guardian]`` section so
        a typo in this agent-only knob does not crash unrelated commands like
        ``encrypt``/``decrypt``/``guard``/``pull`` (see #413). Raises
        ``ConfigValidationError`` (a ``ValueError`` subclass).
        """
        return _validate_guardian_idle_timeout(self.idle_timeout)


@dataclass
class PartialEncryptionConfig:
    """Partial encryption settings."""

    enabled: bool = False
    environments: list[PartialEncryptionEnvironmentConfig] = field(default_factory=list)

    def validate(self) -> None:
        """Validate that each environment has the fields its mode requires.

        Deferred until the partial-encryption commands actually consume this
        section: an unrelated typo in ``[[partial_encryption.environments]]``
        must not crash ``encrypt``/``decrypt``/``guard``/``pull``/``sync``,
        which never read these fields (see #413). Raises ``ConfigValidationError``
        (a ``ValueError`` subclass) so callers that already catch ``ValueError``
        surface a clean message.
        """
        validate_partial_encryption_environments(self.environments)


# Mapping keys that must hold strings when present. Shared shape with
# envdrift.sync.config.SyncConfig.from_toml (the explicit --config path).
_MAPPING_STR_KEYS = (
    "secret_name",
    "folder_path",
    "vault_name",
    "environment",
    "env_file",
    "profile",
    "activate_to",
)


def _validate_sync_mapping_entry(m: Any) -> None:
    """Validate one ``[[vault.sync.mappings]]`` entry, raising a clean ValueError.

    TOML type surprises — a non-table entry (``mappings = [123]``), a missing
    required key, or a non-string value (``folder_path = 123``) — used to
    escape as raw TypeError/KeyError tracebacks from ``Path()``/subscript use
    downstream; validate loudly here instead (#443 #32 #488).
    """
    if not isinstance(m, dict):
        raise ValueError(
            f"[[vault.sync.mappings]] entry must be a table, got {type(m).__name__}: {m!r}"
        )
    missing = [k for k in ("secret_name", "folder_path") if k not in m]
    if missing:
        raise ValueError(
            f"[[vault.sync.mappings]] entry is missing required key(s) {', '.join(missing)}: {m!r}"
        )
    wrong_type = [
        k for k in _MAPPING_STR_KEYS if m.get(k) is not None and not isinstance(m[k], str)
    ]
    if wrong_type:
        raise ValueError(
            f"[[vault.sync.mappings]] entry has non-string value(s) for "
            f"{', '.join(wrong_type)}: {m!r}"
        )


def _build_vault_config(vault_section: dict[str, Any]) -> VaultConfig:
    """Build the vault config, including its nested ``[vault.sync]`` section."""
    sync_section = vault_section.get("sync", {})
    for m in sync_section.get("mappings", []):
        _validate_sync_mapping_entry(m)
    sync_mappings = [
        SyncMappingConfig(
            secret_name=m["secret_name"],
            folder_path=m["folder_path"],
            vault_name=m.get("vault_name"),
            environment=m.get("environment"),  # None = derive from profile
            env_file=m.get("env_file"),
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
        max_workers=normalize_max_workers(sync_section.get("max_workers")),
        ephemeral_keys=sync_section.get("ephemeral_keys", False),
    )
    return VaultConfig(
        provider=vault_section.get("provider", "azure"),
        azure_vault_url=vault_section.get("azure", {}).get("vault_url"),
        aws_region=vault_section.get("aws", {}).get("region", "us-east-1"),
        hashicorp_url=vault_section.get("hashicorp", {}).get("url"),
        gcp_project_id=vault_section.get("gcp", {}).get("project_id"),
        mappings=vault_section.get("mappings", {}),
        sync=sync_config,
    )


def _build_encryption_config(encryption_section: dict[str, Any]) -> EncryptionConfig:
    """Build the encryption config from the ``[encryption]`` section."""
    sops_section = encryption_section.get("sops", {})
    dotenvx_section = encryption_section.get("dotenvx", {})
    return EncryptionConfig(
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


def _build_partial_encryption_config(
    partial_encryption_section: dict[str, Any],
) -> PartialEncryptionConfig:
    """Build the partial_encryption config from its section.

    Required-field validation (including the ``name`` field) is deferred to
    ``PartialEncryptionConfig.validate()``, called by the partial-encryption
    commands that consume this section, so a typo here cannot crash an unrelated
    command (encrypt/decrypt/guard/pull/sync) that never reads it (#413). We use
    ``.get("name", "")`` rather than ``env["name"]`` so a missing name surfaces
    as a clean deferred ``ConfigValidationError``, not an eager ``KeyError``.
    """
    environments = [
        PartialEncryptionEnvironmentConfig(
            name=env.get("name", ""),
            clear_file=env.get("clear_file", ""),
            secret_file=env.get("secret_file", ""),
            combined_file=env.get("combined_file", ""),
            secrets_only=env.get("secrets_only", False),
            secrets_dir=env.get("secrets_dir", ""),
            pattern=env.get("pattern", ".env*"),
        )
        for env in partial_encryption_section.get("environments", [])
    ]
    return PartialEncryptionConfig(
        enabled=partial_encryption_section.get("enabled", False),
        environments=environments,
    )


def _build_guard_config(guard_section: dict[str, Any]) -> GuardConfig:
    """Build the guard config from the ``[guard]`` section."""
    scanners = guard_section.get("scanners", ["native", "gitleaks"])
    if isinstance(scanners, str):
        scanners = [scanners]
    elif not isinstance(scanners, list) or not all(isinstance(s, str) for s in scanners):
        # A non-iterable / non-string-list (e.g. ``scanners = 123``) used to crash
        # guard with an uncaught TypeError when iterated (#443 #29).
        raise ValueError(
            f"[guard] scanners must be a string or a list of strings, got {scanners!r}"
        )
    return GuardConfig(
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


def _build_guardian_config(guardian_section: dict[str, Any]) -> GuardianWatchConfig:
    """Build the guardian config from the ``[guardian]`` section.

    ``idle_timeout`` validation is deferred to ``GuardianWatchConfig.validate()``,
    invoked by the agent commands, so a typo in this agent-only knob doesn't
    crash unrelated commands (encrypt/decrypt/guard/pull/sync) that never read
    it (#413).
    """
    return GuardianWatchConfig(
        enabled=guardian_section.get("enabled", False),
        idle_timeout=guardian_section.get("idle_timeout", "5m"),
        patterns=guardian_section.get("patterns", [".env*"]),
        exclude=guardian_section.get("exclude", [".env.example", ".env.sample", ".env.keys"]),
        notify=guardian_section.get("notify", True),
    )


@dataclass
class EnvdriftConfig:
    """Complete envdrift configuration."""

    # Core settings
    schema: str | None = None
    environments: list[str] = field(
        default_factory=lambda: ["development", "staging", "production"]
    )

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
        )

        # Build vault config (and its nested sync config)
        vault = _build_vault_config(vault_section)

        # Build precommit config
        precommit = PrecommitConfig(
            files=precommit_section.get("files", []),
            schemas=precommit_section.get("schemas", {}),
        )

        git_hook_check = GitHookCheckConfig(
            method=git_hook_check_section.get("method"),
            precommit_config=git_hook_check_section.get("precommit_config"),
        )

        return cls(
            schema=envdrift_section.get("schema"),
            environments=envdrift_section.get(
                "environments", ["development", "staging", "production"]
            ),
            validation=validation,
            vault=vault,
            encryption=_build_encryption_config(encryption_section),
            precommit=precommit,
            git_hook_check=git_hook_check,
            partial_encryption=_build_partial_encryption_config(data.get("partial_encryption", {})),
            guard=_build_guard_config(data.get("guard", {})),
            guardian=_build_guardian_config(data.get("guardian", {})),
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
        if not path.is_file():
            # A directory (or other non-file) passed as --config used to reach
            # open() and raise an uncaught IsADirectoryError traceback (#443 #30).
            raise ConfigNotFoundError(f"Configuration path is not a file: {path}")
    else:
        path = find_config()
        if path is None:
            # Return default config if no file found
            return EnvdriftConfig()

    with open(path, "rb") as f:
        data = tomllib.load(f)

    # Check if this is pyproject.toml with [tool.envdrift]
    if path.name == "pyproject.toml":
        data = _restructure_pyproject(data)

    return EnvdriftConfig.from_dict(data)


# Top-level sections that live under [tool.envdrift.*] in pyproject.toml and must
# be hoisted to the root for from_dict (everything else stays under "envdrift").
_PYPROJECT_TOPLEVEL_SECTIONS = (
    "validation",
    "vault",
    "encryption",
    "precommit",
    "git_hook_check",
    "partial_encryption",
    "guard",
    "guardian",
)


def _restructure_pyproject(data: dict[str, Any]) -> dict[str, Any]:
    """Hoist a pyproject.toml's ``[tool.envdrift.*]`` config to from_dict's shape.

    Returns ``data`` unchanged when there is no ``[tool.envdrift]`` table.
    """
    tool_config = data.get("tool", {}).get("envdrift", {})
    if not tool_config:
        return data

    # Copy so we never mutate the caller's parsed pyproject data.
    envdrift_section = dict(tool_config)
    restructured: dict[str, Any] = {"envdrift": envdrift_section}
    for section in _PYPROJECT_TOPLEVEL_SECTIONS:
        if section in envdrift_section:
            restructured[section] = envdrift_section.pop(section)
    return restructured


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

[validation]
# Consumed by `envdrift validate` (see docs/reference/configuration.md).
# Default for the encryption check; the --check-encryption/--no-check-encryption
# CLI flag overrides this when passed explicitly.
check_encryption = true

# When true (default), variables not present in the schema are checked and
# rejected if the schema sets extra="forbid". Set to false to skip the
# extra-variable check entirely.
strict_extra = true

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

# Combine mode: clear + secret files are merged into a combined committed file
# [[partial_encryption.environments]]
# name = "production"
# clear_file = ".env.production.clear"
# secret_file = ".env.production.secret"
# combined_file = ".env.production"

# Secrets-only mode: encrypt/decrypt a secrets directory in place.
# envdrift has zero awareness of any configs directory — it only touches secrets_dir.
# [[partial_encryption.environments]]
# name = "production"
# secrets_only = true
# secrets_dir = "secrets/production/"
# pattern = ".env*"   # optional glob, default ".env*"

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

    # TOML is UTF-8 by spec and EXAMPLE_CONFIG contains a non-ASCII em-dash;
    # write UTF-8 explicitly so the file we generate is readable by tomllib on
    # Windows too (the default there is cp1252, which load_config can't decode).
    path.write_text(EXAMPLE_CONFIG, encoding="utf-8")
    return path
