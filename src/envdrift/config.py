"""Configuration loader for envdrift.toml."""

from __future__ import annotations

import difflib
import math
import re
import sys
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

    ``check_entropy`` is tri-state: ``None`` (unset) keeps the default of
    entropy detection on env files only; ``true`` extends it to all scanned
    files; ``false`` disables it entirely — including env files (#478).

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
    check_entropy: bool | None = None  # None = entropy on env files only (default)
    entropy_threshold: float = 4.5
    fail_on_severity: str = "high"
    skip_clear_files: bool = False  # Skip .clear files from scanning
    skip_encrypted_files: bool = True  # Skip findings from encrypted files (dotenvx/SOPS)
    skip_duplicate: bool = False  # Show only unique findings by secret value
    skip_gitignored: bool = False  # Skip findings from gitignored files
    ignore_paths: list[str] = field(default_factory=list)
    ignore_rules: dict[str, list[str]] = field(default_factory=dict)
    verify_secrets: bool = False  # For trufflehog verification


def coerce_entropy_threshold(value: Any) -> float:
    """Validate/coerce ``[guard] entropy_threshold`` into a float.

    A quoted number (``entropy_threshold = "3.5"``) used to flow through the
    config layer untouched and crash the native scanner mid-scan, which was
    swallowed as a non-fatal scanner error and turned the whole guard run into
    a green false PASS (#478). Coerce numeric strings, reject everything else
    with a clean ``ValueError`` at config-load time. Non-finite values
    (``nan``/``inf``, quoted or bare TOML floats) are rejected too: they parse
    as floats but make every ``entropy >= threshold`` comparison False,
    silently disabling the entropy gate — the same failure class.
    """
    if isinstance(value, bool):
        raise ValueError(f"[guard] entropy_threshold must be a number, got {value!r}")
    if isinstance(value, (int, float)):
        result = float(value)
    elif isinstance(value, str):
        try:
            result = float(value.strip())
        except ValueError:
            raise ValueError(f"[guard] entropy_threshold must be a number, got {value!r}") from None
    else:
        raise ValueError(f"[guard] entropy_threshold must be a number, got {value!r}")
    if not math.isfinite(result):
        raise ValueError(f"[guard] entropy_threshold must be a finite number, got {value!r}")
    return result


def coerce_check_entropy(value: Any) -> bool | None:
    """Validate the tri-state ``[guard] check_entropy`` knob (bool or unset)."""
    if value is None or isinstance(value, bool):
        return value
    raise ValueError(f"[guard] check_entropy must be a boolean, got {value!r}")


def coerce_fail_on_severity(value: Any) -> str:
    """Validate that ``[guard] fail_on_severity`` is a string at config load.

    A non-string value (``fail_on_severity = 123``) used to escape the guard
    CLI's ``except ValueError`` as an ``AttributeError`` on ``.lower()`` — a
    Rich traceback, empty ``--json`` stdout, and exit 1 colliding with
    critical's code (#478). Reject non-strings with a clean ``ValueError``;
    severity-name membership stays validated downstream (the guard CLI, which
    also covers the ``--fail-on`` flag, and ``GuardConfig.from_dict``).
    """
    if isinstance(value, str):
        return value
    raise ValueError(f"[guard] fail_on_severity must be a severity string, got {value!r}")


def normalize_ignore_rules(value: Any) -> dict[str, list[str]]:
    """Validate/normalize ``[guard] ignore_rules`` into ``{rule: [globs]}``.

    The documented shape is a TOML table mapping rule ids to path-pattern
    lists. A wrong-typed value (e.g. a bare list of rule ids) used to crash
    guard mid-scan with an uncaught TypeError — but only on the first run that
    had findings, leaving ``--json`` stdout empty (#478). Reject non-table
    shapes with a clean ``ValueError`` at config-load time; a single string
    pattern value is coerced to a one-item list.
    """
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(
            "[guard] ignore_rules must be a TOML table mapping rule ids to "
            "path-pattern lists, e.g.\n"
            "    [guard.ignore_rules]\n"
            '    "unencrypted-env-file" = ["**/fixtures/**"]\n'
            f"got {value!r}"
        )
    normalized: dict[str, list[str]] = {}
    for rule_id, patterns in value.items():
        if isinstance(patterns, str):
            normalized[str(rule_id)] = [patterns]
        elif isinstance(patterns, list) and all(isinstance(p, str) for p in patterns):
            normalized[str(rule_id)] = list(patterns)
        else:
            raise ValueError(
                f"[guard] ignore_rules entry {rule_id!r} must map to a path "
                f"pattern string or a list of pattern strings, got {patterns!r}"
            )
    return normalized


def normalize_ignore_paths(value: Any) -> list[str]:
    """Validate/normalize ``[guard] ignore_paths`` into a list of globs.

    A single string is coerced to a one-item list; any other non-list shape is
    rejected with a clean ``ValueError`` (a bare string would otherwise be
    iterated character-by-character downstream — same wrong-shape family as
    ``ignore_rules``, #478).
    """
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(p, str) for p in value):
        return list(value)
    raise ValueError(f"[guard] ignore_paths must be a string or a list of strings, got {value!r}")


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


def _validate_sync_mapping_entry(m: Any) -> None:
    """Validate one ``[[vault.sync.mappings]]`` entry, raising a clean ValueError.

    TOML type surprises — a non-table entry (``mappings = [123]``), a missing
    required key, or a wrong-typed value (``folder_path = 123``) — used to
    escape as raw TypeError/KeyError tracebacks from ``Path()``/subscript use
    downstream; validate loudly here instead (#443 #32 #488). The key shapes
    are shared with :func:`envdrift.sync.config.invalid_mapping_value_keys`
    (the explicit ``--config`` path) so the two layers cannot drift.
    """
    from envdrift.sync.config import MAPPING_REQUIRED_STR_KEYS, invalid_mapping_value_keys

    if not isinstance(m, dict):
        raise ValueError(
            f"[[vault.sync.mappings]] entry must be a table, got {type(m).__name__}: {m!r}"
        )
    missing = [k for k in MAPPING_REQUIRED_STR_KEYS if k not in m]
    if missing:
        raise ValueError(
            f"[[vault.sync.mappings]] entry is missing required key(s) {', '.join(missing)}: {m!r}"
        )
    wrong_type = invalid_mapping_value_keys(m)
    if wrong_type:
        raise ValueError(
            f"[[vault.sync.mappings]] entry has wrong value type(s) for "
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
        # Wrong-typed guard knobs are rejected here, at config-load time, with
        # a clean ValueError instead of crashing a scanner mid-scan into a
        # green false PASS or an uncaught traceback (#478).
        check_entropy=coerce_check_entropy(guard_section.get("check_entropy")),
        entropy_threshold=coerce_entropy_threshold(guard_section.get("entropy_threshold", 4.5)),
        fail_on_severity=coerce_fail_on_severity(guard_section.get("fail_on_severity", "high")),
        skip_clear_files=guard_section.get("skip_clear_files", False),
        skip_encrypted_files=guard_section.get("skip_encrypted_files", True),
        skip_duplicate=guard_section.get("skip_duplicate", False),
        skip_gitignored=guard_section.get("skip_gitignored", False),
        ignore_paths=normalize_ignore_paths(guard_section.get("ignore_paths")),
        ignore_rules=normalize_ignore_rules(guard_section.get("ignore_rules")),
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


class ConfigLoadError(ValueError):
    """An existing config file could not be read, parsed, or built.

    Raised by :func:`load_config` for every malformed/unreadable shape — a TOML
    syntax error, an unreadable path (permissions), or a wrong-typed/invalid
    section — so CLI commands can convert one exception type into a clean
    one-line error instead of a Rich traceback or a silent fallback to default
    settings (#491). Subclasses ``ValueError`` so pre-existing
    ``except ValueError`` boundaries (e.g. validate/guard) keep converting it
    into a clean message.
    """

    def __init__(self, path: Path, message: str) -> None:
        self.path = path
        super().__init__(message)


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
        # Only regular files qualify: a directory (or socket/fifo) named
        # envdrift.toml used to be handed to open() by load_config and crash
        # guard/sync/lock/pull with an uncaught IsADirectoryError (#491).
        if config_path.is_file():
            return config_path

        # Also check pyproject.toml for [tool.envdrift] section
        pyproject = current / "pyproject.toml"
        if pyproject.is_file():
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
        ConfigLoadError: If the config exists but cannot be read, parsed, or
            built (TOML syntax error, unreadable file, wrong-typed/invalid
            sections). A ``ValueError`` subclass (#491).
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

    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except tomllib.TOMLDecodeError as e:
        raise ConfigLoadError(path, f"TOML syntax error in {path}: {e}") from e
    except OSError as e:
        # PermissionError, a directory that raced past find_config, etc. —
        # surface as a reportable config error, never a traceback (#491).
        raise ConfigLoadError(path, f"Cannot read config file {path}: {e}") from e

    # A pyproject.toml without [tool.envdrift] holds nothing envdrift consumes;
    # skip the unknown-key pass so [project]/[build-system] don't trigger noise.
    # For pyproject files the pass runs on the original [tool.envdrift] table —
    # not the restructured dict — so a typo'd section like [tool.envdrift.gaurd]
    # is reported where the user wrote it, with a did-you-mean hint drawn from
    # the real section names (#491).
    unknown_key_data: dict[str, Any] | None = data
    unknown_key_spec: dict[str, Any] | None = None
    unknown_key_section = ""
    try:
        if path.name == "pyproject.toml":
            unknown_key_data = data.get("tool", {}).get("envdrift") or None
            unknown_key_spec = _PYPROJECT_KEY_SPEC
            unknown_key_section = "tool.envdrift"
            data = _restructure_pyproject(data)
        config = EnvdriftConfig.from_dict(data)
    except (ValueError, TypeError, AttributeError, KeyError) as e:
        # Wrong-typed sections (e.g. ``vault = "a string"``) used to escape as
        # raw AttributeError/TypeError tracebacks from pull/lock/sync (#491).
        raise ConfigLoadError(path, f"Invalid config in {path}: {e}") from e

    if unknown_key_data:
        _emit_unknown_key_warnings(path, unknown_key_data, unknown_key_spec, unknown_key_section)

    return config


# Sentinel for tables whose keys are user-defined by design (e.g.
# [vault.mappings], [guard.ignore_rules], [precommit.schemas]): the unknown-key
# pass never descends into them.
_FREEFORM_TABLE = "freeform"

# Every key envdrift consumes from a config file, mirroring the dataclasses
# above and the ``_build_*_config`` helpers. Leaf values are ``None``; nested
# tables are dicts; arrays of tables ([[section]]) are single-element lists
# holding the per-entry spec. ``test_example_config_has_no_unknown_keys`` keeps
# this in sync with EXAMPLE_CONFIG.
_CONFIG_KEY_SPEC: dict[str, Any] = {
    "envdrift": {"schema": None, "environments": None},
    "validation": {"check_encryption": None, "strict_extra": None},
    "vault": {
        "provider": None,
        "mappings": _FREEFORM_TABLE,
        "azure": {"vault_url": None},
        "aws": {"region": None},
        "hashicorp": {"url": None},
        "gcp": {"project_id": None},
        "sync": {
            "default_vault_name": None,
            "env_keys_filename": None,
            "max_workers": None,
            "ephemeral_keys": None,
            "mappings": [
                {
                    "secret_name": None,  # nosec B105 - key-spec entry, not a credential
                    "folder_path": None,
                    "vault_name": None,
                    "environment": None,
                    "env_file": None,
                    "profile": None,
                    "activate_to": None,
                    "ephemeral_keys": None,
                }
            ],
        },
    },
    "encryption": {
        "backend": None,
        "smart_encryption": None,
        "dotenvx": {"auto_install": None},
        "sops": {
            "auto_install": None,
            "config_file": None,
            "age_key_file": None,
            "age_recipients": None,
            "kms_arn": None,
            "gcp_kms": None,
            "azure_kv": None,
        },
    },
    "precommit": {"files": None, "schemas": _FREEFORM_TABLE},
    "git_hook_check": {"method": None, "precommit_config": None},
    "partial_encryption": {
        "enabled": None,
        "environments": [
            {
                "name": None,
                "clear_file": None,
                "secret_file": None,  # nosec B105 - key-spec entry, not a credential
                "combined_file": None,
                "secrets_only": None,
                "secrets_dir": None,
                "pattern": None,
            }
        ],
    },
    "guard": {
        "scanners": None,
        "auto_install": None,
        "include_history": None,
        "check_entropy": None,
        "entropy_threshold": None,
        "fail_on_severity": None,
        "skip_clear_files": None,
        "skip_encrypted_files": None,
        "skip_duplicate": None,
        "skip_gitignored": None,
        "ignore_paths": None,
        "ignore_rules": _FREEFORM_TABLE,
        "verify_secrets": None,
    },
    "guardian": {
        "enabled": None,
        "idle_timeout": None,
        "patterns": None,
        "exclude": None,
        "notify": None,
    },
}


def find_unknown_config_keys(
    data: dict[str, Any],
    spec: dict[str, Any] | None = None,
    section: str = "",
) -> list[str]:
    """Return one finding per config key that envdrift does not consume (#491).

    A typo'd key (``fail_on_severty``, ``ephemerl_keys``) used to silently
    revert behavior to the default — flipping security posture with zero
    diagnostic. Each finding names the key and its section and suggests the
    closest known key when one is similar enough.
    """
    if spec is None:
        spec = _CONFIG_KEY_SPEC
    findings: list[str] = []
    if not isinstance(data, dict):
        return findings
    for key, value in data.items():
        if key not in spec:
            where = f"in [{section}]" if section else "at the top level"
            close = difflib.get_close_matches(key, list(spec), n=1, cutoff=0.6)
            hint = f" (did you mean '{close[0]}'?)" if close else ""
            findings.append(f"unknown config key '{key}' {where}{hint}")
            continue
        sub_spec = spec[key]
        child_section = f"{section}.{key}" if section else key
        if isinstance(sub_spec, dict):
            findings.extend(find_unknown_config_keys(value, sub_spec, child_section))
        elif isinstance(sub_spec, list) and isinstance(value, list):
            # Array of tables ([[section]]): check each entry.
            for entry in value:
                findings.extend(find_unknown_config_keys(entry, sub_spec[0], child_section))
    return findings


# Findings already emitted this process, keyed by (path, finding): commands load
# the same config more than once (e.g. encrypt + its git-hook check), and the
# warning must not repeat for every load.
_emitted_unknown_key_warnings: set[tuple[str, str]] = set()


def _emit_unknown_key_warnings(
    path: Path,
    data: dict[str, Any],
    spec: dict[str, Any] | None = None,
    section: str = "",
) -> None:
    """Print unknown-key findings to stderr, once per process per finding.

    stderr (not the Rich stdout console) so machine-readable stdout — guard
    ``--json``/``--sarif``, ``diff --format json`` — stays parseable (#491).
    """
    for finding in find_unknown_config_keys(data, spec, section):
        dedupe_key = (str(path), finding)
        if dedupe_key in _emitted_unknown_key_warnings:
            continue
        _emitted_unknown_key_warnings.add(dedupe_key)
        print(f"Warning: {path}: {finding}", file=sys.stderr)


# Top-level sections that live under [tool.envdrift.*] in pyproject.toml and must
# be hoisted to the root for from_dict (everything else stays under "envdrift").
# Derived from the key spec so a new section cannot drift out of sync.
_PYPROJECT_TOPLEVEL_SECTIONS = tuple(k for k in _CONFIG_KEY_SPEC if k != "envdrift")

# In pyproject.toml everything lives on one [tool.envdrift] table: the core keys
# sit directly on it and every other section nests beneath it, so the unknown-key
# pass needs both merged into one spec (#491).
_PYPROJECT_KEY_SPEC: dict[str, Any] = {
    **{k: v for k, v in _CONFIG_KEY_SPEC.items() if k != "envdrift"},
    **_CONFIG_KEY_SPEC["envdrift"],
}


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
