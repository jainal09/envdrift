"""Sync configuration models and parser."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from envdrift.utils import normalize_max_workers


class SyncConfigError(Exception):
    """Error loading sync configuration."""

    pass


@dataclass
class ServiceMapping:
    """Mapping of a vault secret to a local service folder."""

    secret_name: str
    folder_path: Path
    vault_name: str | None = None
    environment: str | None = None  # Defaults to profile if set, else "production"
    profile: str | None = None  # Profile name for filtering (e.g., "local", "prod")
    activate_to: Path | None = None  # Path to copy decrypted file when profile is activated
    ephemeral_keys: bool | None = None  # None = inherit from central SyncConfig

    @property
    def effective_environment(self) -> str:
        """
        Return the effective environment.

        Priority: explicit environment > profile > "production"
        """
        if self.environment is not None:
            return self.environment
        if self.profile is not None:
            return self.profile
        return "production"

    @property
    def env_key_name(self) -> str:
        """Return the environment key name (e.g., DOTENV_PRIVATE_KEY_PRODUCTION)."""
        return f"DOTENV_PRIVATE_KEY_{self.effective_environment.upper()}"


@dataclass
class SyncConfig:
    """Complete sync configuration."""

    mappings: list[ServiceMapping] = field(default_factory=list)
    default_vault_name: str | None = None
    env_keys_filename: str = ".env.keys"
    max_workers: int | None = None
    ephemeral_keys: bool = False  # When True, never store .env.keys locally

    @classmethod
    def from_file(cls, path: Path) -> SyncConfig:
        """
        Load sync config from a pair.txt-style file.

        Format:
            # Comments start with #
            secret-name=folder-path
            vault-name/secret-name=folder-path
        """
        if not path.exists():
            raise SyncConfigError(f"Config file not found: {path}")

        mappings: list[ServiceMapping] = []

        with path.open() as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()

                # Skip empty lines and comments
                if not line or line.startswith("#"):
                    continue

                # Parse key=value
                if "=" not in line:
                    raise SyncConfigError(
                        f"Invalid format at line {line_num}: {line!r}. "
                        "Expected: secret-name=folder-path"
                    )

                secret_part, folder_path = line.split("=", 1)
                secret_part = secret_part.strip()
                folder_path = folder_path.strip()

                if not secret_part or not folder_path:
                    raise SyncConfigError(f"Empty value at line {line_num}: {line!r}")

                # Check for vault-name/secret-name format
                if "/" in secret_part:
                    vault_name, secret_name = secret_part.split("/", 1)
                    vault_name = vault_name.strip()
                    secret_name = secret_name.strip()
                else:
                    vault_name = None
                    secret_name = secret_part

                mappings.append(
                    ServiceMapping(
                        secret_name=secret_name,
                        folder_path=Path(folder_path),
                        vault_name=vault_name,
                    )
                )

        return cls(mappings=mappings)

    @classmethod
    def from_toml(cls, data: dict[str, Any]) -> SyncConfig:
        """
        Load sync config from TOML [vault.sync] section.

        Format:
            [vault.sync]
            default_vault_name = "my-keyvault"
            env_keys_filename = ".env.keys"
            max_workers = 4

            [[vault.sync.mappings]]
            secret_name = "myapp-key"
            folder_path = "services/myapp"
            vault_name = "other-vault"  # Optional
            environment = "staging"     # Optional
        """
        mappings: list[ServiceMapping] = []
        max_workers = normalize_max_workers(data.get("max_workers"))

        for mapping_data in data.get("mappings", []):
            if "secret_name" not in mapping_data:
                raise SyncConfigError("Missing 'secret_name' in mapping")
            if "folder_path" not in mapping_data:
                raise SyncConfigError("Missing 'folder_path' in mapping")

            activate_to = mapping_data.get("activate_to")
            mappings.append(
                ServiceMapping(
                    secret_name=mapping_data["secret_name"],
                    folder_path=Path(mapping_data["folder_path"]),
                    vault_name=mapping_data.get("vault_name"),
                    environment=mapping_data.get("environment"),  # None = use effective_environment
                    profile=mapping_data.get("profile"),
                    activate_to=Path(activate_to) if activate_to else None,
                    ephemeral_keys=mapping_data.get("ephemeral_keys"),  # None = inherit
                )
            )

        return cls(
            mappings=mappings,
            default_vault_name=data.get("default_vault_name"),
            env_keys_filename=data.get("env_keys_filename", ".env.keys"),
            max_workers=max_workers,
            ephemeral_keys=data.get("ephemeral_keys", False),
        )

    def get_effective_vault_name(self, mapping: ServiceMapping) -> str | None:
        """Get the effective vault name for a mapping (mapping override or default)."""
        return mapping.vault_name or self.default_vault_name

    def get_effective_ephemeral(self, mapping: ServiceMapping) -> bool:
        """Get effective ephemeral_keys setting for a mapping.

        Returns:
            True if ephemeral mode is enabled (mapping override or central default).
        """
        if mapping.ephemeral_keys is not None:
            return mapping.ephemeral_keys
        return self.ephemeral_keys

    def filter_by_profile(self, profile: str | None) -> list[ServiceMapping]:
        """
        Filter mappings by profile.

        If profile is None, returns only mappings without a profile (regular mappings).
        If profile is specified, returns:
          - All mappings without a profile (regular mappings)
          - Plus the mapping that matches the specified profile
        """
        if profile is None:
            # No profile specified: return only non-profile mappings
            return [m for m in self.mappings if m.profile is None]

        # Profile specified: return non-profile mappings + matching profile
        return [m for m in self.mappings if m.profile is None or m.profile == profile]

    @classmethod
    def from_toml_file(cls, path: Path) -> SyncConfig:
        """
        Load sync config from a TOML file.

        Supports both standalone TOML files with [vault.sync] section
        and pyproject.toml with [tool.envdrift.vault.sync] section.

        Format:
            [vault.sync]
            default_vault_name = "my-keyvault"
            env_keys_filename = ".env.keys"

            [[vault.sync.mappings]]
            secret_name = "myapp-key"
            folder_path = "services/myapp"
            vault_name = "other-vault"  # Optional
            environment = "staging"     # Optional
        """
        if not path.exists():
            raise SyncConfigError(f"Config file not found: {path}")

        try:
            with path.open("rb") as f:
                data = tomllib.load(f)
        except tomllib.TOMLDecodeError as e:
            raise SyncConfigError(f"Invalid TOML syntax: {e}") from e

        # Handle pyproject.toml with [tool.envdrift] structure
        if path.name == "pyproject.toml":
            tool_config = data.get("tool", {}).get("envdrift", {})
            sync_data = tool_config.get("vault", {}).get("sync", {})
        else:
            # Standalone envdrift.toml or sync.toml
            sync_data = data.get("vault", {}).get("sync", {})
            # Also support top-level sync section for dedicated sync config files
            if not sync_data and "mappings" in data:
                sync_data = data

        if not sync_data:
            raise SyncConfigError(
                f"No sync configuration found in {path}. "
                "Expected [vault.sync] section with [[vault.sync.mappings]]"
            )

        return cls.from_toml(sync_data)
