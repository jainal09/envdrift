"""Sync configuration models and parser."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class SyncConfigError(Exception):
    """Error loading sync configuration."""

    pass


@dataclass
class ServiceMapping:
    """Mapping of a vault secret to a local service folder."""

    secret_name: str
    folder_path: Path
    vault_name: str | None = None
    environment: str = "production"

    @property
    def env_key_name(self) -> str:
        """Return the environment key name (e.g., DOTENV_PRIVATE_KEY_PRODUCTION)."""
        return f"DOTENV_PRIVATE_KEY_{self.environment.upper()}"


@dataclass
class SyncConfig:
    """Complete sync configuration."""

    mappings: list[ServiceMapping] = field(default_factory=list)
    default_vault_name: str | None = None
    env_keys_filename: str = ".env.keys"

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

            [[vault.sync.mappings]]
            secret_name = "myapp-key"
            folder_path = "services/myapp"
            vault_name = "other-vault"  # Optional
            environment = "staging"     # Optional
        """
        mappings: list[ServiceMapping] = []

        for mapping_data in data.get("mappings", []):
            if "secret_name" not in mapping_data:
                raise SyncConfigError("Missing 'secret_name' in mapping")
            if "folder_path" not in mapping_data:
                raise SyncConfigError("Missing 'folder_path' in mapping")

            mappings.append(
                ServiceMapping(
                    secret_name=mapping_data["secret_name"],
                    folder_path=Path(mapping_data["folder_path"]),
                    vault_name=mapping_data.get("vault_name"),
                    environment=mapping_data.get("environment", "production"),
                )
            )

        return cls(
            mappings=mappings,
            default_vault_name=data.get("default_vault_name"),
            env_keys_filename=data.get("env_keys_filename", ".env.keys"),
        )

    def get_effective_vault_name(self, mapping: ServiceMapping) -> str | None:
        """Get the effective vault name for a mapping (mapping override or default)."""
        return mapping.vault_name or self.default_vault_name
