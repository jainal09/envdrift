"""Configuration and vault-client loading for sync-family commands."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import typer

from envdrift.output.rich import print_error, print_warning

if TYPE_CHECKING:
    from envdrift.sync.config import ServiceMapping, SyncConfig

# Missing-setting messages shared with the vault-push/vault-pull seam
# (envdrift.cli_commands.vault_helpers) so the same condition cannot drift
# into two phrasings again (#441 audit).
AZURE_VAULT_URL_REQUIRED = (
    "Azure provider requires --vault-url (or [vault.azure] vault_url in config)"
)
HASHICORP_VAULT_URL_REQUIRED = (
    "HashiCorp provider requires --vault-url (or [vault.hashicorp] url in config, "
    "or the VAULT_ADDR environment variable)"
)
GCP_PROJECT_ID_REQUIRED = "GCP provider requires --project-id (or [vault.gcp] project_id in config)"


@dataclass(frozen=True)
class SyncLoadRequest:
    """CLI inputs used to load sync mappings and their vault client."""

    config_file: Path | None
    provider: str | None
    vault_url: str | None
    region: str | None
    project_id: str | None


@dataclass(frozen=True)
class _ConfigDefaults:
    path: Path | None
    config: Any | None


@dataclass(frozen=True)
class _VaultSettings:
    provider: str | None
    vault_url: str | None
    region: str | None
    project_id: str | None


def _defaults_path(request: SyncLoadRequest) -> Path | None:
    from envdrift.config import find_config

    if request.config_file is not None and request.config_file.suffix.lower() == ".toml":
        return request.config_file
    if request.config_file is None:
        return find_config()
    return None


def _load_envdrift_config(path: Path | None) -> Any | None:
    from envdrift.config import ConfigLoadError, ConfigNotFoundError, load_config

    if path is None:
        return None
    try:
        return load_config(path)
    except ConfigNotFoundError:
        return None
    except ConfigLoadError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from None


def _load_defaults(request: SyncLoadRequest) -> _ConfigDefaults:
    path = _defaults_path(request)
    return _ConfigDefaults(path=path, config=_load_envdrift_config(path))


def _provider_vault_url(
    provider: str | None, explicit_url: str | None, vault_config: Any | None
) -> str | None:
    if explicit_url is not None:
        return explicit_url
    attribute = {"azure": "azure_vault_url", "hashicorp": "hashicorp_url"}.get(provider or "")
    url = getattr(vault_config, attribute, None) if attribute else None
    if url is None and provider == "hashicorp":
        # Honor the standard env var every HashiCorp tool reads (#441 audit).
        # Strip so a padded value is usable and a whitespace-only value still
        # hits the missing-URL guard instead of a late connection failure.
        return (os.environ.get("VAULT_ADDR") or "").strip() or None
    return url


def _config_default(explicit: str | None, vault_config: Any | None, attribute: str) -> str | None:
    if explicit is not None or vault_config is None:
        return explicit
    return getattr(vault_config, attribute, None)


def _resolve_vault_settings(request: SyncLoadRequest, defaults: _ConfigDefaults) -> _VaultSettings:
    vault_config = getattr(defaults.config, "vault", None)
    provider = request.provider or getattr(vault_config, "provider", None)
    return _VaultSettings(
        provider=provider,
        vault_url=_provider_vault_url(provider, request.vault_url, vault_config),
        region=_config_default(request.region, vault_config, "aws_region"),
        project_id=_config_default(request.project_id, vault_config, "gcp_project_id"),
    )


def _load_explicit_sync_config(config_file: Path) -> SyncConfig:
    from envdrift.sync.config import SyncConfig, SyncConfigError

    if not config_file.exists():
        print_error(f"Config file not found: {config_file}")
        raise typer.Exit(code=1)
    try:
        if config_file.suffix.lower() == ".toml":
            return SyncConfig.from_toml_file(config_file)
        return SyncConfig.from_file(config_file)
    except SyncConfigError as exc:
        print_error(f"Invalid config file: {exc}")
        raise typer.Exit(code=1) from None


def _mapping_from_project(mapping: Any):
    from envdrift.sync.config import ServiceMapping

    return ServiceMapping(
        secret_name=mapping.secret_name,
        folder_path=Path(mapping.folder_path),
        vault_name=mapping.vault_name,
        environment=mapping.environment,
        env_file=Path(mapping.env_file) if mapping.env_file else None,
        profile=mapping.profile,
        activate_to=Path(mapping.activate_to) if mapping.activate_to else None,
        ephemeral_keys=mapping.ephemeral_keys,
    )


def _sync_config_from_project(vault_sync: Any) -> SyncConfig:
    from envdrift.sync.config import SyncConfig

    return SyncConfig(
        mappings=[_mapping_from_project(mapping) for mapping in vault_sync.mappings],
        default_vault_name=vault_sync.default_vault_name,
        env_keys_filename=vault_sync.env_keys_filename,
        max_workers=vault_sync.max_workers,
        ephemeral_keys=vault_sync.ephemeral_keys,
    )


def _load_discovered_sync_config(config_path: Path) -> SyncConfig | None:
    from envdrift.sync.config import SyncConfig, SyncConfigError

    try:
        return SyncConfig.from_toml_file(config_path)
    except SyncConfigError as exc:
        print_warning(f"Could not load sync config from {config_path}: {exc}")
        return None


def _load_sync_config(request: SyncLoadRequest, defaults: _ConfigDefaults) -> SyncConfig | None:
    if request.config_file is not None:
        return _load_explicit_sync_config(request.config_file)
    vault_sync = getattr(getattr(defaults.config, "vault", None), "sync", None)
    if vault_sync and vault_sync.mappings:
        return _sync_config_from_project(vault_sync)
    if defaults.path and defaults.path.suffix.lower() == ".toml":
        return _load_discovered_sync_config(defaults.path)
    return None


def _require_sync_config(sync_config: SyncConfig | None) -> SyncConfig:
    if sync_config is not None and sync_config.mappings:
        return sync_config
    print_error(
        "No sync configuration found. Provide one of:\n"
        "  [vault.sync] section in envdrift.toml (auto-discovered)\n"
        "  [tool.envdrift.vault.sync] section in pyproject.toml\n"
        "  --config <file.toml>  TOML config with [vault.sync] section\n"
        "  --config <pair.txt>   Legacy format: secret=folder"
    )
    raise typer.Exit(code=1)


def require_profile_mappings(sync_config: SyncConfig, profile: str | None) -> list[ServiceMapping]:
    """Return regular plus selected profile mappings, failing on an empty selection."""
    mappings = sync_config.filter_by_profile(profile)
    if mappings:
        return mappings
    if profile:
        print_error(f"No mappings found for profile '{profile}'")
    else:
        print_warning("No non-profile mappings found. Use --profile to specify one.")
    raise typer.Exit(code=1)


def _require_provider(settings: _VaultSettings) -> str:
    if settings.provider is None:
        print_error(
            "--provider is required (or set [vault] provider in config). "
            "Options: azure, aws, hashicorp, gcp"
        )
        raise typer.Exit(code=1)
    return settings.provider


def _validate_provider_options(provider: str, settings: _VaultSettings) -> None:
    requirements = {
        "azure": (settings.vault_url, AZURE_VAULT_URL_REQUIRED),
        "hashicorp": (settings.vault_url, HASHICORP_VAULT_URL_REQUIRED),
        "gcp": (settings.project_id, GCP_PROJECT_ID_REQUIRED),
    }
    requirement = requirements.get(provider)
    if requirement is None or requirement[0]:
        return
    print_error(requirement[1])
    raise typer.Exit(code=1)


def _validate_vault_settings(settings: _VaultSettings) -> str:
    provider = _require_provider(settings)
    _validate_provider_options(provider, settings)
    return provider


def _vault_client_kwargs(settings: _VaultSettings) -> dict[str, str | None]:
    kwargs_by_provider: dict[str, dict[str, str | None]] = {
        "azure": {"vault_url": settings.vault_url},
        "aws": {"region": settings.region or "us-east-1"},
        "hashicorp": {"url": settings.vault_url},
        "gcp": {"project_id": settings.project_id},
    }
    return kwargs_by_provider.get(settings.provider or "", {})


def _create_vault_client(provider: str, settings: _VaultSettings) -> Any:
    from envdrift.vault import get_vault_client

    try:
        return get_vault_client(provider, **_vault_client_kwargs(settings))
    except (ImportError, ValueError) as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from None


def load_sync_connection(
    request: SyncLoadRequest,
) -> tuple[SyncConfig, Any, str, str | None, str | None, str | None]:
    """Load sync mappings, resolve provider settings, and build their client."""

    defaults = _load_defaults(request)
    settings = _resolve_vault_settings(request, defaults)
    sync_config = _require_sync_config(_load_sync_config(request, defaults))
    provider = _validate_vault_settings(settings)
    client = _create_vault_client(provider, settings)
    return (
        sync_config,
        client,
        provider,
        settings.vault_url,
        settings.region,
        settings.project_id,
    )
