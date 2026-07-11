"""Execution helpers for the vault CLI commands."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import typer

from envdrift.env_files import EnvFileDetection, resolve_custom_env_file, resolve_mapping_env_file
from envdrift.output.rich import console, print_error, print_success, print_warning

if TYPE_CHECKING:
    from envdrift.encryption import EncryptionProvider
    from envdrift.encryption.base import EncryptionBackend
    from envdrift.sync.config import ServiceMapping, SyncConfig
    from envdrift.vault.base import SecretValue, VaultClient


@dataclass(frozen=True)
class VaultSettings:
    """Effective vault provider settings after CLI/config resolution."""

    provider: str
    vault_url: str | None
    region: str | None
    project_id: str | None


@dataclass(frozen=True)
class VaultPushRequest:
    """Parsed inputs for a vault-push invocation."""

    folder: Path | None
    secret_name: str | None
    environment: str | None
    direct: bool
    all_services: bool
    force: bool
    skip_encrypt: bool
    config: Path | None
    provider: str | None
    vault_url: str | None
    region: str | None
    project_id: str | None


@dataclass(frozen=True)
class VaultPullRequest:
    """Parsed inputs for a vault-pull invocation."""

    folder: Path
    secret_name: str
    environment: str
    config: Path | None
    provider: str | None
    vault_url: str | None
    region: str | None
    project_id: str | None
    no_decrypt: bool
    env_file: Path | None


@dataclass(frozen=True)
class _BulkPushContext:
    sync_config: SyncConfig
    client: VaultClient
    vault_provider: str
    backend: EncryptionBackend
    backend_provider: EncryptionProvider
    sops_kwargs: dict[str, Any]
    force: bool
    skip_encrypt: bool


@dataclass
class _PushStats:
    pushed: int = 0
    skipped: int = 0
    errors: int = 0
    dotenvx_mismatch: bool = False


@dataclass(frozen=True)
class _PushTarget:
    mapping: ServiceMapping
    detection: EnvFileDetection
    env_file: Path
    environment: str


def _load_vault_config(config: Path | None) -> Any | None:
    """Load discovered or explicit config, failing loudly on invalid files."""
    from envdrift.config import ConfigLoadError, ConfigNotFoundError, find_config, load_config

    config_path = config if config is not None else find_config()
    if config_path is None:
        return None
    try:
        return load_config(config_path)
    except (ConfigNotFoundError, ConfigLoadError) as e:
        print_error(str(e))
        raise typer.Exit(code=1) from None


def _provider_vault_url(
    provider: str,
    explicit_url: str | None,
    vault_config: Any | None,
) -> str | None:
    """Resolve provider-specific URL, preserving explicit CLI precedence."""
    if explicit_url is not None or vault_config is None:
        return explicit_url
    if provider == "azure":
        return getattr(vault_config, "azure_vault_url", None)
    if provider == "hashicorp":
        return getattr(vault_config, "hashicorp_url", None)
    return None


def _validate_vault_settings(settings: VaultSettings) -> None:
    """Reject missing provider-specific settings with CLI-facing errors."""
    if settings.provider in ("azure", "hashicorp") and not settings.vault_url:
        print_error(f"--vault-url required for {settings.provider}")
        raise typer.Exit(code=1)
    if settings.provider == "gcp" and not settings.project_id:
        print_error("--project-id required for gcp")
        raise typer.Exit(code=1)


def resolve_vault_settings(
    config: Path | None,
    provider: str | None,
    vault_url: str | None,
    region: str | None,
    project_id: str | None,
) -> VaultSettings:
    """Merge CLI flags with the config's vault settings and validate them."""
    envdrift_config = _load_vault_config(config)
    vault_config = getattr(envdrift_config, "vault", None)
    effective_provider = provider or getattr(vault_config, "provider", None)
    if not effective_provider:
        print_error("Vault provider required. Use --provider or configure in envdrift.toml")
        raise typer.Exit(code=1)

    settings = VaultSettings(
        provider=effective_provider,
        vault_url=_provider_vault_url(effective_provider, vault_url, vault_config),
        region=region or getattr(vault_config, "aws_region", None),
        project_id=project_id or getattr(vault_config, "gcp_project_id", None),
    )
    _validate_vault_settings(settings)
    return settings


def _vault_client_kwargs(settings: VaultSettings) -> dict[str, str | None]:
    """Build provider-specific client keyword arguments."""
    if settings.provider == "azure":
        return {"vault_url": settings.vault_url}
    if settings.provider == "aws":
        return {"region": settings.region or "us-east-1"}
    if settings.provider == "hashicorp":
        return {"url": settings.vault_url}
    if settings.provider == "gcp":
        return {"project_id": settings.project_id}
    return {}


def build_authenticated_client(settings: VaultSettings) -> VaultClient:
    """Create and authenticate a vault client for effective settings."""
    from envdrift.vault import VaultError, get_vault_client

    try:
        client = get_vault_client(settings.provider, **_vault_client_kwargs(settings))
        client.authenticate()
    except ImportError as e:
        print_error(str(e))
        raise typer.Exit(code=1) from None
    except ValueError as e:
        print_error(f"Invalid vault configuration: {e}")
        raise typer.Exit(code=1) from None
    except VaultError as e:
        print_error(f"Vault authentication failed: {e}")
        raise typer.Exit(code=1) from None
    return client


def execute_vault_push(request: VaultPushRequest) -> None:
    """Validate push-mode flags and dispatch bulk or single-service execution."""
    if request.skip_encrypt and not request.all_services:
        print_warning("--skip-encrypt is only applicable with --all mode, ignoring")
    if request.force and not request.all_services:
        print_warning("--force is only applicable with --all mode, ignoring")
    if request.all_services:
        _push_all_services(request)
        return
    _push_single_secret(request)


def _load_bulk_push_context(request: VaultPushRequest) -> _BulkPushContext:
    """Load sync, vault, and encryption dependencies for bulk push."""
    from envdrift.cli_commands.encryption_helpers import (
        build_sops_encrypt_kwargs,
        resolve_encryption_backend,
    )
    from envdrift.cli_commands.sync import load_sync_config_and_client
    from envdrift.config import ConfigLoadError, ConfigNotFoundError
    from envdrift.encryption import EncryptionProvider
    from envdrift.vault import VaultError

    sync_config, client, vault_provider, _, _, _ = load_sync_config_and_client(
        config_file=request.config,
        provider=request.provider,
        vault_url=request.vault_url,
        region=request.region,
        project_id=request.project_id,
    )
    try:
        client.authenticate()
    except VaultError as e:
        print_error(str(e))
        raise typer.Exit(code=1) from None

    try:
        backend, backend_provider, encryption_config = resolve_encryption_backend(request.config)
    except (ConfigNotFoundError, ConfigLoadError) as e:
        print_error(str(e))
        raise typer.Exit(code=1) from None
    except ValueError as e:
        print_error(f"Unsupported encryption backend: {e}")
        raise typer.Exit(code=1) from None

    if not backend.is_installed():
        print_error(f"{backend.name} is not installed")
        console.print(backend.install_instructions())
        raise typer.Exit(code=1)
    sops_kwargs = (
        build_sops_encrypt_kwargs(encryption_config)
        if backend_provider == EncryptionProvider.SOPS
        else {}
    )
    return _BulkPushContext(
        sync_config=sync_config,
        client=client,
        vault_provider=vault_provider,
        backend=backend,
        backend_provider=backend_provider,
        sops_kwargs=sops_kwargs,
        force=request.force,
        skip_encrypt=request.skip_encrypt,
    )


def _print_bulk_push_header(context: _BulkPushContext) -> None:
    """Render the bulk-push execution summary."""
    console.print("[bold]Vault Push All[/bold]")
    console.print(f"Provider: {context.vault_provider}")
    console.print(f"Services: {len(context.sync_config.mappings)}")
    if context.force:
        console.print("[dim]Force: overwrite existing secrets (--force)[/dim]")
    if context.skip_encrypt:
        console.print("[dim]Encryption: skipped (--skip-encrypt)[/dim]")
    console.print()


def _push_all_services(request: VaultPushRequest) -> None:
    """Push every configured mapping and report aggregate status."""
    context = _load_bulk_push_context(request)
    _print_bulk_push_header(context)
    stats = _PushStats()
    for mapping in context.sync_config.mappings:
        _push_mapping(context, mapping, stats)
    console.print()
    console.print(f"Done. Pushed: {stats.pushed}, Skipped: {stats.skipped}, Errors: {stats.errors}")
    if stats.dotenvx_mismatch or stats.errors > 0:
        raise typer.Exit(code=1)


def _resolve_push_target(mapping: ServiceMapping, stats: _PushStats) -> _PushTarget | None:
    """Resolve a mapping's env file and reject broken folder paths."""
    detection = resolve_mapping_env_file(mapping)
    if detection.status == "folder_not_found":
        print_error(
            f"Error processing {mapping.folder_path}: folder does not exist or is not a "
            "directory (check folder_path in your sync config)"
        )
        stats.errors += 1
        return None
    env_file = (
        detection.path
        if detection.path is not None
        else mapping.folder_path / f".env.{mapping.effective_environment}"
    )
    return _PushTarget(
        mapping=mapping,
        detection=detection,
        env_file=env_file,
        environment=detection.environment or mapping.effective_environment,
    )


def _skip_existing_secret(
    context: _BulkPushContext,
    target: _PushTarget,
    stats: _PushStats,
) -> bool:
    """Skip an existing secret before any local file mutation."""
    from envdrift.vault import VaultError
    from envdrift.vault.base import SecretNotFoundError

    if context.force:
        return False
    try:
        context.client.get_secret(target.mapping.secret_name)
    except SecretNotFoundError:
        return False
    except VaultError as e:
        print_error(f"Vault error checking {target.mapping.secret_name}: {e}")
        stats.errors += 1
        return True
    console.print(
        f"[dim]Skipped[/dim] {target.mapping.folder_path}: "
        f"Secret '{target.mapping.secret_name}' already exists"
    )
    stats.skipped += 1
    return True


def _skip_missing_env_file(target: _PushTarget, stats: _PushStats) -> bool:
    """Report a missing file when encryption is required."""
    if target.detection.status == "found" and target.detection.path is not None:
        return False
    missing_description = (
        f"{target.env_file.name} file" if target.mapping.env_file is not None else ".env file"
    )
    console.print(
        f"[dim]Skipped[/dim] {target.mapping.folder_path}: No {missing_description} found"
    )
    stats.skipped += 1
    return True


def _handle_provider_mismatch(
    context: _BulkPushContext,
    target: _PushTarget,
    detected_provider: EncryptionProvider,
    stats: _PushStats,
) -> bool:
    """Report cross-backend ciphertext and stop processing the mapping."""
    from envdrift.encryption import EncryptionProvider

    if detected_provider == context.backend_provider:
        return False
    if (
        detected_provider == EncryptionProvider.DOTENVX
        and context.backend_provider != EncryptionProvider.DOTENVX
    ):
        print_error(
            f"{target.env_file}: encrypted with dotenvx, "
            f"but config uses {context.backend_provider.value}"
        )
        stats.errors += 1
        stats.dotenvx_mismatch = True
        return True
    console.print(
        f"[dim]Skipped[/dim] {target.mapping.folder_path}: "
        f"Encrypted with {detected_provider.value}, config uses {context.backend_provider.value}"
    )
    stats.skipped += 1
    return True


def _encrypt_target(
    context: _BulkPushContext,
    target: _PushTarget,
    stats: _PushStats,
) -> bool:
    """Encrypt one plaintext target, returning whether processing may continue."""
    from envdrift.encryption import EncryptionBackendError, EncryptionNotFoundError

    console.print(f"Encrypting {target.env_file} with {context.backend.name}...")
    try:
        result = context.backend.encrypt(target.env_file, **context.sops_kwargs)
    except (EncryptionNotFoundError, EncryptionBackendError) as e:
        print_error(f"Failed to encrypt {target.env_file}: {e}")
        stats.errors += 1
        return False
    if not result.success:
        print_error(result.message)
        stats.errors += 1
        return False
    return True


def _normalize_mapping_metadata(context: _BulkPushContext, target: _PushTarget) -> None:
    """Canonicalize dotenvx metadata for custom env filenames."""
    from envdrift.encryption import EncryptionProvider
    from envdrift.integrations.dotenvx import (
        dotenvx_filename_needs_normalization,
        normalize_dotenvx_metadata,
    )

    if context.backend_provider != EncryptionProvider.DOTENVX:
        return
    if not dotenvx_filename_needs_normalization(target.env_file, target.environment):
        return
    normalize_dotenvx_metadata(
        target.env_file,
        target.mapping.folder_path / (context.sync_config.env_keys_filename or ".env.keys"),
        target.environment,
    )


def _ensure_encrypted(
    context: _BulkPushContext,
    target: _PushTarget,
    stats: _PushStats,
) -> bool:
    """Ensure a target uses the configured backend, then normalize its metadata."""
    from envdrift.cli_commands.encryption_helpers import is_encrypted_content
    from envdrift.encryption import detect_encryption_provider

    content = target.env_file.read_text()
    if not is_encrypted_content(context.backend_provider, context.backend, content):
        detected_provider = detect_encryption_provider(target.env_file)
        if detected_provider and _handle_provider_mismatch(
            context, target, detected_provider, stats
        ):
            return False
        if not _encrypt_target(context, target, stats):
            return False
    _normalize_mapping_metadata(context, target)
    return True


def _mapping_secret_value(
    context: _BulkPushContext,
    target: _PushTarget,
    stats: _PushStats,
) -> str | None:
    """Read the canonical private key value for one mapping."""
    from envdrift.sync.operations import EnvKeysFile

    env_keys_path = target.mapping.folder_path / (
        context.sync_config.env_keys_filename or ".env.keys"
    )
    if not env_keys_path.exists():
        print_error(f"Skipped {target.mapping.folder_path}: .env.keys not found")
        stats.errors += 1
        return None
    key_name = f"DOTENV_PRIVATE_KEY_{target.environment.upper()}"
    key_value = EnvKeysFile(env_keys_path).read_key(key_name)
    if not key_value:
        print_error(f"Skipped {target.mapping.folder_path}: {key_name} not found in keys file")
        stats.errors += 1
        return None
    return f"{key_name}={key_value}"


def _push_mapping(
    context: _BulkPushContext,
    mapping: ServiceMapping,
    stats: _PushStats,
) -> None:
    """Process one bulk-push mapping without leaking per-service failures."""
    from envdrift.vault import VaultError

    try:
        target = _resolve_push_target(mapping, stats)
        if target is None or _skip_existing_secret(context, target, stats):
            return
        if not context.skip_encrypt:
            if _skip_missing_env_file(target, stats):
                return
            if not _ensure_encrypted(context, target, stats):
                return
        value = _mapping_secret_value(context, target, stats)
        if value is None:
            return
        context.client.set_secret(mapping.secret_name, value)
        print_success(f"Pushed {mapping.secret_name}")
        stats.pushed += 1
    except (VaultError, OSError, ValueError) as e:
        print_error(f"Error processing {mapping.folder_path}: {e}")
        stats.errors += 1


def _single_push_value(request: VaultPushRequest) -> tuple[str, str]:
    """Resolve the secret name/value for direct or .env.keys mode."""
    if request.direct:
        if not request.folder or not request.secret_name:
            print_error("Direct mode requires: envdrift vault-push --direct <secret-name> <value>")
            raise typer.Exit(code=1)
        return str(request.folder), request.secret_name
    return _file_push_value(request)


def _file_push_value(request: VaultPushRequest) -> tuple[str, str]:
    """Read one private key from a service's .env.keys file."""
    from envdrift.sync.operations import EnvKeysFile

    if not request.folder or not request.secret_name or not request.environment:
        print_error(
            "Required: envdrift vault-push <folder> <secret-name> --env <environment> "
            "(or use --all)"
        )
        raise typer.Exit(code=1)
    env_keys_path = request.folder / ".env.keys"
    if not env_keys_path.exists():
        print_error(f"File not found: {env_keys_path}")
        raise typer.Exit(code=1)
    key_name = f"DOTENV_PRIVATE_KEY_{request.environment.upper()}"
    try:
        key_value = EnvKeysFile(env_keys_path).read_key(key_name)
    except (OSError, ValueError) as e:
        print_error(f"Cannot read {env_keys_path}: {e}")
        raise typer.Exit(code=1) from None
    if not key_value:
        print_error(f"Key '{key_name}' not found in {env_keys_path}")
        raise typer.Exit(code=1)
    return request.secret_name, f"{key_name}={key_value}"


def _push_single_secret(request: VaultPushRequest) -> None:
    """Push one direct value or one key read from a service folder."""
    from envdrift.vault import VaultError

    settings = resolve_vault_settings(
        request.config,
        request.provider,
        request.vault_url,
        request.region,
        request.project_id,
    )
    secret_name, value = _single_push_value(request)
    client = build_authenticated_client(settings)
    try:
        result = client.set_secret(secret_name, value)
    except VaultError as e:
        print_error(f"Failed to push secret: {e}")
        raise typer.Exit(code=1) from None
    print_success(f"Pushed secret '{secret_name}' to {settings.provider} vault")
    if result.version:
        console.print(f"  Version: {result.version}")


def _validate_pull_folder(folder: Path) -> None:
    """Reject missing or non-directory targets before the vault round trip."""
    if not folder.exists():
        print_error(f"Folder not found: {folder}")
        raise typer.Exit(code=1)
    if not folder.is_dir():
        print_error(f"Not a directory: {folder}")
        raise typer.Exit(code=1)


def _missing_secret_region_note(settings: VaultSettings, client: VaultClient) -> str:
    """Describe the effective AWS region for a not-found error."""
    if settings.provider != "aws":
        return ""
    client_region = getattr(client, "region", None)
    return f" (region {client_region})" if client_region else ""


def _fetch_pull_secret(
    request: VaultPullRequest,
    settings: VaultSettings,
    client: VaultClient,
) -> SecretValue:
    """Fetch one vault secret with provider-specific failure context."""
    from envdrift.vault import VaultError
    from envdrift.vault.base import SecretNotFoundError

    try:
        return client.get_secret(request.secret_name)
    except SecretNotFoundError:
        region_note = _missing_secret_region_note(settings, client)
        print_error(
            f"Secret '{request.secret_name}' not found in {settings.provider} vault{region_note}"
        )
        raise typer.Exit(code=1) from None
    except VaultError as e:
        print_error(f"Failed to fetch secret: {e}")
        raise typer.Exit(code=1) from None


def _extract_pull_key(request: VaultPullRequest, secret: SecretValue) -> tuple[str, str]:
    """Normalize vault key material and reject environment-prefix mismatches."""
    from envdrift.vault.keymaterial import KeyMaterialError, extract_key_material

    key_name = f"DOTENV_PRIVATE_KEY_{request.environment.upper()}"
    try:
        key_value, stored_suffix = extract_key_material(secret, request.environment)
    except KeyMaterialError as e:
        print_error(f"Cannot install secret as a dotenvx key: {e}")
        raise typer.Exit(code=1) from None
    if stored_suffix is not None and stored_suffix.upper() != request.environment.upper():
        print_error(
            f"Secret holds 'DOTENV_PRIVATE_KEY_{stored_suffix.upper()}' but "
            f"--env {request.environment} expects '{key_name}'. "
            "Re-run with --env matching the environment the secret was pushed for "
            "(or push the secret under the correct environment)."
        )
        raise typer.Exit(code=1)
    return key_name, key_value


def _write_pull_key(request: VaultPullRequest, key_name: str, key_value: str) -> Path:
    """Write fetched key material while preserving clean filesystem errors."""
    from envdrift.sync.operations import EnvKeysFile

    env_keys_path = request.folder / ".env.keys"
    try:
        EnvKeysFile(env_keys_path).write_key(
            key_name,
            key_value,
            environment=request.environment,
        )
    except (OSError, ValueError) as e:
        print_error(f"Cannot write {env_keys_path}: {e}")
        raise typer.Exit(code=1) from None
    return env_keys_path


def _resolve_pull_target(request: VaultPullRequest) -> Path:
    """Resolve an optional custom env filename under the service folder."""
    try:
        if request.env_file is not None:
            return resolve_custom_env_file(request.folder, request.env_file)
        return request.folder / f".env.{request.environment}"
    except ValueError as e:
        print_error(f"Invalid --env-file: {e}")
        raise typer.Exit(code=1) from None


def _resolve_pull_backend(config: Path | None) -> tuple[EncryptionBackend, EncryptionProvider]:
    """Resolve and validate the encryption backend used after a key pull."""
    from envdrift.cli_commands.encryption_helpers import resolve_encryption_backend
    from envdrift.config import ConfigLoadError, ConfigNotFoundError

    if config is not None and config.suffix.lower() != ".toml":
        print_warning(
            f"--config {config} has no .toml suffix; it is used for vault settings "
            "but ignored when selecting the encryption backend (auto-detected instead)."
        )
    try:
        backend, provider, _ = resolve_encryption_backend(config)
    except (ConfigNotFoundError, ConfigLoadError) as e:
        print_error(str(e))
        raise typer.Exit(code=1) from None
    except ValueError as e:
        print_error(f"Unsupported encryption backend: {e}")
        raise typer.Exit(code=1) from None
    if not backend.is_installed():
        print_error(f"{backend.name} is not installed")
        console.print(backend.install_instructions())
        raise typer.Exit(code=1)
    return backend, provider


def _decrypt_pull_target(
    request: VaultPullRequest,
    target: Path,
    env_keys_path: Path,
) -> None:
    """Normalize custom dotenvx metadata and decrypt the target file."""
    from envdrift.encryption import (
        EncryptionBackendError,
        EncryptionNotFoundError,
        EncryptionProvider,
    )

    backend, provider = _resolve_pull_backend(request.config)
    if provider == EncryptionProvider.DOTENVX and request.env_file is not None:
        from envdrift.integrations.dotenvx import normalize_dotenvx_metadata

        normalize_dotenvx_metadata(target, env_keys_path, request.environment)
    try:
        result = backend.decrypt(target.resolve(), keys_file=env_keys_path.resolve())
    except (EncryptionNotFoundError, EncryptionBackendError) as e:
        print_error(f"Failed to decrypt {target}: {e}")
        raise typer.Exit(code=1) from None
    if not result.success:
        print_error(f"Failed to decrypt {target}: {result.message}")
        raise typer.Exit(code=1)
    print_success(f"Decrypted {target}")


def execute_vault_pull(request: VaultPullRequest) -> None:
    """Fetch, install, and optionally use one vault-backed encryption key."""
    _validate_pull_folder(request.folder)
    settings = resolve_vault_settings(
        request.config,
        request.provider,
        request.vault_url,
        request.region,
        request.project_id,
    )
    client = build_authenticated_client(settings)
    secret = _fetch_pull_secret(request, settings, client)
    key_name, key_value = _extract_pull_key(request, secret)
    env_keys_path = _write_pull_key(request, key_name, key_value)
    print_success(f"Pulled '{request.secret_name}' -> {key_name} written to {env_keys_path}")
    if request.no_decrypt:
        return
    target = _resolve_pull_target(request)
    if not target.exists():
        console.print(f"[dim]Key written; no {target} found to decrypt.[/dim]")
        return
    _decrypt_pull_target(request, target, env_keys_path)
