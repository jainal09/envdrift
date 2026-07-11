"""Execution workflows for the high-level sync CLI commands."""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import typer
from rich.panel import Panel

from envdrift.env_files import resolve_mapping_env_file
from envdrift.output.rich import console, print_error, print_success, print_warning
from envdrift.vault.base import SecretNotFoundError, VaultError

if TYPE_CHECKING:
    from envdrift.encryption import EncryptionProvider
    from envdrift.sync.config import ServiceMapping, SyncConfig


@dataclass(frozen=True)
class PullRequest:
    """User-selected options for ``envdrift pull``."""

    config_file: Path | None
    provider: str | None
    vault_url: str | None
    region: str | None
    project_id: str | None
    force: bool
    profile: str | None
    skip_sync: bool
    merge: bool


@dataclass(frozen=True)
class PullRuntime:
    """Patchable sync-module seams used by the pull workflow."""

    load_sync: Callable[..., tuple[SyncConfig, Any, str, str | None, str | None, str | None]]
    run_tasks: Callable[..., Any]
    normalize_metadata: Callable[..., None]
    load_partial_paths: Callable[[Path | None], tuple[set[Path], set[Path], set[Path]]]
    maybe_activate_profile: Callable[[ServiceMapping, Path, str | None], str]
    find_config_path: Callable[[Path | None], Path | None]
    write_merged_file: Callable[[Path, Path, Path], None]


@dataclass(frozen=True)
class SyncCommandContext:
    """Configuration shared by the phases of one sync command."""

    sync_config: SyncConfig
    vault_client: Any
    effective_provider: str
    mappings: list[ServiceMapping]
    filtered_config: SyncConfig


@dataclass(frozen=True)
class _EncryptionRuntime:
    backend: Any
    provider: EncryptionProvider
    config: Any


@dataclass(frozen=True)
class _DecryptTask:
    mapping: ServiceMapping
    env_file: Path
    ephemeral_key: str | None = None
    ephemeral_key_name: str | None = None


@dataclass
class _PullDecryptState:
    tasks: list[_DecryptTask] = field(default_factory=list)
    decrypted: int = 0
    skipped: int = 0
    errors: int = 0
    activated: int = 0
    activation_errors: int = 0


@dataclass
class _PullPartialState:
    decrypted: int = 0
    merged: int = 0
    skipped: int = 0
    errors: list[str] = field(default_factory=list)


def _load_command_context(request: PullRequest, runtime: PullRuntime) -> SyncCommandContext:
    from envdrift.integrations.hook_check import ensure_git_hook_setup
    from envdrift.sync.config import SyncConfig as SyncConfigClass

    sync_config, vault_client, effective_provider, _, _, _ = runtime.load_sync(
        config_file=request.config_file,
        provider=request.provider,
        vault_url=request.vault_url,
        region=request.region,
        project_id=request.project_id,
    )
    hook_errors = ensure_git_hook_setup(config_file=request.config_file)
    if hook_errors:
        for error in hook_errors:
            print_error(error)
        raise typer.Exit(code=1)

    mappings = sync_config.filter_by_profile(request.profile)
    if not mappings:
        if request.profile:
            print_error(f"No mappings found for profile '{request.profile}'")
        else:
            print_warning("No non-profile mappings found. Use --profile to specify one.")
        raise typer.Exit(code=1)

    filtered_config = SyncConfigClass(
        mappings=mappings,
        default_vault_name=sync_config.default_vault_name,
        env_keys_filename=sync_config.env_keys_filename,
        max_workers=sync_config.max_workers,
        ephemeral_keys=sync_config.ephemeral_keys,
    )
    return SyncCommandContext(
        sync_config=sync_config,
        vault_client=vault_client,
        effective_provider=effective_provider,
        mappings=mappings,
        filtered_config=filtered_config,
    )


def _new_sync_engine(context: SyncCommandContext, force: bool):
    from envdrift.sync.engine import SyncEngine, SyncMode

    def progress_callback(msg: str) -> None:
        console.print(f"[dim]{msg}[/dim]")

    def prompt_callback(msg: str) -> bool:
        if force:
            return True
        response = console.input(f"{msg} (y/N): ").strip().lower()
        return response in ("y", "yes")

    return SyncEngine(
        config=context.filtered_config,
        vault_client=context.vault_client,
        mode=SyncMode(force_update=force),
        prompt_callback=prompt_callback,
        progress_callback=progress_callback,
    )


def _print_pull_header(request: PullRequest, context: SyncCommandContext) -> None:
    console.print()
    profile_info = f" (profile: {request.profile})" if request.profile else ""
    action = (
        "Decrypting env files" if request.skip_sync else "Syncing keys and decrypting env files"
    )
    console.print(f"[bold]Pull[/bold] - {action}{profile_info}")
    console.print(
        f"[dim]Provider: {context.effective_provider} | Services: {len(context.mappings)}[/dim]"
    )
    console.print()


def _ephemeral_keys_from_sync_result(sync_result: Any, mappings: list[ServiceMapping]):
    from envdrift.sync.result import SyncAction

    mappings_by_folder: dict[Path, ServiceMapping] = {}
    for mapping in mappings:
        mappings_by_folder.setdefault(mapping.folder_path.resolve(), mapping)

    ephemeral_keys: dict[Path, tuple[str, str]] = {}
    for service_result in sync_result.services:
        action = getattr(service_result, "action", None)
        key_value = getattr(service_result, "vault_key_value", None)
        if action != SyncAction.EPHEMERAL or not key_value:
            continue
        matched = mappings_by_folder.get(service_result.folder_path.resolve())
        environment = (
            matched.effective_environment
            if matched is not None
            else service_result.folder_path.name
        )
        ephemeral_keys[service_result.folder_path.resolve()] = (
            f"DOTENV_PRIVATE_KEY_{environment.upper()}",
            key_value,
        )
    return ephemeral_keys


def _sync_pull_keys(
    request: PullRequest, context: SyncCommandContext, engine: Any
) -> dict[Path, tuple[str, str]]:
    from envdrift.output.rich import print_service_sync_status, print_sync_result
    from envdrift.sync.config import SyncConfigError

    if request.skip_sync:
        console.print("[dim]Step 1: Skipped (--skip-sync)[/dim]")
        return {}

    console.print("[bold cyan]Step 1:[/bold cyan] Syncing keys from vault...")
    console.print()
    try:
        sync_result = engine.sync_all()
    except (VaultError, SyncConfigError, SecretNotFoundError) as exc:
        print_error(f"Sync failed: {exc}")
        raise typer.Exit(code=1) from None

    for service_result in sync_result.services:
        print_service_sync_status(service_result)
    print_sync_result(sync_result)
    if sync_result.has_errors:
        print_error("Setup incomplete due to sync errors")
        raise typer.Exit(code=1)
    return _ephemeral_keys_from_sync_result(sync_result, context.mappings)


def _load_encryption_runtime(config_file: Path | None) -> _EncryptionRuntime:
    from envdrift.cli_commands import encryption_helpers
    from envdrift.config import ConfigLoadError, ConfigNotFoundError

    try:
        backend, provider, config = encryption_helpers.resolve_encryption_backend(config_file)
        if not backend.is_installed():
            print_error(f"{backend.name} is not installed")
            console.print(backend.install_instructions())
            raise typer.Exit(code=1)
    except (ConfigNotFoundError, ConfigLoadError) as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from None
    except ValueError as exc:
        print_error(f"Unsupported encryption backend: {exc}")
        raise typer.Exit(code=1) from None
    return _EncryptionRuntime(backend=backend, provider=provider, config=config)


def _resolve_pull_mapping_file(
    mapping: ServiceMapping, state: _PullDecryptState
) -> tuple[Path, str] | None:
    try:
        detection = resolve_mapping_env_file(mapping)
    except ValueError as exc:
        console.print(f"  [red]![/red] {mapping.folder_path} [red]- invalid env_file: {exc}[/red]")
        state.errors += 1
        return None

    environment = detection.environment or mapping.effective_environment
    env_file = detection.path or mapping.folder_path / f".env.{environment}"
    if detection.status == "found" and detection.path is not None:
        return env_file, environment
    if detection.status == "folder_not_found":
        console.print(
            f"  [red]![/red] {mapping.folder_path} "
            f"[red]- error: folder does not exist or is not a directory "
            f"(check folder_path in your sync config)[/red]"
        )
        state.errors += 1
    elif detection.status == "multiple_found":
        console.print(
            f"  [yellow]?[/yellow] {mapping.folder_path} "
            f"[yellow]- skipped (multiple .env.* files, specify environment)[/yellow]"
        )
        state.skipped += 1
    else:
        console.print(f"  [dim]=[/dim] {env_file} [dim]- skipped (not found)[/dim]")
        state.skipped += 1
    return None


def _skip_pull_partial_file(
    env_file: Path, partial_clear: set[Path], partial_combined: set[Path]
) -> bool:
    resolved = env_file.resolve()
    if resolved in partial_combined:
        console.print(
            f"  [dim]=[/dim] {env_file} [dim]- skipped (partial encryption combined file)[/dim]"
        )
        return True
    if resolved in partial_clear:
        console.print(
            f"  [dim]=[/dim] {env_file} [dim]- skipped (partial encryption clear file)[/dim]"
        )
        return True
    return False


def _record_activation(
    mapping: ServiceMapping,
    env_file: Path,
    profile: str | None,
    state: _PullDecryptState,
    runtime: PullRuntime,
) -> None:
    outcome = runtime.maybe_activate_profile(mapping, env_file, profile)
    if outcome == "activated":
        state.activated += 1
    elif outcome == "error":
        state.activation_errors += 1


def _should_queue_decryption(
    mapping: ServiceMapping,
    env_file: Path,
    environment: str,
    request: PullRequest,
    context: SyncCommandContext,
    encryption: _EncryptionRuntime,
    state: _PullDecryptState,
    runtime: PullRuntime,
) -> bool:
    from envdrift.cli_commands import encryption_helpers
    from envdrift.encryption import EncryptionProvider, detect_encryption_provider

    keys_file = mapping.folder_path / (context.sync_config.env_keys_filename or ".env.keys")
    try:
        runtime.normalize_metadata(env_file, keys_file, environment, encryption.provider)
        content = env_file.read_text(encoding="utf-8")
    except (OSError, ValueError) as exc:
        console.print(f"  [red]![/red] {env_file} [red]- error reading file: {exc}[/red]")
        state.errors += 1
        return False

    if encryption_helpers.should_attempt_decryption(
        encryption.provider, encryption.backend, content
    ):
        return True

    detected = detect_encryption_provider(env_file)
    if detected and detected != encryption.provider:
        if (
            detected == EncryptionProvider.DOTENVX
            and encryption.provider != EncryptionProvider.DOTENVX
        ):
            console.print(
                f"  [red]![/red] {env_file} [red]- encrypted with dotenvx, but config uses "
                f"{encryption.provider.value}[/red]"
            )
            state.errors += 1
            return False
        console.print(
            f"  [dim]=[/dim] {env_file} [dim]- skipped (encrypted with {detected.value}, "
            f"config uses {encryption.provider.value})[/dim]"
        )
        state.skipped += 1
        return False

    console.print(f"  [dim]=[/dim] {env_file} [dim]- skipped (not encrypted)[/dim]")
    state.skipped += 1
    _record_activation(mapping, env_file, request.profile, state, runtime)
    return False


def _queue_pull_mapping(
    mapping: ServiceMapping,
    request: PullRequest,
    context: SyncCommandContext,
    encryption: _EncryptionRuntime,
    partial_clear: set[Path],
    partial_combined: set[Path],
    ephemeral_keys: dict[Path, tuple[str, str]],
    state: _PullDecryptState,
    runtime: PullRuntime,
) -> None:
    resolved = _resolve_pull_mapping_file(mapping, state)
    if resolved is None:
        return
    env_file, environment = resolved
    if _skip_pull_partial_file(env_file, partial_clear, partial_combined):
        state.skipped += 1
        return
    if not _should_queue_decryption(
        mapping, env_file, environment, request, context, encryption, state, runtime
    ):
        return
    key_name, key_value = ephemeral_keys.get(mapping.folder_path.resolve(), (None, None))
    state.tasks.append(
        _DecryptTask(
            mapping=mapping,
            env_file=env_file,
            ephemeral_key=key_value,
            ephemeral_key_name=key_name,
        )
    )


def _decrypt_one(task: _DecryptTask, backend: Any):
    from envdrift.encryption import EncryptionBackendError, EncryptionNotFoundError

    try:
        env_override = None
        if task.ephemeral_key and task.ephemeral_key_name:
            env_override = dict(os.environ)
            env_override[task.ephemeral_key_name] = task.ephemeral_key
        return task, backend.decrypt(task.env_file.resolve(), env=env_override), None
    except (EncryptionNotFoundError, EncryptionBackendError) as exc:
        return task, None, exc


def _run_pull_decrypt_tasks(
    request: PullRequest,
    context: SyncCommandContext,
    encryption: _EncryptionRuntime,
    state: _PullDecryptState,
    runtime: PullRuntime,
) -> None:
    from envdrift.utils import normalize_max_workers

    worker = lambda task: _decrypt_one(task, encryption.backend)  # noqa: E731
    max_workers = normalize_max_workers(context.sync_config.max_workers)
    for task, result, error in runtime.run_tasks(state.tasks, worker, max_workers):
        if error is not None:
            console.print(f"  [red]![/red] {task.env_file} [red]- error: {error}[/red]")
            state.errors += 1
            continue
        if result is None or not result.success:
            message = result.message if result else "unknown error"
            console.print(f"  [red]![/red] {task.env_file} [red]- error: {message}[/red]")
            state.errors += 1
            continue
        console.print(f"  [green]+[/green] {task.env_file} [dim]- decrypted[/dim]")
        state.decrypted += 1
        _record_activation(task.mapping, task.env_file, request.profile, state, runtime)


def _print_pull_decrypt_summary(state: _PullDecryptState) -> None:
    lines = [
        f"Decrypted: {state.decrypted}",
        f"Skipped: {state.skipped}",
        f"Errors: {state.errors}",
    ]
    if state.activated > 0:
        lines.append(f"Activated: {state.activated}")
    if state.activation_errors > 0:
        lines.append(f"Activation errors: {state.activation_errors}")
    console.print()
    console.print(Panel("\n".join(lines), title="Decrypt Summary", expand=False))
    if state.errors > 0:
        print_warning("Some files could not be decrypted")
    if state.activation_errors > 0:
        print_warning("Some profile files could not be activated")
    if state.errors > 0 or state.activation_errors > 0:
        raise typer.Exit(code=1)


def _decrypt_pull_files(
    request: PullRequest,
    context: SyncCommandContext,
    ephemeral_keys: dict[Path, tuple[str, str]],
    runtime: PullRuntime,
) -> None:
    console.print()
    console.print("[bold cyan]Step 2:[/bold cyan] Decrypting environment files...")
    console.print()
    encryption = _load_encryption_runtime(request.config_file)
    partial_clear, _, partial_combined = runtime.load_partial_paths(request.config_file)
    state = _PullDecryptState()
    for mapping in context.mappings:
        _queue_pull_mapping(
            mapping,
            request,
            context,
            encryption,
            partial_clear,
            partial_combined,
            ephemeral_keys,
            state,
            runtime,
        )
    _run_pull_decrypt_tasks(request, context, encryption, state, runtime)
    _print_pull_decrypt_summary(state)


def _load_partial_config(config_file: Path | None, runtime: PullRuntime):
    from envdrift.config import ConfigLoadError, ConfigNotFoundError, load_config

    config_path = runtime.find_config_path(config_file)
    if not config_path:
        return None
    try:
        return load_config(config_path)
    except ConfigNotFoundError:
        return None
    except ConfigLoadError as exc:
        print_warning(f"Unable to read config for partial encryption: {exc}")
        return None


def _pull_secrets_only_environment(env_config: Any, state: _PullPartialState) -> None:
    from envdrift.core.partial_encryption import PartialEncryptionError, pull_secrets_only

    try:
        result = pull_secrets_only(env_config)
    except PartialEncryptionError as exc:
        console.print(f"  [red]![/red] {env_config.secrets_dir} [red]- error: {exc}[/red]")
        state.errors.append(f"{env_config.name}: {exc}")
        return
    if result["decrypted"]:
        console.print(
            f"  [green]+[/green] {env_config.secrets_dir} "
            f"[dim]- {result['decrypted']} file(s) decrypted[/dim]"
        )
        state.decrypted += result["decrypted"]
    else:
        console.print(
            f"  [dim]=[/dim] {env_config.secrets_dir} [dim]- skipped (already decrypted)[/dim]"
        )
    state.skipped += result["already_decrypted"]


def _merge_pull_environment(
    env_config: Any,
    secret_file: Path,
    state: _PullPartialState,
    runtime: PullRuntime,
) -> None:
    combined_file = Path(env_config.combined_file)
    try:
        runtime.write_merged_file(Path(env_config.clear_file), secret_file, combined_file)
    except (OSError, UnicodeDecodeError) as exc:
        console.print(f"  [red]![/red] {combined_file} [red]- merge failed: {exc}[/red]")
        state.errors.append(f"{env_config.name}: {exc}")
        return
    console.print(f"  [cyan]→[/cyan] {combined_file} [dim]- merged (decrypted)[/dim]")
    state.merged += 1


def _pull_combined_environment(
    env_config: Any,
    merge: bool,
    state: _PullPartialState,
    runtime: PullRuntime,
) -> None:
    from envdrift.core.partial_encryption import PartialEncryptionError, pull_partial_encryption

    secret_file = Path(env_config.secret_file)
    if not secret_file.exists():
        console.print(f"  [dim]=[/dim] {secret_file} [dim]- skipped (not found)[/dim]")
        state.skipped += 1
        return
    try:
        was_decrypted, _ = pull_partial_encryption(env_config)
    except PartialEncryptionError as exc:
        console.print(f"  [red]![/red] {secret_file} [red]- error: {exc}[/red]")
        state.errors.append(f"{env_config.name}: {exc}")
        return
    if was_decrypted:
        console.print(f"  [green]+[/green] {secret_file} [dim]- decrypted[/dim]")
        state.decrypted += 1
    else:
        console.print(f"  [dim]=[/dim] {secret_file} [dim]- skipped (already decrypted)[/dim]")
        state.skipped += 1
    if merge:
        _merge_pull_environment(env_config, secret_file, state, runtime)


def _print_partial_pull_summary(state: _PullPartialState, merge: bool) -> None:
    lines = [f"Decrypted: {state.decrypted}", f"Skipped: {state.skipped}"]
    if merge:
        lines.append(f"Merged: {state.merged}")
    if state.errors:
        lines.append(f"Errors: {len(state.errors)}")
    console.print()
    console.print(Panel("\n".join(lines), title="Partial Encryption Summary", expand=False))
    if state.errors:
        print_warning("Some partial encryption files had errors")
        for error in state.errors:
            console.print(f"  • {error}")
        raise typer.Exit(code=1)


def _process_pull_partial_encryption(request: PullRequest, runtime: PullRuntime) -> None:
    partial_config = _load_partial_config(request.config_file, runtime)
    if not partial_config or not partial_config.partial_encryption.enabled:
        return
    console.print()
    console.print("[bold cyan]Step 3:[/bold cyan] Processing partial encryption files...")
    console.print()
    if request.merge:
        from envdrift.cli_commands.partial import _ensure_combined_gitignore

        _ensure_combined_gitignore(partial_config.partial_encryption.environments)
    state = _PullPartialState()
    for env_config in partial_config.partial_encryption.environments:
        if env_config.secrets_only:
            _pull_secrets_only_environment(env_config, state)
        else:
            _pull_combined_environment(env_config, request.merge, state, runtime)
    _print_partial_pull_summary(state, request.merge)


def execute_pull(request: PullRequest, runtime: PullRuntime) -> None:
    """Run the pull workflow while keeping the Typer command as an adapter."""

    context = _load_command_context(request, runtime)
    engine = _new_sync_engine(context, request.force)
    _print_pull_header(request, context)
    ephemeral_keys = _sync_pull_keys(request, context, engine)
    _decrypt_pull_files(request, context, ephemeral_keys, runtime)
    _process_pull_partial_encryption(request, runtime)
    console.print()
    print_success("Setup complete! Your environment files are ready to use.")


@dataclass(frozen=True)
class LockRequest:
    """User-selected options for ``envdrift lock``."""

    config_file: Path | None
    provider: str | None
    vault_url: str | None
    region: str | None
    project_id: str | None
    force: bool
    profile: str | None
    verify_vault: bool
    sync_keys: bool
    check_only: bool
    all_files: bool


@dataclass(frozen=True)
class LockRuntime:
    """Patchable sync-module seams used by the lock workflow."""

    load_sync: Callable[..., tuple[SyncConfig, Any, str, str | None, str | None, str | None]]
    run_tasks: Callable[..., Any]
    normalize_metadata: Callable[..., None]
    load_partial_paths: Callable[[Path | None], tuple[set[Path], set[Path], set[Path]]]
    find_config_path: Callable[[Path | None], Path | None]
    find_stale_key: Callable[[Path, str], str | None]
    rekey_file: Callable[[Path, Any, dict[str, Any]], tuple[bool, str]]
    verify_summary: Callable[[int, int], str]
    sops_missing_recipients: Callable[[Any, EncryptionProvider, dict[str, Any], str], list[str]]
    lock_factory: Callable[[], Any]


@dataclass(frozen=True)
class _EncryptTask:
    mapping: ServiceMapping
    env_file: Path
    env_keys_file: Path
    effective_environment: str


@dataclass
class _LockState:
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    tasks: list[_EncryptTask] = field(default_factory=list)
    dotenvx_locks: dict[Path, Any] = field(default_factory=dict)
    encrypted: int = 0
    skipped: int = 0
    error_count: int = 0
    already_encrypted: int = 0
    verification_issues: int = 0
    unusable_keys: int = 0


@dataclass
class _LockPartialState:
    encrypted: int = 0
    combined_deleted: int = 0
    secrets_only_skipped: int = 0
    secrets_only_pending: list[tuple[str, int]] = field(default_factory=list)


@dataclass(frozen=True)
class _LockEncryptContext:
    request: LockRequest
    command: SyncCommandContext
    encryption: _EncryptionRuntime
    sops_kwargs: dict[str, Any]
    partial_clear: set[Path]
    partial_combined: set[Path]
    runtime: LockRuntime


def _load_lock_context(request: LockRequest, runtime: LockRuntime) -> SyncCommandContext:
    from envdrift.integrations.hook_check import ensure_git_hook_setup
    from envdrift.sync.config import SyncConfig as SyncConfigClass

    sync_config, vault_client, effective_provider, _, _, _ = runtime.load_sync(
        config_file=request.config_file,
        provider=request.provider,
        vault_url=request.vault_url,
        region=request.region,
        project_id=request.project_id,
    )
    hook_errors = ensure_git_hook_setup(config_file=request.config_file)
    if hook_errors:
        for error in hook_errors:
            print_error(error)
        raise typer.Exit(code=1)
    mappings = sync_config.filter_by_profile(request.profile)
    if not mappings:
        if request.profile:
            print_error(f"No mappings found for profile '{request.profile}'")
        else:
            print_warning("No non-profile mappings found. Use --profile to specify one.")
        raise typer.Exit(code=1)
    filtered_config = SyncConfigClass(
        mappings=mappings,
        default_vault_name=sync_config.default_vault_name,
        env_keys_filename=sync_config.env_keys_filename,
        max_workers=sync_config.max_workers,
        ephemeral_keys=sync_config.ephemeral_keys,
    )
    return SyncCommandContext(
        sync_config=sync_config,
        vault_client=vault_client,
        effective_provider=effective_provider,
        mappings=mappings,
        filtered_config=filtered_config,
    )


def _print_lock_header(request: LockRequest, context: SyncCommandContext) -> None:
    console.print()
    profile_info = f" (profile: {request.profile})" if request.profile else ""
    mode = "CHECK" if request.check_only else ("FORCE" if request.force else "Interactive")
    all_info = " | Including partial encryption" if request.all_files else ""
    console.print(f"[bold]Lock[/bold] - Verifying keys and encrypting env files{profile_info}")
    console.print(
        f"[dim]Provider: {context.effective_provider} | Mode: {mode} | "
        f"Services: {len(context.mappings)}{all_info}[/dim]"
    )
    console.print()


def _sync_lock_keys(request: LockRequest, context: SyncCommandContext) -> None:
    from envdrift.output.rich import print_service_sync_status, print_sync_result
    from envdrift.sync.config import SyncConfigError

    engine = _new_sync_engine(context, request.force)
    try:
        sync_result = engine.sync_all()
    except (VaultError, SyncConfigError, SecretNotFoundError) as exc:
        print_error(f"Key sync failed: {exc}")
        raise typer.Exit(code=1) from None
    for service_result in sync_result.services:
        print_service_sync_status(service_result)
    print_sync_result(sync_result)
    if sync_result.has_errors:
        print_error(
            "Cannot proceed with encryption due to key sync errors. "
            "Nothing was encrypted. Fix the vault secrets (or publish "
            "local keys with 'envdrift vault-push') and rerun."
        )
        raise typer.Exit(code=1)


def _read_local_lock_key(
    mapping: ServiceMapping, context: SyncCommandContext, state: _LockState
) -> tuple[str, str] | None:
    from envdrift.sync.operations import EnvKeysFile

    environment = mapping.effective_environment
    keys_file = mapping.folder_path / (context.sync_config.env_keys_filename or ".env.keys")
    key_name = f"DOTENV_PRIVATE_KEY_{environment.upper()}"
    if not keys_file.exists():
        console.print(
            f"  [red]✗[/red] {mapping.folder_path} "
            f"[red]- cannot verify: {keys_file.name} not found[/red]"
        )
        state.errors.append(
            f"{mapping.folder_path}: cannot verify - {keys_file.name} missing "
            f"(run 'envdrift lock --sync-keys' to fetch keys from vault)"
        )
        state.verification_issues += 1
        return None
    local_key = EnvKeysFile(keys_file).read_key(key_name)
    if local_key:
        return local_key, environment
    console.print(
        f"  [red]✗[/red] {mapping.folder_path} "
        f"[red]- cannot verify: {key_name} not found in {keys_file.name}[/red]"
    )
    state.errors.append(
        f"{mapping.folder_path}: cannot verify - {key_name} missing from "
        f"{keys_file.name} (run 'envdrift lock --sync-keys' to fetch it)"
    )
    state.verification_issues += 1
    return None


def _compare_lock_vault_key(
    mapping: ServiceMapping,
    local_key: str,
    environment: str,
    context: SyncCommandContext,
    state: _LockState,
) -> None:
    from envdrift.vault.keymaterial import KeyMaterialError, extract_key_material

    try:
        context.vault_client.ensure_authenticated()
        secret = context.vault_client.get_secret(mapping.secret_name)
        if not _vault_secret_has_value(secret):
            console.print(
                f"  [red]✗[/red] {mapping.folder_path} [red]- cannot verify: vault secret "
                f"'{mapping.secret_name}' is empty[/red]"
            )
            state.errors.append(
                f"{mapping.folder_path}: cannot verify - vault secret "
                f"'{mapping.secret_name}' is empty (push the key with 'envdrift vault-push')"
            )
            state.verification_issues += 1
            return
        vault_key, vault_suffix = extract_key_material(secret, environment)
        if _vault_key_matches(local_key, vault_key, vault_suffix, environment):
            console.print(f"  [green]✓[/green] {mapping.folder_path} [dim]- keys match vault[/dim]")
            return
        console.print(
            f"  [red]✗[/red] {mapping.folder_path} "
            f"[red]- KEY MISMATCH: local key differs from vault![/red]"
        )
        state.errors.append(
            f"{mapping.folder_path}: local key does not match vault "
            f"(run 'envdrift lock --sync-keys' to fix)"
        )
        state.verification_issues += 1
    except SecretNotFoundError:
        console.print(
            f"  [red]✗[/red] {mapping.folder_path} [red]- cannot verify: vault secret "
            f"'{mapping.secret_name}' not found[/red]"
        )
        state.errors.append(
            f"{mapping.folder_path}: cannot verify - vault secret '{mapping.secret_name}' "
            f"not found (push the key with 'envdrift vault-push')"
        )
        state.verification_issues += 1
    except KeyMaterialError as exc:
        console.print(f"  [red]✗[/red] {mapping.folder_path} [red]- KEY UNUSABLE: {exc}[/red]")
        state.errors.append(f"{mapping.folder_path}: vault key material unusable - {exc}")
        state.verification_issues += 1
        state.unusable_keys += 1
    except VaultError as exc:
        console.print(
            f"  [red]![/red] {mapping.folder_path} [red]- error: vault access failed: {exc}[/red]"
        )
        state.errors.append(f"{mapping.folder_path}: vault error - {exc}")
        state.verification_issues += 1


def _vault_secret_has_value(secret: Any) -> bool:
    return bool(secret and secret.value)


def _vault_key_matches(
    local_key: str, vault_key: str, vault_suffix: str | None, environment: str
) -> bool:
    if vault_suffix is not None and vault_suffix.upper() != environment.upper():
        return False
    return local_key == vault_key


def _verify_lock_keys(context: SyncCommandContext, state: _LockState, runtime: LockRuntime) -> None:
    for mapping in context.mappings:
        local = _read_local_lock_key(mapping, context, state)
        if local is not None:
            _compare_lock_vault_key(mapping, local[0], local[1], context, state)
    console.print()
    if state.verification_issues:
        print_error(
            runtime.verify_summary(
                state.verification_issues - state.unusable_keys, state.unusable_keys
            )
        )
        raise typer.Exit(code=1)


def _verify_or_sync_lock_keys(
    request: LockRequest,
    context: SyncCommandContext,
    state: _LockState,
    runtime: LockRuntime,
) -> None:
    if not request.verify_vault:
        return
    console.print("[bold cyan]Step 1:[/bold cyan] Verifying keys with vault...")
    console.print()
    if request.sync_keys:
        _sync_lock_keys(request, context)
    else:
        _verify_lock_keys(context, state, runtime)


def _resolve_lock_mapping_file(
    mapping: ServiceMapping, state: _LockState
) -> tuple[Path, str] | None:
    try:
        detection = resolve_mapping_env_file(mapping)
    except ValueError as exc:
        console.print(f"  [red]![/red] {mapping.folder_path} [red]- invalid env_file: {exc}[/red]")
        state.errors.append(f"{mapping.folder_path}: invalid env_file - {exc}")
        state.error_count += 1
        return None
    environment = detection.environment or mapping.effective_environment
    env_file = detection.path or mapping.folder_path / f".env.{environment}"
    if detection.status == "found" and detection.path is not None:
        return env_file, environment
    if detection.status == "folder_not_found":
        console.print(
            f"  [red]![/red] {mapping.folder_path} "
            f"[red]- error: folder does not exist or is not a directory "
            f"(check folder_path in your sync config)[/red]"
        )
        state.errors.append(
            f"{mapping.folder_path}: folder does not exist or is not a directory "
            "(check folder_path in your sync config)"
        )
        state.error_count += 1
    elif detection.status == "multiple_found":
        console.print(
            f"  [yellow]?[/yellow] {mapping.folder_path} "
            f"[yellow]- skipped (multiple .env.* files, specify environment)[/yellow]"
        )
        state.warnings.append(f"{mapping.folder_path}: multiple .env files found")
        state.skipped += 1
    else:
        console.print(f"  [dim]=[/dim] {env_file} [dim]- skipped (not found)[/dim]")
        state.warnings.append(f"{env_file}: file not found")
        state.skipped += 1
    return None


def _skip_lock_partial_file(env_file: Path, context: _LockEncryptContext) -> bool:
    if context.request.all_files:
        return False
    resolved = env_file.resolve()
    if resolved in context.partial_combined:
        console.print(
            f"  [dim]=[/dim] {env_file} "
            "[dim]- skipped (partial encryption combined file, use --all to include)[/dim]"
        )
        return True
    if resolved in context.partial_clear:
        console.print(
            f"  [dim]=[/dim] {env_file} [dim]- skipped (partial encryption clear file)[/dim]"
        )
        return True
    return False


def _read_lock_content(
    env_file: Path,
    keys_file: Path,
    environment: str,
    context: _LockEncryptContext,
    state: _LockState,
) -> str | None:
    try:
        context.runtime.normalize_metadata(
            env_file,
            keys_file,
            environment,
            context.encryption.provider,
            check_only=context.request.check_only,
        )
        return env_file.read_text(encoding="utf-8")
    except (OSError, ValueError) as exc:
        console.print(f"  [red]![/red] {env_file} [red]- error reading file: {exc}[/red]")
        state.errors.append(f"{env_file}: read failed - {exc}")
        state.error_count += 1
        return None


def _handle_lock_provider_mismatch(
    env_file: Path,
    context: _LockEncryptContext,
    state: _LockState,
) -> bool:
    from envdrift.encryption import EncryptionProvider, detect_encryption_provider

    detected = detect_encryption_provider(env_file)
    if not detected or detected == context.encryption.provider:
        return False
    if (
        detected == EncryptionProvider.DOTENVX
        and context.encryption.provider != EncryptionProvider.DOTENVX
    ):
        console.print(
            f"  [red]![/red] {env_file} [red]- encrypted with dotenvx, but config uses "
            f"{context.encryption.provider.value}[/red]"
        )
        state.errors.append(
            f"{env_file}: encrypted with dotenvx, but config uses "
            f"{context.encryption.provider.value}"
        )
        state.error_count += 1
    else:
        console.print(
            f"  [dim]=[/dim] {env_file} [dim]- skipped (encrypted with {detected.value}, "
            f"config uses {context.encryption.provider.value})[/dim]"
        )
        state.warnings.append(
            f"{env_file}: encrypted with {detected.value}, "
            f"config uses {context.encryption.provider.value}"
        )
        state.skipped += 1
    return True


def _handle_dotenvx_rekey(
    env_file: Path,
    keys_file: Path,
    environment: str,
    context: _LockEncryptContext,
    state: _LockState,
) -> bool:
    from envdrift.encryption import EncryptionProvider

    if context.encryption.provider != EncryptionProvider.DOTENVX:
        return False
    expected = f"DOTENV_PRIVATE_KEY_{environment.upper()}"
    try:
        old_name = context.runtime.find_stale_key(keys_file, expected)
    except (OSError, ValueError) as exc:
        console.print(f"  [red]![/red] {keys_file} [red]- error reading keys file: {exc}[/red]")
        state.errors.append(f"{keys_file}: read failed - {exc}")
        state.error_count += 1
        return True
    if not old_name:
        return False
    if context.request.check_only:
        console.print(
            f"  [cyan]?[/cyan] {env_file} [dim]- would re-key ({old_name} -> {expected})[/dim]"
        )
        state.warnings.append(
            f"{env_file}: key name mismatch, would re-encrypt to generate {expected}"
        )
        state.encrypted += 1
        return True
    console.print(
        f"  [yellow]~[/yellow] {env_file} "
        f"[dim]- key name mismatch ({old_name} -> {expected}), re-encrypting...[/dim]"
    )
    state.warnings.append(f"{env_file}: key name mismatch, re-encrypting to generate {expected}")
    ok, error = context.runtime.rekey_file(
        env_file, context.encryption.backend, context.sops_kwargs
    )
    if not ok:
        console.print(f"  [red]![/red] {env_file} [red]- {error}[/red]")
        state.errors.append(f"{env_file}: {error}")
        state.error_count += 1
        return True
    context.runtime.normalize_metadata(
        env_file, keys_file, environment, context.encryption.provider
    )
    console.print(f"  [green]+[/green] {env_file} [dim]- re-encrypted with new key[/dim]")
    state.encrypted += 1
    return True


def _handle_sops_recipients(
    env_file: Path, content: str, context: _LockEncryptContext, state: _LockState
) -> bool:
    missing = context.runtime.sops_missing_recipients(
        context.encryption.backend,
        context.encryption.provider,
        context.sops_kwargs,
        content,
    )
    if not missing:
        return False
    recipients = ", ".join(missing)
    console.print(
        f"  [red]![/red] {env_file} "
        f"[red]- encrypted, but SOPS metadata is missing requested "
        f"recipient(s): {recipients}[/red]"
    )
    state.errors.append(
        f"{env_file}: SOPS metadata is missing requested recipient(s): {recipients} - "
        f"re-running encrypt cannot add recipients; use `sops rotate --add-age <recipient>` "
        f"or `sops updatekeys`, or decrypt and re-encrypt"
    )
    state.error_count += 1
    return True


def _handle_already_encrypted(
    env_file: Path,
    keys_file: Path,
    environment: str,
    content: str,
    context: _LockEncryptContext,
    state: _LockState,
) -> bool:
    from envdrift.core.partial_encryption import has_plaintext_secret_value

    if has_plaintext_secret_value(env_file):
        state.warnings.append(f"{env_file}: partially encrypted, plaintext values remain")
        if context.request.check_only:
            console.print(
                f"  [cyan]?[/cyan] {env_file} "
                "[dim]- would re-encrypt (plaintext values remain)[/dim]"
            )
            state.encrypted += 1
            return True
        console.print(
            f"  [yellow]~[/yellow] {env_file} "
            "[dim]- partially encrypted (plaintext values remain), re-encrypting...[/dim]"
        )
        return False
    if _handle_dotenvx_rekey(env_file, keys_file, environment, context, state):
        return True
    if _handle_sops_recipients(env_file, content, context, state):
        return True
    console.print(f"  [dim]=[/dim] {env_file} [dim]- skipped (already encrypted)[/dim]")
    state.already_encrypted += 1
    return True


def _encrypt_interactive_file(
    env_file: Path,
    keys_file: Path,
    environment: str,
    context: _LockEncryptContext,
    state: _LockState,
) -> None:
    from envdrift.encryption import EncryptionBackendError, EncryptionNotFoundError

    try:
        result = context.encryption.backend.encrypt(env_file.resolve(), **context.sops_kwargs)
        if not result.success:
            console.print(f"  [red]![/red] {env_file} [red]- error: {result.message}[/red]")
            state.errors.append(f"{env_file}: encryption failed - {result.message}")
            state.error_count += 1
            return
        context.runtime.normalize_metadata(
            env_file, keys_file, environment, context.encryption.provider
        )
        console.print(f"  [green]+[/green] {env_file} [dim]- encrypted[/dim]")
        state.encrypted += 1
    except (EncryptionNotFoundError, EncryptionBackendError) as exc:
        console.print(f"  [red]![/red] {env_file} [red]- error: {exc}[/red]")
        state.errors.append(f"{env_file}: encryption failed - {exc}")
        state.error_count += 1


def _queue_or_encrypt_lock_file(
    mapping: ServiceMapping,
    env_file: Path,
    keys_file: Path,
    environment: str,
    context: _LockEncryptContext,
    state: _LockState,
) -> None:
    from envdrift.cli_commands import encryption_helpers
    from envdrift.encryption import EncryptionProvider

    if context.request.check_only:
        console.print(f"  [cyan]?[/cyan] {env_file} [dim]- would be encrypted[/dim]")
        state.encrypted += 1
        return
    smart = context.encryption.config.smart_encryption if context.encryption.config else False
    should_skip, reason = encryption_helpers.should_skip_reencryption(
        env_file, context.encryption.backend, enabled=smart
    )
    if should_skip:
        console.print(f"  [dim]=[/dim] {env_file} [dim]- skipped ({reason})[/dim]")
        state.already_encrypted += 1
        return
    if not context.request.force:
        response = console.input(f"  Encrypt {env_file}? (y/N): ").strip().lower()
        if response not in ("y", "yes"):
            console.print(f"  [dim]=[/dim] {env_file} [dim]- skipped (user declined)[/dim]")
            state.skipped += 1
            return
        _encrypt_interactive_file(env_file, keys_file, environment, context, state)
        return
    state.tasks.append(
        _EncryptTask(
            mapping=mapping,
            env_file=env_file,
            env_keys_file=keys_file,
            effective_environment=environment,
        )
    )
    if context.encryption.provider == EncryptionProvider.DOTENVX:
        lock_key = keys_file.resolve()
        if lock_key not in state.dotenvx_locks:
            state.dotenvx_locks[lock_key] = context.runtime.lock_factory()


def _process_lock_mapping(
    mapping: ServiceMapping, context: _LockEncryptContext, state: _LockState
) -> None:
    from envdrift.cli_commands import encryption_helpers

    resolved = _resolve_lock_mapping_file(mapping, state)
    if resolved is None:
        return
    env_file, environment = resolved
    if _skip_lock_partial_file(env_file, context):
        state.warnings.append(
            f"{env_file}: use envdrift lock --all or envdrift push for partial encryption"
        )
        state.skipped += 1
        return
    keys_file = _lock_keys_file(mapping, env_file, context, state)
    content = _read_lock_content(env_file, keys_file, environment, context, state)
    if content is None:
        return
    encrypted = encryption_helpers.is_encrypted_content(
        context.encryption.provider, context.encryption.backend, content
    )
    if _lock_content_handled(encrypted, env_file, keys_file, environment, content, context, state):
        return
    _queue_or_encrypt_lock_file(mapping, env_file, keys_file, environment, context, state)


def _lock_keys_file(
    mapping: ServiceMapping,
    env_file: Path,
    context: _LockEncryptContext,
    state: _LockState,
) -> Path:
    from envdrift.encryption import EncryptionProvider

    keys_file = mapping.folder_path / (context.command.sync_config.env_keys_filename or ".env.keys")
    if context.encryption.provider == EncryptionProvider.DOTENVX and not keys_file.exists():
        console.print(
            f"  [yellow]![/yellow] {env_file} "
            f"[yellow]- warning: no .env.keys file, will generate new key[/yellow]"
        )
        state.warnings.append(f"{env_file}: no .env.keys file found, new key will be generated")
    return keys_file


def _lock_content_handled(
    encrypted: bool,
    env_file: Path,
    keys_file: Path,
    environment: str,
    content: str,
    context: _LockEncryptContext,
    state: _LockState,
) -> bool:
    if encrypted:
        return _handle_already_encrypted(env_file, keys_file, environment, content, context, state)
    return _handle_lock_provider_mismatch(env_file, context, state)


def _encrypt_one(task: _EncryptTask, context: _LockEncryptContext, state: _LockState):
    from envdrift.encryption import (
        EncryptionBackendError,
        EncryptionNotFoundError,
        EncryptionProvider,
    )

    try:
        if context.encryption.provider == EncryptionProvider.DOTENVX:
            lock = state.dotenvx_locks.get(task.env_keys_file.resolve())
            if lock:
                with lock:
                    result = context.encryption.backend.encrypt(
                        task.env_file.resolve(), **context.sops_kwargs
                    )
            else:
                result = context.encryption.backend.encrypt(
                    task.env_file.resolve(), **context.sops_kwargs
                )
        else:
            result = context.encryption.backend.encrypt(
                task.env_file.resolve(), **context.sops_kwargs
            )
        return task, result, None
    except (EncryptionNotFoundError, EncryptionBackendError) as exc:
        return task, None, exc


def _run_lock_encrypt_tasks(context: _LockEncryptContext, state: _LockState) -> None:
    from envdrift.utils import normalize_max_workers

    worker = lambda task: _encrypt_one(task, context, state)  # noqa: E731
    max_workers = normalize_max_workers(context.command.sync_config.max_workers)
    for task, result, error in context.runtime.run_tasks(state.tasks, worker, max_workers):
        if error is not None:
            console.print(f"  [red]![/red] {task.env_file} [red]- error: {error}[/red]")
            state.errors.append(f"{task.env_file}: encryption failed - {error}")
            state.error_count += 1
            continue
        if result is None or not result.success:
            message = result.message if result else "unknown error"
            console.print(f"  [red]![/red] {task.env_file} [red]- error: {message}[/red]")
            state.errors.append(f"{task.env_file}: encryption failed - {message}")
            state.error_count += 1
            continue
        context.runtime.normalize_metadata(
            task.env_file,
            task.env_keys_file,
            task.effective_environment,
            context.encryption.provider,
        )
        console.print(f"  [green]+[/green] {task.env_file} [dim]- encrypted[/dim]")
        state.encrypted += 1


def _encrypt_lock_files(
    request: LockRequest,
    command: SyncCommandContext,
    state: _LockState,
    runtime: LockRuntime,
) -> None:
    from envdrift.cli_commands import encryption_helpers
    from envdrift.encryption import EncryptionProvider

    step = "Step 2" if request.verify_vault else "Step 1"
    console.print(f"[bold cyan]{step}:[/bold cyan] Encrypting environment files...")
    console.print()
    encryption = _load_encryption_runtime(request.config_file)
    sops_kwargs = (
        encryption_helpers.build_sops_encrypt_kwargs(encryption.config)
        if encryption.provider == EncryptionProvider.SOPS
        else {}
    )
    partial_clear, _, partial_combined = runtime.load_partial_paths(request.config_file)
    context = _LockEncryptContext(
        request=request,
        command=command,
        encryption=encryption,
        sops_kwargs=sops_kwargs,
        partial_clear=partial_clear,
        partial_combined=partial_combined,
        runtime=runtime,
    )
    for mapping in command.mappings:
        _process_lock_mapping(mapping, context, state)
    if request.force and state.tasks:
        _run_lock_encrypt_tasks(context, state)


def _lock_secrets_only_environment(
    env_config: Any, state: _LockState, partial: _LockPartialState
) -> None:
    from envdrift.core.partial_encryption import PartialEncryptionError, push_secrets_only

    console.print(
        f"  [dim]=[/dim] {env_config.secrets_dir} "
        "[dim]- skipped (secrets-only, managed by 'envdrift push')[/dim]"
    )
    partial.secrets_only_skipped += 1
    try:
        stats = push_secrets_only(env_config, check=True)
    except PartialEncryptionError as exc:
        state.warnings.append(
            f"{env_config.name}: skipped secrets-only environment could not be checked - {exc}"
        )
        return
    pending = int(stats["encrypted"])
    if pending:
        partial.secrets_only_pending.append((env_config.name, pending))


def _lock_partial_secret(
    env_config: Any,
    secret_file: Path,
    request: LockRequest,
    state: _LockState,
    partial: _LockPartialState,
) -> str:
    from envdrift.core.partial_encryption import (
        PartialEncryptionError,
        encrypt_secret_file,
        is_fully_encrypted,
    )

    if not secret_file.exists():
        console.print(f"  [dim]=[/dim] {secret_file} [dim]- skipped (not found)[/dim]")
        return "missing"
    if is_fully_encrypted(secret_file):
        if not request.check_only:
            encrypt_secret_file(env_config)
        console.print(f"  [dim]=[/dim] {secret_file} [dim]- skipped (already encrypted)[/dim]")
        state.already_encrypted += 1
        return "already"
    if request.check_only:
        console.print(f"  [cyan]?[/cyan] {secret_file} [dim]- would be encrypted[/dim]")
        partial.encrypted += 1
        return "encrypted"
    try:
        encrypt_secret_file(env_config)
    except PartialEncryptionError as exc:
        console.print(f"  [red]![/red] {secret_file} [red]- error: {exc}[/red]")
        state.errors.append(f"{secret_file}: encryption failed - {exc}")
        state.error_count += 1
        return "failed"
    console.print(f"  [green]+[/green] {secret_file} [dim]- encrypted[/dim]")
    partial.encrypted += 1
    return "encrypted"


def _delete_lock_combined(
    combined_file: Path,
    encryption_state: str,
    request: LockRequest,
    state: _LockState,
    partial: _LockPartialState,
) -> None:
    if not combined_file.exists():
        return
    if encryption_state not in ("encrypted", "already"):
        reason = "encryption failed" if encryption_state == "failed" else "no .secret source"
        console.print(f"  [yellow]![/yellow] {combined_file} [dim]- kept ({reason})[/dim]")
        return
    if request.check_only:
        console.print(f"  [cyan]?[/cyan] {combined_file} [dim]- would be deleted[/dim]")
        partial.combined_deleted += 1
        return
    try:
        combined_file.unlink()
    except OSError as exc:
        console.print(f"  [red]![/red] {combined_file} [red]- delete failed: {exc}[/red]")
        state.errors.append(f"{combined_file}: delete failed - {exc}")
        state.error_count += 1
        return
    console.print(f"  [yellow]-[/yellow] {combined_file} [dim]- deleted (combined file)[/dim]")
    partial.combined_deleted += 1


def _lock_partial_environment(
    env_config: Any,
    request: LockRequest,
    state: _LockState,
    partial: _LockPartialState,
) -> None:
    if env_config.secrets_only:
        _lock_secrets_only_environment(env_config, state, partial)
        return
    secret_file = Path(env_config.secret_file)
    encryption_state = _lock_partial_secret(env_config, secret_file, request, state, partial)
    _delete_lock_combined(Path(env_config.combined_file), encryption_state, request, state, partial)


def _process_lock_partial_encryption(
    request: LockRequest,
    state: _LockState,
    partial: _LockPartialState,
    runtime: LockRuntime,
) -> None:
    from envdrift.config import ConfigLoadError, ConfigNotFoundError, load_config

    if not request.all_files:
        return
    step = "Step 3" if request.verify_vault else "Step 2"
    console.print()
    console.print(f"[bold cyan]{step}:[/bold cyan] Processing partial encryption files...")
    console.print()
    config_path = runtime.find_config_path(request.config_file)
    if not config_path:
        return
    try:
        config = load_config(config_path)
        if not config.partial_encryption.enabled:
            console.print("  [dim]Partial encryption not enabled in config[/dim]")
            return
        for env_config in config.partial_encryption.environments:
            _lock_partial_environment(env_config, request, state, partial)
    except ConfigNotFoundError:
        print_warning("Could not find partial encryption config")
    except (ConfigLoadError, OSError, AttributeError, KeyError) as exc:
        print_warning(f"Partial encryption step failed: {exc}")
        state.errors.append(f"partial encryption step failed: {exc}")
        state.error_count += 1


def _print_lock_summary(
    request: LockRequest, state: _LockState, partial: _LockPartialState
) -> None:
    lines = [
        f"{'Would encrypt' if request.check_only else 'Encrypted'}: {state.encrypted}",
        f"Already encrypted: {state.already_encrypted}",
        f"Skipped: {state.skipped}",
        f"Errors: {state.error_count}",
    ]
    if request.all_files:
        if request.check_only:
            lines.extend(
                [
                    f"Partial secrets to encrypt: {partial.encrypted}",
                    f"Combined files to delete: {partial.combined_deleted}",
                ]
            )
        else:
            lines.extend(
                [
                    f"Partial secrets encrypted: {partial.encrypted}",
                    f"Combined files deleted: {partial.combined_deleted}",
                ]
            )
        if partial.secrets_only_skipped:
            lines.append(f"Secrets-only environments skipped: {partial.secrets_only_skipped}")
    console.print()
    console.print(Panel("\n".join(lines), title="Lock Summary", expand=False))


def _print_lock_issues(state: _LockState) -> None:
    if state.warnings:
        console.print()
        console.print("[bold yellow]Warnings:[/bold yellow]")
        for warning in state.warnings:
            console.print(f"  [yellow]•[/yellow] {warning}")
    if state.errors:
        console.print()
        console.print("[bold red]Errors:[/bold red]")
        for error in state.errors:
            console.print(f"  [red]•[/red] {error}")
    if state.error_count > 0 or state.errors:
        print_warning("Some files could not be encrypted or had issues")
        raise typer.Exit(code=1)


def _finish_lock(request: LockRequest, state: _LockState, partial: _LockPartialState) -> None:
    console.print()
    if partial.secrets_only_pending:
        pending_total = sum(count for _, count in partial.secrets_only_pending)
        pending_names = ", ".join(name for name, _ in partial.secrets_only_pending)
        print_warning(
            f"Skipped secrets-only environment(s) ({pending_names}) still have "
            f"{pending_total} file(s) needing encryption. Run 'envdrift push' to encrypt them."
        )
        raise typer.Exit(code=1)
    if request.check_only:
        pending = state.encrypted + partial.encrypted
        if pending:
            rerun = "envdrift lock --all" if request.all_files else "envdrift lock"
            print_warning(
                f"Found {pending} file(s) that need encryption. Run '{rerun}' to encrypt them."
            )
            raise typer.Exit(code=1)
        print_success("Check complete! All files are already encrypted.")
        return
    print_success("Lock complete! Your environment files are encrypted and ready to commit.")


def execute_lock(request: LockRequest, runtime: LockRuntime) -> None:
    """Run the lock workflow while keeping the Typer command as an adapter."""

    context = _load_lock_context(request, runtime)
    _print_lock_header(request, context)
    state = _LockState()
    partial = _LockPartialState()
    _verify_or_sync_lock_keys(request, context, state, runtime)
    _encrypt_lock_files(request, context, state, runtime)
    _process_lock_partial_encryption(request, state, partial, runtime)
    _print_lock_summary(request, state, partial)
    _print_lock_issues(state)
    _finish_lock(request, state, partial)
