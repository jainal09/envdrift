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


@dataclass(frozen=True)
class _PullDecryptContext:
    request: PullRequest
    command: SyncCommandContext
    encryption: _EncryptionRuntime
    partial_clear: set[Path]
    partial_combined: set[Path]
    ephemeral_keys: dict[Path, tuple[str, str]]
    state: _PullDecryptState
    runtime: PullRuntime


@dataclass
class _PullPartialState:
    decrypted: int = 0
    merged: int = 0
    skipped: int = 0
    errors: list[str] = field(default_factory=list)


def _load_command_context(request: Any, runtime: Any) -> SyncCommandContext:
    from envdrift.integrations.hook_check import ensure_git_hook_setup
    from envdrift.sync.config import SyncConfig as SyncConfigClass

    sync_config, vault_client, effective_provider, _, _, _ = runtime.load_sync(
        config_file=request.config_file,
        provider=request.provider,
        vault_url=request.vault_url,
        region=request.region,
        project_id=request.project_id,
    )
    _raise_hook_errors(ensure_git_hook_setup(config_file=request.config_file))

    mappings = _require_mappings(sync_config, request.profile)
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


def _raise_hook_errors(errors: list[str]) -> None:
    for error in errors:
        print_error(error)
    if errors:
        raise typer.Exit(code=1)


def _require_mappings(sync_config: SyncConfig, profile: str | None) -> list[ServiceMapping]:
    mappings = sync_config.filter_by_profile(profile)
    if mappings:
        return mappings
    if profile:
        print_error(f"No mappings found for profile '{profile}'")
    else:
        print_warning("No non-profile mappings found. Use --profile to specify one.")
    raise typer.Exit(code=1)


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
    mapping: ServiceMapping, context: _PullDecryptContext
) -> tuple[Path, str] | None:
    try:
        detection = resolve_mapping_env_file(mapping)
    except ValueError as exc:
        console.print(f"  [red]![/red] {mapping.folder_path} [red]- invalid env_file: {exc}[/red]")
        context.state.errors += 1
        return None

    environment = detection.environment or mapping.effective_environment
    env_file = detection.path or mapping.folder_path / f".env.{environment}"
    if detection.status == "found" and detection.path is not None:
        return env_file, environment
    _record_missing_pull_mapping(mapping, env_file, detection.status, context.state)
    return None


def _record_missing_pull_mapping(
    mapping: ServiceMapping, env_file: Path, status: str, state: _PullDecryptState
) -> None:
    if status == "folder_not_found":
        console.print(
            f"  [red]![/red] {mapping.folder_path} "
            f"[red]- error: folder does not exist or is not a directory "
            f"(check folder_path in your sync config)[/red]"
        )
        state.errors += 1
    elif status == "multiple_found":
        console.print(
            f"  [yellow]?[/yellow] {mapping.folder_path} "
            f"[yellow]- skipped (multiple .env.* files, specify environment)[/yellow]"
        )
        state.skipped += 1
    else:
        console.print(f"  [dim]=[/dim] {env_file} [dim]- skipped (not found)[/dim]")
        state.skipped += 1


def _skip_pull_partial_file(env_file: Path, context: _PullDecryptContext) -> bool:
    resolved = env_file.resolve()
    if resolved in context.partial_combined:
        console.print(
            f"  [dim]=[/dim] {env_file} [dim]- skipped (partial encryption combined file)[/dim]"
        )
        return True
    if resolved in context.partial_clear:
        console.print(
            f"  [dim]=[/dim] {env_file} [dim]- skipped (partial encryption clear file)[/dim]"
        )
        return True
    return False


def _record_activation(
    mapping: ServiceMapping,
    env_file: Path,
    context: _PullDecryptContext,
) -> None:
    outcome = context.runtime.maybe_activate_profile(mapping, env_file, context.request.profile)
    if outcome == "activated":
        context.state.activated += 1
    elif outcome == "error":
        context.state.activation_errors += 1


def _should_queue_decryption(
    mapping: ServiceMapping,
    env_file: Path,
    environment: str,
    context: _PullDecryptContext,
) -> bool:
    from envdrift.cli_commands import encryption_helpers
    from envdrift.encryption import EncryptionProvider, detect_encryption_provider

    keys_file = mapping.folder_path / (context.command.sync_config.env_keys_filename or ".env.keys")
    try:
        context.runtime.normalize_metadata(
            env_file, keys_file, environment, context.encryption.provider
        )
        content = env_file.read_text(encoding="utf-8")
    except (OSError, ValueError) as exc:
        console.print(f"  [red]![/red] {env_file} [red]- error reading file: {exc}[/red]")
        context.state.errors += 1
        return False

    if encryption_helpers.should_attempt_decryption(
        context.encryption.provider, context.encryption.backend, content
    ):
        return True

    detected = detect_encryption_provider(env_file)
    if detected and detected != context.encryption.provider:
        if (
            detected == EncryptionProvider.DOTENVX
            and context.encryption.provider != EncryptionProvider.DOTENVX
        ):
            console.print(
                f"  [red]![/red] {env_file} [red]- encrypted with dotenvx, but config uses "
                f"{context.encryption.provider.value}[/red]"
            )
            context.state.errors += 1
            return False
        console.print(
            f"  [dim]=[/dim] {env_file} [dim]- skipped (encrypted with {detected.value}, "
            f"config uses {context.encryption.provider.value})[/dim]"
        )
        context.state.skipped += 1
        return False

    console.print(f"  [dim]=[/dim] {env_file} [dim]- skipped (not encrypted)[/dim]")
    context.state.skipped += 1
    _record_activation(mapping, env_file, context)
    return False


def _queue_pull_mapping(mapping: ServiceMapping, context: _PullDecryptContext) -> None:
    resolved = _resolve_pull_mapping_file(mapping, context)
    if resolved is None:
        return
    env_file, environment = resolved
    if _skip_pull_partial_file(env_file, context):
        context.state.skipped += 1
        return
    if not _should_queue_decryption(mapping, env_file, environment, context):
        return
    key_name, key_value = context.ephemeral_keys.get(mapping.folder_path.resolve(), (None, None))
    context.state.tasks.append(
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


def _run_pull_decrypt_tasks(context: _PullDecryptContext) -> None:
    from envdrift.utils import normalize_max_workers

    worker = lambda task: _decrypt_one(task, context.encryption.backend)  # noqa: E731
    max_workers = normalize_max_workers(context.command.sync_config.max_workers)
    results = context.runtime.run_tasks(context.state.tasks, worker, max_workers)
    for task, result, error in results:
        _record_pull_decrypt_result(task, result, error, context)


def _record_pull_decrypt_result(
    task: _DecryptTask, result: Any, error: Any, context: _PullDecryptContext
) -> None:
    if error is not None:
        console.print(f"  [red]![/red] {task.env_file} [red]- error: {error}[/red]")
        context.state.errors += 1
        return
    if result is None or not result.success:
        message = result.message if result else "unknown error"
        console.print(f"  [red]![/red] {task.env_file} [red]- error: {message}[/red]")
        context.state.errors += 1
        return
    console.print(f"  [green]+[/green] {task.env_file} [dim]- decrypted[/dim]")
    context.state.decrypted += 1
    _record_activation(task.mapping, task.env_file, context)


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
    decrypt_context = _PullDecryptContext(
        request=request,
        command=context,
        encryption=encryption,
        partial_clear=partial_clear,
        partial_combined=partial_combined,
        ephemeral_keys=ephemeral_keys,
        state=state,
        runtime=runtime,
    )
    for mapping in context.mappings:
        _queue_pull_mapping(mapping, decrypt_context)
    _run_pull_decrypt_tasks(decrypt_context)
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
