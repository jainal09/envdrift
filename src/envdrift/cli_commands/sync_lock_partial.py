"""Partial-encryption phase for the high-level sync lock command."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from envdrift.output.rich import console, print_warning

if TYPE_CHECKING:
    from .sync_lock_helpers import LockRequest, LockRuntime, _LockState


@dataclass
class _LockPartialState:
    encrypted: int = 0
    combined_deleted: int = 0
    secrets_only_skipped: int = 0
    secrets_only_pending: list[tuple[str, int]] = field(default_factory=list)


@dataclass(frozen=True)
class _LockPartialContext:
    request: LockRequest
    state: _LockState
    partial: _LockPartialState
    runtime: LockRuntime


def _lock_secrets_only_environment(env_config: Any, context: _LockPartialContext) -> None:
    from envdrift.core.partial_encryption import PartialEncryptionError, push_secrets_only

    console.print(
        f"  [dim]=[/dim] {env_config.secrets_dir} "
        "[dim]- skipped (secrets-only, managed by 'envdrift push')[/dim]"
    )
    context.partial.secrets_only_skipped += 1
    try:
        stats = push_secrets_only(env_config, check=True)
    except PartialEncryptionError as exc:
        context.state.warnings.append(
            f"{env_config.name}: skipped secrets-only environment could not be checked - {exc}"
        )
        return
    pending = int(stats["encrypted"])
    if pending:
        context.partial.secrets_only_pending.append((env_config.name, pending))


def _lock_partial_secret(
    env_config: Any,
    secret_file: Path,
    context: _LockPartialContext,
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
        if not context.request.check_only:
            encrypt_secret_file(env_config)
        console.print(f"  [dim]=[/dim] {secret_file} [dim]- skipped (already encrypted)[/dim]")
        context.state.already_encrypted += 1
        return "already"
    if context.request.check_only:
        console.print(f"  [cyan]?[/cyan] {secret_file} [dim]- would be encrypted[/dim]")
        context.partial.encrypted += 1
        return "encrypted"
    try:
        encrypt_secret_file(env_config)
    except PartialEncryptionError as exc:
        console.print(f"  [red]![/red] {secret_file} [red]- error: {exc}[/red]")
        context.state.errors.append(f"{secret_file}: encryption failed - {exc}")
        context.state.error_count += 1
        return "failed"
    console.print(f"  [green]+[/green] {secret_file} [dim]- encrypted[/dim]")
    context.partial.encrypted += 1
    return "encrypted"


def _delete_lock_combined(
    combined_file: Path,
    encryption_state: str,
    context: _LockPartialContext,
) -> None:
    if not combined_file.exists():
        return
    if encryption_state not in ("encrypted", "already"):
        reason = "encryption failed" if encryption_state == "failed" else "no .secret source"
        console.print(f"  [yellow]![/yellow] {combined_file} [dim]- kept ({reason})[/dim]")
        return
    if context.request.check_only:
        console.print(f"  [cyan]?[/cyan] {combined_file} [dim]- would be deleted[/dim]")
        context.partial.combined_deleted += 1
        return
    try:
        combined_file.unlink()
    except OSError as exc:
        console.print(f"  [red]![/red] {combined_file} [red]- delete failed: {exc}[/red]")
        context.state.errors.append(f"{combined_file}: delete failed - {exc}")
        context.state.error_count += 1
        return
    console.print(f"  [yellow]-[/yellow] {combined_file} [dim]- deleted (combined file)[/dim]")
    context.partial.combined_deleted += 1


def _lock_partial_environment(env_config: Any, context: _LockPartialContext) -> None:
    if env_config.secrets_only:
        _lock_secrets_only_environment(env_config, context)
        return
    secret_file = Path(env_config.secret_file)
    encryption_state = _lock_partial_secret(env_config, secret_file, context)
    _delete_lock_combined(Path(env_config.combined_file), encryption_state, context)


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
        context = _LockPartialContext(
            request=request,
            state=state,
            partial=partial,
            runtime=runtime,
        )
        for env_config in config.partial_encryption.environments:
            _lock_partial_environment(env_config, context)
    except ConfigNotFoundError:
        print_warning("Could not find partial encryption config")
    except (ConfigLoadError, OSError, AttributeError, KeyError) as exc:
        print_warning(f"Partial encryption step failed: {exc}")
        state.errors.append(f"partial encryption step failed: {exc}")
        state.error_count += 1
