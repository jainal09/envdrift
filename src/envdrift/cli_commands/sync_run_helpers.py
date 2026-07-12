"""Execution workflow for the high-level sync command."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import typer

from envdrift.output.rich import console, print_error
from envdrift.vault.base import SecretNotFoundError, VaultError

if TYPE_CHECKING:
    from envdrift.sync.config import SyncConfig


@dataclass(frozen=True)
class SyncRequest:
    """User-selected options for one ``envdrift sync`` invocation."""

    config_file: Path | None
    provider: str | None
    vault_url: str | None
    region: str | None
    project_id: str | None
    verify: bool
    force: bool
    check_decryption: bool
    validate_schema: bool
    schema: str | None
    service_dir: Path | None
    ci: bool


@dataclass(frozen=True)
class SyncRuntime:
    """Patchable seams used by the sync command workflow."""

    load_sync: Callable[..., tuple[SyncConfig, Any, str, str | None, str | None, str | None]]
    find_binary: Callable[[str], str | None]


@dataclass(frozen=True)
class _SyncContext:
    config: SyncConfig
    vault_client: Any
    provider: str


def _require_decryption_tool(request: SyncRequest, runtime: SyncRuntime) -> None:
    if request.check_decryption and runtime.find_binary("dotenvx") is None:
        print_error("dotenvx is not installed - cannot verify decryption")
        raise typer.Exit(code=1)


def _raise_hook_errors(config_file: Path | None) -> None:
    from envdrift.integrations.hook_check import ensure_git_hook_setup

    errors = ensure_git_hook_setup(config_file=config_file)
    for error in errors:
        print_error(error)
    if errors:
        raise typer.Exit(code=1)


def _load_sync_context(request: SyncRequest, runtime: SyncRuntime) -> _SyncContext:
    sync_config, vault_client, provider, _, _, _ = runtime.load_sync(
        config_file=request.config_file,
        provider=request.provider,
        vault_url=request.vault_url,
        region=request.region,
        project_id=request.project_id,
    )
    _raise_hook_errors(request.config_file)
    return _SyncContext(config=sync_config, vault_client=vault_client, provider=provider)


def _new_sync_engine(request: SyncRequest, context: _SyncContext):
    from envdrift.sync.engine import SyncEngine, SyncMode

    mode = SyncMode(
        verify_only=request.verify,
        force_update=request.force,
        check_decryption=request.check_decryption,
        validate_schema=request.validate_schema,
        schema_path=request.schema,
        service_dir=request.service_dir,
    )

    def progress_callback(message: str) -> None:
        if not request.ci:
            console.print(f"[dim]{message}[/dim]")

    def prompt_callback(message: str) -> bool:
        if _prompting_disabled(request):
            return request.force
        response = console.input(f"{message} (y/N): ").strip().lower()
        return response in ("y", "yes")

    return SyncEngine(
        config=context.config,
        vault_client=context.vault_client,
        mode=mode,
        prompt_callback=prompt_callback,
        progress_callback=progress_callback,
    )


def _prompting_disabled(request: SyncRequest) -> bool:
    return request.force or request.verify or request.ci


def _print_sync_header(request: SyncRequest, context: _SyncContext) -> None:
    console.print()
    mode = "VERIFY" if request.verify else ("FORCE" if request.force else "Interactive")
    console.print(f"[bold]Vault Sync[/bold] - Mode: {mode}")
    console.print(
        f"[dim]Provider: {context.provider} | Services: {len(context.config.mappings)}[/dim]"
    )
    console.print()


def _run_sync_engine(engine: Any):
    from envdrift.sync.config import SyncConfigError

    try:
        return engine.sync_all()
    except (VaultError, SyncConfigError, SecretNotFoundError, OSError, UnicodeDecodeError) as exc:
        print_error(f"Sync failed: {exc}")
        raise typer.Exit(code=1) from None


def _print_sync_result(result: Any) -> None:
    from envdrift.output.rich import print_service_sync_status, print_sync_result

    for service_result in result.services:
        print_service_sync_status(service_result)
    print_sync_result(result)


def _raise_sync_result_errors(request: SyncRequest, result: Any) -> None:
    if request.ci and result.has_errors:
        raise typer.Exit(code=1)
    if request.check_decryption and result.decryption_failed > 0:
        raise typer.Exit(code=1)


def execute_sync(request: SyncRequest, runtime: SyncRuntime) -> None:
    """Run the sync workflow while keeping the Typer command as an adapter."""

    _require_decryption_tool(request, runtime)
    context = _load_sync_context(request, runtime)
    engine = _new_sync_engine(request, context)
    _print_sync_header(request, context)
    result = _run_sync_engine(engine)
    _print_sync_result(result)
    _raise_sync_result_errors(request, result)
