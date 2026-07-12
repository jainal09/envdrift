"""Vault-key verification phase for the high-level sync lock command."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import typer

from envdrift.output.rich import console, print_error
from envdrift.vault.base import SecretNotFoundError, VaultError

from .sync_helpers import SyncCommandContext, _new_sync_engine

if TYPE_CHECKING:
    from envdrift.sync.config import ServiceMapping

    from .sync_lock_helpers import LockRequest, LockRuntime, _LockState


@dataclass(frozen=True)
class _LocalLockKey:
    mapping: ServiceMapping
    value: str
    environment: str


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
) -> _LocalLockKey | None:
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
        return _LocalLockKey(mapping=mapping, value=local_key, environment=environment)
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
    local: _LocalLockKey,
    context: SyncCommandContext,
    state: _LockState,
) -> None:
    from envdrift.vault.keymaterial import KeyMaterialError, extract_key_material

    try:
        context.vault_client.ensure_authenticated()
        secret = context.vault_client.get_secret(local.mapping.secret_name)
        if not _vault_secret_has_value(secret):
            console.print(
                f"  [red]✗[/red] {local.mapping.folder_path} "
                f"[red]- cannot verify: vault secret "
                f"'{local.mapping.secret_name}' is empty[/red]"
            )
            state.errors.append(
                f"{local.mapping.folder_path}: cannot verify - vault secret "
                f"'{local.mapping.secret_name}' is empty "
                f"(push the key with 'envdrift vault-push')"
            )
            state.verification_issues += 1
            return
        vault_key, vault_suffix = extract_key_material(secret, local.environment)
        if _vault_key_matches(local.value, vault_key, vault_suffix, local.environment):
            console.print(
                f"  [green]✓[/green] {local.mapping.folder_path} [dim]- keys match vault[/dim]"
            )
            return
        console.print(
            f"  [red]✗[/red] {local.mapping.folder_path} "
            f"[red]- KEY MISMATCH: local key differs from vault![/red]"
        )
        state.errors.append(
            f"{local.mapping.folder_path}: local key does not match vault "
            f"(run 'envdrift lock --sync-keys' to fix)"
        )
        state.verification_issues += 1
    except SecretNotFoundError:
        console.print(
            f"  [red]✗[/red] {local.mapping.folder_path} "
            f"[red]- cannot verify: vault secret "
            f"'{local.mapping.secret_name}' not found[/red]"
        )
        state.errors.append(
            f"{local.mapping.folder_path}: cannot verify - vault secret "
            f"'{local.mapping.secret_name}' "
            f"not found (push the key with 'envdrift vault-push')"
        )
        state.verification_issues += 1
    except KeyMaterialError as exc:
        console.print(
            f"  [red]✗[/red] {local.mapping.folder_path} [red]- KEY UNUSABLE: {exc}[/red]"
        )
        state.errors.append(f"{local.mapping.folder_path}: vault key material unusable - {exc}")
        state.verification_issues += 1
        state.unusable_keys += 1
    except VaultError as exc:
        console.print(
            f"  [red]![/red] {local.mapping.folder_path} "
            f"[red]- error: vault access failed: {exc}[/red]"
        )
        state.errors.append(f"{local.mapping.folder_path}: vault error - {exc}")
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
            _compare_lock_vault_key(local, context, state)
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
