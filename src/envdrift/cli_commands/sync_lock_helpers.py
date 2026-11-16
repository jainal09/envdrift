"""Execution phases for the high-level sync lock command."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import typer
from rich.panel import Panel
from rich.text import Text

from envdrift.env_files import resolve_mapping_env_file
from envdrift.output.rich import console, print_success, print_warning
from envdrift.utils.text import styled_text

from .sync_helpers import (
    SyncCommandContext,
    _EncryptionRuntime,
    _load_command_context,
    _load_encryption_runtime,
)
from .sync_lock_keys import _verify_or_sync_lock_keys
from .sync_lock_partial import _LockPartialState, _process_lock_partial_encryption
from .sync_lock_relabel import RelabelOutcome

if TYPE_CHECKING:
    from envdrift.encryption import EncryptionProvider
    from envdrift.sync.config import ServiceMapping, SyncConfig


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
    relabel_key: Callable[..., RelabelOutcome]
    verify_summary: Callable[[int, int], str]
    sops_missing_recipients: Callable[[Any, EncryptionProvider, dict[str, Any], str], list[str]]
    lock_factory: Callable[[], Any]


@dataclass(frozen=True)
class _EncryptTask:
    mapping: ServiceMapping
    env_file: Path
    env_keys_file: Path
    effective_environment: str


@dataclass(frozen=True)
class _EncryptTaskOutcome:
    task: _EncryptTask
    result: Any
    error: Any


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
    relabeled: int = 0


@dataclass(frozen=True)
class _LockEncryptContext:
    request: LockRequest
    command: SyncCommandContext
    encryption: _EncryptionRuntime
    sops_kwargs: dict[str, Any]
    partial_clear: set[Path]
    partial_combined: set[Path]
    runtime: LockRuntime


@dataclass(frozen=True)
class _LockFile:
    mapping: ServiceMapping
    env_file: Path
    keys_file: Path
    environment: str


@dataclass(frozen=True)
class _LockContent:
    file: _LockFile
    content: str
    encrypted: bool


def _print_lock_header(request: LockRequest, context: SyncCommandContext) -> None:
    console.print()
    profile_info = f" (profile: {request.profile})" if request.profile else ""
    mode = "CHECK" if request.check_only else ("FORCE" if request.force else "Interactive")
    all_info = " | Including partial encryption" if request.all_files else ""
    console.print(
        styled_text("[bold]Lock[/bold] - Verifying keys and encrypting env files{}", profile_info)
    )
    console.print(
        f"[dim]Provider: {context.effective_provider} | Mode: {mode} | "
        f"Services: {len(context.mappings)}{all_info}[/dim]"
    )
    console.print()


def _resolve_lock_mapping_file(
    mapping: ServiceMapping, state: _LockState
) -> tuple[Path, str] | None:
    try:
        detection = resolve_mapping_env_file(mapping)
    except ValueError as exc:
        console.print(
            styled_text(
                "  [red]![/red] {} [red]- invalid env_file: {}[/red]", mapping.folder_path, exc
            )
        )
        state.errors.append(f"{mapping.folder_path}: invalid env_file - {exc}")
        state.error_count += 1
        return None
    environment = detection.environment or mapping.effective_environment
    env_file = detection.path or mapping.folder_path / f".env.{environment}"
    if detection.status == "found" and detection.path is not None:
        return env_file, environment
    _record_missing_lock_mapping(mapping, env_file, detection.status, state)
    return None


def _record_missing_lock_mapping(
    mapping: ServiceMapping, env_file: Path, status: str, state: _LockState
) -> None:
    if status == "folder_not_found":
        console.print(
            styled_text(
                "  [red]![/red] {} [red]- error: folder does not exist or is not a directory "
                "(check folder_path in your sync config)[/red]",
                mapping.folder_path,
            )
        )
        state.errors.append(
            f"{mapping.folder_path}: folder does not exist or is not a directory "
            "(check folder_path in your sync config)"
        )
        state.error_count += 1
    elif status == "multiple_found":
        console.print(
            styled_text(
                "  [yellow]?[/yellow] {} "
                "[yellow]- skipped (multiple .env.* files, specify environment)[/yellow]",
                mapping.folder_path,
            )
        )
        state.warnings.append(f"{mapping.folder_path}: multiple .env files found")
        state.skipped += 1
    else:
        console.print(styled_text("  [dim]=[/dim] {} [dim]- skipped (not found)[/dim]", env_file))
        state.warnings.append(f"{env_file}: file not found")
        state.skipped += 1


def _skip_lock_partial_file(env_file: Path, context: _LockEncryptContext) -> bool:
    if context.request.all_files:
        return False
    resolved = env_file.resolve()
    if resolved in context.partial_combined:
        console.print(
            styled_text(
                "  [dim]=[/dim] {} "
                "[dim]- skipped (partial encryption combined file, use --all to include)[/dim]",
                env_file,
            )
        )
        return True
    if resolved in context.partial_clear:
        console.print(
            styled_text(
                "  [dim]=[/dim] {} [dim]- skipped (partial encryption clear file)[/dim]", env_file
            )
        )
        return True
    return False


def _read_lock_content(
    file: _LockFile,
    context: _LockEncryptContext,
    state: _LockState,
) -> str | None:
    from envdrift.integrations.dotenvx import DotenvxError

    try:
        context.runtime.normalize_metadata(
            file.env_file,
            file.keys_file,
            file.environment,
            context.encryption.provider,
            check_only=context.request.check_only,
        )
        return file.env_file.read_text(encoding="utf-8")
    except DotenvxError as exc:
        _record_lock_key_error(file.env_file, exc, state)
        return None
    except (OSError, ValueError) as exc:
        console.print(
            styled_text("  [red]![/red] {} [red]- error reading file: {}[/red]", file.env_file, exc)
        )
        state.errors.append(f"{file.env_file}: read failed - {exc}")
        state.error_count += 1
        return None


def _record_lock_key_error(env_file: Path, error: object, state: _LockState) -> None:
    """Record a refused key change (an exception or a message) for ``env_file``."""
    console.print(styled_text("  [red]![/red] {} [red]- error: {}[/red]", env_file, error))
    state.errors.append(f"{env_file}: {error}")
    state.error_count += 1


def _normalize_after_encrypt(
    file: _LockFile, context: _LockEncryptContext, state: _LockState
) -> bool:
    """Canonicalize a custom filename's key after encryption; False when refused."""
    from envdrift.integrations.dotenvx import DotenvxError

    try:
        context.runtime.normalize_metadata(
            file.env_file, file.keys_file, file.environment, context.encryption.provider
        )
    except (DotenvxError, OSError, ValueError) as exc:
        _record_lock_key_error(file.env_file, exc, state)
        return False
    return True


def _lock_encrypt_kwargs(context: _LockEncryptContext, keys_file: Path, environment: str):
    """Per-file encrypt options: dotenvx gets the mapping's keys file and environment.

    SOPS gets only its own recipient options. dotenvx is pointed at the
    configured ``env_keys_filename`` (#943) and told the mapping environment,
    so it encrypts with the key the folder holds instead of creating one (#938).
    """
    from envdrift.encryption import EncryptionProvider

    if context.encryption.provider == EncryptionProvider.DOTENVX:
        return {"keys_file": keys_file, "environment": environment}
    return context.sops_kwargs


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
            styled_text(
                "  [red]![/red] {} [red]- encrypted with dotenvx, but config uses {}[/red]",
                env_file,
                context.encryption.provider.value,
            )
        )
        state.errors.append(
            f"{env_file}: encrypted with dotenvx, but config uses "
            f"{context.encryption.provider.value}"
        )
        state.error_count += 1
    else:
        console.print(
            styled_text(
                "  [dim]=[/dim] {} [dim]- skipped (encrypted with {}, config uses {})[/dim]",
                env_file,
                detected.value,
                context.encryption.provider.value,
            )
        )
        state.warnings.append(
            f"{env_file}: encrypted with {detected.value}, "
            f"config uses {context.encryption.provider.value}"
        )
        state.skipped += 1
    return True


def _handle_dotenvx_relabel(
    file: _LockFile,
    context: _LockEncryptContext,
    state: _LockState,
) -> bool:
    """Give the key of an encrypted file the name its mapping expects.

    Re-labels the same key instead of re-encrypting (see
    :mod:`envdrift.cli_commands.sync_lock_relabel`), and reports success only
    once the expected key and header are confirmed on disk.
    """
    from envdrift.encryption import EncryptionProvider

    if context.encryption.provider != EncryptionProvider.DOTENVX:
        return False
    expected = f"DOTENV_PRIVATE_KEY_{file.environment.upper()}"
    outcome = context.runtime.relabel_key(
        file.env_file, file.keys_file, expected, apply=not context.request.check_only
    )
    if outcome.action == "none":
        return False
    if outcome.action == "no_key":
        console.print(
            styled_text(
                "  [yellow]![/yellow] {} [yellow]- warning: {}[/yellow]",
                file.env_file,
                outcome.message,
            )
        )
        state.warnings.append(f"{file.env_file}: {outcome.message}")
        return False
    if outcome.action == "failed":
        _record_lock_key_error(file.env_file, f"cannot re-label its key: {outcome.message}", state)
        return True
    if outcome.action == "planned":
        console.print(
            styled_text(
                "  [cyan]?[/cyan] {} [dim]- would re-key ({} -> {}) by re-labeling the key[/dim]",
                file.env_file,
                outcome.old_name,
                expected,
            )
        )
        state.warnings.append(
            f"{file.env_file}: key name mismatch, would re-label {outcome.old_name} as {expected}"
        )
        state.encrypted += 1
        return True
    if not _normalize_after_encrypt(file, context, state):
        return True
    console.print(
        styled_text(
            "  [green]+[/green] {} [dim]- key re-labeled ({} -> {}), not re-encrypted[/dim]",
            file.env_file,
            outcome.old_name,
            expected,
        )
    )
    state.warnings.append(
        f"{file.env_file}: key name mismatch, re-labeled {outcome.old_name} as {expected}"
    )
    state.relabeled += 1
    return True


def _handle_dotenvx_key_mismatch(
    file: _LockFile,
    content: str,
    context: _LockEncryptContext,
    state: _LockState,
) -> bool:
    """Fail an encrypted file that is not encrypted with the key held for it.

    dotenvx 2.x decrypts with any key in the keys file, so a file encrypted
    with a second, locally created key passed every check (#938). The held
    key must be a single key whose public key is the file's.
    """
    from envdrift.encryption import EncryptionProvider
    from envdrift.integrations.dotenvx_keys import held_key_problem

    if context.encryption.provider != EncryptionProvider.DOTENVX:
        return False
    key_name = f"DOTENV_PRIVATE_KEY_{file.environment.upper()}"
    try:
        keys_text = file.keys_file.read_bytes().decode("utf-8") if file.keys_file.exists() else None
    except (OSError, ValueError) as exc:
        _record_lock_key_error(file.env_file, f"cannot read {file.keys_file}: {exc}", state)
        return True
    problem = held_key_problem(content, keys_text, key_name)
    if problem is None:
        return False
    _record_lock_key_error(
        file.env_file,
        f"{problem} ({file.keys_file}), so the key your team holds may not decrypt it. "
        f"Restore the key it was encrypted with, or decrypt it with that key and lock again",
        state,
    )
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
        styled_text(
            "  [red]![/red] {} [red]- encrypted, but SOPS metadata is missing requested "
            "recipient(s): {}[/red]",
            env_file,
            recipients,
        )
    )
    state.errors.append(
        f"{env_file}: SOPS metadata is missing requested recipient(s): {recipients} - "
        f"re-running encrypt cannot add recipients; use `sops rotate --add-age <recipient>` "
        f"or `sops updatekeys`, or decrypt and re-encrypt"
    )
    state.error_count += 1
    return True


def _handle_already_encrypted(
    file: _LockFile,
    content: str,
    context: _LockEncryptContext,
    state: _LockState,
) -> bool:
    from envdrift.core.partial_encryption import has_plaintext_secret_value

    if has_plaintext_secret_value(file.env_file):
        state.warnings.append(f"{file.env_file}: partially encrypted, plaintext values remain")
        if context.request.check_only:
            console.print(
                styled_text(
                    "  [cyan]?[/cyan] {} [dim]- would re-encrypt (plaintext values remain)[/dim]",
                    file.env_file,
                )
            )
            state.encrypted += 1
            return True
        console.print(
            styled_text(
                "  [yellow]~[/yellow] {} "
                "[dim]- partially encrypted (plaintext values remain), re-encrypting...[/dim]",
                file.env_file,
            )
        )
        return False
    if _handle_dotenvx_relabel(file, context, state):
        return True
    if _handle_dotenvx_key_mismatch(file, content, context, state):
        return True
    if _handle_sops_recipients(file.env_file, content, context, state):
        return True
    console.print(
        styled_text("  [dim]=[/dim] {} [dim]- skipped (already encrypted)[/dim]", file.env_file)
    )
    state.already_encrypted += 1
    return True


def _encrypt_interactive_file(
    file: _LockFile,
    context: _LockEncryptContext,
    state: _LockState,
) -> None:
    from envdrift.encryption import EncryptionBackendError, EncryptionNotFoundError

    try:
        result = context.encryption.backend.encrypt(
            file.env_file.resolve(),
            **_lock_encrypt_kwargs(context, file.keys_file, file.environment),
        )
        if not result.success:
            console.print(
                styled_text(
                    "  [red]![/red] {} [red]- error: {}[/red]", file.env_file, result.message
                )
            )
            state.errors.append(f"{file.env_file}: encryption failed - {result.message}")
            state.error_count += 1
            return
        if not _normalize_after_encrypt(file, context, state):
            return
        console.print(styled_text("  [green]+[/green] {} [dim]- encrypted[/dim]", file.env_file))
        state.encrypted += 1
    except (EncryptionNotFoundError, EncryptionBackendError) as exc:
        console.print(styled_text("  [red]![/red] {} [red]- error: {}[/red]", file.env_file, exc))
        state.errors.append(f"{file.env_file}: encryption failed - {exc}")
        state.error_count += 1


def _queue_or_encrypt_lock_file(
    file: _LockFile,
    context: _LockEncryptContext,
    state: _LockState,
) -> None:
    from envdrift.cli_commands import encryption_helpers
    from envdrift.encryption import EncryptionProvider

    if context.request.check_only:
        console.print(
            styled_text("  [cyan]?[/cyan] {} [dim]- would be encrypted[/dim]", file.env_file)
        )
        state.encrypted += 1
        return
    smart = context.encryption.config.smart_encryption if context.encryption.config else False
    should_skip, reason = encryption_helpers.should_skip_reencryption(
        file.env_file, context.encryption.backend, enabled=smart
    )
    if should_skip:
        console.print(
            styled_text("  [dim]=[/dim] {} [dim]- skipped ({})[/dim]", file.env_file, reason)
        )
        state.already_encrypted += 1
        return
    if not context.request.force:
        _encrypt_or_decline(file, context, state)
        return
    state.tasks.append(
        _EncryptTask(
            mapping=file.mapping,
            env_file=file.env_file,
            env_keys_file=file.keys_file,
            effective_environment=file.environment,
        )
    )
    if context.encryption.provider == EncryptionProvider.DOTENVX:
        lock_key = file.keys_file.resolve()
        if lock_key not in state.dotenvx_locks:
            state.dotenvx_locks[lock_key] = context.runtime.lock_factory()


def _encrypt_or_decline(file: _LockFile, context: _LockEncryptContext, state: _LockState) -> None:
    # Text, not a markup string: Console.input parses a str prompt as markup and
    # emoji codes whatever the console's defaults, and the prompt names the file.
    response = console.input(Text(f"  Encrypt {file.env_file}? (y/N): ")).strip().lower()
    if response not in ("y", "yes"):
        console.print(
            styled_text("  [dim]=[/dim] {} [dim]- skipped (user declined)[/dim]", file.env_file)
        )
        state.skipped += 1
        return
    _encrypt_interactive_file(file, context, state)


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
    file = _LockFile(
        mapping=mapping,
        env_file=env_file,
        keys_file=keys_file,
        environment=environment,
    )
    content = _read_lock_content(file, context, state)
    if content is None:
        return
    encrypted = encryption_helpers.is_encrypted_content(
        context.encryption.provider, context.encryption.backend, content
    )
    lock_content = _LockContent(file=file, content=content, encrypted=encrypted)
    if _lock_content_handled(lock_content, context, state):
        return
    _queue_or_encrypt_lock_file(file, context, state)


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
            styled_text(
                "  [yellow]![/yellow] {} "
                "[yellow]- warning: no {} file, will generate new key[/yellow]",
                env_file,
                keys_file.name,
            )
        )
        state.warnings.append(
            f"{env_file}: no {keys_file.name} file found, new key will be generated"
        )
    return keys_file


def _lock_content_handled(
    content: _LockContent,
    context: _LockEncryptContext,
    state: _LockState,
) -> bool:
    if content.encrypted:
        return _handle_already_encrypted(content.file, content.content, context, state)
    return _handle_lock_provider_mismatch(content.file.env_file, context, state)


def _encrypt_one(task: _EncryptTask, context: _LockEncryptContext, state: _LockState):
    from envdrift.encryption import (
        EncryptionBackendError,
        EncryptionNotFoundError,
        EncryptionProvider,
    )

    kwargs = _lock_encrypt_kwargs(context, task.env_keys_file, task.effective_environment)
    try:
        if context.encryption.provider == EncryptionProvider.DOTENVX:
            lock = state.dotenvx_locks.get(task.env_keys_file.resolve())
            if lock:
                with lock:
                    result = context.encryption.backend.encrypt(task.env_file.resolve(), **kwargs)
            else:
                result = context.encryption.backend.encrypt(task.env_file.resolve(), **kwargs)
        else:
            result = context.encryption.backend.encrypt(task.env_file.resolve(), **kwargs)
        return task, result, None
    except (EncryptionNotFoundError, EncryptionBackendError) as exc:
        return task, None, exc


def _run_lock_encrypt_tasks(context: _LockEncryptContext, state: _LockState) -> None:
    from envdrift.utils import normalize_max_workers

    worker = lambda task: _encrypt_one(task, context, state)  # noqa: E731
    max_workers = normalize_max_workers(context.command.sync_config.max_workers)
    results = context.runtime.run_tasks(state.tasks, worker, max_workers)
    for task, result, error in results:
        _record_lock_encrypt_result(
            _EncryptTaskOutcome(task=task, result=result, error=error), context, state
        )


def _record_lock_encrypt_result(
    outcome: _EncryptTaskOutcome, context: _LockEncryptContext, state: _LockState
) -> None:
    if outcome.error is not None:
        console.print(
            styled_text(
                "  [red]![/red] {} [red]- error: {}[/red]", outcome.task.env_file, outcome.error
            )
        )
        state.errors.append(f"{outcome.task.env_file}: encryption failed - {outcome.error}")
        state.error_count += 1
        return
    if outcome.result is None or not outcome.result.success:
        message = outcome.result.message if outcome.result else "unknown error"
        console.print(
            styled_text("  [red]![/red] {} [red]- error: {}[/red]", outcome.task.env_file, message)
        )
        state.errors.append(f"{outcome.task.env_file}: encryption failed - {message}")
        state.error_count += 1
        return
    task = outcome.task
    file = _LockFile(task.mapping, task.env_file, task.env_keys_file, task.effective_environment)
    if not _normalize_after_encrypt(file, context, state):
        return
    console.print(
        styled_text("  [green]+[/green] {} [dim]- encrypted[/dim]", outcome.task.env_file)
    )
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


def _print_lock_summary(
    request: LockRequest, state: _LockState, partial: _LockPartialState
) -> None:
    lines = [
        f"{'Would encrypt' if request.check_only else 'Encrypted'}: {state.encrypted}",
        f"Already encrypted: {state.already_encrypted}",
        f"Skipped: {state.skipped}",
        f"Errors: {state.error_count}",
    ]
    if state.relabeled:
        lines.append(f"Keys re-labeled: {state.relabeled}")
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
    _print_lock_issue_group("Warnings", "yellow", state.warnings)
    _print_lock_issue_group("Errors", "red", state.errors)
    if state.error_count > 0 or state.errors:
        print_warning("Some files could not be encrypted or had issues")
        raise typer.Exit(code=1)


def _print_lock_issue_group(title: str, color: str, messages: list[str]) -> None:
    if not messages:
        return
    console.print()
    console.print(f"[bold {color}]{title}:[/bold {color}]")
    for message in messages:
        # The messages name files and quote errors: print them as they are.
        console.print(Text.assemble("  ", ("•", color), " ", message))


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

    context = _load_command_context(request, runtime)
    _print_lock_header(request, context)
    state = _LockState()
    partial = _LockPartialState()
    _verify_or_sync_lock_keys(request, context, state, runtime)
    _encrypt_lock_files(request, context, state, runtime)
    _process_lock_partial_encryption(request, state, partial, runtime)
    _print_lock_summary(request, state, partial)
    _print_lock_issues(state)
    _finish_lock(request, state, partial)
