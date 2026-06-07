"""CLI commands for partial encryption functionality."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.panel import Panel

from envdrift.config import load_config, validate_partial_encryption_environments
from envdrift.core.partial_encryption import (
    PartialEncryptionError,
    pull_partial_encryption,
    pull_secrets_only,
    push_partial_encryption,
    push_secrets_only,
)
from envdrift.output.rich import console, print_error, print_success, print_warning
from envdrift.utils import ensure_gitignore_entries

# dotenvx writes the PRIVATE decryption key here during encryption. It must never
# be committed, in either combine or secrets-only mode.
_DOTENVX_KEYS_FILE = ".env.keys"


def _ensure_combined_gitignore(envs_to_process) -> None:
    paths = [
        Path(e.combined_file) for e in envs_to_process if not e.secrets_only and e.combined_file
    ]
    # Always protect the dotenvx private-key file regardless of mode.
    paths.append(Path(_DOTENVX_KEYS_FILE))
    added_entries = ensure_gitignore_entries(paths)
    if added_entries:
        console.print(f"[dim]Updated .gitignore: {', '.join(added_entries)}[/dim]")


def push(
    env: Annotated[
        str | None,
        typer.Option("--env", "-e", help="Environment name (e.g., production, staging)"),
    ] = None,
    check: Annotated[
        bool,
        typer.Option(
            "--check",
            help="Dry run: report whether env files are up to date without "
            "encrypting or overwriting anything. Exits non-zero if a push is needed.",
        ),
    ] = False,
) -> None:
    """
    Encrypt secret files and combine with clear files (prepare for commit).

    This command:
    1. Encrypts .env.{env}.secret files using dotenvx
    2. Combines .env.{env}.clear + encrypted .secret → .env.{env}
    3. Adds warning header to generated file
    4. Adds the combined file to .gitignore (it is a runtime artifact, not committed)

    Commit only .env.{env}.clear and .env.{env}.secret — not the combined file.

    Use --check in CI or a pre-commit hook to verify everything is up to date without
    modifying anything (it never silently overwrites manual edits, and reports a
    plaintext secret file as out of date).

    Examples:
        # Push all environments
        envdrift push

        # Push specific environment
        envdrift push --env production

        # Verify env files are up to date (no changes written)
        envdrift push --check
    """
    # Load config
    try:
        config = load_config()
    except Exception as e:
        print_error(f"Failed to load configuration: {e}")
        raise typer.Exit(code=1) from None

    if not config.partial_encryption.enabled:
        print_error("Partial encryption is not enabled in configuration")
        console.print("\nTo enable partial encryption, add to your envdrift.toml:")
        console.print(
            "[cyan][[partial_encryption.environments]][/cyan]\n"
            '[cyan]name = "production"[/cyan]\n'
            '[cyan]clear_file = ".env.production.clear"[/cyan]\n'
            '[cyan]secret_file = ".env.production.secret"[/cyan]\n'
            '[cyan]combined_file = ".env.production"[/cyan]'
        )
        raise typer.Exit(code=1)

    # Required-field validation is deferred to here (the consuming command) so an
    # unrelated partial_encryption typo never crashes other commands (#413).
    try:
        validate_partial_encryption_environments(config.partial_encryption.environments)
    except ValueError as e:
        print_error(str(e))
        raise typer.Exit(code=1) from None

    # Filter environments
    envs_to_process = config.partial_encryption.environments
    if env:
        envs_to_process = [e for e in envs_to_process if e.name == env]
        if not envs_to_process:
            print_error(f"No partial encryption configuration found for environment '{env}'")
            raise typer.Exit(code=1)

    # In --check mode we never mutate anything, including .gitignore.
    if not check:
        _ensure_combined_gitignore(envs_to_process)

    console.print()
    if check:
        console.print("[bold]Push --check[/bold] - Verifying env files are up to date")
    else:
        console.print("[bold]Push[/bold] - Encrypting and combining env files")
    console.print(f"[dim]Environments: {len(envs_to_process)}[/dim]")
    console.print()

    processed = 0
    combined_files = 0
    total_encrypted_vars = 0
    total_encrypted_files = 0
    out_of_sync = 0
    errors = []

    for env_config in envs_to_process:
        console.print(f"[bold cyan]→[/bold cyan] {env_config.name}")

        try:
            if env_config.secrets_only:
                stats = push_secrets_only(env_config, check=check)
                if check:
                    if stats["in_sync"]:
                        console.print(
                            f"  [green]✓[/green] {env_config.secrets_dir} "
                            f"[dim](all {stats['already_encrypted']} file(s) encrypted)[/dim]"
                        )
                    else:
                        out_of_sync += 1
                        console.print(
                            f"  [yellow]![/yellow] {env_config.secrets_dir} "
                            f"[dim]({stats['encrypted']} file(s) not encrypted — run "
                            f"'envdrift push')[/dim]"
                        )
                else:
                    console.print(
                        f"  [green]✓[/green] Encrypted {stats['encrypted']} file(s) in "
                        f"{env_config.secrets_dir} "
                        f"[dim]({stats['already_encrypted']} already encrypted)[/dim]"
                    )
                    total_encrypted_files += stats["encrypted"]
                processed += 1
            else:
                stats = push_partial_encryption(env_config, check=check)
                if check:
                    if stats["in_sync"]:
                        console.print(
                            f"  [green]✓[/green] {env_config.combined_file} [dim]is up to date[/dim]"
                        )
                    else:
                        out_of_sync += 1
                        console.print(
                            f"  [yellow]![/yellow] {env_config.combined_file} "
                            f"[dim]is out of date — run 'envdrift push'[/dim]"
                        )
                else:
                    console.print(
                        f"  [green]✓[/green] Generated {env_config.combined_file} "
                        f"[dim]({stats['clear_lines']} clear + {stats['secret_vars']} "
                        f"encrypted)[/dim]"
                    )
                    combined_files += 1
                    total_encrypted_vars += stats["secret_vars"]
                processed += 1

        except PartialEncryptionError as e:
            console.print(f"  [red]✗[/red] {e}")
            errors.append(f"{env_config.name}: {e}")
        except Exception as e:
            console.print(f"  [red]✗[/red] Unexpected error: {e}")
            errors.append(f"{env_config.name}: {e}")

    # Summary
    console.print()
    summary_lines = [f"Processed: {processed}/{len(envs_to_process)}"]
    if check:
        summary_lines.append(f"Out of date: {out_of_sync}")
    if combined_files:
        summary_lines.append(f"Combined files: {combined_files}")
        summary_lines.append(f"Encrypted vars: {total_encrypted_vars}")
    if total_encrypted_files:
        summary_lines.append(f"Encrypted files (secrets-only): {total_encrypted_files}")
    if errors:
        summary_lines.append(f"Errors: {len(errors)}")

    title = "Push --check Summary" if check else "Push Summary"
    console.print(Panel("\n".join(summary_lines), title=title, expand=False))

    if errors:
        console.print()
        print_warning("Some environments had errors:")
        for error in errors:
            console.print(f"  • {error}")
        raise typer.Exit(code=1)

    if check:
        console.print()
        if out_of_sync:
            print_warning(
                f"{out_of_sync} environment(s) are out of date. "
                "Run 'envdrift push' to bring them up to date."
            )
            raise typer.Exit(code=1)
        print_success("All environments are up to date.")
        return

    console.print()
    print_success("Push complete! Source files are encrypted and ready to commit.")
    console.print()
    if combined_files:
        console.print(
            "[dim]Combined files are runtime artifacts (auto-gitignored). "
            "Edit source files (.clear and .secret), not the combined file.[/dim]"
        )
    if total_encrypted_files:
        console.print(
            "[dim]Secrets-only files are encrypted in place; "
            "run 'envdrift pull' to edit them.[/dim]"
        )


def pull_cmd(
    env: Annotated[
        str | None,
        typer.Option("--env", "-e", help="Environment name (e.g., production, staging)"),
    ] = None,
) -> None:
    """
    Decrypt secret files for editing (pull operation).

    This command:
    1. Decrypts .env.{env}.secret files in-place using dotenvx
    2. Makes them available for editing

    After pulling, you can edit:
    - .env.{env}.clear (non-sensitive variables)
    - .env.{env}.secret (sensitive variables, now decrypted)

    Run 'envdrift push' before committing to re-encrypt and combine.

    Examples:
        # Pull all environments
        envdrift pull-partial

        # Pull specific environment
        envdrift pull-partial --env production
    """
    # Load config
    try:
        config = load_config()
    except Exception as e:
        print_error(f"Failed to load configuration: {e}")
        raise typer.Exit(code=1) from None

    if not config.partial_encryption.enabled:
        print_error("Partial encryption is not enabled in configuration")
        raise typer.Exit(code=1)

    # Required-field validation is deferred to here (the consuming command) so an
    # unrelated partial_encryption typo never crashes other commands (#413).
    try:
        validate_partial_encryption_environments(config.partial_encryption.environments)
    except ValueError as e:
        print_error(str(e))
        raise typer.Exit(code=1) from None

    # Filter environments
    envs_to_process = config.partial_encryption.environments
    if env:
        envs_to_process = [e for e in envs_to_process if e.name == env]
        if not envs_to_process:
            print_error(f"No partial encryption configuration found for environment '{env}'")
            raise typer.Exit(code=1)

    _ensure_combined_gitignore(envs_to_process)

    console.print()
    console.print("[bold]Pull[/bold] - Decrypting secret files")
    console.print(f"[dim]Environments: {len(envs_to_process)}[/dim]")
    console.print()

    decrypted_count = 0
    skipped_count = 0
    # Tracks whether skip-worktree protection was actually applied to at least one
    # file, so the Security Notice doesn't claim protection that silently failed.
    protected_any = False
    errors = []

    for env_config in envs_to_process:
        console.print(f"[bold cyan]→[/bold cyan] {env_config.name}")

        try:
            if env_config.secrets_only:
                result = pull_secrets_only(env_config)
                skipped_count += result["already_decrypted"]
                protected_any = protected_any or result.get("protected", 0) > 0
                if result["decrypted"]:
                    console.print(
                        f"  [green]✓[/green] Decrypted {result['decrypted']} file(s) in "
                        f"{env_config.secrets_dir} "
                        f"[dim]({result['already_decrypted']} already decrypted)[/dim]"
                    )
                    decrypted_count += result["decrypted"]
                else:
                    console.print(
                        f"  [dim]=[/dim] {env_config.secrets_dir} "
                        f"[dim](all {result['already_decrypted']} file(s) already decrypted)[/dim]"
                    )
            else:
                was_decrypted, protected = pull_partial_encryption(env_config)
                protected_any = protected_any or protected
                if was_decrypted:
                    console.print(f"  [green]✓[/green] Decrypted {env_config.secret_file}")
                    decrypted_count += 1
                else:
                    console.print(
                        f"  [dim]=[/dim] {env_config.secret_file} [dim](already decrypted)[/dim]"
                    )
                    skipped_count += 1

        except PartialEncryptionError as e:
            console.print(f"  [red]✗[/red] {e}")
            errors.append(f"{env_config.name}: {e}")
        except Exception as e:
            console.print(f"  [red]✗[/red] Unexpected error: {e}")
            errors.append(f"{env_config.name}: {e}")

    # Summary
    console.print()
    summary_lines = [
        f"Decrypted: {decrypted_count}",
        f"Skipped: {skipped_count}",
    ]
    if errors:
        summary_lines.append(f"Errors: {len(errors)}")

    console.print(Panel("\n".join(summary_lines), title="Pull Summary", expand=False))

    if errors:
        console.print()
        print_warning("Some environments had errors:")
        for error in errors:
            console.print(f"  • {error}")
        raise typer.Exit(code=1)

    console.print()
    print_success("Pull complete! Secret files are now decrypted for editing.")

    if decrypted_count > 0 and protected_any:
        console.print()
        console.print(
            Panel(
                "[bold yellow]⚠  SECRET FILES ARE NOW PLAINTEXT[/bold yellow]\n\n"
                "They are marked [bold]skip-worktree[/bold] in this clone, so a plain "
                "[bold]git add .[/bold] won't stage them while decrypted.\n"
                "[dim]This is a local guardrail only — it is not shared with teammates and "
                "can be bypassed with [bold]git add -f[/bold]. Never force-add a plaintext "
                "secret file.[/dim]\n\n"
                "Edit your secret files, then run:\n"
                "  [bold cyan]envdrift push[/bold cyan]   ← re-encrypts and lifts the git protection",
                title="[bold yellow]Security Notice[/bold yellow]",
                border_style="yellow",
                expand=False,
            )
        )
    elif decrypted_count > 0:
        console.print()
        console.print(
            Panel(
                "[bold red]🚨  SECRET FILES ARE PLAINTEXT WITH NO GIT PROTECTION[/bold red]\n\n"
                "Decryption succeeded but [bold]git skip-worktree[/bold] could not be applied "
                "(e.g. detached HEAD, untracked file, or git unavailable).\n\n"
                "[bold]A plain [bold cyan]git add .[/bold cyan] WILL stage your plaintext "
                "secrets.[/bold] Do not run git add until you have re-encrypted.\n\n"
                "Re-encrypt immediately with:\n"
                "  [bold cyan]envdrift push[/bold cyan]   ← re-encrypts your secret files",
                title="[bold red]⚠  DANGER: No Git Protection Applied[/bold red]",
                border_style="red",
                expand=False,
            )
        )
