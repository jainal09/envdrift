"""CLI commands for partial encryption functionality."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.panel import Panel

from envdrift.config import load_config
from envdrift.core.partial_encryption import (
    PartialEncryptionError,
    pull_partial_encryption,
    push_partial_encryption,
)
from envdrift.output.rich import console, print_error, print_success, print_warning
from envdrift.utils import ensure_gitignore_entries


def _ensure_combined_gitignore(envs_to_process) -> None:
    combined_paths = [Path(env_config.combined_file) for env_config in envs_to_process]
    added_entries = ensure_gitignore_entries(combined_paths)
    if added_entries:
        console.print(f"[dim]Updated .gitignore: {', '.join(added_entries)}[/dim]")


def push(
    env: Annotated[
        str | None,
        typer.Option("--env", "-e", help="Environment name (e.g., production, staging)"),
    ] = None,
) -> None:
    """
    Encrypt secret files and combine with clear files (prepare for commit).

    This command:
    1. Encrypts .env.{env}.secret files using dotenvx
    2. Combines .env.{env}.clear + encrypted .secret → .env.{env}
    3. Adds warning header to generated file

    The generated .env.{env} file should be committed to git.

    Examples:
        # Push all environments
        envdrift push

        # Push specific environment
        envdrift push --env production
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

    # Filter environments
    envs_to_process = config.partial_encryption.environments
    if env:
        envs_to_process = [e for e in envs_to_process if e.name == env]
        if not envs_to_process:
            print_error(f"No partial encryption configuration found for environment '{env}'")
            raise typer.Exit(code=1)

    _ensure_combined_gitignore(envs_to_process)

    console.print()
    console.print("[bold]Push[/bold] - Encrypting and combining env files")
    console.print(f"[dim]Environments: {len(envs_to_process)}[/dim]")
    console.print()

    total_encrypted = 0
    total_combined = 0
    errors = []

    for env_config in envs_to_process:
        console.print(f"[bold cyan]→[/bold cyan] {env_config.name}")

        try:
            stats = push_partial_encryption(env_config)

            console.print(
                f"  [green]✓[/green] Generated {env_config.combined_file} "
                f"[dim]({stats['clear_lines']} clear + {stats['secret_vars']} encrypted)[/dim]"
            )

            total_combined += 1
            total_encrypted += stats["secret_vars"]

        except PartialEncryptionError as e:
            console.print(f"  [red]✗[/red] {e}")
            errors.append(f"{env_config.name}: {e}")
        except Exception as e:
            console.print(f"  [red]✗[/red] Unexpected error: {e}")
            errors.append(f"{env_config.name}: {e}")

    # Summary
    console.print()
    summary_lines = [
        f"Combined: {total_combined}/{len(envs_to_process)}",
        f"Total encrypted vars: {total_encrypted}",
    ]
    if errors:
        summary_lines.append(f"Errors: {len(errors)}")

    console.print(Panel("\n".join(summary_lines), title="Push Summary", expand=False))

    if errors:
        console.print()
        print_warning("Some environments had errors:")
        for error in errors:
            console.print(f"  • {error}")
        raise typer.Exit(code=1)

    console.print()
    print_success("Push complete! Combined files are ready to commit.")
    console.print()
    console.print(
        "[dim]Remember to edit source files (.clear and .secret), not the combined file.[/dim]"
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
    errors = []

    for env_config in envs_to_process:
        console.print(f"[bold cyan]→[/bold cyan] {env_config.name}")

        try:
            was_decrypted = pull_partial_encryption(env_config)

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
    console.print()
    console.print("[dim]Remember to run 'envdrift push' before committing.[/dim]")
