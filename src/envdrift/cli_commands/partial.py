"""CLI commands for partial encryption functionality."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.panel import Panel
from rich.text import Text

from envdrift.config import (
    EnvdriftConfig,
    load_config,
    validate_partial_encryption_environments,
)
from envdrift.core.partial_encryption import (
    PartialEncryptionError,
    SecretsOnlyPullError,
    dotenvx_key_files,
    pull_partial_encryption,
    pull_secrets_only,
    push_partial_encryption,
    push_secrets_only,
    unprotected_reason,
)
from envdrift.output.rich import console, print_error, print_success, print_warning
from envdrift.utils import ensure_gitignore_entries, unignored_paths
from envdrift.utils.text import styled_text


def _print_line(template: str, *values: object) -> None:
    """Print one line of envdrift's markup, with each value shown as it is."""
    console.print(styled_text(template, *values))


def _validate_partial_config_or_exit(config: EnvdriftConfig) -> None:
    """Validate partial-encryption environments, exiting cleanly on a bad config.

    Required-field validation is deferred to here (the consuming command) so an
    unrelated partial_encryption typo never crashes other commands (#413). Both
    push and pull route through this single helper so they share one call site.
    """
    try:
        validate_partial_encryption_environments(config.partial_encryption.environments)
    except ValueError as e:
        print_error(str(e))
        raise typer.Exit(code=1) from None


def _ensure_combined_gitignore(envs_to_process) -> None:
    paths = [
        Path(e.combined_file) for e in envs_to_process if not e.secrets_only and e.combined_file
    ]
    # Protect the PRIVATE key files dotenvx actually writes, in either mode: next
    # to each secret file, not ./.env.keys. Run from a repository subdirectory,
    # a cwd entry did not cover them and `git add .` staged the key (#961).
    # ensure_gitignore_entries writes repository-root-relative entries, so they
    # stay anchored wherever push runs.
    key_files = [key for env_config in envs_to_process for key in dotenvx_key_files(env_config)]
    added_entries = ensure_gitignore_entries([*paths, *key_files])
    if added_entries:
        # Text, not markup: the entries are printed exactly as written to .gitignore,
        # never parsed as tags (a [/x] folder raised MarkupError) or emoji codes.
        console.print(Text(f"Updated .gitignore: {', '.join(added_entries)}", style="dim"))
    # Fail closed: an entry can still be overridden (by a later `!` rule in a
    # .gitignore), and then `git add .` stages the private key. Ask git, and stop
    # before dotenvx touches a partial-encryption file. (pull --merge gets here
    # after its earlier steps, which may have decrypted mapped files.)
    exposed = unignored_paths(key_files)
    if exposed:
        print_error(
            f"git does not ignore {', '.join(exposed)}, where dotenvx keeps the private "
            "key, so `git add .` would stage it. A rule in your git ignore files "
            "re-includes it (a `!` pattern, for example). Fix that and run again: "
            "envdrift stopped before it encrypted or decrypted any partial-encryption file."
        )
        raise typer.Exit(code=1)


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
        # markup=False so the literal `[[partial_encryption.environments]]` TOML
        # header isn't parsed as Rich markup and collapsed to `[]` — a new user
        # copying the example would otherwise get invalid TOML.
        console.print(
            "[partial_encryption]\n"
            "enabled = true\n\n"
            "[[partial_encryption.environments]]\n"
            'name = "production"\n'
            'clear_file = ".env.production.clear"\n'
            'secret_file = ".env.production.secret"\n'
            'combined_file = ".env.production"',
            style="cyan",
            markup=False,
        )
        raise typer.Exit(code=1)

    _validate_partial_config_or_exit(config)

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
        # Names, paths and errors are printed as they are, never as markup.
        _print_line("[bold cyan]→[/bold cyan] {}", env_config.name)

        try:
            if env_config.secrets_only:
                stats = push_secrets_only(env_config, check=check)
                if check:
                    if stats["in_sync"]:
                        _print_line(
                            "  [green]✓[/green] {} [dim](all {} file(s) encrypted)[/dim]",
                            env_config.secrets_dir,
                            stats["already_encrypted"],
                        )
                    else:
                        out_of_sync += 1
                        _print_line(
                            "  [yellow]![/yellow] {} "
                            "[dim]({} file(s) not encrypted — run 'envdrift push')[/dim]",
                            env_config.secrets_dir,
                            stats["encrypted"],
                        )
                else:
                    _print_line(
                        "  [green]✓[/green] Encrypted {} file(s) in {} "
                        "[dim]({} already encrypted)[/dim]",
                        stats["encrypted"],
                        env_config.secrets_dir,
                        stats["already_encrypted"],
                    )
                    total_encrypted_files += stats["encrypted"]
                processed += 1
            else:
                stats = push_partial_encryption(env_config, check=check)
                if check:
                    if stats["in_sync"]:
                        _print_line(
                            "  [green]✓[/green] {} [dim]is up to date[/dim]",
                            env_config.combined_file,
                        )
                    else:
                        out_of_sync += 1
                        _print_line(
                            "  [yellow]![/yellow] {} "
                            "[dim]is out of date — run 'envdrift push'[/dim]",
                            env_config.combined_file,
                        )
                else:
                    _print_line(
                        "  [green]✓[/green] Generated {} [dim]({} clear + {} encrypted)[/dim]",
                        env_config.combined_file,
                        stats["clear_lines"],
                        stats["secret_vars"],
                    )
                    combined_files += 1
                    total_encrypted_vars += stats["secret_vars"]
                processed += 1

        except PartialEncryptionError as e:
            _print_line("  [red]✗[/red] {}", e)
            errors.append(f"{env_config.name}: {e}")
        except Exception as e:
            _print_line("  [red]✗[/red] Unexpected error: {}", e)
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
            console.print(Text(f"  • {error}"))
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
            "run 'envdrift pull-partial' to edit them.[/dim]"
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

    _validate_partial_config_or_exit(config)

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
    # Skip-worktree protection, per file this run decrypted: the notice must
    # never call the set protected while one of them is not, and a file that
    # was plaintext already does not count (#998).
    protected_count = 0
    unprotected: list[Path] = []
    errors = []

    for env_config in envs_to_process:
        # Names, paths and errors are printed as they are, never as markup.
        _print_line("[bold cyan]→[/bold cyan] {}", env_config.name)

        try:
            if env_config.secrets_only:
                result = pull_secrets_only(env_config)
                skipped_count += result["already_decrypted"]
                protected_count += result.get("protected", 0)
                unprotected.extend(result.get("unprotected", []))
                if result["decrypted"]:
                    _print_line(
                        "  [green]✓[/green] Decrypted {} file(s) in {} "
                        "[dim]({} already decrypted)[/dim]",
                        result["decrypted"],
                        env_config.secrets_dir,
                        result["already_decrypted"],
                    )
                    decrypted_count += result["decrypted"]
                else:
                    _print_line(
                        "  [dim]=[/dim] {} [dim](all {} file(s) already decrypted)[/dim]",
                        env_config.secrets_dir,
                        result["already_decrypted"],
                    )
            else:
                was_decrypted, protected = pull_partial_encryption(env_config)
                if was_decrypted:
                    _print_line("  [green]✓[/green] Decrypted {}", env_config.secret_file)
                    decrypted_count += 1
                    if protected:
                        protected_count += 1
                    else:
                        unprotected.append(Path(env_config.secret_file))
                else:
                    _print_line(
                        "  [dim]=[/dim] {} [dim](already decrypted)[/dim]", env_config.secret_file
                    )
                    skipped_count += 1

        except SecretsOnlyPullError as e:
            # The files decrypted before the failing one are plaintext on disk:
            # count them rather than report the environment as untouched (#948).
            if e.decrypted:
                _print_line(
                    "  [green]✓[/green] Decrypted {} file(s) in {} before the error",
                    e.decrypted,
                    env_config.secrets_dir,
                )
            decrypted_count += e.decrypted
            skipped_count += e.already_decrypted
            protected_count += e.protected
            unprotected.extend(e.unprotected)
            _print_line("  [red]✗[/red] {}", e)
            errors.append(f"{env_config.name}: {e}")
        except PartialEncryptionError as e:
            _print_line("  [red]✗[/red] {}", e)
            errors.append(f"{env_config.name}: {e}")
        except Exception as e:
            _print_line("  [red]✗[/red] Unexpected error: {}", e)
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

    console.print()
    if errors:
        print_warning("Some environments had errors:")
        for error in errors:
            console.print(Text(f"  • {error}"))
    else:
        print_success("Pull complete! Secret files are now decrypted for editing.")

    # The files this run decrypted are plaintext on disk even when another
    # environment failed, so the notice is shown either way (#948).
    _print_plaintext_notice(decrypted_count, protected_count, unprotected)

    if errors:
        raise typer.Exit(code=1)


def _print_plaintext_notice(
    decrypted_count: int, protected_count: int, unprotected: list[Path]
) -> None:
    """Warn that decrypted secret files are plaintext, and how they are protected.

    The yellow notice says they are protected only when every file this run
    decrypted is; otherwise the DANGER warning names the ones that are not (#998).
    """
    if _print_unprotected_warning(decrypted_count, protected_count, unprotected):
        return
    if decrypted_count > 0:
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


def _nothing_left_unprotected(
    decrypted_count: int, protected_count: int, unprotected: list[Path]
) -> bool:
    """Whether the run decrypted nothing, or protected every file it decrypted."""
    if decrypted_count == 0:
        return True
    return not unprotected and protected_count >= decrypted_count


def _print_unprotected_warning(
    decrypted_count: int, protected_count: int, unprotected: list[Path]
) -> bool:
    """Name each decrypted secret file git skip-worktree could not protect, and why.

    Shared by ``pull-partial`` and ``pull`` (#998, #999). Prints only when a file
    this run decrypted is not protected, checked both by the files the pull
    named and by the counts, so the set is never called protected by mistake.
    Decrypting succeeded, so this is a warning; the exit code stays as it is.
    Returns True when it printed.
    """
    if _nothing_left_unprotected(decrypted_count, protected_count, unprotected):
        return False
    body = Text.from_markup(
        "[bold red]🚨  SECRET FILES ARE PLAINTEXT WITH NO GIT PROTECTION[/bold red]\n\n"
        "Decryption succeeded, but [bold]git skip-worktree[/bold] "
    )
    if unprotected:
        body.append("could not be applied to these decrypted files:\n")
        for path in unprotected:
            # Plain text, never markup: escape() let an emoji code in a path such as
            # secrets/:fire:/.env.a print as an emoji, naming a file that does not exist.
            body.append(f"  • {path} ({unprotected_reason(path)})\n")
    else:
        body.append("could not be applied to the decrypted files.\n")
    if protected_count:
        body.append(f"The other {protected_count} decrypted file(s) are marked skip-worktree.\n")
    body.append_text(
        Text.from_markup(
            "\n[bold]Nothing stops a plain [bold cyan]git add .[/bold cyan] from staging "
            "them.[/bold] Do not run git add until you have re-encrypted.\n\n"
            "Re-encrypt immediately with:\n"
            "  [bold cyan]envdrift push[/bold cyan]   ← re-encrypts your secret files"
        )
    )
    console.print()
    console.print(
        Panel(
            body,
            title="[bold red]⚠  DANGER: No Git Protection Applied[/bold red]",
            border_style="red",
            expand=False,
        )
    )
    return True
