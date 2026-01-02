"""Pre-commit hook command for envdrift."""

from __future__ import annotations

from typing import Annotated

import typer

from envdrift.output.rich import console, print_error, print_success


def hook(
    install: Annotated[
        bool, typer.Option("--install", "-i", help="Install pre-commit hook")
    ] = False,
    show_config: Annotated[
        bool, typer.Option("--config", help="Show pre-commit config snippet")
    ] = False,
) -> None:
    """
    Manage the pre-commit hook integration by showing a sample config or installing hooks.

    When invoked with --config or without --install, prints a pre-commit configuration snippet for envdrift hooks.
    When invoked with --install, attempts to install the hooks using the pre-commit integration and prints success on completion.

    Parameters:
        install (bool): If True, install the pre-commit hooks into the project (--install / -i).
        show_config (bool): If True, print the sample pre-commit configuration snippet (--config).

    Raises:
        typer.Exit: If installation is requested but the pre-commit integration is unavailable.
    """
    if show_config or (not install):
        hook_config = """# Add to .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: envdrift-validate
        name: Validate env files
        entry: envdrift validate --ci
        language: system
        files: ^\\.env\\.(production|staging|development)$
        pass_filenames: true

      - id: envdrift-encryption
        name: Check env encryption
        entry: envdrift encrypt --check
        language: system
        files: ^\\.env\\.(production|staging)$
        pass_filenames: true

      # Optional: Verify encryption keys match vault (prevents key drift)
      # - id: envdrift-vault-verify
      #   name: Verify vault key can decrypt
      #   entry: envdrift decrypt --verify-vault -p azure --vault-url https://myvault.vault.azure.net --secret myapp-dotenvx-key --ci
      #   language: system
      #   files: ^\\.env\\.production$
      #   pass_filenames: true
"""
        console.print(hook_config)

        if not install:
            console.print("[dim]Use --install to add hooks to .pre-commit-config.yaml[/dim]")
            return

    if install:
        try:
            from envdrift.integrations.precommit import install_hooks

            install_hooks()
            print_success("Pre-commit hooks installed")
        except ImportError:
            print_error("Pre-commit integration not available")
            console.print("Copy the config above to .pre-commit-config.yaml manually")
            raise typer.Exit(code=1) from None
