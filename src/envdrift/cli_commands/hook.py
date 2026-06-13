"""Pre-commit hook command for envdrift."""

from __future__ import annotations

from typing import Annotated

import typer

from envdrift.output.rich import console, print_error, print_success

_MANUAL_HINT = "Copy the config from `envdrift hook --config` into .pre-commit-config.yaml manually"


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
    When invoked with --install, adds the envdrift hooks to .pre-commit-config.yaml with a
    targeted text edit that preserves existing comments and formatting, and reports whether
    anything actually changed.

    Parameters:
        install (bool): If True, install the pre-commit hooks into the project (--install / -i).
        show_config (bool): If True, print the sample pre-commit configuration snippet (--config).

    Raises:
        typer.Exit: If installation is requested but the pre-commit integration is
            unavailable, or the existing .pre-commit-config.yaml is malformed.
    """
    if show_config or (not install):
        from envdrift.integrations.precommit import get_hook_config

        console.print(get_hook_config())

        if not install:
            console.print("[dim]Use --install to add hooks to .pre-commit-config.yaml[/dim]")
            return

    if install:
        try:
            from envdrift.integrations.precommit import (
                PrecommitConfigError,
                install_hooks,
            )
        except ImportError:
            print_error("Pre-commit integration not available")
            console.print(_MANUAL_HINT)
            raise typer.Exit(code=1) from None

        try:
            changed = install_hooks()
        except ImportError:
            # PyYAML missing — install_hooks needs it to read the existing config.
            print_error("Pre-commit integration not available")
            console.print(_MANUAL_HINT)
            raise typer.Exit(code=1) from None
        except (PrecommitConfigError, OSError) as e:
            print_error(str(e))
            console.print(_MANUAL_HINT)
            raise typer.Exit(code=1) from None

        if changed:
            print_success("Pre-commit hooks installed")
        else:
            print_success("Pre-commit hooks already installed — nothing to do")
