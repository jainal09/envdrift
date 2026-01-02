"""Version command for envdrift."""

from __future__ import annotations

from envdrift import __version__
from envdrift.output.rich import console


def version() -> None:
    """
    Display the installed envdrift version in the console.

    Prints the current package version using the application's styled console output.
    """
    console.print(f"envdrift [bold green]{__version__}[/bold green]")
