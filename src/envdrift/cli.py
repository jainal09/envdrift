"""Command-line interface for envdrift."""

from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel

app = typer.Typer(
    name="envdrift",
    help="Prevent environment variable drift with Pydantic schema validation.",
    no_args_is_help=True,
)
console = Console()


@app.command()
def validate(
    env_file: Annotated[
        Path, typer.Argument(help="Path to .env file to validate")
    ] = Path(".env"),
    schema: Annotated[
        Optional[str],
        typer.Option("--schema", "-s", help="Dotted path to Settings class"),
    ] = None,
    ci: Annotated[
        bool, typer.Option("--ci", help="CI mode: exit with code 1 on failure")
    ] = False,
) -> None:
    """Validate an .env file against a Pydantic schema."""
    console.print(
        Panel(
            "[yellow]Coming soon in v0.1.0[/yellow]\n\n"
            "This command will validate your .env file against a Pydantic Settings schema.",
            title="envdrift validate",
        )
    )
    if ci:
        raise typer.Exit(code=1)


@app.command()
def diff(
    env1: Annotated[Path, typer.Argument(help="First .env file (e.g., .env.dev)")],
    env2: Annotated[Path, typer.Argument(help="Second .env file (e.g., .env.prod)")],
) -> None:
    """Compare two .env files and show differences."""
    console.print(
        Panel(
            "[yellow]Coming soon in v0.1.0[/yellow]\n\n"
            f"This command will compare [bold]{env1}[/bold] and [bold]{env2}[/bold]\n"
            "and show missing, extra, and differing variables.",
            title="envdrift diff",
        )
    )


@app.command()
def init(
    env_file: Annotated[
        Path, typer.Argument(help="Path to .env file to generate schema from")
    ] = Path(".env"),
    output: Annotated[
        Path, typer.Option("--output", "-o", help="Output file for Settings class")
    ] = Path("settings.py"),
) -> None:
    """Generate a Pydantic Settings class from an existing .env file."""
    console.print(
        Panel(
            "[yellow]Coming soon in v0.1.0[/yellow]\n\n"
            f"This command will generate a Pydantic Settings class\n"
            f"from [bold]{env_file}[/bold] and write it to [bold]{output}[/bold].",
            title="envdrift init",
        )
    )


@app.command()
def hook(
    install: Annotated[
        bool, typer.Option("--install", "-i", help="Install pre-commit hook")
    ] = False,
) -> None:
    """Manage pre-commit hook integration."""
    if install:
        console.print(
            Panel(
                "[yellow]Coming soon in v0.1.0[/yellow]\n\n"
                "This command will add envdrift to your .pre-commit-config.yaml",
                title="envdrift hook",
            )
        )
    else:
        console.print("Use --install to add envdrift pre-commit hook")


@app.command()
def version() -> None:
    """Show envdrift version."""
    from envdrift import __version__

    console.print(f"envdrift [bold green]{__version__}[/bold green]")


if __name__ == "__main__":
    app()
