"""Agent CLI commands.

Commands for managing the envdrift-agent background daemon and project registration.

Commands:
    envdrift agent register [PATH]    - Register a project with the agent
    envdrift agent unregister [PATH]  - Unregister a project from the agent
    envdrift agent list               - List registered projects
    envdrift agent status             - Show agent status
"""

from __future__ import annotations

import shutil
import subprocess  # nosec B404 - subprocess needed for agent binary communication
import tomllib
from contextlib import nullcontext
from datetime import datetime
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from envdrift.agent.registry import (
    get_registry,
    list_projects,
    register_project,
    unregister_project,
)
from envdrift.config import find_config, load_config

console = Console()

# Create the agent CLI group
agent_app = typer.Typer(
    name="agent",
    help="Manage the envdrift background agent and project registration.",
    no_args_is_help=True,
)


def _find_agent_binary() -> Path | None:
    """Find the envdrift-agent binary."""
    # Check if in PATH
    agent_path = shutil.which("envdrift-agent")
    if agent_path:
        return Path(agent_path)

    # Check common install locations
    common_paths = [
        Path.home() / ".local" / "bin" / "envdrift-agent",
        Path("/usr/local/bin/envdrift-agent"),
        Path("/opt/homebrew/bin/envdrift-agent"),
    ]
    for path in common_paths:
        if path.exists():
            return path

    return None


def _normalize_project_path(path: str | None) -> Path:
    """Normalize a project path for CLI operations."""
    project_path = Path(path) if path else Path.cwd()

    # Expand ~ to home directory
    if str(project_path).startswith("~"):
        project_path = project_path.expanduser()

    return project_path.resolve()


def _get_agent_status() -> tuple[str, str | None]:
    """Get the agent status.

    Returns:
        Tuple of (status, version) where status is 'running', 'stopped', 'not_installed',
        or 'error'
    """
    agent_binary = _find_agent_binary()
    if not agent_binary:
        return "not_installed", None

    try:
        result = subprocess.run(  # nosec B603 - trusted binary path
            [str(agent_binary), "status"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if result.returncode == 0:
            running_state = None
            for line in result.stdout.splitlines():
                if line.strip().lower().startswith("running:"):
                    value = line.split(":", 1)[1].strip().lower()
                    if value in {"true", "false"}:
                        running_state = value == "true"
                    break

            if running_state is None:
                return "error", None

            if running_state:
                # Try to get version
                version_result = subprocess.run(  # nosec B603
                    [str(agent_binary), "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                version = version_result.stdout.strip() if version_result.returncode == 0 else None
                return "running", version

            return "stopped", None

        return "error", None
    except (subprocess.TimeoutExpired, OSError):
        return "error", None


def _format_timestamp(iso_timestamp: str) -> str:
    """Format an ISO timestamp for display."""
    try:
        dt = datetime.fromisoformat(iso_timestamp.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return iso_timestamp


@agent_app.command("register")
def register(
    path: Annotated[
        str | None,
        typer.Argument(
            help="Path to the project directory. Defaults to current directory.",
        ),
    ] = None,
    auto_enable: Annotated[
        bool,
        typer.Option(
            "--auto-enable/--no-auto-enable",
            help="Print instructions to enable [guardian] in envdrift.toml",
        ),
    ] = True,
) -> None:
    """Register a project with the envdrift background agent.

    The project will be added to ~/.envdrift/projects.json and the agent
    will start watching it for .env file changes.
    """
    project_path = _normalize_project_path(path)

    # Check if project has envdrift.toml
    config_path = find_config(project_path)
    has_config = config_path is not None

    # Register the project
    success, message = register_project(project_path)

    if success:
        console.print(f"[green]✓[/green] {message}")

        if not has_config:
            console.print("\n[yellow]⚠[/yellow] No envdrift.toml found in this project.")
            console.print("  Run [bold]envdrift init[/bold] to create one.")
        elif auto_enable:
            # Check if guardian is enabled in the config
            try:
                config = load_config(config_path)
            except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
                console.print(f"\n[red]✗[/red] Failed to load envdrift config: {config_path}")
                console.print(f"  {exc}")
            else:
                if not config.guardian.enabled:
                    console.print("\n[yellow]⚠[/yellow] Guardian is not enabled in envdrift.toml")
                    console.print("  Add this to your envdrift.toml to enable auto-encryption:\n")
                    console.print("  [dim][guardian][/dim]")
                    console.print("  [dim]enabled = true[/dim]")
    else:
        if "already registered" in message.lower():
            console.print(f"[yellow]⚠[/yellow] {message}")
        else:
            console.print(f"[red]✗[/red] {message}")
            raise typer.Exit(1)


@agent_app.command("unregister")
def unregister(
    path: Annotated[
        str | None,
        typer.Argument(
            help="Path to the project directory. Defaults to current directory.",
        ),
    ] = None,
) -> None:
    """Unregister a project from the envdrift background agent.

    The project will be removed from ~/.envdrift/projects.json and the
    agent will stop watching it.
    """
    project_path = _normalize_project_path(path)
    success, message = unregister_project(project_path)

    if success:
        console.print(f"[green]✓[/green] {message}")
    else:
        console.print(f"[yellow]⚠[/yellow] {message}")


@agent_app.command("list")
def list_registered() -> None:
    """List all projects registered with the agent."""
    projects = list_projects()

    if not projects:
        console.print("[dim]No projects registered.[/dim]")
        console.print("\nTo register a project:")
        console.print("  [bold]envdrift agent register[/bold] [PATH]")
        return

    table = Table(title="Registered Projects")
    table.add_column("Path", style="cyan")
    table.add_column("Registered", style="dim")
    table.add_column("Has Config", style="green")

    config_cache: dict[Path, bool] = {}
    status_context = (
        console.status("Checking project configs...") if len(projects) > 25 else nullcontext()
    )
    with status_context:
        for project in projects:
            # Check if project still exists and has config
            project_path = Path(project.path)
            exists = project_path.exists()
            if exists:
                if project_path not in config_cache:
                    config_cache[project_path] = find_config(project_path) is not None
                has_config = config_cache[project_path]
            else:
                has_config = False

            status = "✓" if has_config else "[yellow]✗[/yellow]"
            if not exists:
                status = "[red]✗ (missing)[/red]"

            table.add_row(
                project.path,
                _format_timestamp(project.added),
                status,
            )

    console.print(table)
    console.print(f"\n[dim]Registry: {get_registry().path}[/dim]")


@agent_app.command("status")
def status() -> None:
    """Show the status of the envdrift background agent."""
    agent_status, version = _get_agent_status()

    # Agent status
    if agent_status == "running":
        console.print("[green]⚡ Agent is running[/green]")
        if version:
            console.print(f"   Version: {version}")
    elif agent_status == "stopped":
        console.print("[red]⭕ Agent is stopped[/red]")
        console.print("   Run [bold]envdrift-agent start[/bold] to start it")
    elif agent_status == "not_installed":
        console.print("[yellow]⚠ Agent is not installed[/yellow]")
        console.print("   Run [bold]envdrift install agent[/bold] to install it")
    elif agent_status == "error":
        console.print("[yellow]⚠ Agent status check failed[/yellow]")
        console.print("   Run [bold]envdrift-agent status[/bold] for details")
    else:
        console.print("[yellow]⚠ Unable to determine agent status[/yellow]")

    # Registry info
    registry = get_registry()
    projects = registry.projects

    console.print(f"\n[bold]Registered Projects:[/bold] {len(projects)}")
    if projects:
        for project in projects[:5]:  # Show first 5
            console.print(f"   • {project.path}")
        if len(projects) > 5:
            console.print(f"   [dim]... and {len(projects) - 5} more[/dim]")

    console.print(f"\n[dim]Registry: {registry.path}[/dim]")


# Export the app
__all__ = ["agent_app"]
