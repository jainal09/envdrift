"""Install commands for envdrift components.

Commands for installing optional components like the background agent.

Commands:
    envdrift install agent  - Install the envdrift background agent
"""

from __future__ import annotations

import contextlib
import os
import platform
import shutil
import stat
import subprocess  # nosec B404 - subprocess needed for agent installation
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

# Create the install CLI group
install_app = typer.Typer(
    name="install",
    help="Install optional envdrift components.",
    no_args_is_help=True,
)


# GitHub release URL templates
GITHUB_RELEASE_URL = (
    "https://github.com/jainal09/envdrift/releases/latest/download/envdrift-agent-{platform}"
)
GITHUB_CHECKSUM_URL = "https://github.com/jainal09/envdrift/releases/latest/download/checksums.txt"


def _detect_platform() -> str:
    """Detect the current platform for binary download.

    Returns:
        Platform string like 'darwin-arm64', 'linux-amd64', 'windows-amd64'
    """
    system = platform.system().lower()
    machine = platform.machine().lower()

    # Map system names
    if system == "darwin":
        os_name = "darwin"
    elif system == "linux":
        os_name = "linux"
    elif system == "windows":
        os_name = "windows"
    else:
        raise typer.BadParameter(f"Unsupported operating system: {system}")

    # Map architecture names
    if machine in ("x86_64", "amd64"):
        arch = "amd64"
    elif machine in ("arm64", "aarch64"):
        arch = "arm64"
    elif machine in ("i386", "i686", "x86"):
        # 32-bit x86 is not supported by envdrift-agent
        raise typer.BadParameter(
            f"Unsupported 32-bit x86 architecture: {machine}. "
            "envdrift-agent is only available for 64-bit platforms (amd64, arm64)."
        )
    else:
        raise typer.BadParameter(f"Unsupported architecture: {machine}")

    return f"{os_name}-{arch}"


def _get_install_path() -> Path:
    """Get the installation path for the agent binary.

    Returns:
        Path to install the binary
    """
    system = platform.system().lower()

    if system == "windows":
        # Windows: Use AppData\Local\Programs
        local_app_data = os.environ.get("LOCALAPPDATA", "")
        if local_app_data:
            install_dir = Path(local_app_data) / "Programs" / "envdrift"
        else:
            install_dir = Path.home() / "AppData" / "Local" / "Programs" / "envdrift"
        install_dir.mkdir(parents=True, exist_ok=True)
        return install_dir / "envdrift-agent.exe"
    else:
        # Unix: Prefer /usr/local/bin, fall back to ~/.local/bin
        preferred_paths = [
            Path("/usr/local/bin"),
            Path("/opt/homebrew/bin"),
            Path.home() / ".local" / "bin",
        ]

        for path in preferred_paths:
            # Only check write access on paths that actually exist
            if path.exists() and os.access(path, os.W_OK):
                return path / "envdrift-agent"

        # Create ~/.local/bin if nothing else works
        local_bin = Path.home() / ".local" / "bin"
        local_bin.mkdir(parents=True, exist_ok=True)
        return local_bin / "envdrift-agent"


def _verify_checksum(file_path: Path, platform_name: str) -> bool:
    """Verify the SHA256 checksum of a downloaded binary.

    Args:
        file_path: Path to the downloaded file
        platform_name: Platform identifier (e.g., 'darwin-arm64')

    Returns:
        True if checksum matches or verification not available, False if mismatch
    """
    import hashlib

    try:
        # Download checksums file
        with urllib.request.urlopen(GITHUB_CHECKSUM_URL, timeout=30) as response:  # nosec B310
            checksums_content = response.read().decode("utf-8")

        # Parse checksums (format: "sha256  filename")
        expected_checksum = None
        binary_name = f"envdrift-agent-{platform_name}"
        if platform_name.startswith("windows"):
            binary_name += ".exe"

        for line in checksums_content.strip().split("\n"):
            parts = line.split()
            # Use exact filename match (not substring) to prevent false positives
            if len(parts) >= 2 and parts[-1].strip() == binary_name:
                expected_checksum = parts[0].lower()
                break

        if not expected_checksum:
            # Checksums file doesn't contain this platform - skip verification
            console.print("[dim]Checksum verification: not available for this release[/dim]")
            return True

        # Calculate actual checksum
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        actual_checksum = sha256.hexdigest().lower()

        if actual_checksum != expected_checksum:
            console.print("[red]Checksum mismatch![/red]")
            console.print(f"  Expected: {expected_checksum}")
            console.print(f"  Actual:   {actual_checksum}")
            return False

        console.print("[dim]Checksum verified ✓[/dim]")
        return True

    except (urllib.error.URLError, OSError) as e:
        # Can't verify checksum - proceed with warning
        console.print(f"[yellow]Warning: Could not verify checksum: {e}[/yellow]")
        return True


def _download_binary(url: str, dest: Path, progress: Progress) -> bool:
    """Download the agent binary from GitHub releases.

    Args:
        url: Download URL
        dest: Destination path
        progress: Rich progress bar

    Returns:
        True if successful, False otherwise
    """
    task = progress.add_task("Downloading agent binary...", total=None)
    tmp_path: Path | None = None

    try:
        # Download to temp file first
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            tmp_path = Path(tmp_file.name)

            # Download with urllib (increased timeout for slow connections)
            with urllib.request.urlopen(url, timeout=120) as response:  # nosec B310
                # Read in chunks
                chunk_size = 8192
                while True:
                    chunk = response.read(chunk_size)
                    if not chunk:
                        break
                    tmp_file.write(chunk)

            progress.update(task, completed=True)

        # Move to final destination
        shutil.move(str(tmp_path), str(dest))
        tmp_path = None  # Successfully moved, don't delete

        # Make executable on Unix (owner-only for security)
        if platform.system().lower() != "windows":
            dest.chmod(dest.stat().st_mode | stat.S_IXUSR)

        return True

    except urllib.error.HTTPError as e:
        progress.update(task, description=f"[red]Download failed: HTTP {e.code}[/red]")
        console.print(f"[red]HTTP Error {e.code}: {e.msg}[/red]")
        return False
    except urllib.error.URLError as e:
        progress.update(task, description=f"[red]Download failed: {e.reason}[/red]")
        console.print(f"[red]Network Error: {e.reason}[/red]")
        return False
    except OSError as e:
        progress.update(task, description=f"[red]Installation failed: {e}[/red]")
        console.print(f"[red]File System Error: {e}[/red]")
        return False
    finally:
        # Clean up temp file if it exists
        if tmp_path is not None and tmp_path.exists():
            with contextlib.suppress(OSError):
                tmp_path.unlink()


def _run_agent_install(binary_path: Path) -> bool:
    """Run the agent's install command to set up auto-start.

    Args:
        binary_path: Path to the agent binary

    Returns:
        True if successful, False otherwise
    """
    try:
        result = subprocess.run(  # nosec B603 - trusted binary path
            [str(binary_path), "install"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        console.print("[yellow]Agent installation command timed out after 30 seconds.[/yellow]")
        return False
    except OSError as e:
        console.print(f"[yellow]Failed to execute agent install command: {e}[/yellow]")
        if not binary_path.exists():
            console.print(f"[red]Agent binary not found at: {binary_path}[/red]")
        return False


@install_app.command("agent")
def install_agent(
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            "-f",
            help="Force reinstall even if already installed",
        ),
    ] = False,
    skip_autostart: Annotated[
        bool,
        typer.Option(
            "--skip-autostart",
            help="Skip setting up auto-start on login",
        ),
    ] = False,
    skip_register: Annotated[
        bool,
        typer.Option(
            "--skip-register",
            help="Skip registering current project with agent",
        ),
    ] = False,
) -> None:
    """Install the envdrift background agent.

    Downloads the latest envdrift-agent binary from GitHub releases,
    installs it to the system path, and optionally sets up auto-start.
    """
    # Check if already installed
    existing = shutil.which("envdrift-agent")
    if existing and not force:
        console.print(f"[yellow]⚠[/yellow] Agent already installed at: {existing}")
        console.print("  Use [bold]--force[/bold] to reinstall")
        return

    # If force reinstall, warn if agent is running
    if existing and force:
        try:
            result = subprocess.run(  # nosec B603 - checking installed binary
                [existing, "status"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            # Check for explicit running status patterns (avoid matching "Running: false")
            output_lower = result.stdout.lower()
            is_running = result.returncode == 0 and (
                "status: running" in output_lower
                or "is running" in output_lower
                or (
                    "running" in output_lower
                    and "not running" not in output_lower
                    and "running: false" not in output_lower
                )
            )
            if is_running:
                console.print(
                    "[yellow]⚠ Warning:[/yellow] Agent is currently running. "
                    "Consider stopping it before reinstalling."
                )
                console.print(f"  To stop: [bold]{existing} stop[/bold]")
        except (subprocess.TimeoutExpired, OSError):
            # Unable to check status; proceed anyway
            pass

    # Detect platform
    try:
        plat = _detect_platform()
    except typer.BadParameter as e:
        console.print(f"[red]✗[/red] {e}")
        raise typer.Exit(1) from None

    console.print(f"[dim]Platform: {plat}[/dim]")

    # Get install path
    install_path = _get_install_path()
    console.print(f"[dim]Install path: {install_path}[/dim]")

    # Build download URL (add .exe for Windows)
    download_url = GITHUB_RELEASE_URL.format(platform=plat)
    if plat.startswith("windows"):
        download_url += ".exe"

    # Download and install
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        success = _download_binary(download_url, install_path, progress)

    if not success:
        console.print("\n[red]✗[/red] Failed to download agent binary")
        console.print(f"  URL: {download_url}")
        console.print("\n  You can download manually from:")
        console.print("  https://github.com/jainal09/envdrift/releases")
        raise typer.Exit(1)

    # Verify checksum
    if not _verify_checksum(install_path, plat):
        console.print("\n[red]✗[/red] Checksum verification failed - binary may be corrupted")
        console.print("  Removing downloaded file for security")
        install_path.unlink(missing_ok=True)
        raise typer.Exit(1)

    console.print(f"[green]✓[/green] Installed agent to: {install_path}")

    # Verify installation
    try:
        result = subprocess.run(  # nosec B603 - just installed binary
            [str(install_path), "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            version = result.stdout.strip()
            console.print(f"  Version: {version}")
    except (subprocess.TimeoutExpired, OSError):
        # The agent was installed successfully; failure to get the version is non-critical,
        # so we intentionally ignore errors from this optional check.
        pass

    # Set up auto-start
    if not skip_autostart:
        console.print("\n[bold]Setting up auto-start...[/bold]")
        if _run_agent_install(install_path):
            console.print("[green]✓[/green] Auto-start configured")
        else:
            console.print("[yellow]⚠[/yellow] Could not configure auto-start")
            console.print(f"  Run manually: [bold]{install_path} install[/bold]")

    # Register current project
    if not skip_register:
        from envdrift.config import find_config

        if find_config() is not None:
            console.print("\n[bold]Registering current project...[/bold]")
            # Use our own registry instead of calling the binary
            from envdrift.agent.registry import register_project

            success, message = register_project()
            if success:
                console.print(f"[green]✓[/green] {message}")
            else:
                console.print(f"[yellow]⚠[/yellow] {message}")

    # Warn if install path is not in PATH
    install_dir = install_path.parent
    path_env = os.environ.get("PATH", "")
    if str(install_dir) not in path_env and install_dir == Path.home() / ".local" / "bin":
        console.print(
            "\n[yellow]⚠ Note:[/yellow] ~/.local/bin is not in your PATH environment variable."
        )
        console.print("  Add it to your shell configuration (~/.bashrc, ~/.zshrc, etc.):")
        console.print('  [bold]export PATH="$HOME/.local/bin:$PATH"[/bold]')

    # Final instructions
    console.print("\n[bold green]✓ Installation complete![/bold green]")
    console.print("\nTo start the agent now:")
    console.print(f"  [bold]{install_path} start[/bold]")
    console.print("\nTo check agent status:")
    console.print("  [bold]envdrift agent status[/bold]")


@install_app.command("check")
def check_installation() -> None:
    """Check the installation status of envdrift components."""
    console.print("[bold]Checking envdrift installation...[/bold]\n")

    # Check Python CLI
    console.print("[bold]Python CLI:[/bold]")
    console.print(f"  ✓ Installed at: {sys.executable}")
    try:
        from envdrift._version import __version__

        console.print(f"  Version: {__version__}")
    except ImportError:
        console.print("  Version: unknown")

    # Check agent
    console.print("\n[bold]Background Agent:[/bold]")
    agent_path = shutil.which("envdrift-agent")
    if agent_path:
        console.print(f"  ✓ Installed at: {agent_path}")
        try:
            result = subprocess.run(  # nosec B603 - checking installed binary
                [agent_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                console.print(f"  Version: {result.stdout.strip()}")
        except (subprocess.TimeoutExpired, OSError):
            console.print("  Version: unknown")

        # Check if running
        try:
            result = subprocess.run(  # nosec B603 - checking installed binary
                [agent_path, "status"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and "running" in result.stdout.lower():
                console.print("  [green]⚡ Running[/green]")
            else:
                console.print("  [dim]⭕ Not running[/dim]")
        except (subprocess.TimeoutExpired, OSError):
            console.print("  [dim]Status: unknown[/dim]")
    else:
        console.print("  [yellow]✗ Not installed[/yellow]")
        console.print("  Run: [bold]envdrift install agent[/bold]")

    # Check registry
    console.print("\n[bold]Project Registry:[/bold]")
    from envdrift.agent.registry import get_registry

    registry = get_registry()
    if registry.path.exists():
        projects = registry.projects
        console.print(f"  ✓ Registry at: {registry.path}")
        console.print(f"  Registered projects: {len(projects)}")
    else:
        console.print(f"  [dim]Not created yet: {registry.path}[/dim]")


# Export the app
__all__ = ["install_app"]
