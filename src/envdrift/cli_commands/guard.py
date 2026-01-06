"""Guard command - scan for secrets and policy violations.

The guard command provides defense-in-depth by detecting:
- Unencrypted .env files (missing dotenvx/SOPS markers)
- Common secret patterns (API keys, tokens, passwords)
- High-entropy strings (potential secrets)
- Previously committed secrets (in git history, with --history)
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from envdrift.scanner.base import FindingSeverity
from envdrift.scanner.engine import GuardConfig, ScanEngine
from envdrift.scanner.output import format_json, format_rich, format_sarif

console = Console()


def guard(
    paths: Annotated[
        list[Path] | None,
        typer.Argument(
            help="Paths to scan (default: current directory)",
        ),
    ] = None,
    # Scanner selection
    gitleaks: Annotated[
        bool,
        typer.Option(
            "--gitleaks/--no-gitleaks",
            help="Use gitleaks scanner (auto-installs if missing)",
        ),
    ] = True,
    trufflehog: Annotated[
        bool,
        typer.Option(
            "--trufflehog/--no-trufflehog",
            help="Use trufflehog scanner (auto-installs if missing)",
        ),
    ] = False,
    native_only: Annotated[
        bool,
        typer.Option(
            "--native-only",
            help="Only use native scanner (no external tools)",
        ),
    ] = False,
    # Scan options
    history: Annotated[
        bool,
        typer.Option(
            "--history",
            "-H",
            help="Scan git history for previously committed secrets",
        ),
    ] = False,
    entropy: Annotated[
        bool,
        typer.Option(
            "--entropy",
            "-e",
            help="Enable entropy-based detection for random secrets",
        ),
    ] = False,
    # Installation options
    auto_install: Annotated[
        bool,
        typer.Option(
            "--auto-install/--no-auto-install",
            help="Auto-install missing scanner binaries",
        ),
    ] = True,
    # Output options
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            "-j",
            help="Output results as JSON",
        ),
    ] = False,
    sarif: Annotated[
        bool,
        typer.Option(
            "--sarif",
            help="Output results as SARIF (for GitHub/GitLab Code Scanning)",
        ),
    ] = False,
    ci: Annotated[
        bool,
        typer.Option(
            "--ci",
            help="CI mode: strict exit codes, no colors",
        ),
    ] = False,
    # Severity threshold
    fail_on: Annotated[
        str,
        typer.Option(
            "--fail-on",
            help="Minimum severity to cause non-zero exit (critical|high|medium|low)",
        ),
    ] = "high",
    # Verbosity
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Show detailed output including scanner info",
        ),
    ] = False,
) -> None:
    """Scan for unencrypted secrets and policy violations.

    This command provides defense-in-depth by detecting secrets that may have
    slipped through other guardrails (git hooks, CI checks).

    \b
    Exit codes:
      0 - No blocking findings
      1 - Critical severity findings detected
      2 - High severity findings detected
      3 - Medium severity findings detected

    \b
    Examples:
      envdrift guard                     # Basic scan with native + gitleaks
      envdrift guard --native-only       # No external dependencies
      envdrift guard --history           # Include git history
      envdrift guard --ci --fail-on high # CI mode, fail on high+ severity
      envdrift guard --json              # JSON output for automation
      envdrift guard ./src ./config      # Scan specific directories
    """
    # Default to current directory
    if not paths:
        paths = [Path.cwd()]

    # Validate paths exist
    for path in paths:
        if not path.exists():
            console.print(f"[red]Error:[/red] Path not found: {path}")
            raise typer.Exit(code=1)

    # Parse fail_on severity
    try:
        fail_severity = FindingSeverity(fail_on.lower())
    except ValueError:
        console.print(
            f"[red]Error:[/red] Invalid severity '{fail_on}'. "
            f"Valid options: critical, high, medium, low"
        )
        raise typer.Exit(code=1)

    # Build configuration
    config = GuardConfig(
        use_native=True,
        use_gitleaks=gitleaks and not native_only,
        use_trufflehog=trufflehog and not native_only,
        auto_install=auto_install,
        include_git_history=history,
        check_entropy=entropy,
        fail_on_severity=fail_severity,
    )

    # Create output console (suppress colors in CI mode or JSON/SARIF output)
    output_console = console
    if ci or json_output or sarif:
        output_console = Console(force_terminal=False, no_color=True)

    # Show scanner info in verbose mode
    if verbose and not json_output and not sarif:
        engine = ScanEngine(config)
        output_console.print("[bold]Scanners:[/bold]")
        for info in engine.get_scanner_info():
            status = "[green]installed[/green]" if info["installed"] else "[yellow]not installed[/yellow]"
            version = f" (v{info['version']})" if info["version"] else ""
            output_console.print(f"  - {info['name']}: {status}{version}")
        output_console.print()

    # Run scan
    engine = ScanEngine(config)
    result = engine.scan(paths)

    # Output results
    if sarif:
        print(format_sarif(result))
    elif json_output:
        print(format_json(result))
    else:
        format_rich(result, output_console)

    # Determine exit code
    exit_code = result.exit_code

    # In CI mode, only fail if severity >= fail_on threshold
    if ci:
        # Map severity levels to which severities they include
        threshold_severities: dict[FindingSeverity, set[FindingSeverity]] = {
            FindingSeverity.CRITICAL: {FindingSeverity.CRITICAL},
            FindingSeverity.HIGH: {FindingSeverity.CRITICAL, FindingSeverity.HIGH},
            FindingSeverity.MEDIUM: {
                FindingSeverity.CRITICAL,
                FindingSeverity.HIGH,
                FindingSeverity.MEDIUM,
            },
            FindingSeverity.LOW: {
                FindingSeverity.CRITICAL,
                FindingSeverity.HIGH,
                FindingSeverity.MEDIUM,
                FindingSeverity.LOW,
            },
        }

        blocking_severities = threshold_severities.get(
            fail_severity,
            {FindingSeverity.CRITICAL, FindingSeverity.HIGH},
        )

        has_blocking = any(
            f.severity in blocking_severities for f in result.unique_findings
        )

        if not has_blocking:
            exit_code = 0

    if exit_code != 0:
        raise typer.Exit(code=exit_code)
