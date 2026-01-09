"""Guard command - scan for secrets and policy violations.

The guard command provides defense-in-depth by detecting:
- Unencrypted .env files (missing dotenvx/SOPS markers)
- Common secret patterns (API keys, tokens, passwords)
- High-entropy strings (potential secrets)
- Previously committed secrets (in git history, with --history)
- Password hashes (bcrypt, sha512crypt, etc.) with Kingfisher

Configuration can be set in envdrift.toml:
    [guard]
    scanners = ["native", "gitleaks"]  # or add "trufflehog", "detect-secrets", "kingfisher"
    auto_install = true
    include_history = false
    check_entropy = false
    fail_on_severity = "high"
    ignore_paths = ["tests/**", "*.test.py"]
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from envdrift.config import load_config
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
        bool | None,
        typer.Option(
            "--gitleaks/--no-gitleaks",
            help="Use gitleaks scanner (auto-installs if missing)",
        ),
    ] = None,
    trufflehog: Annotated[
        bool | None,
        typer.Option(
            "--trufflehog/--no-trufflehog",
            help="Use trufflehog scanner (auto-installs if missing)",
        ),
    ] = None,
    detect_secrets: Annotated[
        bool | None,
        typer.Option(
            "--detect-secrets/--no-detect-secrets",
            help="Use detect-secrets scanner - the 'final boss' with 27+ detectors",
        ),
    ] = None,
    kingfisher: Annotated[
        bool | None,
        typer.Option(
            "--kingfisher/--no-kingfisher",
            help="Use Kingfisher scanner - 700+ rules, password hashes, secret validation",
        ),
    ] = None,
    native_only: Annotated[
        bool,
        typer.Option(
            "--native-only",
            help="Only use native scanner (no external tools)",
        ),
    ] = False,
    # Scan options
    staged: Annotated[
        bool,
        typer.Option(
            "--staged",
            "-s",
            help="Only scan staged files (for pre-commit hooks)",
        ),
    ] = False,
    pr_base: Annotated[
        str | None,
        typer.Option(
            "--pr-base",
            help="Scan all files changed since this base branch/commit (for CI, e.g., 'origin/main')",
        ),
    ] = None,
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
    # Config file
    config_file: Annotated[
        Path | None,
        typer.Option(
            "--config",
            "-c",
            help="Path to envdrift.toml config file (auto-detected if not specified)",
        ),
    ] = None,
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
    import subprocess

    # Handle --staged flag (pre-commit mode)
    if staged:
        try:
            result = subprocess.run(
                ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                staged_files = [Path(f) for f in result.stdout.strip().split("\n") if f]
                paths = [f for f in staged_files if f.exists()]
                if not paths:
                    console.print("[green]No staged files to scan.[/green]")
                    raise typer.Exit(code=0)
                console.print(f"[dim]Scanning {len(paths)} staged file(s)...[/dim]")
            else:
                console.print("[green]No staged files to scan.[/green]")
                raise typer.Exit(code=0)
        except subprocess.TimeoutExpired as err:
            console.print("[red]Error:[/red] Git command timed out")
            raise typer.Exit(code=1) from err
        except FileNotFoundError as err:
            console.print("[red]Error:[/red] Git not found. --staged requires git.")
            raise typer.Exit(code=1) from err

    # Handle --pr-base flag (CI mode for PRs)
    elif pr_base:
        try:
            # Fetch the base branch first to ensure it's up to date
            subprocess.run(
                ["git", "fetch", "origin", pr_base.replace("origin/", "")],
                capture_output=True,
                timeout=30,
            )
            # Get all files changed between base and HEAD
            result = subprocess.run(
                ["git", "diff", "--name-only", "--diff-filter=ACMR", f"{pr_base}...HEAD"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                changed_files = [Path(f) for f in result.stdout.strip().split("\n") if f]
                paths = [f for f in changed_files if f.exists()]
                if not paths:
                    console.print("[green]No changed files to scan in this PR.[/green]")
                    raise typer.Exit(code=0)
                console.print(f"[bold]Scanning {len(paths)} file(s) changed since {pr_base}...[/bold]")
            else:
                console.print("[green]No changed files to scan in this PR.[/green]")
                raise typer.Exit(code=0)
        except subprocess.TimeoutExpired as err:
            console.print("[red]Error:[/red] Git command timed out")
            raise typer.Exit(code=1) from err
        except FileNotFoundError as err:
            console.print("[red]Error:[/red] Git not found. --pr-base requires git.")
            raise typer.Exit(code=1) from err

    # Default behavior: use provided paths or current directory
    else:
        if not paths:
            paths = [Path.cwd()]

        # Validate paths exist
        for path in paths:
            if not path.exists():
                console.print(f"[red]Error:[/red] Path not found: {path}")
                raise typer.Exit(code=1)

    # Load configuration from envdrift.toml (if available)
    file_config = load_config(config_file)
    guard_cfg = file_config.guard

    # Determine fail_on severity (CLI overrides config)
    # Note: typer doesn't distinguish between explicit arg and default,
    # so we always use CLI value (which defaults to "high")
    try:
        fail_severity = FindingSeverity(fail_on.lower())
    except ValueError as e:
        console.print(
            f"[red]Error:[/red] Invalid severity '{fail_on}'. "
            f"Valid options: critical, high, medium, low"
        )
        raise typer.Exit(code=1) from e

    # Determine which scanners to use
    # CLI flags override config file settings when provided
    use_gitleaks_final = (
        gitleaks if gitleaks is not None else "gitleaks" in guard_cfg.scanners
    )
    use_trufflehog_final = (
        trufflehog if trufflehog is not None else "trufflehog" in guard_cfg.scanners
    )
    use_detect_secrets_final = (
        detect_secrets
        if detect_secrets is not None
        else "detect-secrets" in guard_cfg.scanners
    )
    use_kingfisher_final = (
        kingfisher if kingfisher is not None else "kingfisher" in guard_cfg.scanners
    )

    if native_only:
        use_gitleaks_final = False
        use_trufflehog_final = False
        use_detect_secrets_final = False
        use_kingfisher_final = False

    # Extract allowed clear files from partial_encryption config
    # These files are intentionally unencrypted and should not be flagged
    allowed_clear_files = []
    if file_config.partial_encryption.enabled:
        for env in file_config.partial_encryption.environments:
            if env.clear_file:
                allowed_clear_files.append(env.clear_file)

    # Build configuration merging file config with CLI overrides
    config = GuardConfig(
        use_native=True,
        use_gitleaks=use_gitleaks_final,
        use_trufflehog=use_trufflehog_final,
        use_detect_secrets=use_detect_secrets_final,
        use_kingfisher=use_kingfisher_final,
        auto_install=auto_install,
        include_git_history=history or guard_cfg.include_history,
        check_entropy=entropy or guard_cfg.check_entropy,
        entropy_threshold=guard_cfg.entropy_threshold,
        ignore_paths=guard_cfg.ignore_paths,
        fail_on_severity=fail_severity,
        allowed_clear_files=allowed_clear_files,
    )

    # Create output console (suppress colors in CI mode or JSON/SARIF output)
    output_console = console
    if ci or json_output or sarif:
        output_console = Console(force_terminal=False, no_color=True)

    # Create scan engine
    engine = ScanEngine(config)

    # Show scanner info in verbose mode or when running interactively
    if not json_output and not sarif:
        scanner_names = [s.name for s in engine.scanners]
        if scanner_names:
            output_console.print(f"[bold]Running scanners:[/bold] {', '.join(scanner_names)}")
            output_console.print("[dim]Scanners run in parallel for better performance...[/dim]")
            output_console.print()
        
        if verbose:
            output_console.print("[bold]Scanner details:[/bold]")
            for info in engine.get_scanner_info():
                status = "[green]installed[/green]" if info["installed"] else "[yellow]not installed[/yellow]"
                version = f" (v{info['version']})" if info["version"] else ""
                output_console.print(f"  - {info['name']}: {status}{version}")
            output_console.print()

    # Run scan
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
