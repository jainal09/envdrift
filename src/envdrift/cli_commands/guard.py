"""Guard command - scan for secrets and policy violations.

The guard command provides defense-in-depth by detecting:
- Unencrypted .env files (missing dotenvx/SOPS markers)
- Common secret patterns (API keys, tokens, passwords)
- High-entropy strings (potential secrets)
- Previously committed secrets (in git history, with --history)
- Password hashes (bcrypt, sha512crypt, etc.) with Kingfisher
- AWS credentials (with git-secrets)
- Encoded content and file analysis (with Talisman)
- Comprehensive multi-target scanning (with Trivy)
- 140+ secret types detection (with Infisical)

Configuration can be set in envdrift.toml:
    [guard]
    scanners = ["native", "gitleaks"]  # or add "trufflehog", "detect-secrets", "kingfisher",
                                       # "git-secrets", "talisman", "trivy", "infisical"
    auto_install = true
    include_history = false
    check_entropy = false
    fail_on_severity = "high"
    ignore_paths = ["tests/**", "*.test.py"]
"""

from __future__ import annotations

import time as time_module
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.live import Live
from rich.spinner import Spinner
from rich.text import Text

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
    git_secrets: Annotated[
        bool | None,
        typer.Option(
            "--git-secrets/--no-git-secrets",
            help="Use git-secrets scanner - AWS credential detection, pre-commit hooks",
        ),
    ] = None,
    talisman: Annotated[
        bool | None,
        typer.Option(
            "--talisman/--no-talisman",
            help="Use Talisman scanner - ThoughtWorks secret scanner with entropy detection",
        ),
    ] = None,
    trivy: Annotated[
        bool | None,
        typer.Option(
            "--trivy/--no-trivy",
            help="Use Trivy scanner - Aqua Security comprehensive security scanner",
        ),
    ] = None,
    infisical: Annotated[
        bool | None,
        typer.Option(
            "--infisical/--no-infisical",
            help="Use Infisical scanner - 140+ secret types with git history support",
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
    skip_clear: Annotated[
        bool | None,
        typer.Option(
            "--skip-clear/--no-skip-clear",
            help="Skip .clear files from scanning (default: scan them)",
        ),
    ] = None,
    skip_duplicate: Annotated[
        bool | None,
        typer.Option(
            "--skip-duplicate/--no-skip-duplicate",
            help="Show only unique secrets by value (ignore scanner source and location)",
        ),
    ] = None,
    skip_encrypted: Annotated[
        bool | None,
        typer.Option(
            "--skip-encrypted/--no-skip-encrypted",
            help="Skip findings from encrypted files (dotenvx/SOPS markers detected)",
        ),
    ] = None,
    skip_gitignored: Annotated[
        bool | None,
        typer.Option(
            "--skip-gitignored/--no-skip-gitignored",
            help="Skip findings from files in .gitignore (uses git check-ignore)",
        ),
    ] = None,
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
        str | None,
        typer.Option(
            "--fail-on",
            help="Minimum severity to cause non-zero exit (critical|high|medium|low)",
        ),
    ] = None,
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
    import subprocess  # nosec B404

    # Handle --staged flag (pre-commit mode)
    if staged:
        try:
            result = subprocess.run(  # nosec B603, B607
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
            base_ref = pr_base.replace("origin/", "")
            if not base_ref:
                base_ref = pr_base
            fetch_result = subprocess.run(  # nosec B603, B607
                ["git", "fetch", "origin", base_ref],
                capture_output=True,
                timeout=30,
            )
            if fetch_result.returncode != 0 and verbose:
                console.print(
                    f"[yellow]Warning:[/yellow] Could not fetch {pr_base}, using local refs"
                )
            # Get all files changed between base and HEAD
            result = subprocess.run(  # nosec B603, B607
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
                console.print(
                    f"[bold]Scanning {len(paths)} file(s) changed since {pr_base}...[/bold]"
                )
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
    fail_on_value = fail_on or guard_cfg.fail_on_severity or "high"
    try:
        fail_severity = FindingSeverity(fail_on_value.lower())
    except ValueError as e:
        console.print(
            f"[red]Error:[/red] Invalid severity '{fail_on_value}'. "
            f"Valid options: critical, high, medium, low"
        )
        raise typer.Exit(code=1) from e

    # Determine which scanners to use
    # CLI flags override config file settings when provided
    use_gitleaks_final = gitleaks if gitleaks is not None else "gitleaks" in guard_cfg.scanners
    use_trufflehog_final = (
        trufflehog if trufflehog is not None else "trufflehog" in guard_cfg.scanners
    )
    use_detect_secrets_final = (
        detect_secrets if detect_secrets is not None else "detect-secrets" in guard_cfg.scanners
    )
    use_kingfisher_final = (
        kingfisher if kingfisher is not None else "kingfisher" in guard_cfg.scanners
    )
    use_git_secrets_final = (
        git_secrets if git_secrets is not None else "git-secrets" in guard_cfg.scanners
    )
    use_talisman_final = talisman if talisman is not None else "talisman" in guard_cfg.scanners
    use_trivy_final = trivy if trivy is not None else "trivy" in guard_cfg.scanners
    use_infisical_final = infisical if infisical is not None else "infisical" in guard_cfg.scanners

    if native_only:
        use_gitleaks_final = False
        use_trufflehog_final = False
        use_detect_secrets_final = False
        use_kingfisher_final = False
        use_git_secrets_final = False
        use_talisman_final = False
        use_trivy_final = False
        use_infisical_final = False

    # Extract allowed clear files from partial_encryption config
    # These files are intentionally unencrypted and should not be flagged
    allowed_clear_files = []
    combined_files = []
    if file_config.partial_encryption.enabled:
        for env in file_config.partial_encryption.environments:
            if env.clear_file:
                allowed_clear_files.append(env.clear_file)
            if env.combined_file:
                combined_files.append(env.combined_file)

    # Determine skip_clear_files (CLI overrides config)
    skip_clear_final = skip_clear if skip_clear is not None else guard_cfg.skip_clear_files

    # Determine skip_duplicate (CLI overrides config)
    skip_duplicate_final = (
        skip_duplicate if skip_duplicate is not None else guard_cfg.skip_duplicate
    )

    # Determine skip_encrypted_files (CLI overrides config)
    skip_encrypted_final = (
        skip_encrypted if skip_encrypted is not None else guard_cfg.skip_encrypted_files
    )

    # Determine skip_gitignored (CLI overrides config)
    skip_gitignored_final = (
        skip_gitignored if skip_gitignored is not None else guard_cfg.skip_gitignored
    )

    # Build configuration merging file config with CLI overrides
    config = GuardConfig(
        use_native=True,
        use_gitleaks=use_gitleaks_final,
        use_trufflehog=use_trufflehog_final,
        use_detect_secrets=use_detect_secrets_final,
        use_kingfisher=use_kingfisher_final,
        use_git_secrets=use_git_secrets_final,
        use_talisman=use_talisman_final,
        use_trivy=use_trivy_final,
        use_infisical=use_infisical_final,
        auto_install=auto_install,
        include_git_history=history or guard_cfg.include_history,
        check_entropy=entropy or guard_cfg.check_entropy,
        entropy_threshold=guard_cfg.entropy_threshold,
        skip_clear_files=skip_clear_final,
        skip_encrypted_files=skip_encrypted_final,
        skip_duplicate=skip_duplicate_final,
        skip_gitignored=skip_gitignored_final,
        ignore_paths=guard_cfg.ignore_paths,
        ignore_rules=guard_cfg.ignore_rules,
        fail_on_severity=fail_severity,
        allowed_clear_files=allowed_clear_files,
        combined_files=combined_files,
    )

    # Create output console (suppress colors in CI mode or JSON/SARIF output)
    output_console = console
    if ci or json_output or sarif:
        output_console = Console(force_terminal=False, no_color=True)

    # Create scan engine
    engine = ScanEngine(config)

    # Check combined files security (should be in .gitignore)
    # Only check if partial_encryption is enabled and not in JSON/SARIF mode
    if combined_files and not json_output and not sarif:
        security_warnings = engine.check_combined_files_security()
        for warning in security_warnings:
            output_console.print(f"[bold red]{warning}[/bold red]")
        if security_warnings:
            output_console.print()

    # Show scanner info in verbose mode or when running interactively
    scanner_names = [s.name for s in engine.scanners]
    show_progress = not json_output and not sarif and scanner_names

    if show_progress:
        output_console.print(f"[bold]Running scanners:[/bold] {', '.join(scanner_names)}")
        output_console.print("[dim]Scanners run in parallel for better performance...[/dim]")

        if verbose:
            output_console.print()
            output_console.print("[bold]Scanner details:[/bold]")
            for info in engine.get_scanner_info():
                status = (
                    "[green]installed[/green]"
                    if info["installed"]
                    else "[yellow]not installed[/yellow]"
                )
                version = f" (v{info['version']})" if info["version"] else ""
                output_console.print(f"  - {info['name']}: {status}{version}")

    # Track completed scanners for progress display
    completed_scanners: dict[str, float] = {}  # name -> duration in seconds
    total_scanners = len(scanner_names)
    scan_start_time = time_module.time()

    def format_duration(seconds: float) -> str:
        """Format duration as human readable string."""
        if seconds < 60:
            return f"{seconds:.1f}s"
        minutes = int(seconds // 60)
        secs = seconds % 60
        return f"{minutes}m {secs:.0f}s"

    def make_progress_text() -> Text:
        """Build progress display text."""
        text = Text()
        done_count = len(completed_scanners)
        elapsed = time_module.time() - scan_start_time
        text.append(f"Scanning {done_count}/{total_scanners} complete ", style="bold")
        text.append(f"({format_duration(elapsed)})\n\n", style="dim")
        for name in scanner_names:
            if name in completed_scanners:
                duration = completed_scanners[name]
                text.append("  [*] ", style="green bold")
                text.append(f"{name:<15}", style="green")
                text.append(f" done in {format_duration(duration)}\n", style="green")
            else:
                text.append("  [ ] ", style="yellow")
                text.append(f"{name:<15}", style="yellow")
                text.append(" running...\n", style="yellow dim")
        return text

    def on_scanner_complete(
        name: str,
        completed: int,
        total: int,
        result: object | None = None,
    ) -> None:
        """Callback when a scanner completes."""
        elapsed = time_module.time() - scan_start_time
        duration = elapsed
        # Prefer scanner-reported duration if available
        if result is not None and hasattr(result, "duration_ms"):
            try:
                duration_ms = float(getattr(result, "duration_ms", 0))
                if duration_ms > 0:
                    duration = duration_ms / 1000.0
            except (TypeError, ValueError):
                pass
        completed_scanners[name] = duration
        if show_progress and live:
            live.update(Spinner("dots", text=make_progress_text()))

    # Run scan with progress indicator
    if show_progress:
        output_console.print()
        live = Live(
            Spinner("dots", text=make_progress_text()),
            console=output_console,
            refresh_per_second=10,
        )
        with live:
            result = engine.scan(paths, on_scanner_complete=on_scanner_complete)
        output_console.print()
    else:
        live = None
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

        has_blocking = any(f.severity in blocking_severities for f in result.unique_findings)

        if not has_blocking:
            exit_code = 0

    if exit_code != 0:
        raise typer.Exit(code=exit_code)
