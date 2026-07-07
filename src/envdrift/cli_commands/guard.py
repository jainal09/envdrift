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

import dataclasses
import json
import os
import sys
import tempfile
import time as time_module
import tomllib
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.live import Live
from rich.markup import escape
from rich.spinner import Spinner
from rich.text import Text

from envdrift.config import ConfigNotFoundError, EnvdriftConfig, load_config
from envdrift.env_files import resolve_custom_env_file
from envdrift.scanner.base import AggregatedScanResult, FindingSeverity, ScanFinding
from envdrift.scanner.engine import GuardConfig, ScanEngine
from envdrift.scanner.output import (
    format_json,
    format_rich,
    format_sarif,
    format_sarif_error,
)

console = Console()

# Early-exit prose for the git-discovery branches; emitted only in human mode
# (machine modes get an empty-findings doc via _emit_empty_or_prose).
_NO_STAGED = "[green]No staged files to scan.[/green]"
_NO_PR_CHANGES = "[green]No changed files to scan in this PR.[/green]"


def _empty_scan_result() -> AggregatedScanResult:
    """Build an empty (no-findings) scan result for machine-readable output.

    Used by the early-exit branches (nothing staged / no PR diff) so that
    ``--json``/``--sarif`` consumers always receive a valid empty-findings
    document on stdout instead of human-readable prose (#413).
    """
    return AggregatedScanResult(
        results=[],
        total_findings=0,
        unique_findings=[],
        scanners_used=[],
        total_duration_ms=0,
    )


def _emit_empty_or_prose(json_output: bool, sarif: bool, prose: str) -> None:
    """Emit an empty-findings document (json/sarif) or human-readable prose.

    Keeps machine-readable stdout valid on the early-exit branches (#413): a
    consumer that always parses guard stdout receives a real empty-findings
    JSON/SARIF document instead of a sentence like ``No staged files to scan.``.
    """
    if sarif:
        print(format_sarif(_empty_scan_result()))
    elif json_output:
        print(format_json(_empty_scan_result()))
    else:
        console.print(prose)


def _load_guard_config(config_file: Path | None, json_output: bool, sarif: bool) -> EnvdriftConfig:
    """Load envdrift config, converting load failures into a clean CLI exit.

    ``load_config`` can raise ``ConfigNotFoundError`` (explicit --config that
    doesn't exist), ``tomllib.TOMLDecodeError`` (malformed TOML), or
    ``ValueError`` (eager config validation). All three are turned into a
    structured error document (json/sarif) or error prose plus ``Exit(1)`` so a
    Rich traceback never contaminates machine output (#413). Mirrors sync.py /
    encryption_helpers.py.
    """
    try:
        return load_config(config_file)
    except (ConfigNotFoundError, tomllib.TOMLDecodeError, ValueError) as exc:
        _emit_error(json_output, sarif, f"Could not load config: {exc}")
        raise typer.Exit(code=1) from None


def _emit_error(json_output: bool, sarif: bool, message: str) -> None:
    """Emit a structured error (json/sarif) or human-readable error prose.

    In ``--sarif`` mode a schema-valid SARIF run with ``executionSuccessful:
    false`` is written so a Code Scanning consumer that always expects SARIF
    still parses cleanly (mirrors the ``format_sarif`` success path). In
    ``--json`` mode a clean ``{"error": ...}`` object is written instead. Either
    way stdout never receives a Rich traceback or a bare ``Error:`` sentence
    (#413), and the literal ``message`` is emitted via stdlib ``json``/``print``
    so no ANSI escapes leak into machine output.
    """
    if sarif:
        print(format_sarif_error(message))
    elif json_output:
        print(json.dumps({"error": message}, indent=2))
    else:
        # Escape the dynamic message so bracketed literals (e.g. TOML section
        # names like ``[vault.sync]``) survive Rich markup instead of being
        # interpreted as console tags and silently dropped (mirrors
        # output/rich.py print_error). The static label stays markup.
        console.print(f"[red]Error:[/red] {escape(message)}")


def _machine_mode(json_output: bool, sarif: bool) -> bool:
    """Whether machine-readable output (``--json`` / ``--sarif``) is active.

    Centralizes the ``json_output or sarif`` predicate so the call sites that
    must suppress human-readable progress/status prose (to keep stdout valid
    JSON/SARIF, #413) read as a single flat condition instead of repeating the
    two-term boolean inline.
    """
    return json_output or sarif


def _emit_progress(json_output: bool, sarif: bool, message: str) -> None:
    """Print a human-mode progress/status line, suppressed in machine modes.

    A no-op under ``--json``/``--sarif`` so machine-readable stdout never gains
    a stray prose line (#413); otherwise the Rich-styled ``message`` is printed.
    Keeps the discovery branches flat (no inline ``not json_output and not
    sarif`` guard at each progress print).
    """
    if not _machine_mode(json_output, sarif):
        console.print(message)


def _warn_stderr(message: str) -> None:
    """Print a warning on stderr (visible in every output mode).

    Warnings must reach the user even under ``--json``/``--sarif``, where prose
    on stdout would corrupt the machine-readable document — stderr keeps them
    visible in CI logs without contaminating stdout (#476).
    """
    print(f"Warning: {message}", file=sys.stderr)


def _materialize_staged_index(
    staged_files: list[str], repo_root: Path
) -> tuple[tempfile.TemporaryDirectory, list[Path], dict[Path, Path]]:
    """Mirror the staged *index blobs* of ``staged_files`` into a temp dir.

    ``--staged`` must scan what is about to be committed — the blob staged in
    the git index — not the current working-tree copy: a secret staged and then
    edited away (or deleted) in the working tree would otherwise pass with exit
    0 while the commit still ships it (#476). Each repo-root-relative staged
    path (the form ``git diff --cached --name-only`` emits) is read with ``git
    show :<path>`` and written under the mirror with the same relative layout,
    so filename/suffix rules and path-pattern ignores keep matching.

    Returns the ``TemporaryDirectory`` handle (caller cleans up), the mirror
    paths to scan, and a map of resolved mirror path -> display path
    (cwd-relative, like the other collection branches) used to rewrite finding
    locations after the scan.
    """
    import subprocess  # nosec B404

    tmpdir = tempfile.TemporaryDirectory(prefix="envdrift-staged-", ignore_cleanup_errors=True)
    mirror_root = Path(tmpdir.name)
    scan_paths: list[Path] = []
    display_paths: dict[Path, Path] = {}
    cwd = Path.cwd()

    try:
        for rel in staged_files:
            # ``:<path>`` reads the staged blob; <path> is repo-root-relative
            # regardless of cwd, but run from the repo root for unambiguity.
            show = subprocess.run(  # nosec B603, B607
                ["git", "show", f":{rel}"],
                capture_output=True,
                timeout=30,
                cwd=str(repo_root),
            )
            if show.returncode != 0:
                # E.g. a submodule (gitlink) entry: there is no blob to
                # content-scan. Skip it loudly, never silently.
                detail = show.stderr.decode("utf-8", errors="replace").strip()
                _warn_stderr(
                    f"skipping staged entry '{rel}' — could not read its index blob"
                    + (f" ({detail})" if detail else "")
                )
                continue
            dest = mirror_root / Path(rel)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(show.stdout)
            scan_paths.append(dest)
            display_paths[dest.resolve()] = Path(os.path.relpath(repo_root / rel, cwd))

        if scan_paths:
            _git_index_mirror(mirror_root)
    except BaseException:
        # The caller can only clean up a *returned* handle: if we raise
        # mid-mirror (disk full, git timeout, ...) the temp dir holding staged
        # secret content must not linger until a GC finalizer runs.
        tmpdir.cleanup()
        raise

    return tmpdir, scan_paths, display_paths


def _git_index_mirror(mirror_root: Path) -> None:
    """Stage every mirrored file in a throwaway git repo at ``mirror_root``.

    In the real repository every collected file IS staged, and rules that ask
    git about a file's state (``is_file_tracked`` behind committed-private-key)
    must keep answering "staged" for the mirror copies (#476). Hook-injected
    git env (GIT_DIR/GIT_INDEX_FILE/...) is stripped so the mirror can never
    touch the real repository's index. Failure only degrades those git-state
    rules, so it warns instead of aborting the scan.
    """
    import subprocess  # nosec B404

    env = os.environ.copy()
    for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR"):
        env.pop(key, None)
    # An injected global/system git config (core.hooksPath, init.templateDir,
    # core.fsmonitor, ...) must not shape the throwaway mirror repo either.
    # Point both at the null device — merely unsetting them would fall back to
    # the real ~/.gitconfig / system config.
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_CONFIG_SYSTEM"] = os.devnull
    try:
        for args in (
            ["git", "init", "--quiet", str(mirror_root)],
            # --force: a user-global excludes file must not keep e.g. .env
            # files out of the mirror index.
            ["git", "-C", str(mirror_root), "add", "--force", "--all"],
        ):
            proc = subprocess.run(  # nosec B603, B607
                args, capture_output=True, timeout=30, env=env
            )
            if proc.returncode != 0:
                raise OSError(proc.stderr.decode("utf-8", errors="replace").strip())
    except (subprocess.TimeoutExpired, OSError) as exc:
        _warn_stderr(
            f"could not git-index the staged-file mirror ({exc}); "
            "git-state rules (e.g. committed-private-key) may not fire"
        )


def _remap_finding_paths(
    result: AggregatedScanResult, display_paths: dict[Path, Path]
) -> AggregatedScanResult:
    """Rewrite staged-mirror scan paths in findings back to repo display paths.

    The staged mirror exists only for the duration of the scan; findings (and
    the per-scanner results embedded in the aggregate) must point at the real
    cwd-relative repo paths in every output mode, exactly like the other
    collection branches (#476). Descriptions are rewritten too: scanners embed
    the scanned path in prose (e.g. native's "Run 'envdrift encrypt <path>'"),
    and a mirror temp path there is both a leak and a dead suggestion — the
    directory is deleted right after the scan.
    """

    def remap(finding: ScanFinding) -> ScanFinding:
        try:
            resolved = Path(finding.file_path).resolve()
        except OSError:
            return finding
        display = display_paths.get(resolved)
        if display is None:
            return finding
        description = finding.description
        for mirror_str in (str(finding.file_path), str(resolved)):
            if mirror_str in description:
                description = description.replace(mirror_str, str(display))
        return dataclasses.replace(finding, file_path=display, description=description)

    # dataclasses.replace carries every unlisted field forward, so a future
    # AggregatedScanResult field can never be silently dropped here.
    return dataclasses.replace(
        result,
        results=[
            dataclasses.replace(scan, findings=[remap(f) for f in scan.findings])
            for scan in result.results
        ],
        unique_findings=[remap(f) for f in result.unique_findings],
    )


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
      4 - Low severity findings detected

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

    if sarif and json_output:
        # SARIF takes precedence over JSON; warn on stderr so the choice is not
        # silent, without contaminating the (SARIF) stdout (#443 #31).
        print(
            "[WARN] --json is ignored because --sarif was also passed "
            "(SARIF output takes precedence).",
            file=sys.stderr,
        )

    def _git_toplevel() -> Path:
        """Return the git repository root, falling back to cwd if unavailable.

        ``git diff`` emits paths relative to the repository root, so returned
        paths must be resolved against the toplevel (not the process cwd) or
        every file is dropped by the ``.exists()`` filter when guard is invoked
        from a subdirectory.
        """
        try:
            toplevel = subprocess.run(  # nosec B603, B607
                ["git", "rev-parse", "--show-toplevel"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
            )
            if toplevel.returncode == 0 and toplevel.stdout.strip():
                return Path(toplevel.stdout.strip())
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return Path.cwd()

    # Staged-mirror state (set only by the --staged branch): the temp dir
    # holding the staged index blobs and the mirror-path -> display-path map
    # used to rewrite finding locations after the scan (#476).
    staged_tmpdir: tempfile.TemporaryDirectory | None = None
    staged_display_paths: dict[Path, Path] = {}

    # Handle --staged flag (pre-commit mode)
    if staged:
        try:
            result = subprocess.run(  # nosec B603, B607
                ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
            )
            # A failing ``git diff --cached`` (e.g. not a git repository) is an
            # error, not "nothing staged": conflating the two turned a broken
            # pre-commit gate into a green pass (#476).
            if result.returncode != 0:
                detail = (result.stderr or "").strip() or "unknown git error"
                _emit_error(
                    json_output,
                    sarif,
                    f"--staged could not list staged files (git diff --cached failed): {detail}",
                )
                raise typer.Exit(code=1)
            staged_files = [f for f in result.stdout.strip().split("\n") if f]
            if not staged_files:
                _emit_empty_or_prose(json_output, sarif, _NO_STAGED)
                raise typer.Exit(code=0)
            # Scan the staged *index blobs*, not the working-tree copies: the
            # blob is what the commit ships, and the two can differ (#476).
            # Findings are remapped to cwd-relative repo paths after the scan
            # so output and path-based config matching are unchanged.
            staged_tmpdir, paths, staged_display_paths = _materialize_staged_index(
                staged_files, _git_toplevel()
            )
            if not paths:
                staged_tmpdir.cleanup()
                _emit_error(
                    json_output,
                    sarif,
                    "--staged could not read any staged file content from the git index.",
                )
                raise typer.Exit(code=1)
            _emit_progress(
                json_output, sarif, f"[dim]Scanning {len(paths)} staged file(s)...[/dim]"
            )
        except subprocess.TimeoutExpired as err:
            console.print("[red]Error:[/red] Git command timed out")
            raise typer.Exit(code=1) from err
        except FileNotFoundError as err:
            console.print("[red]Error:[/red] Git not found. --staged requires git.")
            raise typer.Exit(code=1) from err

    # Handle --pr-base flag (CI mode for PRs)
    elif pr_base:
        try:
            # Fetch the base branch first to ensure it's up to date.
            # Strip only a leading "origin/" prefix; a global replace would
            # corrupt refs that contain "origin/" elsewhere (e.g.
            # "release/origin-mirror").
            base_ref = pr_base.removeprefix("origin/")
            if not base_ref:
                base_ref = pr_base
            fetch_result = subprocess.run(  # nosec B603, B607
                ["git", "fetch", "origin", base_ref],
                capture_output=True,
                timeout=30,
            )
            if fetch_result.returncode != 0:
                # Surface fetch failures unconditionally (#476): they used to be
                # verbose-gated and swallowed in machine modes, hiding the usual
                # root cause of an unresolvable base ref.
                _warn_stderr(f"could not fetch '{base_ref}' from origin; using local refs")
            # Get all files changed between base and HEAD
            result = subprocess.run(  # nosec B603, B607
                ["git", "diff", "--name-only", "--diff-filter=ACMR", f"{pr_base}...HEAD"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
            )
            # rc != 0 means git itself failed (unknown revision, shallow clone
            # missing the base, ...) — distinct from a successful empty diff.
            # Conflating the two passed the CI secret gate green on a typo'd or
            # unfetched base ref (#476).
            if result.returncode != 0:
                stderr_lines = (result.stderr or "").strip().splitlines()
                reason = stderr_lines[0] if stderr_lines else "unknown git error"
                _emit_error(
                    json_output,
                    sarif,
                    f"--pr-base '{pr_base}' could not be diffed against: {reason} "
                    f"Fetch or fix the base ref (e.g. 'git fetch origin {base_ref}').",
                )
                raise typer.Exit(code=1)
            if result.stdout.strip():
                repo_root = _git_toplevel()
                candidates = [repo_root / f for f in result.stdout.strip().split("\n") if f]
                # Resolve against the repo root for existence, scan with
                # cwd-relative paths so findings display the short relative
                # filename (a long absolute path gets truncated by the Rich
                # panel) and path-based config matching behaves as it did from
                # the repo root.
                paths = [Path(os.path.relpath(p, Path.cwd())) for p in candidates if p.exists()]
                if not paths:
                    _emit_empty_or_prose(json_output, sarif, _NO_PR_CHANGES)
                    raise typer.Exit(code=0)
                _emit_progress(
                    json_output,
                    sarif,
                    f"[bold]Scanning {len(paths)} file(s) changed since {pr_base}...[/bold]",
                )
            else:
                _emit_empty_or_prose(json_output, sarif, _NO_PR_CHANGES)
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
                _emit_error(json_output, sarif, f"Path not found: {path}")
                raise typer.Exit(code=1)

    # Load configuration from envdrift.toml (a bad/missing --config exits
    # cleanly via _load_guard_config instead of a Rich traceback; see #413).
    file_config = _load_guard_config(config_file, json_output, sarif)
    guard_cfg = file_config.guard

    # Determine fail_on severity (CLI overrides config)
    fail_on_value = fail_on or guard_cfg.fail_on_severity or "high"
    try:
        fail_severity = FindingSeverity(fail_on_value.lower())
    except ValueError as e:
        # Route through _emit_error so --json/--sarif get a clean error document
        # instead of Rich-markup human prose contaminating machine stdout (#28).
        _emit_error(
            json_output,
            sarif,
            f"Invalid severity '{fail_on_value}'. Valid options: critical, high, medium, low",
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
    mapped_env_files = []
    if file_config.partial_encryption.enabled:
        for env in file_config.partial_encryption.environments:
            if env.clear_file:
                allowed_clear_files.append(env.clear_file)
            if env.combined_file:
                combined_files.append(env.combined_file)

    for mapping in file_config.vault.sync.mappings:
        if mapping.env_file:
            try:
                mapped_env_files.append(
                    str(
                        resolve_custom_env_file(
                            Path(mapping.folder_path), mapping.env_file
                        ).resolve()
                    )
                )
            except ValueError as e:
                console.print(f"[red]Error:[/red] Invalid env_file for {mapping.folder_path}: {e}")
                raise typer.Exit(code=1) from e

    # In --staged mode the scan runs on mirror copies of the index blobs, but
    # mapped env files are matched by canonical absolute path. Alias each
    # staged mirror copy of a mapped file or the unencrypted-env-file policy
    # would silently stop firing for custom vault.sync env files (#476).
    if staged_display_paths and mapped_env_files:
        cwd = Path.cwd()
        mapped_set = set(mapped_env_files)
        mapped_env_files.extend(
            str(mirror)
            for mirror, display in staged_display_paths.items()
            if str((cwd / display).resolve()) in mapped_set
        )

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
        mapped_env_files=mapped_env_files,
    )

    # Create output console (suppress colors in CI mode or JSON/SARIF output)
    output_console = console
    if ci or _machine_mode(json_output, sarif):
        output_console = Console(force_terminal=False, no_color=True)

    # Create scan engine
    engine = ScanEngine(config)

    # Refuse a history request that no active scanner can satisfy: silently
    # dropping the flag reported "No secrets detected" over an unscanned git
    # history — a false security PASS (#476).
    if config.include_git_history and not any(s.supports_git_history for s in engine.scanners):
        active = ", ".join(s.name for s in engine.scanners) or "none"
        _emit_error(
            json_output,
            sarif,
            "Git history scanning was requested (--history or include_history in "
            f"config), but no active scanner ({active}) supports it. Enable a "
            "history-capable scanner (gitleaks, trufflehog, kingfisher, "
            "git-secrets, talisman, or infisical) or drop --history.",
        )
        raise typer.Exit(code=1)

    # Check combined files security (should be in .gitignore)
    # Only check if partial_encryption is enabled and not in JSON/SARIF mode
    if combined_files and not _machine_mode(json_output, sarif):
        security_warnings = engine.check_combined_files_security()
        for warning in security_warnings:
            output_console.print(f"[bold red]{warning}[/bold red]")
        if security_warnings:
            output_console.print()

    # Show scanner info in verbose mode or when running interactively
    scanner_names = [s.name for s in engine.scanners]
    show_progress = not _machine_mode(json_output, sarif) and scanner_names

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
    try:
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

        if staged_display_paths:
            # Findings point into the staged mirror; rewrite them to the real
            # cwd-relative repo paths before any output (#476).
            result = _remap_finding_paths(result, staged_display_paths)
    finally:
        if staged_tmpdir is not None:
            staged_tmpdir.cleanup()

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

        # Fail CI iff a finding meets the threshold, using the severity-derived
        # code so each severity stays distinguishable (CRITICAL=1/HIGH=2/MEDIUM=3/
        # LOW=4). ``result.exit_code`` is already nonzero for any finding, so a
        # blocking LOW (``--fail-on low`` with LOW-only findings) now fails CI with
        # its own code 4 instead of silently passing or colliding with HIGH's 2
        # (#413). No blocking finding => clean exit 0.
        exit_code = result.exit_code if has_blocking else 0

    if exit_code != 0:
        raise typer.Exit(code=exit_code)
