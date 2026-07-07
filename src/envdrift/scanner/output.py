"""Output formatters for scan results.

This module provides multiple output formats for scan results:
- Rich: Terminal UI with colors and tables
- JSON: Machine-readable format for automation
- SARIF: Static Analysis Results Interchange Format for GitHub/GitLab
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from envdrift import __version__
from envdrift.scanner.base import (
    EXIT_OPERATIONAL_ERROR,
    FINDINGS_EXIT_CODES,
    AggregatedScanResult,
    FindingSeverity,
    ScanFinding,
)
from envdrift.utils.git import get_git_root

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import PurePath

# The real project repository, reported as the SARIF driver's informationUri
# (Code Scanning displays it on every alert — #489).
_REPOSITORY_URL = "https://github.com/jainal09/envdrift"

# Symbolic name of the source-root URI base. SARIF 2.1.0 resolves a result's
# ``uriBaseId`` by EXACT string lookup in ``originalUriBaseIds`` (§3.4.4 /
# §3.14.14 — bare names, no percent signs), so the emitting and declaring
# sides must share this one constant or consumers cannot resolve the URIs.
_SRCROOT_BASE_ID = "SRCROOT"

# Truncation length for the secret content hash embedded in SARIF
# fingerprints: 16 hex chars (64 bits) is plenty to keep two distinct secrets
# on the same line distinct, without disclosing the full SHA-256 digest.
_FINGERPRINT_HASH_LENGTH = 16


# Color mapping for severity levels
SEVERITY_COLORS: dict[FindingSeverity, str] = {
    FindingSeverity.CRITICAL: "red bold",
    FindingSeverity.HIGH: "red",
    FindingSeverity.MEDIUM: "yellow",
    FindingSeverity.LOW: "blue",
    FindingSeverity.INFO: "dim",
}

# Icon mapping for severity levels
SEVERITY_ICONS: dict[FindingSeverity, str] = {
    FindingSeverity.CRITICAL: "X",
    FindingSeverity.HIGH: "!",
    FindingSeverity.MEDIUM: "?",
    FindingSeverity.LOW: "i",
    FindingSeverity.INFO: ".",
}

# At or above this terminal width the findings table shows all five columns;
# below it the secondary Rule/Preview columns are dropped so the essential
# Sev/Location/Description stay on one readable line each.
_WIDE_TERMINAL_WIDTH = 100


def _severity_cell(finding: ScanFinding) -> Text:
    """Render the styled severity cell, e.g. a red ``[X] CRIT``."""
    cell = Text(f"[{SEVERITY_ICONS[finding.severity]}] {finding.severity.value[:4].upper()}")
    cell.stylize(SEVERITY_COLORS[finding.severity])
    return cell


def _build_full_findings_table(findings: list[ScanFinding]) -> Table:
    """Findings table for non-interactive output (``guard --ci``, piped, hooks).

    Keeps all five columns so the rule id and preview are never *dropped* from CI
    logs (the regression this guards against). Individual values may still
    ellipsize or fold at a narrow CI width — use ``--format json`` for the
    complete values. This is the pre-PR layout, kept verbatim so hook/CI output
    stays stable.
    """
    table = Table(show_header=True, header_style="bold", expand=True)
    table.add_column("Sev", width=8, justify="center")
    table.add_column("Location", style="cyan", no_wrap=True, max_width=40)
    table.add_column("Rule", style="magenta", max_width=25)
    table.add_column("Description", overflow="fold")
    table.add_column("Preview", style="dim", max_width=20)
    for f in findings:
        table.add_row(
            _severity_cell(f), f.location, f.rule_id, f.description, f.secret_preview or "-"
        )
    return table


def _build_compact_findings_table(findings: list[ScanFinding], *, wide: bool) -> Table:
    """Compact, width-aware findings table for an interactive terminal.

    Text columns are no_wrap + ellipsis (truncate with "…" on one line instead of
    word-wrapping into fragments), Description is the flexible (ratio=1) column so
    it absorbs the leftover width without starving the fixed Sev column, and below
    ~100 cols the secondary Rule/Preview columns drop.
    """
    table = Table(show_header=True, header_style="bold", expand=True)
    table.add_column("Sev", width=8, justify="center")
    table.add_column("Location", style="cyan", no_wrap=True, max_width=40, overflow="ellipsis")
    if wide:
        table.add_column("Rule", style="magenta", no_wrap=True, max_width=20, overflow="ellipsis")
    table.add_column("Description", ratio=1, no_wrap=True, overflow="ellipsis")
    if wide:
        table.add_column("Preview", style="dim", no_wrap=True, max_width=14, overflow="ellipsis")
    for f in findings:
        row: list[str | Text] = [_severity_cell(f), f.location]
        if wide:
            row.append(f.rule_id)
        row.append(f.description)
        if wide:
            row.append(f.secret_preview or "-")
        table.add_row(*row)
    return table


def _build_findings_table(result: AggregatedScanResult, *, interactive: bool, wide: bool) -> Table:
    """Dispatch to the full (non-interactive) or compact (interactive) table."""
    findings = sorted(result.unique_findings, key=lambda f: f.severity, reverse=True)
    if not interactive:
        return _build_full_findings_table(findings)
    return _build_compact_findings_table(findings, wide=wide)


def format_rich(result: AggregatedScanResult, console: Console | None = None) -> None:
    """Format and print results using Rich for terminal output.

    Args:
        result: Aggregated scan results to display.
        console: Rich console to use. If None, creates a new one.
    """
    if console is None:
        console = Console()

    # Surface scanner errors prominently. Filter on the ScanResult.success
    # contract (error is not None), not truthiness, so an empty-string failure
    # still lands in the panel and matches the Scan Incomplete verdict (#478).
    errors = [r for r in result.results if not r.success]
    if errors:
        error_lines: list[str] = []
        for r in errors:
            msg = (r.error or "").strip()
            if len(msg) > 200:
                msg = f"{msg[:200]}…"
            error_lines.append(f"[red]{r.scanner_name}[/red]: {msg}")
        console.print(
            Panel(
                "\n".join(error_lines),
                title="Scanner Errors",
                border_style="red",
            )
        )
        console.print()

    if not result.unique_findings:
        if errors:
            # A selected scanner ran and failed: the requested scan never
            # completed, so the run must not be presented as a clean pass
            # (it exits EXIT_SCAN_ERROR, not 0 — #478).
            console.print(
                Panel(
                    "[yellow]No findings reported, but the scan is incomplete: "
                    f"{len(errors)} scanner(s) failed (see Scanner Errors above). "
                    "This run must not be treated as a clean pass.[/yellow]",
                    title="envdrift guard - Scan Incomplete",
                    border_style="yellow",
                )
            )
        else:
            console.print(
                Panel(
                    "[green]No secrets or policy violations detected[/green]",
                    title="envdrift guard",
                    border_style="green",
                )
            )
        _print_scan_info(result, console)
        return

    # Summary panel
    summary_parts = []
    for severity in [
        FindingSeverity.CRITICAL,
        FindingSeverity.HIGH,
        FindingSeverity.MEDIUM,
        FindingSeverity.LOW,
    ]:
        count = sum(1 for f in result.unique_findings if f.severity == severity)
        if count > 0:
            color = SEVERITY_COLORS[severity]
            summary_parts.append(f"[{color}]{count} {severity.value}[/{color}]")

    border_style = "red" if result.has_blocking_findings else "yellow"
    console.print(
        Panel(
            " | ".join(summary_parts) if summary_parts else "No findings",
            title="envdrift guard - Findings Summary",
            border_style=border_style,
        )
    )

    # Findings table. A non-interactive console (`guard --ci`, piped, redirected)
    # keeps all columns (so CI logs retain the rule id + preview); an interactive
    # terminal gets the compact, width-aware one (dropping the secondary columns
    # only when genuinely narrow).
    console.print(
        _build_findings_table(
            result,
            interactive=console.is_terminal,
            wide=console.width >= _WIDE_TERMINAL_WIDTH,
        )
    )

    # Scan info
    _print_scan_info(result, console)

    # Remediation hints
    if result.has_blocking_findings:
        console.print()
        console.print("[bold]Remediation:[/bold]")
        console.print("  - For unencrypted .env files: [cyan]envdrift encrypt <file>[/cyan]")
        console.print("  - For exposed secrets: Rotate the secret immediately")
        console.print("  - To scan git history: [cyan]envdrift guard --history[/cyan]")


def _print_scan_info(result: AggregatedScanResult, console: Console) -> None:
    """Print scan metadata."""
    total_files_reported = sum(r.files_scanned for r in result.results)
    files_with_findings = len({str(f.file_path) for f in result.unique_findings})
    console.print(
        f"\n[dim]Scanners: {', '.join(result.scanners_used)} | "
        f"Files with findings: {files_with_findings} | "
        f"Files reported: {total_files_reported} | "
        f"Duration: {result.total_duration_ms}ms[/dim]"
    )


def format_json(result: AggregatedScanResult, exit_code: int | None = None) -> str:
    """Format results as JSON.

    Args:
        result: Aggregated scan results.
        exit_code: The effective process exit code for this run. When the
            caller applies a ``--ci --fail-on`` threshold it must pass the
            threshold-adjusted code so the machine-readable ``exit_code`` /
            ``has_blocking_findings`` fields agree with the actual process
            exit instead of contradicting it (#478). Defaults to the result's
            own threshold-unaware code.

    Returns:
        JSON string representation.
    """
    effective = result.exit_code if exit_code is None else exit_code
    data = {
        "findings": [f.to_dict() for f in result.unique_findings],
        "summary": {
            "total": result.total_findings,
            "unique": len(result.unique_findings),
            "by_severity": {
                severity.value: sum(1 for f in result.unique_findings if f.severity == severity)
                for severity in FindingSeverity
            },
        },
        "scanners": result.scanners_used,
        "scanner_results": [
            {
                "name": r.scanner_name,
                "files_scanned": r.files_scanned,
                "duration_ms": r.duration_ms,
                "error": r.error,
            }
            for r in result.results
        ],
        "duration_ms": result.total_duration_ms,
        "exit_code": effective,
        # True iff findings caused this run's (effective) non-zero exit — the
        # same verdict the process exit code carries, by construction (#478).
        "has_blocking_findings": effective in FINDINGS_EXIT_CODES,
    }
    return json.dumps(data, indent=2)


def _sarif_rule(finding: ScanFinding) -> dict[str, Any]:
    """Build the SARIF ``rules`` entry for a finding."""
    return {
        "id": finding.rule_id,
        "name": finding.rule_description,
        "shortDescription": {"text": finding.rule_description},
        "fullDescription": {"text": finding.description},
        "defaultConfiguration": {"level": _severity_to_sarif_level(finding.severity)},
        "properties": {
            "tags": ["security", "secrets"],
            "security-severity": _severity_to_security_severity(finding.severity),
        },
    }


def _sarif_source_root(finding_paths: Sequence[Path] = ()) -> Path:
    """Resolve the ``SRCROOT`` base directory for SARIF artifact URIs.

    Artifact URIs are emitted relative to the enclosing git repository root
    (``git rev-parse --show-toplevel``) so alerts map to repo files no matter
    which directory guard was invoked from.

    The root is derived from the git repo that actually contains the scanned
    findings, then the invocation cwd's repo, and finally cwd itself when
    nothing is under git. Preferring the findings' repo means
    ``guard --sarif /path/to/repo`` run from an unrelated cwd still emits
    repo-relative URIs instead of absolute ``file://`` fallbacks that Code
    Scanning cannot map (#489).
    """
    for candidate in (*finding_paths, Path.cwd()):
        base = candidate if candidate.is_dir() else candidate.parent
        root = get_git_root(base)
        if root is not None:
            return root.resolve()
    return Path.cwd().resolve()


def _sarif_artifact_location(file_path: PurePath, srcroot: PurePath) -> dict[str, Any]:
    """Build a SARIF ``artifactLocation`` with a portable URI.

    Both arguments must be absolute. A path under ``srcroot`` becomes a
    srcroot-relative URI with forward slashes — on Windows too, per SARIF
    2.1.0 §3.4.4 — tagged with ``uriBaseId: SRCROOT``, percent-encoded so a
    space, ``#`` or non-ASCII character still yields a valid RFC 3986
    URI-reference (§3.4.3), matching the ``as_uri()`` fallback's encoding. A
    path outside the source root cannot be expressed relative to it, so it
    falls back to an absolute ``file://`` URI with no base id (an absolute
    URI under a base id is contradictory and Code Scanning drops such
    alerts — #489).
    """
    try:
        relative = file_path.relative_to(srcroot)
    except ValueError:
        return {"uri": file_path.as_uri()}
    return {"uri": quote(relative.as_posix()), "uriBaseId": _SRCROOT_BASE_ID}


def _resolved_finding_path(file_path: Path) -> Path:
    """Absolutize a finding path against the invocation cwd.

    Scanners report paths relative to the cwd guard ran in, so they must be
    anchored there (then resolved, collapsing symlinks like macOS ``/tmp``)
    before relativizing against the source root.
    """
    path = file_path if file_path.is_absolute() else Path.cwd() / file_path
    return path.resolve()


def _sarif_result(finding: ScanFinding, srcroot: Path) -> dict[str, Any]:
    """Build the SARIF ``results`` entry for a finding (location + fingerprints)."""
    region: dict[str, Any] = {"startLine": finding.line_number or 1}
    if finding.column_number:
        region["startColumn"] = finding.column_number

    artifact_location = _sarif_artifact_location(_resolved_finding_path(finding.file_path), srcroot)

    # The fingerprint must uniquely identify each finding: two DISTINCT
    # secrets on the same line carry different columns and content hashes, so
    # both alerts survive Code Scanning's fingerprint-based dedup (#489 /
    # #348). The truncated SHA-256 of the secret value is stable across runs
    # and never embeds the matched text itself.
    fingerprint_parts = [
        artifact_location["uri"],
        str(finding.line_number or 0),
        str(finding.column_number or 0),
        finding.rule_id,
    ]
    if finding.secret_hash:
        fingerprint_parts.append(finding.secret_hash[:_FINGERPRINT_HASH_LENGTH])

    sarif_result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "level": _severity_to_sarif_level(finding.severity),
        "message": {"text": finding.description},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": artifact_location,
                    "region": region,
                }
            }
        ],
        "fingerprints": {"primary": ":".join(fingerprint_parts)},
    }
    if finding.secret_hash:
        # Hash-based, never the redacted preview: redaction collapses the
        # middle of similar secrets, so previews of distinct secrets can be
        # identical and would merge their alerts (#489).
        sarif_result["partialFingerprints"] = {
            "secretHash/v1": finding.secret_hash[:_FINGERPRINT_HASH_LENGTH]
        }
    if finding.secret_preview:
        # Keep the human-readable redacted preview, but as a property — it
        # must not participate in alert deduplication.
        sarif_result["properties"] = {"secretPreview": finding.secret_preview}
    return sarif_result


def _sarif_document(
    rules: list[dict[str, Any]],
    results: list[dict[str, Any]],
    invocation: dict[str, Any],
    srcroot: Path | None = None,
) -> str:
    """Wrap rules/results/invocation in the shared SARIF 2.1.0 run envelope.

    The driver block carries the real package version and repository URL —
    Code Scanning displays them on every alert (#489). When ``srcroot`` is
    given, the run declares it as the ``SRCROOT`` base via
    ``originalUriBaseIds`` (SARIF 2.1.0 §3.14.14, base URIs end with a slash)
    under the exact key every ``uriBaseId`` references.
    """
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "envdrift guard",
                "version": __version__,
                "informationUri": _REPOSITORY_URL,
                "rules": rules,
            }
        },
        "results": results,
        "invocations": [invocation],
    }
    if srcroot is not None:
        srcroot_uri = srcroot.as_uri()
        if not srcroot_uri.endswith("/"):
            srcroot_uri += "/"
        run["originalUriBaseIds"] = {_SRCROOT_BASE_ID: {"uri": srcroot_uri}}
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }
    return json.dumps(sarif, indent=2)


def format_sarif(result: AggregatedScanResult, exit_code: int | None = None) -> str:
    """Format results as SARIF for GitHub/GitLab Code Scanning.

    SARIF (Static Analysis Results Interchange Format) is an OASIS standard
    for the output of static analysis tools.

    Artifact URIs are emitted relative to the enclosing git repository root
    (declared as ``SRCROOT`` in ``originalUriBaseIds``) regardless of the
    invocation cwd, and each result's fingerprint folds in the rule id,
    column and a truncated content hash so two distinct secrets on one line
    stay distinct alerts (#489).

    The invocation object carries the run's verdict so it can never contradict
    the process exit (#478): ``exitCode`` is the effective exit code passed by
    the caller (or the result's own threshold-unaware code), and
    ``executionSuccessful`` is false when any selected scanner ran but failed,
    with one error ``toolExecutionNotifications`` entry per failed scanner.

    Args:
        result: Aggregated scan results.
        exit_code: The effective process exit code for this run (see
            :func:`format_json`).

    Returns:
        SARIF JSON string.
    """
    effective = result.exit_code if exit_code is None else exit_code

    # Deduplicate rules by rule_id while preserving first-seen order.
    rules_by_id: dict[str, dict[str, Any]] = {}
    for finding in result.unique_findings:
        rules_by_id.setdefault(finding.rule_id, _sarif_rule(finding))

    # Derive the source root from the findings' own paths so scanning an
    # explicit path outside the cwd still yields repo-relative URIs (#489).
    resolved_paths = [_resolved_finding_path(f.file_path) for f in result.unique_findings]
    srcroot = _sarif_source_root(resolved_paths)
    return _sarif_document(
        rules=list(rules_by_id.values()),
        results=[_sarif_result(f, srcroot) for f in result.unique_findings],
        invocation={
            "executionSuccessful": not result.has_errors,
            "exitCode": effective,
            # Filter on the ScanResult.success contract (error is not None), not
            # error truthiness, so an empty-string failure that flips
            # executionSuccessful to false still emits a notification explaining
            # the failure instead of leaving the consumer with no reason (#478).
            "toolExecutionNotifications": [
                {
                    "level": "error",
                    "message": {"text": f"{r.scanner_name}: {(r.error or '').strip()}"},
                }
                for r in result.results
                if not r.success
            ],
        },
        srcroot=srcroot,
    )


def format_sarif_error(message: str, exit_code: int = EXIT_OPERATIONAL_ERROR) -> str:
    """Format a tool/configuration error as a valid SARIF document.

    Used by the error paths (missing/malformed config, path-not-found) so a
    consumer that always parses ``guard --sarif`` stdout receives a
    schema-valid SARIF run with ``executionSuccessful: false`` and an ``error``
    notification, instead of a bare ``{"error": ...}`` object that would fail
    SARIF validation (mirrors ``format_sarif`` on the success path).

    Args:
        message: Human-readable error message.
        exit_code: The process exit code for this failed run, carried in the
            invocation so SARIF consumers see the same verdict as the process
            exit (#478). Defaults to ``EXIT_OPERATIONAL_ERROR``.

    Returns:
        SARIF JSON string describing the failed invocation.
    """
    return _sarif_document(
        rules=[],
        results=[],
        invocation={
            "executionSuccessful": False,
            "exitCode": exit_code,
            "toolConfigurationNotifications": [{"level": "error", "message": {"text": message}}],
        },
    )


def _severity_to_sarif_level(severity: FindingSeverity) -> str:
    """Map FindingSeverity to SARIF level.

    Args:
        severity: Finding severity.

    Returns:
        SARIF level string.
    """
    mapping = {
        FindingSeverity.CRITICAL: "error",
        FindingSeverity.HIGH: "error",
        FindingSeverity.MEDIUM: "warning",
        FindingSeverity.LOW: "note",
        FindingSeverity.INFO: "note",
    }
    return mapping[severity]


def _severity_to_security_severity(severity: FindingSeverity) -> str:
    """Map FindingSeverity to GitHub security severity score.

    GitHub uses a scale of 0.0-10.0 for security severity.

    Args:
        severity: Finding severity.

    Returns:
        Security severity score as string.
    """
    mapping = {
        FindingSeverity.CRITICAL: "9.0",
        FindingSeverity.HIGH: "7.0",
        FindingSeverity.MEDIUM: "5.0",
        FindingSeverity.LOW: "3.0",
        FindingSeverity.INFO: "1.0",
    }
    return mapping[severity]
