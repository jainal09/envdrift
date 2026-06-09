"""Output formatters for scan results.

This module provides multiple output formats for scan results:
- Rich: Terminal UI with colors and tables
- JSON: Machine-readable format for automation
- SARIF: Static Analysis Results Interchange Format for GitHub/GitLab
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from envdrift.scanner.base import (
    AggregatedScanResult,
    FindingSeverity,
    ScanFinding,
)

if TYPE_CHECKING:
    pass


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


def _build_findings_table(result: AggregatedScanResult, *, wide: bool) -> Table:
    """Build the findings table, dropping secondary columns on a narrow terminal.

    Five columns can't fit under ~100 cols without Rich squeezing the severity
    column to nothing, so on a narrow terminal only Sev/Location/Description are
    shown. Text columns are no_wrap + ellipsis (truncate with "…" on one line
    instead of word-wrapping into fragments); Description is the flexible
    (ratio=1) column so it absorbs the leftover width without starving Sev.
    """
    table = Table(show_header=True, header_style="bold", expand=True)
    table.add_column("Sev", width=8, justify="center")
    table.add_column("Location", style="cyan", no_wrap=True, max_width=40, overflow="ellipsis")
    if wide:
        table.add_column("Rule", style="magenta", no_wrap=True, max_width=20, overflow="ellipsis")
    table.add_column("Description", ratio=1, no_wrap=True, overflow="ellipsis")
    if wide:
        table.add_column("Preview", style="dim", no_wrap=True, max_width=14, overflow="ellipsis")

    for finding in sorted(result.unique_findings, key=lambda f: f.severity, reverse=True):
        severity_text = Text(
            f"[{SEVERITY_ICONS[finding.severity]}] {finding.severity.value[:4].upper()}"
        )
        severity_text.stylize(SEVERITY_COLORS[finding.severity])

        row: list[str | Text] = [severity_text, finding.location]
        if wide:
            row.append(finding.rule_id)
        row.append(finding.description)
        if wide:
            row.append(finding.secret_preview or "-")
        table.add_row(*row)

    return table


def format_rich(result: AggregatedScanResult, console: Console | None = None) -> None:
    """Format and print results using Rich for terminal output.

    Args:
        result: Aggregated scan results to display.
        console: Rich console to use. If None, creates a new one.
    """
    if console is None:
        console = Console()

    # Surface scanner errors prominently
    errors = [r for r in result.results if r.error]
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

    # Findings table. Only an interactive, genuinely narrow terminal drops the
    # secondary columns (for readability) — a non-interactive console (`guard
    # --ci`, piped, or redirected) reports width 80 but must keep all columns so
    # CI logs retain the rule id and redacted preview for triage.
    wide = (not console.is_terminal) or console.width >= _WIDE_TERMINAL_WIDTH
    console.print(_build_findings_table(result, wide=wide))

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


def format_json(result: AggregatedScanResult) -> str:
    """Format results as JSON.

    Args:
        result: Aggregated scan results.

    Returns:
        JSON string representation.
    """
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
        "exit_code": result.exit_code,
        "has_blocking_findings": result.has_blocking_findings,
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


def _sarif_result(finding: ScanFinding) -> dict[str, Any]:
    """Build the SARIF ``results`` entry for a finding (location + fingerprints)."""
    region: dict[str, Any] = {"startLine": finding.line_number or 1}
    if finding.column_number:
        region["startColumn"] = finding.column_number

    sarif_result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "level": _severity_to_sarif_level(finding.severity),
        "message": {"text": finding.description},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": str(finding.file_path),
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": region,
                }
            }
        ],
        "fingerprints": {"primary": f"{finding.file_path}:{finding.line_number}:{finding.rule_id}"},
    }
    if finding.secret_preview:
        sarif_result["partialFingerprints"] = {"secretPreview": finding.secret_preview}
    return sarif_result


def _sarif_document(
    rules: list[dict[str, Any]],
    results: list[dict[str, Any]],
    invocation: dict[str, Any],
) -> str:
    """Wrap rules/results/invocation in the shared SARIF 2.1.0 run envelope."""
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "envdrift guard",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/your-org/envdrift",
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [invocation],
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def format_sarif(result: AggregatedScanResult) -> str:
    """Format results as SARIF for GitHub/GitLab Code Scanning.

    SARIF (Static Analysis Results Interchange Format) is an OASIS standard
    for the output of static analysis tools.

    Args:
        result: Aggregated scan results.

    Returns:
        SARIF JSON string.
    """
    # Deduplicate rules by rule_id while preserving first-seen order.
    rules_by_id: dict[str, dict[str, Any]] = {}
    for finding in result.unique_findings:
        rules_by_id.setdefault(finding.rule_id, _sarif_rule(finding))

    return _sarif_document(
        rules=list(rules_by_id.values()),
        results=[_sarif_result(f) for f in result.unique_findings],
        invocation={"executionSuccessful": True, "toolExecutionNotifications": []},
    )


def format_sarif_error(message: str) -> str:
    """Format a tool/configuration error as a valid SARIF document.

    Used by the error paths (missing/malformed config, path-not-found) so a
    consumer that always parses ``guard --sarif`` stdout receives a
    schema-valid SARIF run with ``executionSuccessful: false`` and an ``error``
    notification, instead of a bare ``{"error": ...}`` object that would fail
    SARIF validation (mirrors ``format_sarif`` on the success path).

    Args:
        message: Human-readable error message.

    Returns:
        SARIF JSON string describing the failed invocation.
    """
    return _sarif_document(
        rules=[],
        results=[],
        invocation={
            "executionSuccessful": False,
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
