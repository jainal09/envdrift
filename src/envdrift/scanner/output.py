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


def format_rich(result: AggregatedScanResult, console: Console | None = None) -> None:
    """Format and print results using Rich for terminal output.

    Args:
        result: Aggregated scan results to display.
        console: Rich console to use. If None, creates a new one.
    """
    if console is None:
        console = Console()

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

    # Findings table
    table = Table(show_header=True, header_style="bold", expand=True)
    table.add_column("Sev", width=8, justify="center")
    table.add_column("Location", style="cyan", no_wrap=True, max_width=40)
    table.add_column("Rule", style="magenta", max_width=25)
    table.add_column("Description", overflow="fold")
    table.add_column("Preview", style="dim", max_width=20)

    for finding in sorted(result.unique_findings, key=lambda f: f.severity, reverse=True):
        severity_icon = SEVERITY_ICONS[finding.severity]
        severity_color = SEVERITY_COLORS[finding.severity]
        severity_text = Text(f"[{severity_icon}] {finding.severity.value[:4].upper()}")
        severity_text.stylize(severity_color)

        table.add_row(
            severity_text,
            finding.location,
            finding.rule_id,
            finding.description,
            finding.secret_preview or "-",
        )

    console.print(table)

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
    total_files = sum(r.files_scanned for r in result.results)
    console.print(
        f"\n[dim]Scanners: {', '.join(result.scanners_used)} | "
        f"Files: {total_files} | "
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
        "duration_ms": result.total_duration_ms,
        "exit_code": result.exit_code,
        "has_blocking_findings": result.has_blocking_findings,
    }
    return json.dumps(data, indent=2)


def format_sarif(result: AggregatedScanResult) -> str:
    """Format results as SARIF for GitHub/GitLab Code Scanning.

    SARIF (Static Analysis Results Interchange Format) is an OASIS standard
    for the output of static analysis tools.

    Args:
        result: Aggregated scan results.

    Returns:
        SARIF JSON string.
    """
    # Build rules from unique rule IDs
    rules_seen: set[str] = set()
    rules: list[dict[str, Any]] = []

    for finding in result.unique_findings:
        if finding.rule_id not in rules_seen:
            rules.append(
                {
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
            )
            rules_seen.add(finding.rule_id)

    # Build results
    sarif_results: list[dict[str, Any]] = []
    for finding in result.unique_findings:
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
                        "region": {
                            "startLine": finding.line_number or 1,
                        },
                    }
                }
            ],
        }

        # Add column if available
        if finding.column_number:
            sarif_result["locations"][0]["physicalLocation"]["region"]["startColumn"] = (
                finding.column_number
            )

        # Add fingerprint for deduplication
        sarif_result["fingerprints"] = {
            "primary": f"{finding.file_path}:{finding.line_number}:{finding.rule_id}"
        }

        # Add partial fingerprint for secret preview
        if finding.secret_preview:
            sarif_result["partialFingerprints"] = {"secretPreview": finding.secret_preview}

        sarif_results.append(sarif_result)

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
                "results": sarif_results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "toolExecutionNotifications": [],
                    }
                ],
            }
        ],
    }

    return json.dumps(sarif, indent=2)


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
