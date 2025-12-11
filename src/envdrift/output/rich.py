"""Rich console formatting for envdrift output."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from envdrift.core.diff import DiffResult, DiffType
from envdrift.core.encryption import EncryptionReport
from envdrift.core.schema import SchemaMetadata
from envdrift.core.validator import ValidationResult

if TYPE_CHECKING:
    from envdrift.sync.result import ServiceSyncResult, SyncResult

console = Console()


def print_success(message: str) -> None:
    """Print a success message."""
    console.print(f"[green][OK][/green] {message}")


def print_error(message: str) -> None:
    """
    Print a message prefixed with a red "ERROR" badge to the module console.
    """
    console.print(f"[red][ERROR][/red] {message}")


def print_warning(message: str) -> None:
    """
    Display a yellow "WARN" badge followed by the provided message to the shared console.
    """
    console.print(f"[yellow][WARN][/yellow] {message}")


def print_validation_result(
    result: ValidationResult,
    env_path: Path,
    schema: SchemaMetadata,
    verbose: bool = False,
) -> None:
    """
    Render a formatted validation report for an environment file against a schema using Rich console output.

    Prints a header with the environment path and schema, then a PASS or FAIL status. When validation fails, prints any of the following sections as applicable: missing required variables (with schema descriptions when available), extra variables, unencrypted secrets, type errors, warnings, and — when `verbose` is true — missing optional variables (with defaults when available). Finally prints a summary of error and warning counts and a short hint to run with --fix.

    Parameters:
        result (ValidationResult): Validation outcome containing flags and lists of issues.
        env_path (Path): Filesystem path to the validated environment file.
        schema (SchemaMetadata): Schema metadata used for validation (fields, descriptions, defaults).
        verbose (bool): If true, include missing optional variables and their default information.
    """
    # Header
    console.print()
    console.print(
        Panel(
            f"[bold]Validating:[/bold] {env_path}\n"
            f"[bold]Schema:[/bold] {schema.module_path}:{schema.class_name}",
            title="envdrift validate",
        )
    )

    if result.valid:
        console.print()
        console.print("[bold green]Validation PASSED[/bold green]")
    else:
        console.print()
        console.print("[bold red]Validation FAILED[/bold red]")
    console.print()

    # Missing required variables
    if result.missing_required:
        console.print("[bold red]MISSING REQUIRED VARIABLES:[/bold red]")
        for var in sorted(result.missing_required):
            field_meta = schema.fields.get(var)
            desc = f" - {field_meta.description}" if field_meta and field_meta.description else ""
            console.print(f"  [red]*[/red] {var}{desc}")
        console.print()

    # Extra variables
    if result.extra_vars:
        console.print("[bold yellow]EXTRA VARIABLES (not in schema):[/bold yellow]")
        for var in sorted(result.extra_vars):
            console.print(f"  [yellow]*[/yellow] {var}")
        console.print()

    # Unencrypted secrets (warning, not error)
    if result.unencrypted_secrets:
        console.print("[bold yellow]UNENCRYPTED SECRETS (warning):[/bold yellow]")
        for var in sorted(result.unencrypted_secrets):
            console.print(f"  [yellow]*[/yellow] {var} (marked sensitive but not encrypted)")
        console.print("[dim]  Run 'envdrift encrypt --check' for strict enforcement[/dim]")
        console.print()

    # Type errors
    if result.type_errors:
        console.print("[bold red]TYPE ERRORS:[/bold red]")
        for var, error in sorted(result.type_errors.items()):
            console.print(f"  [red]*[/red] {var}: {error}")
        console.print()

    # Warnings
    if result.warnings:
        console.print("[bold yellow]WARNINGS:[/bold yellow]")
        for warning in result.warnings:
            console.print(f"  [yellow]*[/yellow] {warning}")
        console.print()

    # Missing optional (verbose only)
    if verbose and result.missing_optional:
        console.print("[dim]MISSING OPTIONAL VARIABLES (have defaults):[/dim]")
        for var in sorted(result.missing_optional):
            field_meta = schema.fields.get(var)
            has_default = field_meta and field_meta.default is not None
            default = f" (default: {field_meta.default})" if has_default else ""
            console.print(f"  [dim]*[/dim] {var}{default}")
        console.print()

    # Summary (show if there are any issues)
    err_count = result.error_count
    warn_count = result.warning_count
    if err_count > 0 or warn_count > 0:
        console.print(f"[bold]Summary:[/bold] {err_count} error(s), {warn_count} warning(s)")
        console.print()
    if err_count > 0:
        console.print("[dim]Run with --fix to generate template for missing variables.[/dim]")


def print_diff_result(result: DiffResult, show_unchanged: bool = False) -> None:
    """
    Render a human-readable comparison of two environments to the shared console.

    Prints a header showing the two environment paths, a table of variable differences (optionally including unchanged entries), and a concise summary of added/removed/changed counts with a drift notice when differences exist.

    Parameters:
        result (DiffResult): The computed diff between two environments, including paths, per-variable differences, and aggregate counts.
        show_unchanged (bool): If True, include variables that are identical in both environments in the output; otherwise omit them.
    """
    console.print()
    console.print(
        Panel(
            f"[bold]Comparing:[/bold] {result.env1_path} vs {result.env2_path}",
            title="envdrift diff",
        )
    )

    if not result.has_drift:
        console.print()
        console.print("[bold green]No drift detected - environments match[/bold green]")
        console.print()
        return

    # Create table
    table = Table(show_header=True, header_style="bold")
    table.add_column("Variable", style="cyan")
    table.add_column(str(result.env1_path.name), style="dim")
    table.add_column(str(result.env2_path.name), style="dim")
    table.add_column("Status", justify="center")

    for diff in result.differences:
        if diff.diff_type == DiffType.UNCHANGED and not show_unchanged:
            continue

        # Format status
        if diff.diff_type == DiffType.ADDED:
            status = Text("added", style="green")
            value1 = Text("(missing)", style="dim")
            value2 = Text(str(diff.value2) if diff.value2 else "", style="green")
        elif diff.diff_type == DiffType.REMOVED:
            status = Text("removed", style="red")
            value1 = Text(str(diff.value1) if diff.value1 else "", style="red")
            value2 = Text("(missing)", style="dim")
        elif diff.diff_type == DiffType.CHANGED:
            status = Text("changed", style="yellow")
            value1 = Text(str(diff.value1) if diff.value1 else "", style="yellow")
            value2 = Text(str(diff.value2) if diff.value2 else "", style="yellow")
        else:
            status = Text("unchanged", style="dim")
            value1 = Text(str(diff.value1) if diff.value1 else "", style="dim")
            value2 = Text(str(diff.value2) if diff.value2 else "", style="dim")

        # Mark sensitive values
        if diff.is_sensitive:
            name_text = Text()
            name_text.append(diff.name)
            name_text.append(" (sensitive)", style="dim")
        else:
            name_text = Text(diff.name)

        table.add_row(name_text, value1, value2, status)

    console.print()
    console.print(table)
    console.print()

    # Summary
    summary_parts = []
    if result.changed_count:
        summary_parts.append(f"[yellow]{result.changed_count} changed[/yellow]")
    if result.added_count:
        summary_parts.append(f"[green]{result.added_count} added[/green]")
    if result.removed_count:
        summary_parts.append(f"[red]{result.removed_count} removed[/red]")

    console.print(f"[bold]Summary:[/bold] {', '.join(summary_parts)}")

    if result.has_drift:
        console.print()
        console.print("[yellow]Drift detected between environments[/yellow]")


def print_encryption_report(report: EncryptionReport) -> None:
    """
    Render a human-readable encryption summary for a file, including overall status, variable counts, detected plaintext secrets, warnings, and a remediation suggestion.

    Parameters:
        report (EncryptionReport): EncryptionReport for the inspected file (provides path, encryption ratios, lists of encrypted/plaintext/empty variables, plaintext secrets, and warnings).
    """
    console.print()
    console.print(
        Panel(f"[bold]Encryption Status:[/bold] {report.path}", title="envdrift encrypt --check")
    )

    # Overall status
    if report.is_fully_encrypted:
        console.print()
        console.print("[bold green]File is fully encrypted[/bold green]")
    elif report.encrypted_vars and report.plaintext_vars:
        console.print()
        console.print("[bold yellow]File is partially encrypted[/bold yellow]")
    else:
        console.print()
        console.print("[bold red]File is not encrypted[/bold red]")

    console.print()

    # Statistics
    console.print("[bold]Variables:[/bold]")
    console.print(f"  Encrypted:  {len(report.encrypted_vars)}")
    console.print(f"  Plaintext:  {len(report.plaintext_vars)}")
    console.print(f"  Empty:      {len(report.empty_vars)}")
    console.print(f"  Encryption ratio: {report.encryption_ratio:.0%}")
    console.print()

    # Plaintext secrets (critical)
    if report.plaintext_secrets:
        console.print("[bold red]PLAINTEXT SECRETS DETECTED:[/bold red]")
        for var in sorted(report.plaintext_secrets):
            console.print(f"  [red]*[/red] {var}")
        console.print()

    # Warnings
    if report.warnings:
        console.print("[bold yellow]WARNINGS:[/bold yellow]")
        for warning in report.warnings:
            console.print(f"  [yellow]*[/yellow] {warning}")
        console.print()

    # Recommendation
    if report.plaintext_secrets:
        console.print("[bold]Recommendation:[/bold]")
        console.print("  Run: [cyan]dotenvx encrypt -f[/cyan] [dim]<env_file>[/dim]")
        console.print()


def print_sync_summary(
    services_processed: int,
    created: int,
    updated: int,
    skipped: int,
    errors: int,
) -> None:
    """
    Prints a summary of vault synchronization results.

    Parameters:
        services_processed (int): Total number of services that were processed.
        created (int): Number of new keys created.
        updated (int): Number of keys updated.
        skipped (int): Number of keys skipped because no change was needed.
        errors (int): Number of services that failed during syncing.
    """
    console.print()
    console.print(
        Panel(
            f"[bold]Services processed:[/bold] {services_processed}\n"
            f"[green]Created:[/green] {created}\n"
            f"[yellow]Updated:[/yellow] {updated}\n"
            f"[dim]Skipped:[/dim] {skipped}\n"
            f"[red]Errors:[/red] {errors}",
            title="Sync Summary",
        )
    )

    if errors == 0:
        console.print("[bold green]All services synced successfully[/bold green]")
    else:
        console.print(f"[bold red]{errors} service(s) failed[/bold red]")


def print_service_sync_status(result: ServiceSyncResult) -> None:
    """
    Print status for a single service sync operation.

    Parameters:
        result (ServiceSyncResult): Result of syncing a single service.
    """
    from envdrift.sync.result import DecryptionTestResult, SyncAction

    # Determine status icon and color
    if result.action == SyncAction.CREATED:
        icon = "[green]+[/green]"
        status = "[green]created[/green]"
    elif result.action == SyncAction.UPDATED:
        icon = "[yellow]~[/yellow]"
        status = "[yellow]updated[/yellow]"
    elif result.action == SyncAction.SKIPPED:
        icon = "[dim]=[/dim]"
        status = "[dim]skipped[/dim]"
    else:  # ERROR
        icon = "[red]x[/red]"
        status = "[red]error[/red]"

    console.print(f"  {icon} {result.folder_path} - {status}")

    # Show error details
    if result.error:
        console.print(f"    [red]Error: {result.error}[/red]")

    # Show mismatch preview
    if result.local_value_preview and result.vault_value_preview:
        if result.local_value_preview != result.vault_value_preview:
            console.print(f"    [dim]Local:  {result.local_value_preview}[/dim]")
            console.print(f"    [dim]Vault:  {result.vault_value_preview}[/dim]")

    # Show backup path
    if result.backup_path:
        console.print(f"    [dim]Backup: {result.backup_path}[/dim]")

    # Show decryption test result
    if result.decryption_result is not None:
        if result.decryption_result == DecryptionTestResult.PASSED:
            console.print("    [green]Decryption: PASSED[/green]")
        elif result.decryption_result == DecryptionTestResult.FAILED:
            console.print("    [red]Decryption: FAILED[/red]")
        else:
            console.print("    [dim]Decryption: skipped (no encrypted file)[/dim]")

    # Show schema validation result
    if result.schema_valid is not None:
        if result.schema_valid:
            console.print("    [green]Schema: valid[/green]")
        else:
            console.print("    [red]Schema: invalid[/red]")


def print_sync_result(result: SyncResult) -> None:
    """
    Print complete sync results with summary.

    Parameters:
        result (SyncResult): Aggregate sync results.
    """

    console.print()

    # Build summary panel content
    lines = [
        f"[bold]Services processed:[/bold] {result.total_processed}",
        f"[green]Created:[/green] {result.created_count}",
        f"[yellow]Updated:[/yellow] {result.updated_count}",
        f"[dim]Skipped:[/dim] {result.skipped_count}",
        f"[red]Errors:[/red] {result.error_count}",
    ]

    # Add decryption stats if any were tested
    if result.decryption_tested > 0:
        lines.append("")
        lines.append("[bold]Decryption Tests:[/bold]")
        lines.append(f"  [green]Passed:[/green] {result.decryption_passed}")
        lines.append(f"  [red]Failed:[/red] {result.decryption_failed}")
        skipped = result.decryption_tested - result.decryption_passed - result.decryption_failed
        if skipped > 0:
            lines.append(f"  [dim]Skipped:[/dim] {skipped}")

    console.print(Panel("\n".join(lines), title="Sync Summary"))

    # Final status message
    if result.has_errors:
        console.print("[bold red]Sync completed with errors[/bold red]")
    else:
        console.print("[bold green]All services synced successfully[/bold green]")


def print_mismatch_warning(
    service_name: str,
    local_preview: str,
    vault_preview: str,
) -> None:
    """
    Print value mismatch warning.

    Parameters:
        service_name (str): Name of the service with mismatched values.
        local_preview (str): Preview of local value (first N chars).
        vault_preview (str): Preview of vault value (first N chars).
    """
    console.print()
    console.print(f"[bold yellow]VALUE MISMATCH: {service_name}[/bold yellow]")
    console.print(f"  Local:  {local_preview}")
    console.print(f"  Vault:  {vault_preview}")
    console.print()
