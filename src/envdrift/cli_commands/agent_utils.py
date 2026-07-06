"""Shared helpers for the agent-related CLI commands.

Kept in a dedicated module so both ``install`` (``envdrift install check`` /
``envdrift install agent``) and ``agent`` (``envdrift agent status``) parse the
agent ``status`` output and report registry corruption through the same logic,
without either command module importing the other.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from rich.console import Console

    from envdrift.agent.registry import ProjectRegistry


def warn_registry_corruption(registry: ProjectRegistry, console: Console) -> None:
    """Surface a corrupt-registry recovery to the user instead of hiding it (#492).

    Pre-#492 a corrupt ``projects.json`` was silently treated as empty (and
    silently replaced on the next write), so registrations vanished behind a
    clean success message. This prints exactly what happened and where the
    corrupt original went.
    """
    notice = registry.corruption
    if notice is None:
        return
    console.print(f"[yellow]⚠[/yellow] Registry file was corrupt: {registry.path}")
    console.print(f"  ({notice.detail})")
    if notice.backup_path is not None:
        console.print(f"  The corrupt file was backed up to: {notice.backup_path}")
        console.print("  Previously registered projects were discarded — re-register them.")
    elif notice.backup_failed:
        console.print("  The corrupt file could not be backed up; its contents were replaced.")
    else:
        # Only a write can move the file aside, and only `register` (or
        # `clear`) writes over a corrupt registry — an unregister miss on an
        # empty-loaded registry never saves, so never name it here.
        console.print(
            "  Treating it as empty. The file is untouched and will be backed up "
            "to a .corrupt-<timestamp> file by the next register."
        )


def parse_agent_running_status(status_stdout: str) -> bool | None:
    """Parse the agent ``status`` output to determine if it is running.

    The agent always prints a ``Running:   <bool>`` line (with variable
    whitespace after the colon), so a naive ``"running" in stdout`` substring
    check matches both the running and stopped cases. This parses the value of
    the ``Running:`` line precisely instead.

    Args:
        status_stdout: The stdout captured from the agent ``status`` command.

    Returns:
        True if running, False if stopped, or None if no parseable
        ``Running:`` line was found.
    """
    for line in status_stdout.splitlines():
        if line.strip().lower().startswith("running:"):
            value = line.split(":", 1)[1].strip().lower()
            if value in {"true", "false"}:
                return value == "true"
            break
    return None
