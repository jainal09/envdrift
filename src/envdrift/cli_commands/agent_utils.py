"""Shared helpers for the agent-related CLI commands.

Kept in a dedicated module so both ``install`` (``envdrift install check`` /
``envdrift install agent``) and ``agent`` (``envdrift agent status``) parse the
agent ``status`` output through the same logic, without either command module
importing the other.
"""

from __future__ import annotations


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
