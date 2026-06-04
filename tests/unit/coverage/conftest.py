"""Shared guards for the coverage test suite.

These tests assert on substrings of Rich-rendered CLI output. Rich wraps output
to the active console width, and the module-level ``Console`` objects are shared
global state that other tests in the full suite can leave at a narrow width.
A narrow width wraps long lines (which include absolute tmp paths) mid-phrase and
breaks substring assertions in CI even though they pass in isolation. Force every
command console wide before each test so the assertions are width-independent.
"""

import importlib

import pytest

# Modules that define their own module-level ``console = Console()``.
_CONSOLE_MODULES = (
    "envdrift.output.rich",
    "envdrift.cli_commands.agent",
    "envdrift.cli_commands.guard",
    "envdrift.cli_commands.install",
)


@pytest.fixture(autouse=True)
def _force_wide_console():
    """Pin each command console to a wide width so output never wraps mid-phrase."""
    saved = []
    for mod_name in _CONSOLE_MODULES:
        console = getattr(importlib.import_module(mod_name), "console", None)
        if console is None:
            continue
        saved.append((console, console._width))
        console._width = 240
    yield
    for console, width in saved:
        console._width = width
