"""Tests for envdrift.utils.text."""

from __future__ import annotations

import pytest

from envdrift.utils.text import strip_ansi


@pytest.mark.parametrize(
    ("raw", "clean"),
    [
        # gitleaks 8.30.1 stderr for a missing scan path (#843).
        (
            "\x1b[90m4:30AM\x1b[0m \x1b[31mFTL\x1b[0m "
            "\x1b[1mstat proj: no such file or directory\x1b[0m",
            "4:30AM FTL stat proj: no such file or directory",
        ),
        # Infisical 0.43.141 stderr: a colored ``key=value`` field.
        (
            "\x1b[90m2026-10-13T04:30:26Z\x1b[0m \x1b[31mFTL\x1b[0m Failed to load config "
            '\x1b[36merror=\x1b[0m\x1b[31m\x1b[1m"stat proj: no such file"\x1b[0m\x1b[0m',
            '2026-10-13T04:30:26Z FTL Failed to load config error="stat proj: no such file"',
        ),
        # Cursor control and private-mode sequences.
        ("\x1b[2K\x1b[1Gdone\x1b[?25h", "done"),
        ("plain text [not an escape]", "plain text [not an escape]"),
        ("", ""),
    ],
)
def test_strip_ansi(raw: str, clean: str):
    assert strip_ansi(raw) == clean
