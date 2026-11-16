"""Tests for envdrift.utils.text."""

from __future__ import annotations

from pathlib import Path

import pytest

from envdrift.utils.text import strip_ansi, styled_text


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
        # Colon-form truecolor and ``<``-prefixed parameters (full 0x30-0x3F range).
        ("\x1b[38:2::1:2:3mred\x1b[0m", "red"),
        ("\x1b[<5;10;20Mclick", "click"),
        ("plain text [not an escape]", "plain text [not an escape]"),
        ("", ""),
    ],
)
def test_strip_ansi(raw: str, clean: str):
    assert strip_ansi(raw) == clean


# Values that ``rich.markup.escape`` does not round-trip, or that Rich would
# parse as markup or emoji codes when interpolated into a markup string.
_LITERAL_VALUES = [
    "cfg[/x]/a.env",
    "kv/app[legacy]/key",
    "cfg[bold]/a.env",
    ":fire:.env",
    "C:\\",
    "C:\\[2024]\\x",
    "a\\\\[b]",
    "dir\\\\\\[red]x",
    "[red]",
    "{}",
    "",
]


@pytest.mark.parametrize("value", _LITERAL_VALUES)
@pytest.mark.parametrize(
    ("template", "plain"),
    [
        ("{}", "{v}"),
        ("[red]{}[/red]", "{v}"),
        ("[red][ERROR][/red] {}", "[ERROR] {v}"),
        ("  [dim]=[/dim] {} [dim]- skipped ({})[/dim]", "  = {v} - skipped ({v})"),
        (r"\[guardian] {}", "[guardian] {v}"),
    ],
)
def test_styled_text_prints_values_exactly(value: str, template: str, plain: str):
    values = (value,) * template.count("{}")
    assert styled_text(template, *values).plain == plain.replace("{v}", value)


def test_styled_text_values_take_the_style_of_their_slot():
    text = styled_text("  [red]![/red] {} [red]- error: {}[/red]", "cfg[/x]", "x [bold]y")

    assert text.plain == "  ! cfg[/x] - error: x [bold]y"
    red = [(span.start, span.end) for span in text.spans if span.style == "red"]
    assert red == [(2, 3), (12, len(text.plain))]


def test_styled_text_keeps_the_styling_of_a_text_value():
    inner = styled_text("{} [dim]({})[/dim]", "svc", "kv/app[legacy]/key")
    text = styled_text("  [green]+[/green] {} - [green]created[/green]", inner)

    assert text.plain == "  + svc (kv/app[legacy]/key) - created"
    styled = {(span.start, span.end, str(span.style)) for span in text.spans}
    start = text.plain.index("(")
    end = text.plain.index(")") + 1
    assert (start, end, "dim") in styled
    assert (2, 3, "green") in styled


def test_styled_text_stringifies_values():
    assert styled_text("{} file(s) in {}", 3, Path("cfg[/x]")).plain == (
        f"3 file(s) in {Path('cfg[/x]')}"
    )


@pytest.mark.parametrize(("template", "values"), [("{} {}", ("a",)), ("{}", ("a", "b"))])
def test_styled_text_rejects_unpaired_slots(template: str, values: tuple[str, ...]):
    with pytest.raises(ValueError, match="slot"):
        styled_text(template, *values)


def test_styled_text_rejects_a_slot_inside_a_tag():
    with pytest.raises(ValueError, match="markup tag"):
        styled_text("[link={}]x[/link]", "https://example.com")
