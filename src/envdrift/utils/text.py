"""Text helpers shared across envdrift."""

from __future__ import annotations

import re

from rich.text import Span, Text

# CSI escape sequences (colors, styles, cursor control). Go CLIs that log
# through zerolog's console writer, such as gitleaks and Infisical, emit them
# even when stderr is a pipe. Parameter bytes span the full 0x30-0x3F range
# (digits and ``:;<=>?``), so colon-form colors like ``\x1b[38:2::1:2:3m`` match.
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")

# A ``styled_text`` slot, and the private-use character that stands in for it
# while the template's markup is parsed. envdrift's own templates never hold it.
_SLOT = "{}"
_SLOT_MARK = "\ue000"

# The line breaks the .env parser splits at (#486): a newline, as git, grep and the
# external scanners count lines, and a lone carriage return, a line break in old Mac
# files and to editors. str.splitlines() also breaks at \v, \f, \x1c-\x1e, \x85,
# U+2028 and U+2029 (#937).
_LINE_BREAK_RE = re.compile(r"\r\n|\r|\n")

# How many lines a finding filter keeps what it read from. A scanner reports the findings on one
# line together, so a few lines are enough to read each long line once, however many findings it
# holds, and a file of many lines costs no more memory than a few.
LINE_CACHE_SIZE = 64


def split_lines(text: str) -> list[str]:
    """Split ``text`` into lines at ``\\n``, ``\\r\\n`` and ``\\r`` only.

    ``str.splitlines()`` also breaks a line at a form feed, a vertical tab, or a Unicode
    line separator, where git and the external scanners see none. After one, a line
    number counted one way names another line counted the other (#937). A lone ``\\r``
    stays a line break, as it was: git and the scanners count only ``\\n``, so in a file
    with bare ``\\r`` line endings their line numbers stay apart from these. As with
    ``splitlines()``, a line break at the end starts no empty line.
    """
    lines = _LINE_BREAK_RE.split(text)
    if lines[-1] == "":
        lines.pop()
    return lines


def line_and_column(text: str, index: int) -> tuple[int, int]:
    """The 1-based line and column of ``text[index]``, its lines as :func:`split_lines` splits."""
    line, line_start = 1, 0
    for line_break in _LINE_BREAK_RE.finditer(text, 0, index):
        line += 1
        line_start = line_break.end()
    return line, index - line_start + 1


def strip_ansi(text: str) -> str:
    """Return ``text`` without ANSI escape sequences.

    Tool output surfaced as an error message ends up in ``--json`` and SARIF
    documents, which must stay free of terminal escapes.
    """
    return _ANSI_ESCAPE_RE.sub("", text)


def styled_text(template: str, *values: object) -> Text:
    """Render envdrift's own Rich markup with each ``{}`` slot filled by a literal value.

    ``template`` is envdrift's text and may style itself with Rich markup
    (``"[red]Error:[/red] {}"``). Each ``{}`` slot is replaced, in order, by
    ``str(value)`` exactly as it is: the value is never parsed as markup or as
    emoji codes, so a path such as ``cfg[/x]/a.env``, ``C:\\[2024]\\x`` or
    ``:fire:.env`` prints as written instead of raising ``MarkupError`` or
    losing text. ``rich.markup.escape`` cannot promise that: it doubles a
    trailing backslash and drops one before a bracket that is not a tag.

    A value takes the style of the markup around its slot; a ``Text`` value
    also keeps its own styling. A slot cannot stand for a markup tag.

    Raises:
        ValueError: When the slots and the values do not pair up.
    """
    rendered, offsets = _render_with_slot_marks(template, len(values))
    plain, spans = rendered.plain, list(rendered.spans)
    # Right to left, so each replacement only shifts text that is already final.
    for offset, value in reversed(list(zip(offsets, values, strict=True))):
        plain, spans = _fill_slot(plain, spans, offset, value)
    return Text(plain, style=rendered.style, spans=[s for s in spans if s.end > s.start])


def _render_with_slot_marks(template: str, count: int) -> tuple[Text, list[int]]:
    """Render ``template``'s markup with a mark in each slot, and where the marks landed.

    Raises:
        ValueError: When ``template`` does not have ``count`` slots, or a slot sits in a tag.
    """
    pieces = template.split(_SLOT)
    if len(pieces) != count + 1:
        raise ValueError(f"template has {len(pieces) - 1} slot(s) for {count} value(s)")
    rendered = Text.from_markup(_SLOT_MARK.join(pieces), emoji=False)
    offsets = [index for index, char in enumerate(rendered.plain) if char == _SLOT_MARK]
    if len(offsets) != count:
        raise ValueError("a styled_text slot cannot sit inside a markup tag")
    return rendered, offsets


def _fill_slot(plain: str, spans: list[Span], offset: int, value: object) -> tuple[str, list[Span]]:
    """Put ``value`` as it is in the one-character slot at ``offset``, keeping its style."""
    literal = value if isinstance(value, Text) else Text(str(value))
    spans = [_shift_span(span, offset, len(literal) - 1) for span in spans]
    if literal.style:
        spans.append(Span(offset, offset + len(literal), literal.style))
    spans.extend(Span(s.start + offset, s.end + offset, s.style) for s in literal.spans)
    return plain[:offset] + literal.plain + plain[offset + 1 :], spans


def _shift_span(span: Span, offset: int, grow: int) -> Span:
    """Move ``span`` after the one-character slot at ``offset`` grew by ``grow``."""
    if span.end <= offset:
        return span
    if span.start <= offset:
        return Span(span.start, span.end + grow, span.style)
    return Span(span.start + grow, span.end + grow, span.style)
