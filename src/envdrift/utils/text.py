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
    pieces = template.split(_SLOT)
    if len(pieces) != len(values) + 1:
        raise ValueError(f"template has {len(pieces) - 1} slot(s) for {len(values)} value(s)")
    rendered = Text.from_markup(_SLOT_MARK.join(pieces), emoji=False)
    plain = rendered.plain
    offsets = [index for index, char in enumerate(plain) if char == _SLOT_MARK]
    if len(offsets) != len(values):
        raise ValueError("a styled_text slot cannot sit inside a markup tag")
    spans = list(rendered.spans)
    # Right to left, so each replacement only shifts text that is already final.
    for offset, value in reversed(list(zip(offsets, values, strict=True))):
        literal = value if isinstance(value, Text) else Text(str(value))
        grow = len(literal) - 1
        plain = plain[:offset] + literal.plain + plain[offset + 1 :]
        spans = [_shift_span(span, offset, grow) for span in spans]
        if literal.style:
            spans.append(Span(offset, offset + len(literal), literal.style))
        spans.extend(Span(s.start + offset, s.end + offset, s.style) for s in literal.spans)
    return Text(plain, style=rendered.style, spans=[s for s in spans if s.end > s.start])


def _shift_span(span: Span, offset: int, grow: int) -> Span:
    """Move ``span`` after the one-character slot at ``offset`` grew by ``grow``."""
    if span.end <= offset:
        return span
    if span.start <= offset:
        return Span(span.start, span.end + grow, span.style)
    return Span(span.start + grow, span.end + grow, span.style)
