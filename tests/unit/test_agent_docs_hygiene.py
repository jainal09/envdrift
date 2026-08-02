"""Guard how agent instructions are LOADED, not just what they say.

Claude Code reads ``CLAUDE.md``; it does not read ``AGENTS.md``. The only way
AGENTS.md reaches an agent's context is the ``@AGENTS.md`` import line in
CLAUDE.md.

This is guarded because the failure is completely silent. CLAUDE.md previously
linked to AGENTS.md in prose ("Doing substantial work here? Read AGENTS.md"),
which loads nothing — it just hopes the agent opens the file. An agent then ran
a large autonomous change in this repo having only ever seen the summary, and
nothing anywhere reported a problem.

Two ways the import can silently die, both covered below:

1. It gets wrapped in backticks or moved into a fenced block. Claude Code's
   import parser skips code spans and fenced code blocks, so ``@AGENTS.md``
   becomes inert prose that still *looks* correct in the rendered markdown.
2. AGENTS.md is renamed or moved and the import dangles.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CLAUDE_MD = _REPO_ROOT / "CLAUDE.md"
_AGENTS_MD = _REPO_ROOT / "AGENTS.md"

_FENCED_BLOCK = re.compile(r"```.*?```", re.DOTALL)
_CODE_SPAN = re.compile(r"`[^`\n]*`")
_IMPORT_LINE = re.compile(r"(?m)^\s*@([^\s`]+)\s*$")


def _active_imports(markdown: str) -> list[str]:
    """Imports Claude Code would actually honour.

    Mirrors the documented parser behaviour: code spans and fenced code blocks
    are stripped first, so anything inside them is NOT an import.
    """
    without_fences = _FENCED_BLOCK.sub("", markdown)
    without_spans = _CODE_SPAN.sub("", without_fences)
    return _IMPORT_LINE.findall(without_spans)


def test_agents_md_exists() -> None:
    """The import target must exist, or the import dangles silently."""
    assert _AGENTS_MD.is_file(), (
        "AGENTS.md is missing. CLAUDE.md imports it with '@AGENTS.md'; if the "
        "file is renamed, update the import in the same commit."
    )


def test_claude_md_actively_imports_agents_md() -> None:
    """CLAUDE.md must import AGENTS.md, not merely link to it."""
    imports = _active_imports(_CLAUDE_MD.read_text(encoding="utf-8"))
    assert "AGENTS.md" in imports, (
        "CLAUDE.md does not actively import AGENTS.md. A prose link or a "
        "backticked '@AGENTS.md' loads NOTHING — Claude Code reads CLAUDE.md "
        "only, and import parsing skips code spans and fenced blocks. Put a "
        "bare @AGENTS.md on its own line, outside any backticks or fence. "
        f"Imports currently honoured: {imports or 'none'}."
    )


def test_import_is_not_hidden_in_a_code_span_or_fence() -> None:
    """A backticked mention must never be mistaken for a working import.

    Directly pins the subtle failure: the raw text can contain '@AGENTS.md'
    while the parser sees no import at all.
    """
    raw = _CLAUDE_MD.read_text(encoding="utf-8")
    assert "@AGENTS.md" in raw  # sanity: the text is there at all
    assert "AGENTS.md" in _active_imports(raw), (
        "'@AGENTS.md' appears in CLAUDE.md but only inside a code span or "
        "fenced block, so Claude Code will not import it."
    )


@pytest.mark.parametrize("doc", [_CLAUDE_MD, _AGENTS_MD])
def test_docs_do_not_assume_one_contributor_operating_system(doc: Path) -> None:
    """Agent docs must not state a specific dev OS as a universal premise.

    envdrift is open source: contributors run Linux, macOS and Windows, and
    most boxes cannot reach the other two. Docs that assert "this dev box is
    WSL2" mislead an agent into either fabricating platform verification or
    treating an impossible step as mandatory. Machine-specific setup belongs in
    a clearly-scoped maintainer note.
    """
    text = doc.read_text(encoding="utf-8")
    # HTML comments are maintainer notes stripped before reaching context.
    prose = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)

    banned = [
        "This dev box is WSL2",
        "This is a WSL2 box",
    ]
    found = [phrase for phrase in banned if phrase in prose]
    assert not found, (
        f"{doc.name} asserts a specific developer machine ({found}). State the "
        "requirement (prove cross-platform fixes on the target OS, and say so "
        "honestly when you cannot) rather than assuming everyone has the "
        "maintainer's setup."
    )


@pytest.mark.parametrize("doc", [_CLAUDE_MD, _AGENTS_MD])
def test_docs_tell_agents_to_admit_unverifiable_platforms(doc: Path) -> None:
    """Both docs must keep the "say so when you cannot verify" instruction."""
    # Strip markdown emphasis and collapse whitespace so the phrase still
    # matches when it is bolded or wrapped across lines.
    text = re.sub(r"[*_`]", "", doc.read_text(encoding="utf-8").lower())
    text = " ".join(text.split())
    assert "cross-platform" in text, f"{doc.name} lost its cross-platform guidance"
    assert "never claim a platform was verified" in text, (
        f"{doc.name} must keep the explicit instruction never to claim a "
        "platform was verified when it was not — that is the failure this "
        "guidance exists to prevent."
    )
