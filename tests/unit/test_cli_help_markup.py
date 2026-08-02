"""Guard every CLI help string against Rich-markup swallowing.

typer >= 0.21 defaults ``rich_markup_mode`` to ``"rich"``, so Rich parses help
text as console markup. A literal bracket that looks like a style tag — e.g.
``[vault.sync]``, ``[guardian]``, ``[validation]`` — is then interpreted as
markup and silently DELETED from ``--help``. The command still works, the exit
code is still 0, and no test that only checks ``exit_code`` notices.

That is exactly how five commands lost documented TOML section names when
typer moved 0.20 -> 0.27: only three of them had assertions, so ``validate``
and ``agent register`` regressed unnoticed.

Rather than pin the three known strings, this module sweeps EVERY command and
EVERY parameter help string in the app and asserts that no bracketed run is
lost between the source text and what Rich actually renders. New commands are
covered automatically.

The fix for a failure here is to escape the bracket at the source as ``\\[``
(Rich consumes the backslash, so the rendered output shows a bare ``[...]``).
Do NOT "fix" it by setting ``rich_markup_mode=None`` — that also strips the
Rich option panels from the whole CLI.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

import click
import pytest
import typer
from rich.text import Text

from envdrift.cli import app

# A bracketed token that Rich would treat as a style tag. Deliberately narrow:
# TOML section names and similar identifiers, e.g. [vault], [vault.sync],
# [tool.envdrift.vault.sync], [guardian]. Metavars like [OPTIONS] / [env_files]
# are produced by click itself (not our help text) and are filtered out below.
#
# The dash matters: Rich swallows [vault-sync] exactly like [vault], so leaving
# `-` out of the class would let a dashed section name be deleted from --help
# while this sweep still reported green.
_BRACKETED = re.compile(r"\[([a-z][a-z0-9_.-]*)\]")

# Bracketed tokens click/typer generate for usage lines rather than our prose:
# the structural ones, plus every parameter name in the app (typer renders
# optional positionals from the lowercase parameter name, e.g. `[env_files]`,
# `[paths]`). Deriving the parameter names instead of hardcoding a prefix keeps
# this correct as commands are added.
_STRUCTURAL_METAVARS = frozenset({"options", "args", "command"})


def _render(markup: str) -> str:
    """Return what Rich actually prints for ``markup``."""
    return Text.from_markup(markup).plain


def _candidates(text: str, exclude: frozenset[str] = frozenset()) -> set[str]:
    """Bracketed identifiers in ``text`` that Rich could swallow."""
    ignored = _STRUCTURAL_METAVARS | exclude
    return {m.group(1) for m in _BRACKETED.finditer(text) if m.group(1) not in ignored}


def _walk(cmd: Any, path: list[str]) -> Iterator[tuple[list[str], Any]]:
    """Yield every (path, command) in the tree.

    Duck-typed on purpose: typer >= 0.21 vendors click as ``typer._click``, so
    the objects here are NOT instances of the top-level ``click`` classes even
    though they share the API. Annotating them as ``click.Command`` makes the
    type checker reject the very calls that work fine at runtime.
    """
    yield path, cmd
    list_commands = getattr(cmd, "list_commands", None)
    get_command = getattr(cmd, "get_command", None)
    if list_commands is None or get_command is None:
        return
    ctx = click.Context(cmd, info_name=path[-1] if path else "envdrift")
    for name in sorted(list_commands(ctx)):
        sub = get_command(ctx, name)
        if sub is not None:
            yield from _walk(sub, [*path, name])


def _command_help(where: str, cmd: Any) -> list[tuple[str, str]]:
    """The command's own help text, if it has any."""
    return [(f"{where} (command help)", cmd.help)] if cmd.help else []


def _param_help(where: str, cmd: Any) -> list[tuple[str, str]]:
    """Help text for each of the command's parameters that has any."""
    return [
        (f"{where} --{param.name} (param help)", param.help)
        for param in cmd.params
        if getattr(param, "help", None)
    ]


def _param_names(cmd: Any) -> set[str]:
    """Lowercased parameter names — what click renders as usage metavars."""
    return {param.name.lower() for param in cmd.params if param.name}


def _collect() -> tuple[list[tuple[str, str]], frozenset[str]]:
    """Every (location, help_text) in the app, plus all parameter names.

    The parameter names are what click renders as usage-line metavars, so they
    are excluded from the sweep: `[paths]` in a usage string is click's doing,
    not prose we control.
    """
    out: list[tuple[str, str]] = []
    names: set[str] = set()
    for path, cmd in _walk(typer.main.get_command(app), []):
        where = " ".join(path) or "<root>"
        out.extend(_command_help(where, cmd))
        out.extend(_param_help(where, cmd))
        names |= _param_names(cmd)
    return out, frozenset(names)


HELP_STRINGS, PARAM_NAMES = _collect()


def test_sweep_is_not_empty():
    """Guard the guard: an empty sweep would make every assertion vacuous."""
    assert len(HELP_STRINGS) > 50, f"only collected {len(HELP_STRINGS)} help strings"


@pytest.mark.parametrize(
    ("location", "text"),
    HELP_STRINGS,
    ids=[loc for loc, _ in HELP_STRINGS],
)
def test_bracketed_text_survives_rich_markup(location: str, text: str):
    """No bracketed identifier may be deleted by Rich markup parsing."""
    rendered = _render(text)
    lost = sorted(tok for tok in _candidates(text, PARAM_NAMES) if f"[{tok}]" not in rendered)
    assert not lost, (
        f"{location}: Rich markup swallowed {lost} from --help. "
        f"Escape the opening bracket at the source as '\\\\[' (e.g. '\\\\[vault]'), "
        f"which renders as a bare '[vault]'."
    )


@pytest.mark.parametrize(
    ("location", "text"),
    HELP_STRINGS,
    ids=[loc for loc, _ in HELP_STRINGS],
)
def test_no_literal_backslash_leaks_into_help(location: str, text: str):
    """Over-escaping is a regression too — users must never see a raw ``\\[``."""
    assert "\\[" not in _render(text), (
        f"{location}: a literal backslash reaches --help. The source is "
        f"double-escaped (or the string is not a raw literal)."
    )


class TestDetectorItself:
    """Meta-tests: the sweep is only as good as what ``_candidates`` sees.

    A too-narrow pattern makes every assertion above vacuously pass, which is
    the worst possible failure mode for a regression guard.
    """

    @pytest.mark.parametrize(
        "name",
        ["vault", "vault.sync", "tool.envdrift.vault.sync", "guardian", "vault-sync"],
    )
    def test_detects_identifiers_rich_would_swallow(self, name: str):
        """Every shape of section name we document must be detected."""
        assert _candidates(f"see the `[{name}]` section") == {name}
        # ...and Rich really does delete it, which is why we look for it.
        assert f"[{name}]" not in _render(f"see the `[{name}]` section")

    @pytest.mark.parametrize("name", ["vault", "vault-sync", "tool.envdrift.a-b"])
    def test_escaped_form_survives_rich(self, name: str):
        r"""The prescribed fix (``\[``) must actually render a bare bracket."""
        assert f"[{name}]" in _render(f"see the `\\[{name}]` section")

    def test_click_metavars_are_not_flagged(self):
        """Usage-line metavars come from click, not our prose."""
        assert _candidates("Usage: envdrift guard [OPTIONS] [paths]...", PARAM_NAMES) == set()
