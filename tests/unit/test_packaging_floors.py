"""Regression tests for declared dependency floors in ``pyproject.toml``.

envdrift's command signatures use PEP 604 unions (``str | None``) in
``typer.Option``/``typer.Argument`` annotations (e.g. ``cli.py``,
``cli_commands/diff.py``). typer only supports those from 0.13: every older
release crashes on every invocation — including ``--help`` — with
``RuntimeError: Type not yet supported: str | None``. On top of that, typer
0.13-0.15.3 declare ``click >= 8.0`` with no upper bound, and click >= 8.2
changed ``Parameter.make_metavar()`` so ``--help`` rendering crashes with
``TypeError: Parameter.make_metavar() missing 1 required positional argument:
'ctx'``. typer 0.15.4 is the first release whose resolver-legal installs yield
a working CLI (it pins ``click < 8.2``; 0.16+ supports click 8.2+). The
declared floor must therefore never drop below 0.15.4.

Regression tests for https://github.com/jainal09/envdrift/issues/496.
"""

from __future__ import annotations

from tests.helpers import declared_dependency_floor, version_tuple

# Bisected in issue #496 (and re-verified for this fix): typer 0.9.0/0.12.5
# crash on the PEP 604 unions; 0.13.1-0.15.3 resolve click 8.4.x and crash on
# `--help`; 0.15.4 (click<8.2 pin) and 0.16.0+ work end to end.
_MINIMUM_WORKING_TYPER = (0, 15, 4)


def test_typer_floor_supports_pep604_union_annotations() -> None:
    """The typer floor must be a version the CLI actually runs on (>= 0.15.4)."""
    floor = version_tuple(declared_dependency_floor("typer"))
    assert floor >= _MINIMUM_WORKING_TYPER, (
        f"pyproject.toml declares typer>={'.'.join(map(str, floor))}, but the minimum "
        "working floor is 0.15.4: typer 0.13-0.15.3 resolves click >= 8.2, which breaks "
        "`--help` rendering, and typer < 0.13 crashes every envdrift invocation with "
        "'RuntimeError: Type not yet supported: str | None' (PEP 604 unions in the "
        "command signatures); see issue #496"
    )
