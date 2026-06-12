"""Module entry point so ``python -m envdrift`` invokes the CLI.

The Go background agent (and the docs) fall back to ``python -m envdrift ...``
when the ``envdrift`` binary is not on PATH; without this module that
invocation fails with "No module named envdrift.__main__" (#481).
"""

from envdrift.cli import app

if __name__ == "__main__":  # pragma: no cover - exercised via subprocess test
    app()
