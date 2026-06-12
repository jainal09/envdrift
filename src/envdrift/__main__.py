"""Entry point for ``python -m envdrift``.

The VS Code extension (and the Go agent) fall back to ``python -m envdrift``
when the ``envdrift`` binary is not on PATH — common for GUI-launched editors.
Without this module that fallback could never succeed (#482).
"""

from envdrift.cli import app

if __name__ == "__main__":
    app()
