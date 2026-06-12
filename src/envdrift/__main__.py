"""Run the envdrift CLI via ``python -m envdrift``.

The docs recommend ``python -m envdrift ...`` as the PATH-proof escape hatch
(the pre-commit fallback in ``docs/support/troubleshooting.md``, the version
check in ``docs/guides/agent-setup.md``), and the VS Code extension and Go
agent fall back to the same invocation when the ``envdrift`` script is not on
PATH. Dispatch to the same Typer app as the ``envdrift`` console script (#498).
"""

from envdrift.cli import app

if __name__ == "__main__":
    app()
