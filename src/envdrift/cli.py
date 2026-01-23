"""Command-line interface for envdrift."""

from __future__ import annotations

from typing import Annotated

import typer

from envdrift import __version__
from envdrift.cli_commands.agent import agent_app
from envdrift.cli_commands.diff import diff
from envdrift.cli_commands.encryption import decrypt_cmd, encrypt_cmd
from envdrift.cli_commands.guard import guard
from envdrift.cli_commands.hook import hook
from envdrift.cli_commands.init_cmd import init as init_cmd
from envdrift.cli_commands.install import install_app
from envdrift.cli_commands.partial import pull_cmd as pull_partial_cmd
from envdrift.cli_commands.partial import push as push_cmd
from envdrift.cli_commands.sync import lock, pull, sync
from envdrift.cli_commands.validate import validate
from envdrift.cli_commands.vault import vault_push
from envdrift.cli_commands.version import version as version_cmd


def _version_callback(value: bool) -> None:
    """Print version and exit when --version is passed."""
    if value:
        typer.echo(f"envdrift {__version__}")
        raise typer.Exit()


app = typer.Typer(
    name="envdrift",
    help="Prevent environment variable drift with Pydantic schema validation.",
    no_args_is_help=True,
)


@app.callback()
def main(
    _version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            "-V",
            help="Show version and exit.",
            callback=_version_callback,
            is_eager=True,
        ),
    ] = None,
) -> None:
    """Envdrift - Environment variable management and secret scanning."""
    pass


app.command()(validate)
app.command()(diff)
app.command("encrypt")(encrypt_cmd)
app.command("decrypt")(decrypt_cmd)
app.command("init")(init_cmd)
app.command()(guard)
app.command()(hook)
app.command()(sync)
app.command()(pull)
app.command()(lock)
app.command("vault-push")(vault_push)
app.command()(version_cmd)

# Partial encryption commands
app.command("push")(push_cmd)
app.command("pull-partial")(pull_partial_cmd)

# Agent commands
app.add_typer(agent_app, name="agent")

# Install commands
app.add_typer(install_app, name="install")

if __name__ == "__main__":
    app()
