"""Probe CLI application."""

import typer

from probe import __version__
from probe.cli.checks import app as checks_app
from probe.cli.profile import app as profile_app
from probe.cli.run import run
from probe.cli.sandbox import app as sandbox_app
from probe.cli.selfval import selfval

app = typer.Typer(help="Probe: A behavioral, safety, and operability test suite for MCP servers")
app.add_typer(sandbox_app, name="sandbox")
app.add_typer(checks_app, name="checks")
app.add_typer(profile_app, name="profile")
# Everything after `--` is the target command, so unknown options and extra arguments are allowed.
app.command(name="selfval")(selfval)
app.command(context_settings={"allow_extra_args": True, "ignore_unknown_options": True})(run)


@app.callback(invoke_without_command=True)
def main_callback(ctx: typer.Context) -> None:
    """Probe CLI entrypoint."""
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())


@app.command()
def version() -> None:
    """Print the Probe version."""
    typer.echo(f"probe-mcp {__version__}")


def main() -> None:
    """Main entry point for the Probe CLI."""
    app()


if __name__ == "__main__":
    main()
