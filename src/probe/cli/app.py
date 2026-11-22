"""Probe CLI application."""

import typer

from probe import __version__

app = typer.Typer(help="Probe: A behavioral, safety, and operability test suite for MCP servers")


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
