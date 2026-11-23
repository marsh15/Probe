"""``probe checks``: list and describe the checks."""

import difflib
import json
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from probe.checks.base import Check
from probe.checks.docs import check_markdown, render_markdown
from probe.checks.registry import REGISTRY
from probe.engine.outcomes import Family

app = typer.Typer(help="List and describe Probe's checks.", no_args_is_help=True)
FORMATS = ("table", "md", "json")


def _all_checks() -> list[type[Check]]:  # builtin plus any installed plugins
    REGISTRY.load_entry_points()
    return list(REGISTRY)


@app.command("list")
def list_checks(
    family: Annotated[str | None, typer.Option(help="Only this family.")] = None,
    output_format: Annotated[str, typer.Option("--format", help="table, md or json.")] = "table",
) -> None:
    """List the checks in run order. `--format md` is the built-in catalog (docs/checks.md)."""
    if output_format not in FORMATS:
        typer.echo(
            f"probe: unknown format {output_format!r}; choose {', '.join(FORMATS)}", err=True
        )
        raise typer.Exit(2)
    if family is not None and family not in {f.value for f in Family}:
        typer.echo(f"probe: unknown family {family!r}", err=True)
        raise typer.Exit(2)
    if output_format == "md":
        if family is not None:
            typer.echo("probe: --family cannot be combined with --format md", err=True)
            raise typer.Exit(2)
        typer.echo(render_markdown(), nl=False)
        return
    checks = [c for c in _all_checks() if family is None or c.meta.family.value == family]
    if output_format == "json":
        typer.echo(json.dumps([c.meta.model_dump(mode="json") for c in checks], indent=2))
        return
    table = Table(box=None)
    longest = max((len(c.meta.id) for c in checks), default=0)
    table.add_column("id", no_wrap=True, min_width=longest)  # identifiers are never cut
    table.add_column("severity", no_wrap=True)
    table.add_column("phase", no_wrap=True)
    table.add_column("title")
    for check in checks:
        table.add_row(check.meta.id, check.meta.severity.value, check.meta.phase, check.meta.title)
    Console().print(table)


@app.command()
def show(
    check_id: Annotated[str, typer.Argument(help="For example protocol.stdout_clean.")],
) -> None:
    """Describe one check: what it tests, why it matters and how to fix a failure."""
    checks = {c.meta.id: c for c in _all_checks()}
    if check_id not in checks:
        close = difflib.get_close_matches(check_id, list(checks), n=3)
        hint = f"; did you mean {', '.join(close)}?" if close else ""
        typer.echo(f"probe: no check {check_id!r}{hint}", err=True)
        raise typer.Exit(2)
    typer.echo(check_markdown(checks[check_id].meta), nl=False)
