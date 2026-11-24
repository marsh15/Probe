"""``probe report`` and ``probe diff``: turn reports into other formats and compare them."""

import json
from pathlib import Path
from typing import Annotated

import typer

from probe.cli.run import _fail
from probe.report.diff import diff_reports, render_diff_md
from probe.report.outputs import FILE_NAMES, FORMATS, ReportError, load_report, render


def report(
    source: Annotated[Path, typer.Argument(metavar="REPORT", help="report.json from `probe run`.")],
    output_format: Annotated[
        str, typer.Option("--format", help="html, md, sarif, badge or json.")
    ] = "html",
    out: Annotated[
        Path | None, typer.Option(help="Where to write it (default: next to the report).")
    ] = None,
    sarif_anchor: Annotated[
        str, typer.Option(help="File that SARIF results are attached to.")
    ] = "README.md",
    badge_style: Annotated[str, typer.Option(help="grade or coverage.")] = "grade",
) -> None:
    """Write one output format from a finished report."""
    if output_format not in FORMATS:
        raise _fail(f"unknown format {output_format!r}; choose {', '.join(FORMATS)}")
    if badge_style not in ("grade", "coverage"):
        raise _fail("--badge-style must be grade or coverage")
    try:
        loaded = load_report(source)
    except ReportError as exc:
        raise _fail(str(exc)) from exc
    text = render(
        loaded,
        output_format,
        anchor=sarif_anchor,
        badge_style=badge_style,  # type: ignore[arg-type]
    )
    target = out or source.parent / FILE_NAMES[output_format]
    target.write_text(text, encoding="utf-8")
    typer.echo(f"{output_format}: {target}")


def diff(
    base: Annotated[Path, typer.Argument(help="The earlier report.json.")],
    head: Annotated[Path, typer.Argument(help="The later report.json.")],
    output_format: Annotated[str, typer.Option("--format", help="md or json.")] = "md",
) -> None:
    """Score change, new findings and fixed findings between two reports."""
    if output_format not in ("md", "json"):
        raise _fail("--format must be md or json")
    try:
        result = diff_reports(load_report(base), load_report(head))
    except ReportError as exc:
        raise _fail(str(exc)) from exc
    typer.echo(json.dumps(result, indent=2) if output_format == "json" else render_diff_md(result))
