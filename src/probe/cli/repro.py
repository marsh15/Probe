"""``probe repro``: run one finding's check again, or export its requests as a script."""

import asyncio
import os
from pathlib import Path
from typing import Annotated

import typer

from probe.cli.run import _fail, _parse_env
from probe.cli.summary import EXIT_INTERNAL, EXIT_SANDBOX, EXIT_UNAVAILABLE, EXIT_USAGE
from probe.engine.runscan import SandboxUnavailable, UsageError
from probe.repro.bundle import BundleError, load_bundle
from probe.repro.export_script import export_script
from probe.repro.replay import replay
from probe.util.sanitize_console import sanitize_console

EXIT_REPRODUCED = 0
EXIT_NOT_REPRODUCED = 1
EXIT_INCONCLUSIVE = 6


def repro(
    report: Annotated[Path, typer.Argument(help="report.json from `probe run`.")],
    finding: Annotated[str, typer.Option("--finding", help="Finding id (see the report).")],
    export: Annotated[
        Path | None, typer.Option("--export-script", help="Write a standalone shell script.")
    ] = None,
    no_run: Annotated[
        bool, typer.Option("--no-run", help="Only export; do not start the target.")
    ] = False,
    image: Annotated[
        str | None, typer.Option(help="Replay against this image instead of the scanned one.")
    ] = None,
    target_env: Annotated[
        list[str] | None, typer.Option(help="KEY=VALUE overriding the target's environment.")
    ] = None,
    verbose: Annotated[int, typer.Option("--verbose", "-v", count=True)] = 0,
) -> None:
    """Run the finding's check again on a fresh target: REPRODUCED or NOT REPRODUCED.

    Exit codes: 0 reproduced, 1 not reproduced, 2 usage error, 3 target did not start or
    answer, 4 internal error, 5 sandbox unavailable, 6 the check could not run.
    """
    try:
        bundle = load_bundle(report, finding)
    except BundleError as exc:
        raise _fail(str(exc), EXIT_USAGE) from exc
    if export is not None:
        export.write_text(export_script(bundle), encoding="utf-8")
        export.chmod(0o755)
        typer.echo(f"script: {export}")
    if no_run:
        raise typer.Exit(EXIT_REPRODUCED)
    try:
        outcome = asyncio.run(
            replay(bundle, target_env=_parse_env(target_env or []), image=image, environ=os.environ)
        )
    except UsageError as exc:
        raise _fail(str(exc)) from exc
    except SandboxUnavailable as exc:
        raise _fail(str(exc), EXIT_SANDBOX) from exc
    except Exception as exc:
        if verbose:
            raise
        raise _fail(f"internal error: {type(exc).__name__}: {exc}", EXIT_INTERNAL) from exc
    header = f"{bundle.check_id}  {bundle.tool or '-'}  {bundle.case_id}"
    typer.echo(sanitize_console(header))
    typer.echo(f"expected: {sanitize_console(str(bundle.expect))}")
    if outcome.verdict == "reproduced":
        typer.echo(f"REPRODUCED: {sanitize_console(outcome.detail)}")
        raise typer.Exit(EXIT_REPRODUCED)
    label = {
        "not_reproduced": "NOT REPRODUCED",
        "inconclusive": "INCONCLUSIVE",
        "target_unavailable": "TARGET UNAVAILABLE",
    }[outcome.verdict]
    typer.echo(f"{label}: {sanitize_console(outcome.detail)}")
    for other in outcome.other:
        typer.echo(f"  also found: {sanitize_console(other.title)} ({other.finding_id})")
    raise typer.Exit(
        {
            "not_reproduced": EXIT_NOT_REPRODUCED,
            "inconclusive": EXIT_INCONCLUSIVE,
            "target_unavailable": EXIT_UNAVAILABLE,
        }[outcome.verdict]
    )
