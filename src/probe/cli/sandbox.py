"""Report sandbox prerequisites and collect expired, proven-owned resources."""

from pathlib import Path
from typing import Annotated

import typer

from probe.sandbox import gc as sandbox_api
from probe.sandbox.docker_env import DEFAULT_CACHE
from probe.sandbox.spec import validate_scan_id
from probe.util.sanitize_console import sanitize_console

app = typer.Typer(
    help="Inspect sandbox prerequisites and clean up expired scans.", no_args_is_help=True
)


def _diagnostic(message: str) -> None:
    typer.echo(sanitize_console(message, single_line=True, max_len=500), err=True)


@app.command()
def doctor() -> None:
    """Check Docker and sandbox configuration without creating resources."""
    result = sandbox_api.doctor()
    typer.echo(f"Docker CLI: {'available' if result.get('docker_cli') else 'missing'}")
    typer.echo(f"Docker daemon: {'reachable' if result.get('daemon') else 'unreachable'}")
    typer.echo(f"Linux engine: {'yes' if result.get('linux') else 'no'}")
    if result.get("architecture"):
        typer.echo(
            "Architecture: " + sanitize_console(str(result["architecture"]), single_line=True)
        )
    typer.echo(f"Public subnet pool: {'valid' if result.get('public_pool') else 'not verified'}")
    typer.echo(f"gVisor (optional): {'available' if result.get('runsc') else 'not installed'}")
    if result.get("error"):
        _diagnostic(str(result["error"]))
    if not all(result.get(key) for key in ("docker_cli", "daemon", "linux", "public_pool")):
        raise typer.Exit(1)


@app.command()
def gc(
    scan_id: Annotated[
        str | None, typer.Option("--scan-id", help="Collect only this scan's expired resources.")
    ] = None,
    older_than: Annotated[
        float,
        typer.Option("--older-than", min=3600, help="Minimum age in seconds (at least 3600)."),
    ] = 3600,
    cache_dir: Annotated[
        Path,
        typer.Option(
            "--cache-dir", file_okay=False, resolve_path=True, help="Subnet lease directory."
        ),
    ] = DEFAULT_CACHE,
) -> None:
    """Remove expired Probe resources and abandoned subnet leases."""
    if scan_id is not None:
        try:
            validate_scan_id(scan_id)
        except ValueError as exc:
            raise typer.BadParameter(str(exc), param_hint="--scan-id") from exc
    try:
        report = sandbox_api.collect(scan_id=scan_id, age_s=older_than, cache_dir=cache_dir)
    except Exception as exc:
        _diagnostic(f"Sandbox cleanup failed: {exc}")
        raise typer.Exit(1) from None
    typer.echo(
        f"Removed {len(report.removed)} sandbox resource(s); "
        f"released {len(report.leases)} subnet lease(s)."
    )
    for error in report.errors:
        _diagnostic(error)
    if report.errors:
        raise typer.Exit(1)
