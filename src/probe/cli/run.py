"""``probe run``: scan one MCP server and report what was found."""

import asyncio
import math
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from probe.cli.summary import (
    EXIT_INTERNAL,
    EXIT_SANDBOX,
    EXIT_USAGE,
    FAIL_ON,
    exit_code_for,
    render_summary,
)
from probe.config.modes import MODES
from probe.config.profile import Profile, ProfileError, load_profile
from probe.engine.runscan import RunConfig, SandboxUnavailable, UsageError, run_scan
from probe.report.html import write_html
from probe.report.json_out import write_report
from probe.repro.bundle import write_bundles

AVAILABLE_FORMATS = ("json", "html")  # sarif, md and badge arrive with the report tasks


def _fail(message: str, code: int = EXIT_USAGE) -> "typer.Exit":
    typer.echo(f"probe: {message}", err=True)
    return typer.Exit(code)


def _parse_env(pairs: list[str]) -> dict[str, str]:
    env: dict[str, str] = {}
    for pair in pairs:
        key, sep, value = pair.partition("=")
        if not sep or not key:
            raise _fail(f"--target-env needs KEY=VALUE, got {pair!r}")
        env[key] = value
    return env


def run(
    ctx: typer.Context,
    url: Annotated[str | None, typer.Option(help="Scan a running server at this URL.")] = None,
    profile: Annotated[Path | None, typer.Option(help="Profile file (YAML).")] = None,
    mode: Annotated[str, typer.Option(help="quick, standard or deep.")] = "standard",
    seed: Annotated[int, typer.Option(help="Seed for every random choice.")] = 0,
    era: Annotated[str, typer.Option(help="auto, modern or legacy.")] = "auto",
    allow_side_effects: Annotated[
        bool, typer.Option(help="Also call tools that may write.")
    ] = False,
    only: Annotated[
        list[str] | None, typer.Option(help="Run only checks matching this glob.")
    ] = None,
    skip: Annotated[list[str] | None, typer.Option(help="Skip checks matching this glob.")] = None,
    out: Annotated[Path, typer.Option(help="Output directory.")] = Path("probe-out"),
    output_format: Annotated[
        str, typer.Option("--format", help="Comma-separated report formats.")
    ] = "json,html",
    fail_on: Annotated[str, typer.Option(help="critical, high, medium, low or none.")] = "high",
    min_score: Annotated[
        float | None, typer.Option(help="Minimum overall score (0..100); ungraded scans fail.")
    ] = None,
    timeout_scale: Annotated[float, typer.Option(help="Multiply every timeout.")] = 1.0,
    image: Annotated[
        str | None, typer.Option(help="Run the target in the sandbox from this image.")
    ] = None,
    sandbox: Annotated[
        bool | None,
        typer.Option(
            "--sandbox/--no-sandbox", help="Default: on when an image is given (or in the profile)."
        ),
    ] = None,
    i_have_permission: Annotated[
        bool, typer.Option(help="Allow a target that is not local or private.")
    ] = False,
    secret_env: Annotated[
        list[str] | None, typer.Option(help="Env var whose value must never appear in artifacts.")
    ] = None,
    target_env: Annotated[
        list[str] | None, typer.Option(help="KEY=VALUE for the target's environment.")
    ] = None,
    verbose: Annotated[int, typer.Option("--verbose", "-v", count=True)] = 0,
    quiet: Annotated[bool, typer.Option("--quiet", "-q")] = False,
) -> None:
    """Scan an MCP server. Put the server command after `--`; probe options go before it.

    Exit codes: 0 ok, 1 findings at or above --fail-on or --min-score unmet (including null
    scores), 2 usage error, 3 target did not start or answer, 4 internal error,
    5 sandbox unavailable.
    """
    command = list(ctx.args) or None
    if mode not in MODES:
        raise _fail(f"unknown mode {mode!r}; choose quick, standard or deep")
    if era not in ("auto", "modern", "legacy"):
        raise _fail(f"unknown era {era!r}; choose auto, modern or legacy")
    if fail_on not in FAIL_ON:
        raise _fail(f"unknown --fail-on {fail_on!r}; choose {', '.join(FAIL_ON)}")
    if min_score is not None and (not math.isfinite(min_score) or not 0 <= min_score <= 100):
        raise _fail("--min-score must be a finite number from 0 to 100")
    formats = [f.strip() for f in output_format.split(",") if f.strip()]
    unknown = [f for f in formats if f not in AVAILABLE_FORMATS]
    if unknown or not formats:
        raise _fail(
            f"format(s) {', '.join(unknown) or '(none)'} not available yet; "
            f"available: {', '.join(AVAILABLE_FORMATS)}"
        )
    try:
        loaded = load_profile(profile) if profile else Profile()
    except ProfileError as exc:
        raise _fail(str(exc)) from exc
    config = RunConfig(
        out_dir=out,
        command=command,
        url=url,
        profile=loaded,
        mode=mode,
        seed=seed,
        era=era,  # type: ignore[arg-type]
        allow_side_effects=allow_side_effects,
        only=only or [],
        skip=skip or [],
        timeout_scale=timeout_scale,
        image=image,
        sandbox=sandbox,
        i_have_permission=i_have_permission,
        secret_env=secret_env or [],
        target_env=_parse_env(target_env or []),
    )
    console = Console()
    try:
        report = asyncio.run(run_scan(config))
    except UsageError as exc:
        raise _fail(str(exc)) from exc
    except SandboxUnavailable as exc:
        raise _fail(str(exc), EXIT_SANDBOX) from exc
    except Exception as exc:
        if verbose:
            raise
        raise _fail(f"internal error: {type(exc).__name__}: {exc}", EXIT_INTERNAL) from exc
    path = write_report(report, out)
    write_bundles(report, config, out)
    if "html" in formats:
        write_html(report, out)
    render_summary(report, console, verbose=verbose, quiet=quiet)
    console.print(f"report: {path}", highlight=False)
    raise typer.Exit(exit_code_for(report, fail_on, min_score))
