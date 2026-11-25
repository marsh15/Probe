"""``probe selfval``: does Probe notice every bug injected into the reference server?"""

import asyncio
from pathlib import Path
from typing import Annotated

import typer

from probe.cli.summary import EXIT_SANDBOX
from probe.config.modes import MODES
from probe.selfval.expected import CLEAN, ExpectedError, load_expected
from probe.selfval.report import judge, write_reports
from probe.selfval.runner import Job, Setup, run_jobs

# Without Docker, on every pull request: the clean server and bugs that show up locally.
FAST_BUGS = ("b03", "b04", "b07", "b10", "b11", "b12", "b15", "b16", "b21", "b23", "b24", "b57")


def _ints(text: str) -> list[int]:
    try:
        return [int(part) for part in text.split(",") if part.strip()]
    except ValueError:
        raise typer.BadParameter(f"not a list of integers: {text!r}") from None


def selfval(
    bugs: Annotated[str, typer.Option(help="Comma-separated bug ids, or 'all'.")] = "all",
    seeds: Annotated[str, typer.Option(help="Comma-separated seeds.")] = "1,2,3",
    workers: Annotated[int, typer.Option(help="Scans to run at once.")] = 1,
    mode: Annotated[str, typer.Option(help="quick, standard or deep.")] = "deep",
    out: Annotated[Path, typer.Option(help="Output directory.")] = Path("selfval-out"),
    expected: Annotated[Path, typer.Option(help="Expectations file.")] = Path(
        "tests/selfval/expected.yaml"
    ),
    profiles: Annotated[Path, typer.Option(help="Directory with the refserver profiles.")] = Path(
        "profiles"
    ),
    local: Annotated[
        bool, typer.Option("--local", help="Run the server as a plain process, without Docker.")
    ] = False,
    refserver_src: Annotated[
        Path, typer.Option(help="refserver source directory (seeds the data).")
    ] = Path("reference/refserver/src"),
    transports: Annotated[str, typer.Option(help="stdio, http or both (comma-separated).")] = (
        "stdio,http"
    ),
    fast: Annotated[
        bool,
        typer.Option("--fast", help="The pull-request subset: local, stdio, standard, seed 1."),
    ] = False,
) -> None:
    """Scan the reference server clean and with each bug on; report detection, false positives
    and unexpected failures. Exit 0 only if every bug is detected and nothing else fails."""
    if fast:
        local, mode, seeds, transports = True, "standard", "1", "stdio"
        bugs = ",".join(FAST_BUGS)
    if mode not in MODES:
        raise typer.BadParameter(f"unknown mode {mode!r}; choose quick, standard or deep")
    try:
        wanted = load_expected(expected)
    except ExpectedError as exc:
        typer.echo(f"probe: {exc}", err=True)
        raise typer.Exit(2) from exc
    names = [n for n in wanted if n != CLEAN]
    if bugs != "all":
        chosen = [b.strip() for b in bugs.split(",") if b.strip()]
        unknown = [b for b in chosen if b not in wanted or b == CLEAN]
        if unknown:
            typer.echo(f"probe: no expectations for {', '.join(unknown)}", err=True)
            raise typer.Exit(2)
        names = chosen
    allowed_transports = {t.strip() for t in transports.split(",") if t.strip()}
    seed_list = _ints(seeds)
    jobs = [
        Job(name, transport, seed)
        for name in [CLEAN, *names]
        for transport in wanted[name].transports
        if transport in allowed_transports
        for seed in seed_list
    ]
    if not any(job.bug != CLEAN for job in jobs):
        typer.echo(
            "probe: nothing to test: no bug is left to run with these --bugs, --seeds and "
            "--transports",
            err=True,
        )
        raise typer.Exit(2)
    setup = Setup(profiles, out, mode, local, refserver_src)
    typer.echo(f"selfval: {len(jobs)} scans, {workers} at a time ({setup.backend}, {mode})")
    results = asyncio.run(run_jobs(setup, jobs, workers))
    if results and all("SandboxUnavailable" in r.note for r in results):
        typer.echo(f"probe: {results[0].note}\nprobe: use --local to run without Docker", err=True)
        raise typer.Exit(EXIT_SANDBOX)
    wanted_run = {n: wanted[n] for n in [CLEAN, *names]}
    summary = judge(wanted_run, results)
    where = write_reports(summary, results, out, mode=mode, seeds=seed_list, backend=setup.backend)
    typer.echo((where / "report.md").read_text())
    typer.echo(f"report: {where / 'report.json'}")
    raise typer.Exit(0 if summary.passed else 1)
