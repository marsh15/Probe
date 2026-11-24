"""Run one scan of the reference server with a bug switched on, in the sandbox or locally.

The sandbox is the real thing: the image from ``reference/refserver`` run by Docker, fixtures and
all. ``--local`` runs the same server as a plain process (no Docker): fewer checks apply (those
that need fixtures are skipped), but a developer without Docker still gets a quick answer.
"""

import asyncio
import contextlib
import os
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path

from probe.config.profile import Profile, load_profile, resolve_profile, scan_token
from probe.engine.outcomes import Mode, Status
from probe.engine.runscan import RunConfig, run_scan
from probe.report.json_out import write_report
from probe.report.models import ScanReport

PROFILES = {
    ("sandbox", "stdio"): "refserver.yaml",
    ("sandbox", "http"): "refserver-http.yaml",
    ("local", "stdio"): "refserver-local.yaml",
    ("local", "http"): "refserver-http.yaml",
}
_HTTP_START_S = 60.0


@dataclass(frozen=True, slots=True)
class Job:
    bug: str  # "clean" or a bug id
    transport: str
    seed: int

    @property
    def label(self) -> str:
        return f"{self.bug}-{self.transport}-s{self.seed}"


@dataclass(slots=True)
class JobResult:
    job: Job
    scan_status: str  # completed | target_unavailable | aborted | error
    failed: tuple[str, ...] = ()
    errored: tuple[str, ...] = ()
    note: str = ""


def _summarize(job: Job, report: ScanReport) -> JobResult:
    failed = tuple(sorted(r.check_id for r in report.results if r.status is Status.FAIL))
    errored = tuple(sorted(r.check_id for r in report.results if r.status is Status.ERROR))
    return JobResult(job, report.scan.status, failed, errored)


@dataclass(frozen=True, slots=True)
class Setup:
    profiles_dir: Path
    out_dir: Path
    mode: Mode
    local: bool
    refserver_src: Path | None = None  # local runs: where the refserver package lives

    @property
    def backend(self) -> str:
        return "local" if self.local else "sandbox"


def _profile(setup: Setup, job: Job) -> Profile:
    return load_profile(setup.profiles_dir / PROFILES[(setup.backend, job.transport)])


def _bug_env(job: Job) -> dict[str, str]:
    return {} if job.bug == "clean" else {"PROBE_REF_BUGS": job.bug}


async def run_job(setup: Setup, job: Job) -> JobResult:
    out = setup.out_dir / "jobs" / job.label
    try:
        if setup.local:
            report = await _run_local(setup, job, out)
        else:
            report = await run_scan(
                RunConfig(
                    out_dir=out,
                    profile=_profile(setup, job),
                    mode=setup.mode,
                    seed=job.seed,
                    target_env=_bug_env(job),
                )
            )
    except Exception as exc:  # one broken job must not hide the others
        return JobResult(job, "error", note=f"{type(exc).__name__}: {exc}")
    write_report(report, out)
    return _summarize(job, report)


def _refserver_env(setup: Setup, job: Job, data: Path) -> dict[str, str]:
    """What the refserver process needs beyond the inherited environment."""
    src = setup.refserver_src
    if src is None:
        raise ValueError("a local run needs the refserver source directory")
    return {"PYTHONPATH": str(src), "REFSERVER_DATA": str(data), **_bug_env(job)}


def _seed_data(setup: Setup, root: Path, job: Job) -> Path:
    """A private, freshly seeded data directory: scans write to it."""
    data = root / "data"
    env = {**os.environ, **_refserver_env(setup, job, data)}
    env.pop("PROBE_REF_BUGS", None)
    subprocess.run(  # noqa: S603 - fixed argv, this interpreter
        [sys.executable, "-m", "refserver", "seed", "--out", str(data)],
        check=True,
        env=env,
        capture_output=True,
        timeout=120,
    )
    return data


async def _run_local(setup: Setup, job: Job, out: Path) -> ScanReport:
    with tempfile.TemporaryDirectory(prefix=f"selfval-{job.label}-") as scratch:
        data = await asyncio.to_thread(_seed_data, setup, Path(scratch), job)
        env = _refserver_env(setup, job, data)
        profile = _profile(setup, job)
        if job.transport == "stdio":
            argv = [sys.executable, "-m", "refserver", "stdio"]
            return await run_scan(
                RunConfig(
                    out_dir=out,
                    command=argv,
                    target_env=env,
                    profile=profile,
                    mode=setup.mode,
                    seed=job.seed,
                    allow_side_effects=True,
                )
            )
        resolved = resolve_profile(profile, token=scan_token(job.seed, profile.hash), environ={})
        async with _local_http({**os.environ, **env, **resolved.env}) as url:
            return await run_scan(
                RunConfig(
                    out_dir=out,
                    url=url,
                    profile=profile,
                    mode=setup.mode,
                    seed=job.seed,
                    allow_side_effects=True,
                )
            )


@contextlib.asynccontextmanager
async def _local_http(env: dict[str, str]) -> AsyncIterator[str]:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    server = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "refserver",
        "http",
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        env=env,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + _HTTP_START_S
        while True:
            if server.returncode is not None:
                raise RuntimeError("refserver http exited before it was ready")
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
                break
            except OSError:
                if time.monotonic() > deadline:
                    raise RuntimeError("refserver http did not start in time") from None
                await asyncio.sleep(0.2)
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        if server.returncode is None:
            server.terminate()
            try:
                await asyncio.wait_for(server.wait(), 10)
            except TimeoutError:
                server.kill()
                await server.wait()


async def run_jobs(setup: Setup, jobs: list[Job], workers: int) -> list[JobResult]:
    """Every job, at most ``workers`` at a time, in the order given."""
    gate = asyncio.Semaphore(max(1, workers))

    async def guarded(job: Job) -> JobResult:
        async with gate:
            return await run_job(setup, job)

    return list(await asyncio.gather(*(guarded(j) for j in jobs)))
