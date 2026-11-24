"""Every injected bug in the Docker sandbox (nightly and on demand; needs the images)."""

import asyncio
from pathlib import Path

import docker
import pytest

from probe.selfval.expected import CLEAN, load_expected
from probe.selfval.report import judge
from probe.selfval.runner import Job, Setup, run_jobs
from tests.sandbox.refserver_image import ensure_current_image

REPO = Path(__file__).parents[2]
pytestmark = [pytest.mark.docker, pytest.mark.timeout(7200)]


def test_every_bug_is_detected_and_the_clean_server_stays_clean(tmp_path: Path) -> None:
    try:
        client = docker.from_env(timeout=30)
        client.ping()
        client.images.get("probe-fixtures:dev")
    except docker.errors.DockerException as exc:
        pytest.skip(f"Docker or required images unavailable: {exc}")
    ensure_current_image(client)
    wanted = load_expected(REPO / "tests" / "selfval" / "expected.yaml")
    jobs = [
        Job(name, transport, 1) for name, entry in wanted.items() for transport in entry.transports
    ]
    setup = Setup(REPO / "profiles", tmp_path, "deep", local=False)
    results = asyncio.run(run_jobs(setup, jobs, workers=4))
    if all("SandboxUnavailable" in r.note for r in results):
        pytest.skip("Docker is not available")
    summary = judge(wanted, results)
    missed = [r.bug for r in summary.rows if not r.detected]
    assert not missed, missed
    assert not summary.false_positives, summary.false_positives
    assert not summary.unexpected, summary.unexpected
    assert CLEAN in wanted
