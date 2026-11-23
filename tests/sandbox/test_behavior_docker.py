"""The behavior checks against the clean reference server in the sandbox, with fixtures.

The fixtures make the write tools callable and let replay_idempotent and invalid_input_rejected
watch state, so this is the run that exercises everything the fast tests only simulate.
"""

from pathlib import Path
from typing import Any

import docker
import pytest

from probe.config.profile import parse_profile
from probe.engine.runscan import RunConfig, run_scan
from tests.sandbox.refserver_image import ensure_current_image

pytestmark = [pytest.mark.docker, pytest.mark.timeout(1500)]


@pytest.fixture(scope="module", autouse=True)
def _require_images() -> None:
    try:
        client = docker.from_env(timeout=30)
        client.ping()
        client.images.get("probe-fixtures:dev")
    except docker.errors.DockerException as exc:
        pytest.skip(f"Docker or the fixtures image is unavailable: {exc}")
    ensure_current_image(client)


def leftovers(scan_id: str) -> int:
    client = docker.from_env(timeout=10)
    flt: Any = {"label": f"probe.scan={scan_id}"}
    return (
        len(client.containers.list(all=True, filters=flt))
        + len(client.networks.list(filters=flt))
        + len(client.volumes.list(filters=flt))
    )


async def test_the_clean_server_passes_every_behavior_check_with_fixtures(
    tmp_path: Path, seeded_data: Path
) -> None:
    profile = parse_profile(
        f"""
version: 1
name: refserver
target: {{transport: stdio, image: "probe-refserver:dev", command: ["refserver", "stdio"]}}
fixtures:
  fs: {{seed_dir: "{seeded_data}", allowed_roots: ["/data/allowed"], sentinel: false}}
"""
    )
    report = await run_scan(RunConfig(out_dir=tmp_path / "out", profile=profile, mode="standard"))
    by_id = {r.check_id: r for r in report.results}
    behavior = {i: r for i, r in by_id.items() if i.startswith("behavior.")}
    bad = {i: (r.status.value, r.reason) for i, r in behavior.items() if r.status.value != "pass"}
    assert not bad, bad
    assert by_id["schema.output_conforms"].status.value == "pass"
    assert not [r for r in report.results if r.status.value in ("fail", "error")]
    assert leftovers(report.scan.id) == 0
