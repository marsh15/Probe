"""The reference server's HTTP bugs, found by real scans inside the sandbox.

Each scan runs the whole check set against `probe-refserver:dev` in the hardened container,
reached over HTTP through the loopback-only relay, with one bug switched on. What fails must be
exactly what tests/selfval/expected.yaml says: the bug's primary checks plus its justified
collateral, and nothing else. A clean scan must have no failures at all.
"""

import json
from pathlib import Path
from typing import Any

import docker
import pytest
import yaml

from probe.config.profile import load_profile
from probe.engine.runscan import RunConfig, run_scan
from probe.report.models import ScanReport
from tests.sandbox.refserver_image import ensure_current_image

pytestmark = [pytest.mark.docker, pytest.mark.timeout(1500)]  # a stale image is rebuilt once
ROOT = Path(__file__).parents[2]
EXPECTED = yaml.safe_load((ROOT / "tests" / "selfval" / "expected.yaml").read_text())
HTTP_BUGS = sorted(b for b, e in EXPECTED.items() if b != "clean" and "http" in e["transports"])


@pytest.fixture(scope="module", autouse=True)
def _require_images() -> None:
    try:
        client = docker.from_env(timeout=30)
        client.ping()
        client.images.get("probe-fixtures:dev")
    except docker.errors.DockerException as exc:
        pytest.skip(f"Docker or the fixtures image is unavailable: {exc}")
    ensure_current_image(client)  # an out-of-date image would refuse the newer bugs


async def scan(tmp_path: Path, bug: str | None) -> ScanReport:
    profile = load_profile(ROOT / "profiles" / "refserver-http.yaml")
    cfg = RunConfig(
        out_dir=tmp_path / "out",
        profile=profile,
        mode="standard",
        target_env={"PROBE_REF_BUGS": bug} if bug else {},
    )
    return await run_scan(cfg)


def failing(report: ScanReport) -> set[str]:
    return {r.check_id for r in report.results if r.status.value == "fail"}


def leftovers(scan_id: str) -> dict[str, int]:
    client = docker.from_env(timeout=10)
    flt: Any = {"label": f"probe.scan={scan_id}"}
    return {
        "containers": len(client.containers.list(all=True, filters=flt)),
        "networks": len(client.networks.list(filters=flt)),
        "volumes": len(client.volumes.list(filters=flt)),
    }


async def test_the_clean_server_in_the_sandbox_over_http_has_no_failures(tmp_path: Path) -> None:
    report = await scan(tmp_path, None)
    assert report.scan.status == "completed"
    assert report.scan.sandboxed and report.target.transport.value == "http"
    assert report.target.image_digest and report.target.image_digest.startswith("sha256:")
    assert not failing(report)
    assert not [r for r in report.results if r.status.value == "error"]
    assert leftovers(report.scan.id) == {"containers": 0, "networks": 0, "volumes": 0}


@pytest.mark.parametrize("bug", HTTP_BUGS)
async def test_http_bug_is_found_in_the_sandbox(tmp_path: Path, bug: str) -> None:
    expected = EXPECTED[bug]
    report = await scan(tmp_path, bug)
    found = failing(report)
    primary = set(expected["primary"])
    allowed = primary | set(expected.get("allowed_collateral", []))
    assert primary <= found, f"{bug}: missed {sorted(primary - found)}"
    assert found <= allowed, f"{bug}: unexpected failures {sorted(found - allowed)}"
    assert leftovers(report.scan.id) == {"containers": 0, "networks": 0, "volumes": 0}


def test_the_relay_port_is_published_on_loopback_only() -> None:
    """The relay is the one door into the target network: it must never be reachable remotely."""
    import asyncio
    import uuid

    from probe.runners.container_http import ContainerHttpRunner
    from probe.sandbox.docker_env import DockerEnv

    async def inspect() -> list[str]:
        scan_id = f"relay-{uuid.uuid4().hex[:8]}"
        env = DockerEnv(scan_id)
        runner = ContainerHttpRunner(
            "probe-refserver:dev",
            sandbox=env,
            command=["refserver", "http", "--port", "3000"],
        )
        try:
            await runner.start()
            relay = runner._relay  # the fixture container
            relay.reload()
            ports = relay.attrs["NetworkSettings"]["Ports"]["8080/tcp"]
            return [binding["HostIp"] for binding in ports]
        finally:
            await runner.stop()

    assert set(asyncio.run(inspect())) == {"127.0.0.1"}


def test_expected_yaml_names_the_http_bugs_this_file_covers() -> None:
    assert HTTP_BUGS == ["b01", "b02", "b03", "b04", "b05", "b06", "b08", "b51"]
    json.dumps(EXPECTED)  # sanity: plain data
