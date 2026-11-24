"""All six operability checks on the clean sandboxed reference server."""

import json
from pathlib import Path

import docker
import pytest

from probe.config.profile import Profile
from probe.engine.runscan import RunConfig, run_scan
from tests.sandbox.refserver_image import ensure_current_image
from tests.sandbox.test_http_bugs import leftovers

pytestmark = [pytest.mark.docker, pytest.mark.timeout(300)]


async def test_operability_clean_refserver(tmp_path: Path) -> None:
    try:
        client = docker.from_env(timeout=30)
        client.ping()
        client.images.get("probe-fixtures:dev")
        client.images.get("probe-refserver:dev")
    except docker.errors.DockerException as exc:
        pytest.skip(f"Docker or required images unavailable: {exc}")
    ensure_current_image(client)
    routes = tmp_path / "routes.yaml"
    routes.write_text(
        "collections:\n  items:\n    id_field: id\n    seed: [{id: 1, title: seeded}]\n"
    )
    profile = Profile.model_validate(
        {
            "version": 1,
            "target": {
                "image": "probe-refserver:dev",
                "command": ["refserver", "stdio"],
                "env": {
                    "REFSERVER_BACKEND_URL": "http://api.example.test",
                    "REFSERVER_BACKEND_TOKEN": "fixture-backend-token",
                },
            },
            "fixtures": {"http": {"routes": str(routes), "aliases": ["api.example.test"]}},
            "inputs": {"call_backend": [{"item_id": 1}]},
        }
    )
    report = await run_scan(
        RunConfig(
            out_dir=tmp_path / "out",
            profile=profile,
            mode="standard",
            only=["operability.*"],
        )
    )
    expected = {
        "operability.trace_propagated": "pass",
        "operability.meta_tolerated": "pass",
        "operability.burst_resilient": "pass",
        # The clean refserver holds its backend token in config, not a tool parameter.
        "operability.logs_no_secrets": "not_applicable",
        "operability.clean_shutdown": "pass",
        "operability.startup_time": "pass",
    }
    results = {r.check_id: r.status.value for r in report.results if r.check_id in expected}
    print(json.dumps({"scan_id": report.scan.id, "results": results}, sort_keys=True))
    assert report.scan.status == "completed"
    assert results == expected, report.model_dump_json(indent=2)
    assert leftovers(report.scan.id) == {"containers": 0, "networks": 0, "volumes": 0}
    # A PASS must reflect exercised tracing and backend faults, rather than empty coverage.
    by_id = {r.check_id: r for r in report.results}
    assert by_id["operability.trace_propagated"].calls > 0
    assert by_id["operability.burst_resilient"].calls >= 101
