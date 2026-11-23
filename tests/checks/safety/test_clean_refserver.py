"""The clean reference server refuses private and file URLs in the real sandbox."""

from pathlib import Path
from typing import Any

import docker
import pytest

from probe.config.profile import Profile
from probe.engine.outcomes import Status
from probe.engine.runscan import RunConfig, run_scan
from tests.sandbox.refserver_image import ensure_current_image

pytestmark = [pytest.mark.docker, pytest.mark.timeout(1500)]


@pytest.fixture(scope="module", autouse=True)
def require_images() -> None:
    try:
        client = docker.from_env(timeout=30)
        client.ping()
        client.images.get("probe-fixtures:dev")
        client.images.get("probe-refserver:dev")
    except docker.errors.DockerException as exc:
        pytest.skip(f"Docker or the fixture/reference images are unavailable: {exc}")
    ensure_current_image(client)


@pytest.mark.parametrize("transport", ["stdio", "http"])
async def test_safety_clean_refserver_passes_and_cleans_up(tmp_path: Path, transport: str) -> None:
    seed = tmp_path / "seed"
    seed.mkdir()
    profile = Profile.model_validate(
        {
            "target": {
                "transport": transport,
                "image": "probe-refserver:dev",
                "env": {"REFSERVER_DATA": "/data"},
                "command": [
                    "refserver",
                    transport,
                    *(["--port", "3000"] if transport == "http" else []),
                ],
                **({"http": {"port": 3000, "path": "/mcp"}} if transport == "http" else {}),
            },
            "fixtures": {
                "fs": {"seed_dir": str(seed), "sentinel": True},
                "http": {},
                # This file tells the refserver to use /data instead of generating its
                # own unrelated sentinel and 10,000-note seed during startup.
                "sqlite": {"path": "/data/db/notes.db"},
            },
        }
    )
    report = await run_scan(RunConfig(out_dir=tmp_path / "out", profile=profile, only=["safety.*"]))
    assert report.scan.status == "completed"
    outcomes = {r.check_id: r.status for r in report.results if r.check_id.startswith("safety.")}
    assert outcomes == {
        "safety.ssrf_blocked": Status.PASS,
        "safety.file_scheme_blocked": Status.PASS,
    }
    assert not [f for f in report.findings if f.check_id.startswith("safety.")]
    client = docker.from_env(timeout=10)
    filters: Any = {"label": f"probe.scan={report.scan.id}"}
    assert not client.containers.list(all=True, filters=filters)
    assert not client.networks.list(filters=filters)
    assert not client.volumes.list(filters=filters)
