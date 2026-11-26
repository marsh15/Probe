"""The conformance container runner against a fake Docker environment (no daemon needed), and
the live one in the nightly run."""

import os
import subprocess
import uuid
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import docker
import pytest

from probe import __version__
from probe.checks.official.conformance import LEGACY_PREFIX, MODERN_PREFIX, parse_stream
from probe.engine.runscan import RunConfig, _conformance_runner, _key
from probe.engine.versions import CATALOG_VERSION
from probe.runners.container_http import ContainerHttpRunner
from probe.sandbox import conformance
from probe.sandbox.conformance import ConformanceImageUnavailable, ContainerConformanceRunner
from probe.sandbox.docker_env import DockerEnv
from probe.sandbox.spec import labels, owned


def fake_sandbox() -> Any:
    container = MagicMock()
    container.logs.return_value = b"@@PROBE-END@@ 0\n"
    sandbox = MagicMock()
    sandbox.scan_id = "abc123"
    sandbox.created = 1_700_000_000.0
    sandbox.names = {
        "priv": "probe-priv-abc123",
        "pub": "probe-pub-abc123",
        "data": "probe-data-abc123",
    }
    sandbox._container.return_value = container
    return sandbox, container


async def test_the_container_is_private_hardened_and_always_removed() -> None:
    sandbox, container = fake_sandbox()
    out = await ContainerConformanceRunner(sandbox, "probe-conformance:dev").run(
        ["/opt/c020a11", "http://127.0.0.1:3000/mcp"], 30
    )
    assert out.startswith("@@PROBE-END@@")
    role, spec = sandbox._container.call_args.args
    assert role == "conformance" and spec["network"] == "probe-priv-abc123"
    assert spec["volumes"] == {} and spec["read_only"] is True and spec["cap_drop"] == ["ALL"]
    assert spec["command"] == ["/opt/c020a11", "http://127.0.0.1:3000/mcp"]
    assert "ports" not in spec and spec["user"] == "10001:10001"
    assert spec["environment"]["HOME"] == "/tmp"  # noqa: S108 - private container tmpfs
    container.start.assert_called_once()
    sandbox.remove_container.assert_called_once_with(container)


async def test_an_overrunning_suite_is_killed_and_its_output_still_read() -> None:
    sandbox, container = fake_sandbox()
    container.wait.side_effect = TimeoutError("too slow")
    out = await ContainerConformanceRunner(sandbox, "img").run(["x"], 1)
    container.kill.assert_called_once()
    assert out and sandbox.remove_container.called


def test_the_runner_is_used_only_for_sandboxed_http_targets_and_can_be_turned_off() -> None:
    http = MagicMock(spec=ContainerHttpRunner)
    http.sandbox = object()
    other = SimpleNamespace()
    cfg = RunConfig(out_dir=Path("x"))
    assert isinstance(_conformance_runner(cfg, http), ContainerConformanceRunner)
    assert _conformance_runner(cfg, other) is None  # type: ignore[arg-type]
    off = RunConfig(out_dir=cfg.out_dir, conformance=False)
    assert _conformance_runner(off, http) is None


def test_conformance_container_is_owned_for_teardown() -> None:
    resource = SimpleNamespace(
        name="probe-conformance-abc123-0123456789ab",
        attrs={"Config": {"Labels": labels("abc123", 1)}},
    )
    assert owned(resource, "abc123")
    assert not owned(resource, "another-scan")


def test_the_suite_uses_a_loopback_host_header() -> None:
    sandbox, _ = fake_sandbox()
    runner = ContainerHttpRunner("image", sandbox=sandbox, port=3001, path="/rpc")
    assert runner.conformance_url() == "http://127.0.0.1:3001/rpc"


async def test_missing_local_image_is_pulled_before_starting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox, _ = fake_sandbox()
    sandbox.client.images.get.side_effect = [docker.errors.ImageNotFound("gone"), object()]
    pull = MagicMock()
    monkeypatch.setattr(conformance.subprocess, "run", pull)
    await ContainerConformanceRunner(sandbox, "example/suite:1").run(["x"], 1)
    pull.assert_called_once()
    assert pull.call_args.args[0] == ["docker", "pull", "--", "example/suite:1"]
    assert 0 < pull.call_args.kwargs["timeout"] <= 1
    sandbox._container.assert_called_once()


async def test_local_image_is_not_pulled(monkeypatch: pytest.MonkeyPatch) -> None:
    sandbox, _ = fake_sandbox()
    pull = MagicMock()
    monkeypatch.setattr(conformance.subprocess, "run", pull)
    await ContainerConformanceRunner(sandbox, "example/suite:1").run(["x"], 1)
    pull.assert_not_called()


async def test_pull_failure_leaves_no_container(monkeypatch: pytest.MonkeyPatch) -> None:
    sandbox, _ = fake_sandbox()
    sandbox.client.images.get.side_effect = docker.errors.ImageNotFound("gone")
    pull = MagicMock(side_effect=subprocess.CalledProcessError(1, "docker pull"))
    monkeypatch.setattr(conformance.subprocess, "run", pull)
    with pytest.raises(ConformanceImageUnavailable):
        await ContainerConformanceRunner(sandbox, "example/suite:1").run(["x"], 1)
    sandbox._container.assert_not_called()


def test_default_suite_image_matches_the_release_and_override_reaches_the_runner() -> None:
    cfg = RunConfig(out_dir=Path("x"))
    assert cfg.conformance_image == f"ghcr.io/marsh15/conformance:{__version__}"
    target = MagicMock(spec=ContainerHttpRunner)
    target.sandbox = fake_sandbox()[0]
    override = _conformance_runner(replace(cfg, conformance_image="example/suite:1"), target)
    assert override._image == "example/suite:1"


def test_catalog_and_scan_key_track_the_new_optional_check() -> None:
    cfg = RunConfig(out_dir=Path("x"))
    assert CATALOG_VERSION == "0.2"
    assert _key(cfg, "profile", True) != _key(replace(cfg, conformance=False), "profile", True)


@pytest.mark.docker
@pytest.mark.parametrize(
    ("prefix", "scenario"),
    [(LEGACY_PREFIX, "server-initialize"), (MODERN_PREFIX, "server-stateless")],
)
async def test_pinned_suite_reaches_the_refserver_with_host_validation(
    prefix: str, scenario: str, tmp_path: Path
) -> None:
    image = os.environ.get("PROBE_CONFORMANCE_TEST_IMAGE", "probe-conformance:dev")
    refserver = "probe-refserver:dev"
    try:
        client = docker.from_env(timeout=10)
        for required in (image, refserver, "probe-fixtures:dev"):
            client.images.get(required)
    except docker.errors.DockerException as exc:
        pytest.skip(f"Docker or a required local image is unavailable: {exc}")

    sandbox = DockerEnv(f"t36-{uuid.uuid4().hex[:12]}", client=client, cache_dir=tmp_path)
    target = ContainerHttpRunner(
        refserver, sandbox=sandbox, command=["refserver", "http", "--port", "3000"]
    )
    try:
        await target.start()
        stream = parse_stream(
            await ContainerConformanceRunner(sandbox, image).run(
                [prefix, target.conformance_url(), "--scenario", scenario], 45
            )
        )
        assert stream.error is None and stream.exit_status is not None, stream
        assert any(c.scenario == scenario and c.status == "pass" for c in stream.checks), stream
        assert not any(c.host_rejection for c in stream.checks), stream
        assert len(sandbox.containers) == 3  # data holder, server and relay
    finally:
        await target.stop()
    assert not sandbox.containers and not sandbox.networks and sandbox.lease is None
