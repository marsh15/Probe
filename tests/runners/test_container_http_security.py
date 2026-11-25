from unittest.mock import AsyncMock

from probe.config.profile import parse_profile
from probe.engine.runscan import RunConfig, _container_runner, _resolve
from probe.runners.container_http import ContainerHttpRunner
from probe.sandbox.docker_env import DockerEnv
from probe.wire.recorder import Recorder
from tests.sandbox.fakes import Client


async def test_http_restarts_replace_relay_with_current_private_ip(tmp_path, monkeypatch):
    with DockerEnv("httprelay", client=Client(), cache_dir=tmp_path) as env:
        runner = ContainerHttpRunner("image", sandbox=env, request_timeout_s=180)
        create = env.create_target
        addresses = iter(("172.16.0.2", "172.16.0.3"))

        def create_target(*args, **kwargs):
            target = create(*args, **kwargs)
            target.attrs["NetworkSettings"]["Networks"][env.names["priv"]] = {
                "IPAddress": next(addresses)
            }
            return target

        monkeypatch.setattr(env, "create_target", create_target)
        monkeypatch.setattr(env, "control_url", lambda *args: "http://127.0.0.1:12345")
        monkeypatch.setattr(runner, "_wait_ready", AsyncMock())
        first = await runner._spawn()
        old_relay = runner._relay
        second = await runner._spawn()
        assert old_relay.removed
        command = runner._relay.kwargs["command"]
        assert command[command.index("--target-host") + 1] == "172.16.0.3"
        assert float(runner._relay.kwargs["environment"]["PROBE_RELAY_IDLE_TIMEOUT"]) == 190
        await first.transport.close()
        await second.transport.close()


def test_scaled_request_timeout_reaches_http_runner(tmp_path, monkeypatch):
    profile = parse_profile("version: 1\ntarget:\n  transport: http\n  image: fake\n")
    cfg = RunConfig(out_dir=tmp_path, profile=profile, mode="deep", timeout_scale=3)
    resolved, _ = _resolve(cfg)
    monkeypatch.setattr(
        "probe.engine.runscan.DockerEnv",
        lambda scan: DockerEnv(scan, client=Client(), cache_dir=tmp_path),
    )
    recorder = Recorder(tmp_path / "trace.jsonl")
    try:
        runner = _container_runner(cfg, resolved, recorder, "scaled", "fake", 1000)
    finally:
        recorder.close()
    assert isinstance(runner, ContainerHttpRunner)
    assert runner.relay_idle_timeout_s == 190
