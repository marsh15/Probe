"""FixtureSet wiring preserves scans without profile fixtures."""


async def test_scan_connect_prepares_fixtures_and_shares_the_profile_token(monkeypatch, tmp_path):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    from probe.config.profile import Profile, resolve_profile, scan_token
    from probe.engine import runscan
    from probe.runners.container import ContainerRunner

    profile = Profile.model_validate({"fixtures": {}, "target": {"image": "image"}})
    cfg = runscan.RunConfig(out_dir=tmp_path, profile=profile, seed=7)
    resolved = resolve_profile(profile, token=scan_token(7, profile.hash), environ={})
    prepared = SimpleNamespace(start=AsyncMock())
    seen = {}

    def fixtures(sandbox, config, *, token):
        seen.update(sandbox=sandbox, config=config, token=token)
        return prepared

    runner = ContainerRunner(
        "image", sandbox=SimpleNamespace(scan_id="wiring"), initialize_data=False
    )
    runner.start = AsyncMock(return_value="transport")
    monkeypatch.setattr(runscan, "FixtureSet", fixtures, raising=False)
    monkeypatch.setattr(runscan.Session, "open", AsyncMock(return_value=SimpleNamespace()))
    monkeypatch.setattr(runscan, "list_tools", AsyncMock(return_value=SimpleNamespace(tools=[])))
    monkeypatch.setattr(runscan, "ScanContext", lambda **kw: SimpleNamespace(**kw))
    ctx = await runscan._connect(cfg, resolved, runner, None, 10, 10)
    assert ctx.fixtures is prepared
    prepared.start.assert_awaited_once()
    assert seen["token"] == scan_token(7, profile.hash)
    assert seen["config"] == profile.fixtures


def test_fixture_runner_initialization_and_environment_defaults(monkeypatch, tmp_path):
    from types import SimpleNamespace

    from probe.config.profile import Profile, resolve_profile
    from probe.engine import runscan

    monkeypatch.setattr(runscan, "DockerEnv", lambda scan: SimpleNamespace(scan_id=scan))
    for transport in ("stdio", "http"):
        for requested in (False, True):
            data = {
                "target": {"image": "image", "transport": transport, "env": {"EXPLICIT": "target"}}
            }
            if requested:
                data["fixtures"] = {
                    "http": {"env_base_urls": {"DEFAULT": "http://fakehttp", "EXPLICIT": "fixture"}}
                }
            profile = Profile.model_validate(data)
            cfg = runscan.RunConfig(
                out_dir=tmp_path, profile=profile, target_env={"OVERRIDE": "cli"}
            )
            resolved = resolve_profile(profile, token="0123456789ab", environ={})
            runner = runscan._make_runner(cfg, resolved, None, "wiring", 10)
            assert runner.initialize_data is (not requested)
            assert runner.env["EXPLICIT"] == "target"
            assert runner.env["OVERRIDE"] == "cli"
            assert runner.env.get("DEFAULT") == ("http://fakehttp" if requested else None)
