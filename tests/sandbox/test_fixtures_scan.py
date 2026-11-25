"""FixtureSet wiring preserves scans without profile fixtures."""


async def test_fixture_reset_restores_only_while_target_is_stopped(monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    from probe.config.profile import FixturesSection
    from probe.sandbox.fixtures import FixtureSet

    fixtures = FixtureSet(SimpleNamespace(), FixturesSection(), token="test")
    running = True
    events = []

    async def inspect(*args, **kwargs):
        assert not running, "restoring files while a target holds deleted inodes"
        events.append("restore")

    async def reset_target(restore):
        nonlocal running
        running = False
        await restore()
        running = True

    fixtures.reset_target = reset_target
    monkeypatch.setattr(fixtures, "_inspect", inspect)
    monkeypatch.setattr(fixtures, "_admin", AsyncMock())
    await fixtures.reset()
    assert events == ["restore"] and running


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
    assert callable(prepared.reset_target)
    assert ctx.fixtures is prepared
    prepared.start.assert_awaited_once()
    assert seen["token"] == scan_token(7, profile.hash)
    assert seen["config"] == profile.fixtures
    restored = AsyncMock()
    ctx.reconnect = AsyncMock()

    async def reset_data(restore):
        await restore()
        return "fresh transport"

    runner.reset_data = AsyncMock(side_effect=reset_data)
    # The callback captured the bound method before the patch, so rebuild it through connect.
    ctx = await runscan._connect(cfg, resolved, runner, None, 10, 10)
    ctx.reconnect = AsyncMock()
    await prepared.reset_target(restored)
    restored.assert_awaited_once()
    ctx.reconnect.assert_awaited_once_with(transport="fresh transport")


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
