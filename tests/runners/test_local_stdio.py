"""LocalStdioRunner: real child processes (the fake servers from the wire tests)."""

import sys
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from probe.engine.outcomes import Transport as TransportKind
from probe.runners.base import TargetUnavailable
from probe.runners.local_stdio import DEFAULT_ENV, LocalStdioRunner
from probe.wire.jsonrpc import Request
from probe.wire.transport_stdio import StdioTransport

FAKES = Path(__file__).parents[1] / "wire" / "fake_servers"


def argv(name: str, *args: str) -> list[str]:
    return [sys.executable, str(FAKES / f"{name}.py"), *args]


@pytest.fixture
async def runner() -> AsyncIterator[LocalStdioRunner]:
    runner = LocalStdioRunner(argv("echo"))
    yield runner
    await runner.stop()


async def ask(transport: object) -> object:
    assert isinstance(transport, StdioTransport)
    return (await transport.request(Request(1, "ping").to_obj(), timeout=10)).unwrap()


def test_declares_what_it_is() -> None:
    runner = LocalStdioRunner(argv("echo"))
    assert runner.transport_kind is TransportKind.STDIO
    assert runner.sandboxed is False


def test_an_empty_command_is_refused() -> None:
    with pytest.raises(ValueError, match="command"):
        LocalStdioRunner([])


async def test_start_gives_a_working_transport(runner: LocalStdioRunner) -> None:
    transport = await runner.start()
    assert await ask(transport) == {"method": "ping", "params": {}}
    state = await runner.state()
    assert (state.running, state.exit_code, state.oom_killed) == (True, None, False)


async def test_state_before_start_is_not_running(runner: LocalStdioRunner) -> None:
    assert (await runner.state()).running is False
    assert await runner.logs() == ""


async def test_restart_gives_a_fresh_process_and_stops_the_old_one(
    runner: LocalStdioRunner,
) -> None:
    first = await runner.start()
    second = await runner.restart()
    assert second is not first
    assert not first.alive()
    assert await ask(second) == {"method": "ping", "params": {}}


async def test_second_instance_is_independent_and_stopped_with_the_runner() -> None:
    runner = LocalStdioRunner(argv("echo"))
    main = await runner.start()
    other = await runner.second_instance()
    assert other is not None and other is not main
    assert await ask(other) == {"method": "ping", "params": {}}
    await runner.stop()
    assert not main.alive() and not other.alive()


async def test_a_crash_is_visible_in_state_and_logs() -> None:
    runner = LocalStdioRunner(argv("crash", "7"))
    transport = await runner.start()
    with pytest.raises(Exception):  # noqa: B017 - the server exits without answering
        await transport.request(Request(1, "ping").to_obj(), timeout=10)
    state = await runner.state()
    assert (state.running, state.exit_code) == (False, 7)
    assert "fatal: something broke" in await runner.logs()
    await runner.stop()


async def test_stop_is_idempotent(runner: LocalStdioRunner) -> None:
    await runner.start()
    await runner.stop()
    await runner.stop()
    assert (await runner.state()).running is False


async def test_a_missing_command_is_target_unavailable() -> None:
    runner = LocalStdioRunner(["/no/such/server-binary"])
    with pytest.raises(TargetUnavailable, match="could not start"):
        await runner.start()


async def test_environment_defaults_can_be_overridden(tmp_path: Path) -> None:
    script = tmp_path / "env.py"
    script.write_text(
        "import json, os, sys\n"
        "for line in sys.stdin:\n"
        "    m = json.loads(line)\n"
        "    out = {k: os.environ.get(k) for k in ('TZ', 'LANG', 'PROBE_X', 'CWD_NAME')}\n"
        "    out['cwd'] = os.path.basename(os.getcwd())\n"
        "    print(json.dumps({'jsonrpc': '2.0', 'id': m['id'], 'result': out}), flush=True)\n"
    )
    runner = LocalStdioRunner(
        [sys.executable, str(script)], env={"PROBE_X": "1", "LANG": "de_DE.UTF-8"}, cwd=tmp_path
    )
    try:
        seen = await ask(await runner.start())
    finally:
        await runner.stop()
    assert seen["TZ"] == DEFAULT_ENV["TZ"]  # type: ignore[index]
    assert seen["LANG"] == "de_DE.UTF-8"  # type: ignore[index]
    assert seen["PROBE_X"] == "1"  # type: ignore[index]
    assert seen["cwd"] == tmp_path.name  # type: ignore[index]


async def test_the_environment_can_be_withheld(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PROBE_SECRET_TOKEN", "hunter2")
    script = tmp_path / "env.py"
    script.write_text(
        "import json, os, sys\n"
        "for line in sys.stdin:\n"
        "    m = json.loads(line)\n"
        "    print(json.dumps({'jsonrpc': '2.0', 'id': m['id'],"
        " 'result': {'token': os.environ.get('PROBE_SECRET_TOKEN')}}), flush=True)\n"
    )
    inherited = LocalStdioRunner([sys.executable, str(script)])
    isolated = LocalStdioRunner([sys.executable, str(script)], inherit_env=False)
    try:
        assert await ask(await inherited.start()) == {"token": "hunter2"}
        assert await ask(await isolated.start()) == {"token": None}
    finally:
        await inherited.stop()
        await isolated.stop()
