"""Runner lifecycle uses a Docker boundary fake and a fake stdio attachment."""

import asyncio
import threading

import docker
import pytest

from probe.engine.outcomes import Transport as TransportKind
from probe.runners.base import Runner, TargetUnavailable
from probe.runners.container import ContainerRunner
from probe.sandbox.docker_env import DockerEnv
from probe.wire.transport_base import CloseResult
from tests.sandbox.fakes import Client


class Attachment:
    def __init__(self):
        self.closed = False

    async def close(self, **kwargs):
        self.closed = True
        return CloseResult(0, terminated=False, killed=False)

    def stderr_tail(self, n=4096):
        return "attach stderr"

    def alive(self):
        return not self.closed


@pytest.mark.parametrize("cancellations", [2, 3, 5])
async def test_repeated_start_cancellation_joins_creation_before_cleanup(
    boundary, monkeypatch, cancellations
):
    client, env, _ = boundary
    entered = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    cleanup_started = threading.Event()
    original_create = env.create
    original_network = client.networks.create
    original_close = env.close

    def network(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return original_network(*args, **kwargs)

    def create():
        try:
            original_create()
        finally:
            finished.set()

    def close():
        cleanup_started.set()
        return original_close()

    monkeypatch.setattr(client.networks, "create", network)
    monkeypatch.setattr(env, "create", create)
    monkeypatch.setattr(env, "close", close)
    runner = ContainerRunner("img", sandbox=env)
    startup = asyncio.create_task(runner.start())
    try:
        assert await asyncio.to_thread(entered.wait, 2)
        for _ in range(cancellations):
            startup.cancel()
            await asyncio.sleep(0)  # Deliver each cancellation while the worker is blocked.
        assert not await asyncio.to_thread(cleanup_started.wait, 0.2)
        assert env.lease is not None
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await startup
        assert finished.is_set()
        assert not client.containers.list() and not client.networks.list()
        assert not client.volumes.list() and not list(env.allocator.root.glob("*.json"))
        assert env.lease is None and not env.ready
    finally:
        release.set()
        assert await asyncio.to_thread(finished.wait, 5)
        await asyncio.gather(startup, return_exceptions=True)
        await runner.stop()


@pytest.mark.parametrize("cancellations", [2, 3, 5])
async def test_repeated_start_cancellation_joins_and_closes_attachment(
    boundary, monkeypatch, cancellations
):
    client, env, _ = boundary
    entered = asyncio.Event()
    release = asyncio.Event()
    cancelled = asyncio.Event()
    attachment = Attachment()

    async def spawn(command, **kwargs):
        client.containers.get(command[-1]).start()
        entered.set()
        try:
            await release.wait()
            return attachment
        except asyncio.CancelledError:
            cancelled.set()
            raise

    monkeypatch.setattr("probe.runners.container.StdioTransport.spawn", spawn)
    runner = ContainerRunner("img", sandbox=env)
    startup = asyncio.create_task(runner.start())
    try:
        await asyncio.wait_for(entered.wait(), 2)
        for _ in range(cancellations):
            startup.cancel()
            await asyncio.sleep(0)
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await startup
        assert not cancelled.is_set()
        assert attachment.closed
        assert not client.containers.list() and not client.networks.list()
        assert not client.volumes.list() and not list(env.allocator.root.glob("*.json"))
    finally:
        release.set()
        await asyncio.gather(startup, return_exceptions=True)
        await runner.stop()


@pytest.fixture
def boundary(tmp_path, monkeypatch):
    client = Client()
    env = DockerEnv("runner", client=client, cache_dir=tmp_path)
    monkeypatch.setattr(env, "initialize_data", lambda image: None)
    argv = []

    async def spawn(command, **kwargs):
        target = client.containers.get(command[-1])
        assert set(target.connections) == {env.names["pub"], env.names["priv"]}
        assert target.started is False
        target.start()
        argv.append(command)
        return Attachment()

    monkeypatch.setattr("probe.runners.container.StdioTransport.spawn", spawn)
    return client, env, argv


async def test_runner_contract_restart_second_instance_and_cleanup(boundary):
    client, env, argv = boundary
    runner = ContainerRunner("img", sandbox=env, mode_deadline_s=30)
    contract: Runner = runner
    assert contract.sandboxed is True and contract.transport_kind is TransportKind.STDIO
    assert (await runner.state()).running is False
    first = await runner.start()
    main = client.containers.items[-1]
    assert argv[0] == ["docker", "start", "-ai", main.id]
    second = await runner.second_instance()
    extra = client.containers.items[-1]
    assert second is not first and extra.name != main.name
    fresh = await runner.restart()
    assert fresh is not first and first.closed
    assert main.removed and not extra.removed
    assert (await runner.state()).running
    await runner.stop()
    assert not client.containers.list() and not client.networks.list() and not client.volumes.list()
    assert second.closed
    await runner.stop()


async def test_state_and_logs_track_exit_and_oom(boundary):
    client, env, _ = boundary
    runner = ContainerRunner("img", sandbox=env)
    await runner.start()
    container = client.containers.items[-1]
    container.attrs["State"] = {"Running": False, "ExitCode": 137, "OOMKilled": True}
    state = await runner.state()
    assert (state.running, state.exit_code, state.oom_killed) == (False, 137, True)
    assert "stderr" in await runner.logs()
    await runner.stop()
    assert (await runner.state()).oom_killed  # cached after removal


async def test_failed_attachment_cleans_everything(boundary, monkeypatch):
    client, env, _ = boundary

    async def fail(*args, **kwargs):
        raise OSError("docker executable missing")

    monkeypatch.setattr("probe.runners.container.StdioTransport.spawn", fail)
    runner = ContainerRunner("img", sandbox=env)
    with pytest.raises(TargetUnavailable):
        await runner.start()
    assert not client.containers.list() and not client.networks.list() and not client.volumes.list()


async def test_stop_escalates_to_kill_and_still_cleans(boundary):
    client, env, _ = boundary
    runner = ContainerRunner("img", sandbox=env)
    await runner.start()
    container = client.containers.items[-1]
    container.stop_fails = True
    await runner.stop()
    assert container.killed and container.removed


async def test_deadline_uses_mode_budget_plus_sixty_and_kills_all(boundary, monkeypatch):
    client, env, _ = boundary
    gate = asyncio.Event()
    delays = []

    async def wait(seconds):
        delays.append(seconds)
        await gate.wait()

    monkeypatch.setattr("probe.runners.container._deadline_sleep", wait)
    runner = ContainerRunner("img", sandbox=env, mode_deadline_s=12)
    await runner.start()
    await runner.second_instance()
    await asyncio.sleep(0)
    assert delays == [72]
    gate.set()
    await asyncio.wait_for(runner.wait_deadline(), timeout=3)
    assert runner.deadline_exceeded
    assert all(c.killed for c in client.containers.items)
    assert not client.containers.list() and not client.networks.list()


@pytest.mark.parametrize("budget", [-1, float("nan"), float("inf")])
def test_deadline_must_be_finite_and_nonnegative(boundary, budget):
    _, env, _ = boundary
    with pytest.raises(ValueError):
        ContainerRunner("img", sandbox=env, mode_deadline_s=budget)


async def test_start_cancellation_waits_for_inflight_creation_and_cleans(boundary, monkeypatch):
    client, env, _ = boundary
    entered = threading.Event()
    finish = threading.Event()
    original = env.create_target

    def slow_create(*args, **kwargs):
        entered.set()
        assert finish.wait(timeout=5)
        return original(*args, **kwargs)

    monkeypatch.setattr(env, "create_target", slow_create)
    runner = ContainerRunner("img", sandbox=env)
    start = asyncio.create_task(runner.start())
    assert await asyncio.to_thread(entered.wait, 5)
    start.cancel()
    finish.set()
    with pytest.raises(asyncio.CancelledError):
        await start
    assert not client.containers.list() and not client.networks.list() and not client.volumes.list()


async def test_attachment_failure_on_second_cleans_main_and_fixtures(boundary, monkeypatch):
    client, env, _ = boundary
    runner = ContainerRunner("img", sandbox=env)
    await runner.start()

    async def fail(*args, **kwargs):
        raise OSError("cannot attach")

    monkeypatch.setattr("probe.runners.container.StdioTransport.spawn", fail)
    with pytest.raises(OSError, match="cannot attach"):
        await runner.second_instance()
    assert not client.containers.list() and not client.networks.list() and not client.volumes.list()


async def test_volume_initializer_uses_trusted_fixtures_not_target_image(boundary, monkeypatch):
    _, env, _ = boundary
    seen = []
    monkeypatch.setattr(env, "initialize_data", seen.append)
    runner = ContainerRunner("untrusted-target", sandbox=env)
    try:
        await runner.start()
        assert seen == [env.fixtures_image]
    finally:
        await runner.stop()


async def test_restart_stop_failure_still_cleans_scan_resources(boundary, monkeypatch):
    client, env, _ = boundary
    runner = ContainerRunner("img", sandbox=env)
    await runner.start()
    container = client.containers.items[-1]
    container.stop_fails = True

    def fail_kill():
        raise RuntimeError("daemon kill failed")

    monkeypatch.setattr(container, "kill", fail_kill)
    with pytest.raises(RuntimeError, match="kill failed"):
        await runner.restart()
    assert not client.containers.list() and not client.networks.list() and not client.volumes.list()


async def test_precreated_sandbox_still_initializes_unless_explicitly_disabled(
    boundary, monkeypatch
):
    _, env, _ = boundary
    env.create()
    seen = []
    monkeypatch.setattr(env, "initialize_data", seen.append)
    runner = ContainerRunner("img", sandbox=env)
    try:
        await runner.start()
        assert seen == [env.fixtures_image]
    finally:
        await runner.stop()


@pytest.mark.parametrize("operation", ["start", "restart", "second_instance"])
async def test_deadline_during_creation_kills_without_lifecycle_lock(
    boundary, monkeypatch, operation
):
    client, env, argv = boundary
    deadline = asyncio.Event()
    killed = asyncio.Event()
    entered = threading.Event()
    release = threading.Event()
    loop = asyncio.get_running_loop()
    expired = asyncio.Event()

    async def wait(seconds):
        await deadline.wait()
        loop.call_soon(expired.set)

    monkeypatch.setattr("probe.runners.container._deadline_sleep", wait)
    runner = ContainerRunner("img", sandbox=env)
    if operation != "start":
        await runner.start()
        # Keep an existing target even when restart replaces the main instance.
        await runner.second_instance()
        existing = client.containers.items[-1]
        original_kill = existing.kill

        def kill():
            original_kill()
            loop.call_soon_threadsafe(killed.set)

        monkeypatch.setattr(existing, "kill", kill)
    original_create = env.create_target

    def blocked_create(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return original_create(*args, **kwargs)

    monkeypatch.setattr(env, "create_target", blocked_create)
    task = asyncio.create_task(getattr(runner, operation)())
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        launches = len(argv)
        deadline.set()
        if operation != "start":
            await asyncio.wait_for(killed.wait(), 1)
            assert not existing.attrs["State"]["Running"]
        else:
            # Let the watchdog mark expiry while the first SDK create is blocked.
            await asyncio.wait_for(expired.wait(), 1)
            assert runner.deadline_exceeded
        release.set()
        with pytest.raises(TargetUnavailable, match=r"deadline|stopped"):
            await task
        assert len(argv) == launches  # no attachment may launch the late-created target
        assert all(not c.attrs["State"]["Running"] for c in client.containers.items)
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)
        await runner.stop()
        assert not client.containers.list()
        assert not client.networks.list()
        assert not client.volumes.list()
        assert not list(env.allocator.root.glob("*.json"))


@pytest.mark.parametrize("race_stop", [False, True])
async def test_deadline_tolerates_exited_target_and_racing_stop(boundary, monkeypatch, race_stop):
    client, env, _ = boundary
    deadline = asyncio.Event()
    entered_kill = asyncio.Event()
    loop = asyncio.get_running_loop()
    release = threading.Event()

    async def wait(seconds):
        await deadline.wait()

    monkeypatch.setattr("probe.runners.container._deadline_sleep", wait)
    runner = ContainerRunner("img", sandbox=env)
    await runner.start()
    target = client.containers.items[-1]
    target.attrs["State"]["Running"] = False

    def exited_kill():
        loop.call_soon_threadsafe(entered_kill.set)
        assert release.wait(5)
        raise docker.errors.APIError("container is not running")

    monkeypatch.setattr(target, "kill", exited_kill)
    try:
        deadline.set()
        await asyncio.wait_for(entered_kill.wait(), 1)
        stop = asyncio.create_task(runner.stop()) if race_stop else None
        release.set()
        await asyncio.wait_for(stop if stop is not None else runner.wait_deadline(), 3)
        assert not client.containers.list() and not client.networks.list()
        assert not client.volumes.list()
        assert runner._deadline.done()
    finally:
        release.set()
        await runner.stop()


async def test_deadline_and_cancelled_creation_leave_no_resources_or_task_errors(
    boundary, monkeypatch
):
    client, env, argv = boundary
    deadline = asyncio.Event()
    killed = asyncio.Event()
    entered = threading.Event()
    release = threading.Event()
    loop = asyncio.get_running_loop()
    errors = []
    previous_handler = loop.get_exception_handler()
    loop.set_exception_handler(lambda loop, context: errors.append(context))

    async def wait(seconds):
        await deadline.wait()

    monkeypatch.setattr("probe.runners.container._deadline_sleep", wait)
    runner = ContainerRunner("img", sandbox=env)
    await runner.start()
    target = client.containers.items[-1]
    original_kill = target.kill

    def kill():
        original_kill()
        loop.call_soon_threadsafe(killed.set)

    monkeypatch.setattr(target, "kill", kill)
    original_create = env.create_target

    def blocked_create(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return original_create(*args, **kwargs)

    monkeypatch.setattr(env, "create_target", blocked_create)
    task = asyncio.create_task(runner.second_instance())
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        deadline.set()
        await asyncio.wait_for(killed.wait(), 1)
        task.cancel()
        stop = asyncio.create_task(runner.stop())
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.wait_for(stop, 3)
        assert len(argv) == 1
        assert not client.containers.list() and not client.networks.list()
        assert not client.volumes.list() and not list(env.allocator.root.glob("*.json"))
        assert runner._deadline.done()
        assert not errors
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)
        await runner.stop()
        loop.set_exception_handler(previous_handler)


@pytest.mark.parametrize("cancel_creation", [False, True])
async def test_deadline_removes_target_while_attachment_is_in_flight(
    boundary, monkeypatch, cancel_creation
):
    client, env, _ = boundary
    deadline = asyncio.Event()
    entered = asyncio.Event()
    release = asyncio.Event()
    removed = asyncio.Event()
    loop = asyncio.get_running_loop()
    attachment = Attachment()
    original_remove = env.remove_container

    async def wait(seconds):
        await deadline.wait()

    async def delayed_attachment(command, **kwargs):
        target = client.containers.get(command[-1])
        target.start()
        entered.set()
        await release.wait()
        return attachment

    def remove(container):
        original_remove(container)
        loop.call_soon_threadsafe(removed.set)

    monkeypatch.setattr("probe.runners.container._deadline_sleep", wait)
    monkeypatch.setattr("probe.runners.container.StdioTransport.spawn", delayed_attachment)
    monkeypatch.setattr(env, "remove_container", remove)
    runner = ContainerRunner("img", sandbox=env)
    start = asyncio.create_task(runner.start())
    try:
        await asyncio.wait_for(entered.wait(), 1)
        target = client.containers.items[-1]
        deadline.set()
        await asyncio.wait_for(removed.wait(), 1)
        assert target.removed  # force-removal does not wait for subprocess attachment
        if cancel_creation:
            start.cancel()
        release.set()
        expected = asyncio.CancelledError if cancel_creation else TargetUnavailable
        with pytest.raises(expected):
            await start
        assert attachment.closed
        assert not client.containers.list() and not client.networks.list()
        assert not client.volumes.list()
    finally:
        release.set()
        await asyncio.gather(start, return_exceptions=True)
        await runner.stop()


async def test_shutdown_reports_attachment_sigterm_as_forced_exit(boundary, monkeypatch):
    _client, env, _argv = boundary
    runner = ContainerRunner("img", sandbox=env)
    await runner.start()
    transport = await runner.second_instance()
    instance = runner._extras[-1]

    async def close(**kwargs):
        # docker start forwards the attachment's SIGTERM and the server exits cleanly.
        instance.container.attrs["State"]["Running"] = False
        return CloseResult(0, terminated=True, killed=False)

    async def second():
        return transport

    def kill(**kwargs):
        instance.container.attrs["State"]["Running"] = False

    monkeypatch.setattr(transport, "close", close)
    monkeypatch.setattr(runner, "second_instance", second)
    monkeypatch.setattr(instance.container, "kill", kill)
    try:
        result = await runner.check_shutdown()
        assert result.terminated
    finally:
        await runner.stop()


async def test_shutdown_tolerates_deadline_clearing_extras(boundary, monkeypatch):
    _client, env, _ = boundary
    runner = ContainerRunner("img", sandbox=env)
    await runner.start()
    transport = await runner.second_instance()
    instance = runner._extras[-1]

    async def close(**kwargs):
        runner._extras.clear()
        instance.container.attrs["State"]["Running"] = False
        return CloseResult(0, terminated=False, killed=False)

    async def second():
        return transport

    monkeypatch.setattr(transport, "close", close)
    monkeypatch.setattr(runner, "second_instance", second)
    try:
        await runner.check_shutdown()
    finally:
        await runner.stop()


async def test_fixture_reset_stops_all_targets_before_restore_and_restarts(boundary):
    client, env, _ = boundary
    runner = ContainerRunner("img", sandbox=env)
    await runner.start()
    await runner.second_instance()
    old = [runner._main, *runner._extras]
    calls = []

    async def restore():
        assert all(instance.container.removed for instance in old)
        assert not client.containers.list()
        assert env.ready  # Fixtures and volumes survive the target restart.
        calls.append("restored")

    try:
        fresh = await runner.reset_data(restore)
        assert calls == ["restored"]
        assert runner._main.transport is fresh
        assert not runner._extras
        assert (await runner.state()).running
    finally:
        await runner.stop()
