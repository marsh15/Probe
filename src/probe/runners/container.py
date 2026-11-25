"""Hardened Docker target speaking stdio through a local ``docker start -ai``."""

import asyncio
import contextlib
import math
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import docker  # type: ignore[import-untyped]

from probe.engine.outcomes import Transport as TransportKind
from probe.runners.base import RunnerState, TargetUnavailable
from probe.sandbox.docker_env import DockerEnv
from probe.sandbox.spec import target_spec
from probe.wire.limits import STDERR_RING_BYTES
from probe.wire.recorder import Recorder
from probe.wire.transport_base import CloseResult, Transport
from probe.wire.transport_stdio import StdioTransport

_deadline_sleep = asyncio.sleep


async def _join_after_cancel[T](task: asyncio.Task[T]) -> T:
    """Keep joining owned work even if its caller is cancelled again."""
    while True:
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            if task.cancelled():
                raise


async def _docker[T](call: Callable[[], T]) -> T:
    """Let in-flight SDK creation finish before cancellation triggers owned cleanup."""
    task = asyncio.create_task(asyncio.to_thread(call))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        with contextlib.suppress(Exception):
            await _join_after_cancel(task)
        raise


@dataclass
class _Instance:
    container: Any
    transport: Transport


class ContainerRunner:
    transport_kind = TransportKind.STDIO
    sandboxed = True

    def __init__(
        self,
        image: str,
        *,
        sandbox: DockerEnv,
        command: Sequence[str] | None = None,
        env: Mapping[str, str] | None = None,
        runtime: str | None = None,
        mode_deadline_s: float = 300,
        recorder: Recorder | None = None,
        initialize_data: bool = True,
    ) -> None:
        if not math.isfinite(mode_deadline_s) or mode_deadline_s < 0:
            raise ValueError("mode deadline must be finite and nonnegative")
        target_spec(sandbox.scan_id, image, command=command, env=env, runtime=runtime)
        self.image = image
        self.sandbox = sandbox
        self.command = list(command) if command is not None else None
        self.env = dict(env or {})
        self.runtime = runtime
        self.mode_deadline_s = mode_deadline_s
        self.recorder = recorder
        self.initialize_data = initialize_data
        self.deadline_exceeded = False
        self._main: _Instance | None = None
        self._extras: list[_Instance] = []
        self._launching: Any = None
        self._deadline: asyncio.Task[None] | None = None
        self._lock = asyncio.Lock()
        self._last_state = RunnerState(running=False)
        self._last_logs = ""
        self._stopped = False

    async def start(self) -> Transport:
        async with self._lock:
            if self._stopped or self.deadline_exceeded:
                raise TargetUnavailable("container runner has stopped")
            if self._main is not None:
                return self._main.transport
            # One scan-wide clock; restarts and second instances never extend it.
            if self._deadline is None:
                self._deadline = asyncio.create_task(self._watch_deadline())
                # Keep failures available to wait_deadline without an unhandled task error
                # when orchestration instead observes the stopped runner.
                self._deadline.add_done_callback(
                    lambda task: task.exception() if not task.cancelled() else None
                )
            try:
                await _docker(self.sandbox.create)
                if self.initialize_data:
                    await _docker(lambda: self.sandbox.initialize_data(self.sandbox.fixtures_image))
                self._main = await self._spawn()
                return self._main.transport
            except BaseException as exc:
                await self._cleanup()
                if isinstance(exc, asyncio.CancelledError):
                    raise
                raise TargetUnavailable(
                    f"could not start container: {type(exc).__name__}: {exc}"
                ) from exc

    async def restart(self) -> Transport:
        async with self._lock:
            if self._stopped or self.deadline_exceeded:
                raise TargetUnavailable("container runner has stopped")
            try:
                if self._main is not None:
                    await self._stop_instance(self._main)
                    self._main = None
                if self.sandbox.ready:
                    self._main = await self._spawn()
                    return self._main.transport
            except BaseException:
                await self._cleanup()
                raise
        return await self.start()

    async def reset_data(self, restore: Callable[[], Awaitable[None]]) -> Transport:
        """Stop every target before restoring fixtures, then open a fresh main instance."""
        async with self._lock:
            if self._stopped or self.deadline_exceeded:
                raise TargetUnavailable("container runner has stopped")
            try:
                for instance in [*self._extras, *([self._main] if self._main else [])]:
                    await self._stop_instance(instance, kill=True)
                self._extras.clear()
                self._main = None
                await restore()
                self._main = await self._spawn()
                return self._main.transport
            except BaseException:
                await self._cleanup(kill=True)
                raise

    async def second_instance(self) -> Transport | None:
        async with self._lock:
            if self._main is None or self._stopped or self.deadline_exceeded:
                raise TargetUnavailable("main instance must be started first")
            try:
                instance = await self._spawn()
                instance.transport.instance = f"second-{len(self._extras) + 1}"
                self._extras.append(instance)
                return instance.transport
            except BaseException:
                await self._cleanup()
                raise

    async def _spawn(self) -> _Instance:
        self._check_deadline()
        container = await _docker(
            lambda: self.sandbox.create_target(
                self.image,
                command=self.command,
                env=self.env,
                runtime=self.runtime,
            )
        )
        transport = None
        try:
            self._check_deadline()
            self._launching = container

            async def attach() -> StdioTransport:
                self._check_deadline()
                return await StdioTransport.spawn(
                    ["docker", "start", "-ai", container.id],
                    recorder=self.recorder,
                )

            attachment = asyncio.create_task(attach())
            try:
                transport = await asyncio.shield(attachment)
            except asyncio.CancelledError:
                # A subprocess creation already in flight must be joined and closed too.
                with contextlib.suppress(Exception):
                    transport = await _join_after_cancel(attachment)
                raise
            self._check_deadline()
            return _Instance(container, transport)
        except BaseException:
            try:
                await _docker(lambda: self.sandbox.remove_container(container))
            finally:
                if transport is not None:
                    await transport.close(grace_s=0, kill_after_s=0)
            raise
        finally:
            self._launching = None

    def _check_deadline(self) -> None:
        if self.deadline_exceeded:
            raise TargetUnavailable("container runner deadline exceeded")

    async def _close_transport(self, instance: _Instance, *, patient: bool) -> None:
        """Close the attachment; ``patient`` gives the target a moment to exit by itself."""
        grace = 0.1 if patient else 0
        await instance.transport.close(grace_s=grace, kill_after_s=grace)  # type: ignore[call-arg]

    async def _read_logs(self, instance: _Instance) -> str:
        return instance.transport.stderr_tail(STDERR_RING_BYTES)

    async def check_shutdown(self) -> CloseResult:
        """Observe the container, rather than mistaking attachment exit for target exit."""
        transport = await self.second_instance()
        instance = next(i for i in self._extras if i.transport is transport)
        try:
            # EOF first; terminating docker start is not evidence the container stopped.
            closed = await instance.transport.close(grace_s=5, kill_after_s=0)  # type: ignore[call-arg]
            state = await self._state(instance)
            # docker start forwards SIGTERM, so attachment escalation also forced the target.
            terminated = state.running or closed.terminated
            if state.running:
                await _docker(lambda: instance.container.kill(signal="SIGTERM"))
                deadline = time.monotonic() + 5
                while state.running and time.monotonic() < deadline:
                    await asyncio.sleep(0.05)
                    state = await self._state(instance)
            return CloseResult(state.exit_code, terminated, state.running)
        finally:
            await self._stop_instance(instance, kill=True)
            if instance in self._extras:
                self._extras.remove(instance)

    async def logs(self) -> str:
        if self._main is not None:
            return await self._read_logs(self._main)
        return self._last_logs

    async def state(self) -> RunnerState:
        if self._main is not None:
            self._last_state = await self._state(self._main)
        return self._last_state

    @staticmethod
    async def _state(instance: _Instance) -> RunnerState:
        await _docker(instance.container.reload)
        state = instance.container.attrs.get("State", {})
        running = bool(state.get("Running"))
        return RunnerState(
            running=running,
            exit_code=None if running else state.get("ExitCode"),
            oom_killed=bool(state.get("OOMKilled", False)),
        )

    async def _stop_instance(self, instance: _Instance, *, kill: bool = False) -> None:
        try:
            if kill:
                await self._kill(instance.container)
            else:
                # Closing attachment stdin gives the target a chance to exit; Docker stop
                # then supplies SIGTERM and enforces a five-second grace period itself.
                with contextlib.suppress(Exception):
                    await self._close_transport(instance, patient=True)
                try:
                    await _docker(lambda: instance.container.stop(timeout=5))
                except Exception:
                    await self._kill(instance.container)
        finally:
            if instance is self._main:
                self._last_logs = await self._read_logs(instance)
                with contextlib.suppress(Exception):
                    self._last_state = await self._state(instance)
            try:
                await self._close_transport(instance, patient=False)
            finally:
                await _docker(lambda: self.sandbox.remove_container(instance.container))

    @staticmethod
    async def _kill(container: Any) -> None:
        try:
            await _docker(container.kill)
        except docker.errors.NotFound:
            pass
        except docker.errors.APIError:
            # Docker rejects killing an exited container. Only suppress the error
            # after inspection proves there is no live process left to enforce on.
            try:
                await _docker(container.reload)
            except docker.errors.NotFound:
                return
            if container.attrs.get("State", {}).get("Running", True):
                raise

    async def _cleanup(self, *, kill: bool = False) -> None:
        errors: list[str] = []
        try:
            for instance in [*self._extras, *([self._main] if self._main is not None else [])]:
                try:
                    await self._stop_instance(instance, kill=kill)
                except Exception as exc:
                    errors.append(str(exc))
            self._extras.clear()
            self._main = None
        finally:
            errors.extend(await _docker(self.sandbox.close))
            self._stopped = True
            deadline = self._deadline
            if deadline is not None and deadline is not asyncio.current_task():
                deadline.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await deadline
        if errors:
            raise RuntimeError("sandbox cleanup incomplete: " + "; ".join(errors))

    async def stop(self) -> None:
        async with self._lock:
            await self._cleanup()

    async def _watch_deadline(self) -> None:
        await _deadline_sleep(self.mode_deadline_s + 60)
        self.deadline_exceeded = True
        # Enforce before acquiring the lifecycle lock: SDK creation/restart can hold
        # it for an entire request timeout while other targets are still running.
        instances = [*self._extras, *([self._main] if self._main is not None else [])]
        enforcement = [self._kill(instance.container) for instance in instances]
        if self._launching is not None:
            container = self._launching
            # Removal also prevents an in-flight docker start from launching it late.
            enforcement.append(_docker(lambda: self.sandbox.remove_container(container)))
        await asyncio.gather(*enforcement, return_exceptions=True)
        async with self._lock:
            await self._cleanup(kill=True)

    async def wait_deadline(self) -> None:
        """Await the watchdog, useful for orchestration and deterministic boundary tests."""
        if self._deadline is not None:
            await self._deadline
