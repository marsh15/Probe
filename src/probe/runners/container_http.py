"""A hardened Docker target speaking streamable HTTP, reached through the loopback relay.

The target sits on the internal networks only. The relay fixture is the one door: it listens
on a loopback-only published port and forwards raw TCP to the target's private IP. Probe's HTTP
client talks to that port. Each target instance gets a relay pinned to its inspected private IP.
"""

import asyncio
import contextlib
import time
from collections.abc import Mapping, Sequence
from typing import Any

import httpx

from probe.engine.outcomes import Transport as TransportKind
from probe.runners.base import TargetUnavailable
from probe.runners.container import ContainerRunner, _docker, _Instance
from probe.sandbox.docker_env import DockerEnv
from probe.wire.limits import STARTUP_TIMEOUT_S
from probe.wire.recorder import Recorder
from probe.wire.transport_base import Transport
from probe.wire.transport_http import HttpTransport

RELAY_PORT = 8080  # the relay's published control/data port (see DockerEnv.start_fixture)
_PROBE_INTERVAL_S = 0.25
_LOG_TAIL_LINES = 200


class ContainerHttpRunner(ContainerRunner):
    transport_kind = TransportKind.HTTP

    def __init__(
        self,
        image: str,
        *,
        sandbox: DockerEnv,
        command: Sequence[str] | None = None,
        env: Mapping[str, str] | None = None,
        port: int = 3000,
        path: str = "/mcp",
        headers: Mapping[str, str] | None = None,
        startup_timeout_s: float = STARTUP_TIMEOUT_S,
        request_timeout_s: float = 30,
        runtime: str | None = None,
        mode_deadline_s: float = 300,
        recorder: Recorder | None = None,
        initialize_data: bool = True,
    ) -> None:
        super().__init__(
            image,
            sandbox=sandbox,
            command=command,
            env=env,
            runtime=runtime,
            mode_deadline_s=mode_deadline_s,
            recorder=recorder,
            initialize_data=initialize_data,
        )
        if not path.startswith("/"):
            raise ValueError("the HTTP path must start with /")
        self.port = port
        self.path = path
        self.headers = dict(headers or {})
        self.startup_timeout_s = startup_timeout_s
        self.relay_idle_timeout_s = max(startup_timeout_s, request_timeout_s) + 10
        self._relay: Any = None

    async def second_instance(self) -> Transport | None:
        """None: an HTTP server is stateless per request, so a new connection serves instead."""
        return None

    async def _spawn(self) -> _Instance:
        self._check_deadline()
        container = await _docker(
            lambda: self.sandbox.create_target(
                self.image, command=self.command, env=self.env, runtime=self.runtime
            )
        )
        try:
            self._launching = container
            await _docker(container.start)
            await _docker(container.reload)
            target_ip = container.attrs["NetworkSettings"]["Networks"][self.sandbox.names["priv"]][
                "IPAddress"
            ]
            if self._relay is not None:
                await _docker(lambda: self.sandbox.remove_container(self._relay))
                self._relay = None
            self._relay = await _docker(
                lambda: self.sandbox.start_fixture(
                    "relay",
                    target_port=self.port,
                    target_host=target_ip,
                    idle_timeout=self.relay_idle_timeout_s,
                )
            )
            url = (
                await _docker(lambda: self.sandbox.control_url(self._relay, RELAY_PORT)) + self.path
            )
            await self._wait_ready(url, container)
            self._check_deadline()
            return _Instance(
                container, HttpTransport(url, headers=self.headers, recorder=self.recorder)
            )
        except BaseException:
            with contextlib.suppress(Exception):
                await _docker(lambda: self.sandbox.remove_container(container))
            raise
        finally:
            self._launching = None

    async def _wait_ready(self, url: str, container: Any) -> None:
        """Poll until the target answers HTTP through the relay (any status counts), or give up.

        The relay accepts connections before the target is listening, so a TCP connect proves
        nothing; an HTTP response (even 404 or 405) proves a server is there.
        """
        deadline = time.monotonic() + self.startup_timeout_s
        async with httpx.AsyncClient(timeout=2.0, trust_env=False) as client:
            while True:
                self._check_deadline()
                try:
                    await client.get(url)
                    return
                except httpx.HTTPError:
                    pass
                await _docker(container.reload)
                if container.attrs.get("State", {}).get("Running") is False:
                    tail = await self._container_logs(container)
                    raise TargetUnavailable(f"the target exited before it was ready: {tail}")
                if time.monotonic() >= deadline:
                    raise TargetUnavailable(
                        f"the target did not answer HTTP within {self.startup_timeout_s:g} s"
                    )
                await asyncio.sleep(_PROBE_INTERVAL_S)

    @staticmethod
    async def _container_logs(container: Any) -> str:
        raw = await _docker(lambda: container.logs(tail=_LOG_TAIL_LINES, stdout=True, stderr=True))
        return str(raw.decode("utf-8", "replace")).strip()[-2000:]

    async def _close_transport(self, instance: _Instance, *, patient: bool) -> None:
        await instance.transport.close()

    async def _read_logs(self, instance: _Instance) -> str:
        with contextlib.suppress(Exception):
            return await self._container_logs(instance.container)
        return ""
