"""Raw asynchronous TCP forwarding, with bounded admission and buffers."""

import asyncio
import ipaddress
import math
import socket
from contextlib import suppress


class Relay:
    def __init__(
        self,
        target_host,
        target_port,
        listen_host="127.0.0.1",
        listen_port=0,
        *,
        max_connections=128,
        idle_timeout=60,
        target_subnet=None,
    ):
        try:
            address = ipaddress.ip_address(target_host)
            subnet = ipaddress.ip_network(target_subnet) if target_subnet is not None else None
        except ValueError as exc:
            raise ValueError("invalid relay target address") from exc
        private = tuple(
            ipaddress.ip_network(value)
            for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
        )
        if (
            subnet is not None
            and (
                subnet.version != 4
                or subnet.prefixlen != 24
                or not any(subnet.subnet_of(network) for network in private)
                or address not in subnet
            )
        ) or (subnet is None and not address.is_loopback):
            raise ValueError("relay target must be in its private subnet")
        if (
            not target_host
            or not 1 <= target_port <= 65535
            or not 0 <= listen_port <= 65535
            or not 1 <= max_connections <= 1024
            or not math.isfinite(idle_timeout)
            or idle_timeout <= 0
        ):
            raise ValueError("invalid relay configuration")
        self.target_host, self.target_port = str(address), target_port
        self.family = socket.AF_INET if address.version == 4 else socket.AF_INET6
        self.listen_host, self.listen_port = listen_host, listen_port
        self.max_connections, self.idle_timeout = max_connections, idle_timeout
        self.tasks = set()
        self.server = None

    @property
    def port(self):
        return self.server.sockets[0].getsockname()[1]

    async def __aenter__(self):
        self.server = await asyncio.start_server(
            self.accept, self.listen_host, self.listen_port, limit=65536
        )
        return self

    async def __aexit__(self, *_):
        self.server.close()
        for task in list(self.tasks):
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        self.tasks.clear()
        await self.server.wait_closed()

    def accept(self, reader, writer):
        if len(self.tasks) >= self.max_connections:
            writer.close()
            return
        task = asyncio.create_task(self.forward(reader, writer))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def forward(self, reader, writer):
        upstream = None
        try:
            async with asyncio.timeout(10):
                source, upstream = await asyncio.open_connection(
                    self.target_host,
                    self.target_port,
                    limit=65536,
                    family=self.family,
                    flags=socket.AI_NUMERICHOST,
                )

            async def pipe(incoming, outgoing):
                while True:
                    async with asyncio.timeout(self.idle_timeout):
                        data = await incoming.read(65536)
                        if not data:
                            if outgoing.can_write_eof():
                                outgoing.write_eof()
                                await outgoing.drain()
                            return
                        outgoing.write(data)
                        await outgoing.drain()

            async with asyncio.TaskGroup() as group:
                group.create_task(pipe(reader, upstream))
                group.create_task(pipe(source, writer))
        except* (OSError, TimeoutError):
            pass
        finally:
            for stream in (writer, upstream):
                if stream:
                    stream.close()
            for stream in (writer, upstream):
                if stream:
                    with suppress(OSError, TimeoutError):
                        async with asyncio.timeout(2):
                            await stream.wait_closed()
