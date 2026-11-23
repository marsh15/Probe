"""Raw asynchronous TCP forwarding, with bounded admission and buffers."""

import asyncio
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
    ):
        if (
            not target_host
            or not 1 <= target_port <= 65535
            or not 0 <= listen_port <= 65535
            or not 1 <= max_connections <= 1024
            or not 0 < idle_timeout <= 3600
        ):
            raise ValueError("invalid relay configuration")
        self.target_host, self.target_port = target_host, target_port
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
                    self.target_host, self.target_port, limit=65536
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
