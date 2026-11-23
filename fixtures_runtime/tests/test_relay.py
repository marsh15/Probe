import asyncio

import pytest

from fixtures_runtime.relay import Relay


@pytest.mark.asyncio
async def test_raw_tcp_bidirectional_bytes_and_half_close():
    async def target(reader, writer):
        writer.write(b"greeting\x00\xff")
        await writer.drain()
        data = await reader.read()
        writer.write(data[::-1])
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(target, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server, Relay("127.0.0.1", port) as relay:
        reader, writer = await asyncio.open_connection("127.0.0.1", relay.port)
        assert await asyncio.wait_for(reader.readexactly(10), 2) == b"greeting\x00\xff"
        payload = bytes(range(256)) * 1000
        writer.write(payload)
        await writer.drain()
        writer.write_eof()
        assert await asyncio.wait_for(reader.read(), 3) == payload[::-1]
        writer.close()
        await writer.wait_closed()
    assert not relay.tasks


@pytest.mark.asyncio
async def test_cancellation_and_connection_failure_cleanup():
    finished = asyncio.Event()

    async def target(reader, writer):
        try:
            await reader.read()
        finally:
            writer.close()
            await writer.wait_closed()
            finished.set()

    server = await asyncio.start_server(target, "127.0.0.1", 0)
    async with server:
        relay = Relay("127.0.0.1", server.sockets[0].getsockname()[1])
        async with relay:
            reader, writer = await asyncio.open_connection("127.0.0.1", relay.port)
            writer.write(b"open")
            await writer.drain()
            await asyncio.sleep(0.02)
        assert await asyncio.wait_for(reader.read(), 2) == b""
        await asyncio.wait_for(finished.wait(), 2)
        assert not relay.tasks
        writer.close()
        await writer.wait_closed()
    async with Relay(
        "127.0.0.1", server.sockets[0].getsockname()[1] if server.sockets else relay.target_port
    ) as failed:
        reader, writer = await asyncio.open_connection("127.0.0.1", failed.port)
        assert await asyncio.wait_for(reader.read(), 2) == b""
        writer.close()
        await writer.wait_closed()


@pytest.mark.asyncio
async def test_connection_limit_and_idle_timeout_close_clients():
    connected = asyncio.Event()
    closed = asyncio.Event()

    async def target(reader, writer):
        connected.set()
        try:
            await reader.read()
        finally:
            writer.close()
            await writer.wait_closed()
            closed.set()

    server = await asyncio.start_server(target, "127.0.0.1", 0)
    async with (
        server,
        Relay(
            "127.0.0.1", server.sockets[0].getsockname()[1], max_connections=1, idle_timeout=0.1
        ) as relay,
    ):
        first_reader, first_writer = await asyncio.open_connection("127.0.0.1", relay.port)
        await asyncio.wait_for(connected.wait(), 2)
        reader, writer = await asyncio.open_connection("127.0.0.1", relay.port)
        assert await asyncio.wait_for(reader.read(), 2) == b""
        writer.close()
        await writer.wait_closed()
        assert await asyncio.wait_for(first_reader.read(), 2) == b""
        first_writer.close()
        await first_writer.wait_closed()
        await asyncio.wait_for(closed.wait(), 2)
    assert not relay.tasks
    with pytest.raises(ValueError):
        Relay("127.0.0.1", 0)
