"""The standalone fixtures command; JSON inspector output is stable and concise."""

import argparse
import asyncio
import json
import os
import signal
import socket
import sys
from functools import partial
from pathlib import Path

import uvicorn

from fixtures_runtime.http import create_canary, create_fakehttp, integer
from fixtures_runtime.http_protocol import BoundedH11Protocol
from fixtures_runtime.inspector import Inspector, diff
from fixtures_runtime.paths import MAX_FILE, directory, read_file
from fixtures_runtime.relay import Relay

MAX_HTTP_CONNECTIONS = 128
HTTP_HEADER_TIMEOUT = 5


def port(value):
    try:
        return integer(value, 1, 65535)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def parser():
    root = argparse.ArgumentParser(prog="fixtures")
    commands = root.add_subparsers(dest="mode", required=True)
    for mode in ("fakehttp", "canary"):
        cmd = commands.add_parser(mode)
        cmd.add_argument("--host", default="0.0.0.0")  # noqa: S104 - data listener contract
        cmd.add_argument("--admin-host", default="127.0.0.1")
        cmd.add_argument("--admin-port", type=port, default=9090)
        if mode == "fakehttp":
            cmd.add_argument("--port", type=port, default=80)
            cmd.add_argument("--routes", type=Path)
        else:
            cmd.add_argument("--ports", default="80,8080")
    cmd = commands.add_parser("relay")
    cmd.add_argument("--listen-host", default="127.0.0.1")
    cmd.add_argument("--listen-port", type=port, default=8080)
    cmd.add_argument("--target-host", required=True)
    cmd.add_argument("--target-port", type=port, required=True)
    cmd = commands.add_parser("inspect")
    cmd.add_argument("--root", type=Path, default=Path("/data"))
    actions = cmd.add_subparsers(dest="action", required=True)
    actions.add_parser("hash")
    child = actions.add_parser("diff")
    child.add_argument("before", type=Path)
    child.add_argument("after", type=Path)
    for action in ("exists", "sqlite-checksum"):
        actions.add_parser(action).add_argument("path")
    actions.add_parser("reset").add_argument("--seed", type=Path, required=True)
    return root


def read_snapshot(path):
    path = path.absolute()
    with directory(path.parent) as fd:
        return json.loads(read_file(fd, path.name, MAX_FILE))


class ManagedServer(uvicorn.Server):
    def capture_signals(self):
        # One signal owner for the group of separately bound servers.
        from contextlib import nullcontext

        return nullcontext()


async def serve_http(args):
    data, admin = create_fakehttp(args.routes) if args.mode == "fakehttp" else create_canary()
    ports = (
        [args.port] if args.mode == "fakehttp" else [port(value) for value in args.ports.split(",")]
    )
    if not 1 <= len(ports) <= 8 or len(set(ports)) != len(ports):
        raise ValueError("expected one to eight distinct data ports")
    bindings = [(data, args.host, value) for value in ports] + [
        (admin, args.admin_host, args.admin_port)
    ]
    sockets, servers = [], []
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(signum, stop.set)
    try:
        # Bind the exact supplied addresses before starting any service. In particular,
        # the admin DNS alias must never fall back to a wildcard address.
        for app, host, number in bindings:
            addresses = await loop.getaddrinfo(host, number, type=socket.SOCK_STREAM)
            if not addresses:
                raise ValueError("listener address did not resolve")
            bound = []
            for family, kind, proto, _, address in dict.fromkeys(addresses):
                sock = socket.socket(family, kind, proto)
                sockets.append(sock)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if family == socket.AF_INET6:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                sock.bind(address)
                sock.setblocking(False)
                bound.append(sock)
            config = uvicorn.Config(
                app,
                host=host,
                port=number,
                log_level="warning",
                access_log=False,
                proxy_headers=False,
                http=partial(
                    BoundedH11Protocol,
                    connection_limit=MAX_HTTP_CONNECTIONS,
                    header_timeout=HTTP_HEADER_TIMEOUT,
                ),
                ws="none",
                # uvicorn checks >= including the current connection; admission
                # already caps sockets, so permit every admitted socket to run.
                limit_concurrency=MAX_HTTP_CONNECTIONS + 1,
                timeout_keep_alive=5,
                h11_max_incomplete_event_size=65536,
            )
            servers.append((ManagedServer(config), bound))
        async with asyncio.TaskGroup() as group:
            tasks = [group.create_task(server.serve(sockets=bound)) for server, bound in servers]
            stop_task = group.create_task(stop.wait())
            try:
                await asyncio.wait([stop_task, *tasks], return_when=asyncio.FIRST_COMPLETED)
            finally:
                for server, _ in servers:
                    server.should_exit = True
                stop_task.cancel()
    finally:
        for sock in sockets:
            sock.close()
        for signum in (signal.SIGINT, signal.SIGTERM):
            loop.remove_signal_handler(signum)


async def serve_relay(args):
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(signum, stop.set)
    try:
        async with Relay(
            args.target_host,
            args.target_port,
            args.listen_host,
            args.listen_port,
            target_subnet=os.environ.get("PROBE_RELAY_TARGET_SUBNET"),
            idle_timeout=float(os.environ.get("PROBE_RELAY_IDLE_TIMEOUT", "60")),
        ):
            await stop.wait()
    finally:
        for signum in (signal.SIGINT, signal.SIGTERM):
            loop.remove_signal_handler(signum)


def main():
    args = parser().parse_args()
    try:
        if args.mode == "inspect":
            inspector = Inspector(args.root)
            if args.action == "hash":
                result = inspector.snapshot()
            elif args.action == "diff":
                result = diff(read_snapshot(args.before), read_snapshot(args.after))
            elif args.action == "sqlite-checksum":
                result = inspector.sqlite_checksum(args.path)
            elif args.action == "exists":
                result = {"exists": inspector.exists(args.path)}
            else:
                inspector.reset(args.seed)
                result = {"reset": True}
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        else:
            asyncio.run(serve_relay(args) if args.mode == "relay" else serve_http(args))
    except (ValueError, OSError, RecursionError, argparse.ArgumentTypeError):
        print('{"error":"invalid configuration or operation"}', file=sys.stderr)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
