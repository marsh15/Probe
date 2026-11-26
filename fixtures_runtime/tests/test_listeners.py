import json
import socket
import subprocess
import sys
import time
from contextlib import contextmanager
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

import pytest

OPENER = build_opener(ProxyHandler({}))


def free_ports(count):
    sockets = []
    try:
        for _ in range(count):
            sock = socket.socket()
            sock.bind(("127.0.0.1", 0))
            sockets.append(sock)
        return [sock.getsockname()[1] for sock in sockets]
    finally:
        for sock in sockets:
            sock.close()


def request(port, path, data=None):
    req = Request(f"http://127.0.0.1:{port}{path}", data=data)
    try:
        with OPENER.open(req, timeout=2) as response:
            return response.status, response.read()
    except HTTPError as exc:
        return exc.code, exc.read()


@contextmanager
def running(args, ports, tmp_path, *, small_limits=False):
    command = ["fixtures"]
    if small_limits:
        command = [
            sys.executable,
            "-c",
            "import asyncio; from fixtures_runtime import cli; "
            "cli.MAX_HTTP_CONNECTIONS=2; cli.HTTP_HEADER_TIMEOUT=0.6; "
            "asyncio.run(cli.serve_http(cli.parser().parse_args()))",
        ]
    with (tmp_path / "server.log").open("wb") as log:
        process = subprocess.Popen([*command, *args], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 5
            for port in ports:
                while True:
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                            break
                    except OSError:
                        if process.poll() is not None or time.monotonic() >= deadline:
                            pytest.fail((tmp_path / "server.log").read_text())
                        time.sleep(0.02)
            yield process
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
                pytest.fail("fixture CLI did not stop on SIGTERM")


def test_fakehttp_live_cli_separate_admin_and_no_forwarded_source(tmp_path):
    data, admin = free_ports(2)
    args = ["fakehttp", "--host", "127.0.0.1", "--port", str(data), "--admin-port", str(admin)]
    with running(args, [data, admin], tmp_path) as process:
        assert request(data, "/hello.txt") == (200, b"probe-public-ok")
        assert request(data, "/_probe/log")[0] == 404
        assert request(admin, "/hello.txt")[0] == 404
        req = Request(
            f"http://127.0.0.1:{data}/hello.txt", headers={"X-Forwarded-For": "192.0.2.1"}
        )
        with OPENER.open(req, timeout=2):
            pass
        records = json.loads(request(admin, "/_probe/log")[1])
        assert records[-1]["source_ip"] == "127.0.0.1"
        assert records[-1]["headers"]["x-forwarded-for"] == "192.0.2.1"
    assert process.returncode == 0


def test_canary_live_multiport_shared_hits(tmp_path):
    first, second, admin = free_ports(3)
    args = [
        "canary",
        "--host",
        "127.0.0.1",
        "--ports",
        f"{first},{second}",
        "--admin-port",
        str(admin),
    ]
    with running(args, [first, second, admin], tmp_path) as process:
        assert request(first, "/one") == (200, b"probe-canary")
        assert request(second, "/two", b"binary\x00") == (200, b"probe-canary")
        hits = json.loads(request(admin, "/_probe/hits")[1])
        assert [hit["path"] for hit in hits] == ["/one", "/two"]
        assert request(second, "/_probe/hits")[0] == 404
    assert process.returncode == 0


def test_invalid_admin_address_fails_before_data_listener(tmp_path):
    data, admin = free_ports(2)
    result = subprocess.run(
        [
            "fixtures",
            "fakehttp",
            "--host",
            "127.0.0.1",
            "--port",
            str(data),
            "--admin-host",
            "256.256.256.256",
            "--admin-port",
            str(admin),
        ],
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert result.returncode == 2
    assert b"Traceback" not in result.stderr
    with pytest.raises(OSError), socket.create_connection(("127.0.0.1", data), timeout=0.2):
        pass


@pytest.mark.parametrize("mode", ["fakehttp", "canary"])
def test_idle_connection_admission_is_per_listener_and_recovers(tmp_path, mode):
    ports = free_ports(3 if mode == "canary" else 2)
    data, admin = ports[0], ports[-1]
    args = [mode, "--host", "127.0.0.1", "--admin-port", str(admin)]
    args += (
        ["--ports", ",".join(map(str, ports[:-1]))] if mode == "canary" else ["--port", str(data)]
    )
    with running(args, ports, tmp_path, small_limits=True) as process:
        time.sleep(0.05)  # Allow readiness connections to disconnect before filling the slots.
        for port in ports:
            with (
                socket.create_connection(("127.0.0.1", port), timeout=1) as first,
                socket.create_connection(("127.0.0.1", port), timeout=1) as second,
                socket.create_connection(("127.0.0.1", port), timeout=1) as excess,
            ):
                excess.settimeout(0.3)
                assert excess.recv(1) == b"", "excess idle connection was left open"
                # A full listener must not consume a different listener's allowance.
                other = admin if port != admin else data
                path = "/_probe/hits" if mode == "canary" else "/_probe/log"
                assert request(other, path if other == admin else "/hello.txt")[0] == 200
                for idle in (first, second):
                    idle.settimeout(1.5)
                    assert idle.recv(1) == b"", "initial header deadline did not close idle socket"
            path = "/_probe/hits" if mode == "canary" else "/_probe/log"
            assert request(port, path if port == admin else "/hello.txt")[0] == 200
            # Disconnects must release slots without waiting for the header deadline.
            for _ in range(3):
                with socket.create_connection(("127.0.0.1", port), timeout=1) as client:
                    client.sendall(b"GET / HTTP/1.1\r\n")
                assert request(port, path if port == admin else "/hello.txt")[0] == 200
        # SIGTERM while an initial-header timer is live must cleanly close the connection.
        with socket.create_connection(("127.0.0.1", data), timeout=1) as idle:
            time.sleep(0.05)
            process.terminate()
            idle.settimeout(2)
            assert idle.recv(1) == b""
    assert process.returncode == 0


@pytest.mark.parametrize("listener", ["data", "admin"])
def test_partial_initial_headers_do_not_extend_deadline(tmp_path, listener):
    data, admin = free_ports(2)
    args = ["fakehttp", "--host", "127.0.0.1", "--port", str(data), "--admin-port", str(admin)]
    with running(args, [data, admin], tmp_path, small_limits=True):
        port = data if listener == "data" else admin
        with socket.create_connection(("127.0.0.1", port), timeout=1) as client:
            client.sendall(b"GET /hello.txt HTTP/1.1\r\nHost: ")
            client.settimeout(0.08)
            deadline = time.monotonic() + 1.5
            while True:
                try:
                    chunk = client.recv(1)
                except TimeoutError:
                    assert time.monotonic() < deadline, "dripped headers postponed the deadline"
                    try:
                        client.sendall(b"x")
                    except (BrokenPipeError, ConnectionResetError):
                        break  # closed while we were dripping, inside the deadline just checked
                except ConnectionResetError:
                    # Closing with a dripped byte still unread makes the kernel send RST, not FIN.
                    assert time.monotonic() < deadline, "the reset came after the deadline"
                    break
                else:
                    assert chunk == b""
                    break
        assert request(data, "/hello.txt") == (200, b"probe-public-ok")
        assert request(admin, "/_probe/state")[0] == 200


@pytest.mark.parametrize("listener", ["data", "admin"])
def test_last_admitted_connection_serves_then_keepalive_headers_expire(tmp_path, listener):
    from http.client import HTTPResponse

    data, admin = free_ports(2)
    args = ["fakehttp", "--host", "127.0.0.1", "--port", str(data), "--admin-port", str(admin)]
    with running(args, [data, admin], tmp_path, small_limits=True):
        time.sleep(0.05)
        port = data if listener == "data" else admin
        path = "/hello.txt" if listener == "data" else "/_probe/state"
        with (
            socket.create_connection(("127.0.0.1", port), timeout=1),
            socket.create_connection(("127.0.0.1", port), timeout=1) as client,
        ):
            client.sendall(f"GET {path} HTTP/1.1\r\nHost: fixture\r\n\r\n".encode())
            response = HTTPResponse(client)
            response.begin()
            assert response.status == 200, "last admission slot must serve requests"
            response.read()
            response.close()
            client.sendall(b"GET / HTTP/1.1\r\nHost: ")
            client.settimeout(0.08)
            deadline = time.monotonic() + 1.5
            while True:
                try:
                    chunk = client.recv(1)
                except TimeoutError:
                    assert time.monotonic() < deadline, "keepalive drips postponed header deadline"
                    try:
                        client.sendall(b"x")
                    except (BrokenPipeError, ConnectionResetError):
                        break  # closed while we were dripping, inside the deadline just checked
                except ConnectionResetError:
                    # Closing with a dripped byte still unread makes the kernel send RST, not FIN.
                    assert time.monotonic() < deadline, "the reset came after the deadline"
                    break
                else:
                    assert chunk == b""
                    break
        assert request(data, "/hello.txt")[0] == 200
        assert request(admin, "/_probe/state")[0] == 200


def test_completed_headers_allow_slow_body_response_and_pipeline(tmp_path):
    data, admin = free_ports(2)
    args = ["fakehttp", "--host", "127.0.0.1", "--port", str(data), "--admin-port", str(admin)]
    with running(args, [data, admin], tmp_path, small_limits=True):
        # Response latency and body reads have separate bounds, not the header deadline.
        assert request(data, "/slow?ms=800")[0] == 200
        with socket.create_connection(("127.0.0.1", data), timeout=2) as client:
            client.sendall(
                b"POST /missing HTTP/1.1\r\nHost: fixture\r\nContent-Length: 2\r\n"
                b"Connection: close\r\n\r\na"
            )
            time.sleep(0.8)
            client.sendall(b"b")
            assert b"404 Not Found" in client.recv(4096)
        with socket.create_connection(("127.0.0.1", data), timeout=2) as client:
            client.sendall(
                b"GET /hello.txt HTTP/1.1\r\nHost: fixture\r\n\r\n"
                b"GET /hello.txt HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n"
            )
            chunks = []
            while chunk := client.recv(4096):
                chunks.append(chunk)
            assert b"".join(chunks).count(b"probe-public-ok") == 2
