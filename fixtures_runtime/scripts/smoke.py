"""Local Docker acceptance smoke. Creates disposable internal networks, never pushes."""

import hashlib
import json
import shutil
import socket
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener

IMAGE = "probe-fixtures:dev"
DOCKER = shutil.which("docker")
OPENER = build_opener(ProxyHandler({}))
PREFIX = "fixtures-smoke-" + uuid.uuid4().hex[:10]
CONTAINERS, NETWORKS = [], []


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def docker(*args):
    return subprocess.check_output([DOCKER, *args], text=True).strip()  # noqa: S603


def http(port, path, value=None):
    body = None if value is None else json.dumps(value).encode()
    request = Request(f"http://127.0.0.1:{port}{path}", data=body)
    try:
        with OPENER.open(request, timeout=3) as response:
            return response.status, response.read()
    except HTTPError as exc:
        return exc.code, exc.read()


def mapped(name, port):
    bindings = json.loads(docker("inspect", name))[0]["NetworkSettings"]["Ports"]
    if not bindings.get(f"{port}/tcp"):
        raise RuntimeError("container did not publish port: " + docker("logs", name))
    return int(bindings[f"{port}/tcp"][0]["HostPort"])


def ready(name, port, path):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            if http(port, path)[0] == 200:
                return
        except (OSError, URLError):
            pass
        time.sleep(0.05)
    raise RuntimeError("listener not ready: " + docker("logs", name))


def start(name, *args):
    CONTAINERS.append(name)
    docker("run", "-d", "--name", name, *args)
    return name


def network(name, *, internal=True):
    docker("network", "create", *(["--internal"] if internal else []), name)
    NETWORKS.append(name)
    return name


def run():
    info = json.loads(docker("image", "inspect", IMAGE))[0]
    check(info["Size"] < 150000000, "image exceeds size gate")
    check(info["Config"]["User"] == "10001:10001", "wrong image user")
    check(
        docker("run", "--rm", "--network", "none", IMAGE, "inspect", "hash") == "{}",
        "empty /data snapshot",
    )
    modules = docker(
        "run",
        "--rm",
        "--network",
        "none",
        "--entrypoint",
        "python3",
        IMAGE,
        "-c",
        "import os,importlib.util; assert (os.getuid(),os.getgid())==(10001,10001); "
        'assert all(importlib.util.find_spec(n) is None for n in ("pytest","httpx","pip")); '
        'print("runtime-only")',
    )
    check(modules == "runtime-only", "unexpected runtime dependencies")
    print(f"image: linux/{info['Architecture']} Size={info['Size']} user=10001:10001 runtime-only")
    control = network(PREFIX + "-control", internal=False)
    public = network(PREFIX + "-public")
    with tempfile.TemporaryDirectory(prefix=PREFIX) as temporary:
        base = Path(temporary)
        routes, data, seed = [base / name for name in ("routes", "data", "seed")]
        for directory in (routes, data, seed):
            directory.mkdir(mode=0o755)
        data.chmod(0o777)
        (seed / "seeded.txt").write_text("seed")
        (routes / "literal.txt").write_text("literal")
        (routes / "routes.yaml").write_text(
            "collections: {tasks: {id_field: id, seed: []}}\n"
            "routes: [{method: GET, path: /literal, body_file: literal.txt}]\n"
        )
        fake = PREFIX + "-fake"
        alias = PREFIX + "-admin"
        start(
            fake,
            "--network",
            control,
            "--network-alias",
            alias,
            "-p",
            "127.0.0.1::80",
            "-p",
            "127.0.0.1::9090",
            "--mount",
            f"type=bind,source={routes},target=/routes,readonly",
            IMAGE,
            "fakehttp",
            "--admin-host",
            alias,
            "--routes",
            "/routes/routes.yaml",
        )
        docker("network", "connect", "--alias", "public-fixture", public, fake)
        data_port, admin_port = mapped(fake, 80), mapped(fake, 9090)
        ready(fake, data_port, "/hello.txt")
        ready(fake, admin_port, "/_probe/log")
        check(http(data_port, "/literal") == (200, b"literal"), "literal route")
        check(http(data_port, "/c/tasks", {"title": "created"})[0] == 201, "collection create")
        check(
            json.loads(http(admin_port, "/_probe/state")[1])["collections"]["tasks"]
            == [{"id": 1, "title": "created"}],
            "collection state",
        )
        check(http(data_port, "/_probe/state")[0] == 404, "admin exposed on data listener")
        check(http(admin_port, "/hello.txt")[0] == 404, "data exposed on admin listener")
        http(
            admin_port,
            "/_probe/fault",
            {"route": "/hello.txt", "status": 429, "retry_after": 2, "count": 1},
        )
        check(http(data_port, "/hello.txt")[0] == 429, "fault missing")
        check(http(data_port, "/hello.txt")[0] == 200, "fault count")
        isolation = f"""
import socket
from urllib.request import urlopen
from urllib.error import URLError
assert urlopen("http://public-fixture/hello.txt", timeout=2).read() == b"probe-public-ok"
try:
    urlopen("http://public-fixture:9090/_probe/log", timeout=2)
except URLError:
    pass
else:
    raise AssertionError("admin port reachable from public network")
try:
    socket.getaddrinfo({alias!r},9090)
except socket.gaierror:
    pass
else:
    raise AssertionError("admin alias leaked to public network")
print("isolated")
"""
        check(
            docker(
                "run",
                "--rm",
                "--network",
                public,
                "--entrypoint",
                "python3",
                IMAGE,
                "-c",
                isolation,
            )
            == "isolated",
            "network isolation",
        )
        http(admin_port, "/_probe/reset", {})
        check(
            json.loads(http(admin_port, "/_probe/state")[1]) == {"collections": {"tasks": []}},
            "reset",
        )
        print(
            "fakehttp: YAML/literal, CRUD/state, bounded fault, reset, "
            "separate listeners, control-only DNS/IP PASS"
        )
        canary = PREFIX + "-canary"
        start(
            canary,
            "--network",
            control,
            "--network-alias",
            PREFIX + "-canary-admin",
            "-p",
            "127.0.0.1::80",
            "-p",
            "127.0.0.1::8080",
            "-p",
            "127.0.0.1::9090",
            IMAGE,
            "canary",
            "--admin-host",
            PREFIX + "-canary-admin",
        )
        first, second, admin = [mapped(canary, port) for port in (80, 8080, 9090)]
        ready(canary, admin, "/_probe/hits")
        check(http(first, "/one")[1] == b"probe-canary", "canary port 80")
        check(http(second, "/two", {"fake": "simulated"})[1] == b"probe-canary", "canary port 8080")
        hits = json.loads(http(admin, "/_probe/hits")[1])
        check([hit["path"] for hit in hits] == ["/one", "/two"], "shared canary hits")
        check(
            hits[1]["body_sha256"]
            == hashlib.sha256(json.dumps({"fake": "simulated"}).encode()).hexdigest(),
            "canary body hash",
        )
        print("canary: 80/8080, shared hits, body SHA256 PASS")
        target_code = """
import socket
server=socket.socket(); server.bind(("0.0.0.0",8888)); server.listen()
print("ready",flush=True)
while True:
    client,_=server.accept()
    with client:
        try:
            client.sendall(b"banner\\x00")
            chunks=[]
            while chunk:=client.recv(65536): chunks.append(chunk)
            client.sendall(b"".join(chunks)[::-1])
        except OSError: pass
"""
        target = start(
            PREFIX + "-target",
            "--network",
            control,
            "--network-alias",
            "raw-target",
            "--entrypoint",
            "python3",
            IMAGE,
            "-u",
            "-c",
            target_code,
        )
        deadline = time.monotonic() + 5
        while "ready" not in docker("logs", target):
            check(time.monotonic() < deadline, "raw target not ready")
            time.sleep(0.05)
        relay = start(
            PREFIX + "-relay",
            "--network",
            control,
            "-p",
            "127.0.0.1::8080",
            IMAGE,
            "relay",
            "--listen-host",
            "0.0.0.0",  # noqa: S104 - disposable private TCP smoke listener
            "--target-host",
            "raw-target",
            "--target-port",
            "8888",
        )
        relay_port = mapped(relay, 8080)
        deadline = time.monotonic() + 5
        while True:
            connection = None
            try:
                connection = socket.create_connection(("127.0.0.1", relay_port), timeout=2)
                greeting = bytearray()
                while len(greeting) < 7:
                    chunk = connection.recv(7 - len(greeting))
                    if not chunk:
                        raise ConnectionError("listener is not ready yet")
                    greeting.extend(chunk)
                check(greeting == b"banner\x00", "relay greeting: " + repr(greeting))
                break
            except OSError:
                if connection is not None:
                    connection.close()
                check(time.monotonic() < deadline, "relay not ready: " + docker("logs", relay))
                time.sleep(0.05)
        with connection:
            payload = bytes(range(256)) * 1024
            connection.sendall(payload)
            connection.shutdown(socket.SHUT_WR)
            chunks = []
            while chunk := connection.recv(65536):
                chunks.append(chunk)
            check(b"".join(chunks) == payload[::-1], "relay bytes/EOF")
        docker("stop", "-t", "5", relay)
        check(json.loads(docker("inspect", relay))[0]["State"]["ExitCode"] == 0, "relay shutdown")
        print("relay: binary bidirectional transfer, half-close, SIGTERM PASS")
        mounts = [
            "--mount",
            f"type=bind,source={data},target=/data",
            "--mount",
            f"type=bind,source={seed},target=/seed,readonly",
        ]
        check(
            json.loads(
                docker(
                    "run",
                    "--rm",
                    "--network",
                    "none",
                    *mounts,
                    IMAGE,
                    "inspect",
                    "reset",
                    "--seed",
                    "/seed",
                )
            )
            == {"reset": True},
            "inspector reset",
        )
        snapshot = json.loads(
            docker("run", "--rm", "--network", "none", *mounts, IMAGE, "inspect", "hash")
        )
        check(
            snapshot["seeded.txt"]["sha256"] == hashlib.sha256(b"seed").hexdigest(),
            "inspector snapshot",
        )
        check(
            json.loads(
                docker(
                    "run",
                    "--rm",
                    "--network",
                    "none",
                    *mounts,
                    IMAGE,
                    "inspect",
                    "exists",
                    "seeded.txt",
                )
            )
            == {"exists": True},
            "inspector exists",
        )
        print("inspector: nonroot /data, readonly /seed reset/hash/exists PASS")


if __name__ == "__main__":
    try:
        run()
    finally:
        for name in reversed(CONTAINERS):
            subprocess.run([DOCKER, "rm", "-f", name], capture_output=True, check=False)  # noqa: S603
        for name in reversed(NETWORKS):
            subprocess.run([DOCKER, "network", "rm", name], capture_output=True, check=False)  # noqa: S603
