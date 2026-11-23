"""Real-Docker gates. Missing local images skip; runtime/topology defects fail."""

import http.client
import ipaddress
import time
import urllib.error
import urllib.request
import uuid

import docker
import pytest

from probe.runners.container import ContainerRunner
from probe.sandbox.docker_env import DockerEnv
from probe.sandbox.gc import collect
from probe.sandbox.spec import labels, target_spec
from probe.wire.jsonrpc import Request

pytestmark = pytest.mark.docker
IMAGE = "probe-refserver:dev"
FIXTURES = "probe-fixtures:dev"


def require_docker(*images):
    try:
        client = docker.from_env(timeout=10)
        client.ping()
    except docker.errors.DockerException as exc:
        pytest.skip(f"Docker daemon unavailable: {exc}")
    for image in images:
        try:
            client.images.get(image)
        except docker.errors.ImageNotFound:
            pytest.skip(f"required local image missing: {image}")
    return client


def assert_clean(client, scan):
    filters = {"label": f"probe.scan={scan}"}
    assert not client.containers.list(all=True, filters=filters)
    assert not client.networks.list(filters=filters)
    assert not client.volumes.list(filters=filters)


def run_script(env, script, *, network=None):
    if network is None:
        container = env.create_target(IMAGE, command=["python", "-c", script])
    else:
        spec = target_spec(env.scan_id, IMAGE, command=["python", "-c", script])
        spec["network"] = env.names[network]
        container = env._container("target", spec)
    container.start()
    code = container.wait(timeout=15)["StatusCode"]
    output = container.logs().decode()
    assert code == 0, output
    return output


async def test_sandbox_refserver_real_stdio_hardening_and_cleanup(tmp_path):
    client = require_docker(IMAGE)
    scan = "t14-" + uuid.uuid4().hex[:12]
    env = DockerEnv(scan, client=client, cache_dir=tmp_path)
    # The available reference image is trusted for this empty-volume setup.
    # Production initialization defaults to the trusted fixtures image.
    runner = ContainerRunner(IMAGE, sandbox=env, mode_deadline_s=30, initialize_data=False)
    try:
        env.create()
        env.initialize_data(IMAGE)
        transport = await runner.start()
        response = await transport.request(
            Request(
                1,
                "initialize",
                {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "sandbox-gate", "version": "1"},
                },
            ).to_obj(),
            timeout=15,
        )
        assert "serverInfo" in response.unwrap()
        target = env.containers[-1]
        target.reload()
        cfg, host = target.attrs["Config"], target.attrs["HostConfig"]
        assert cfg["User"] == "10001:10001"
        assert host["ReadonlyRootfs"] and host["Init"]
        assert host["CapDrop"] == ["ALL"]
        assert host["SecurityOpt"] == ["no-new-privileges"]
        assert host["Memory"] == host["MemorySwap"] == 1024**3
        assert host["NanoCpus"] == 10**9 and host["PidsLimit"] == 256
        assert host["Ulimits"] == [{"Name": "nofile", "Hard": 1024, "Soft": 1024}]
        assert set(target.attrs["NetworkSettings"]["Networks"]) == {
            env.names["pub"],
            env.names["priv"],
        }
        assert all(m["Type"] == "volume" for m in target.attrs["Mounts"])
        extra = await runner.second_instance()
        response = await extra.request(
            Request(
                2,
                "initialize",
                {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "second", "version": "1"},
                },
            ).to_obj(),
            timeout=15,
        )
        assert "serverInfo" in response.unwrap()
        old = transport
        transport = await runner.restart()
        assert transport is not old and not old.alive()
    finally:
        await runner.stop()
        assert_clean(client, scan)
        assert not list(tmp_path.glob("*.json"))


@pytest.mark.parametrize("network", ["pub", "priv", None])
def test_sandbox_internal_debug_containers_have_no_internet(tmp_path, network):
    client = require_docker(IMAGE)
    scan = "t14-" + uuid.uuid4().hex[:12]
    try:
        with DockerEnv(scan, client=client, cache_dir=tmp_path) as env:
            output = run_script(
                env,
                """
import urllib.request
try:
    urllib.request.urlopen('https://example.com', timeout=2)
except Exception:
    print('blocked')
else:
    raise RuntimeError('external connectivity escaped sandbox')
""",
                network=network,
            )
            assert "blocked" in output
    finally:
        assert_clean(client, scan)
        assert not list(tmp_path.glob("*.json"))


def test_sandbox_real_command_overrides_image_entrypoint_and_volume_owner(tmp_path):
    client = require_docker(IMAGE)
    scan = "t14-" + uuid.uuid4().hex[:12]
    try:
        with DockerEnv(scan, client=client, cache_dir=tmp_path) as env:
            env.initialize_data(IMAGE)
            output = run_script(
                env,
                """
import os
from pathlib import Path
assert os.getuid() == 10001
Path('/data/test.txt').write_text('ok')
assert os.stat('/data').st_uid == 10001
try:
    Path('/root-writable').write_text('bad')
except OSError:
    print('readonly')
else:
    raise RuntimeError('writable root')
""",
            )
            assert "readonly" in output
    finally:
        assert_clean(client, scan)


def wait_admin(env, container, path):
    url = env.control_url(container) + path
    deadline = time.monotonic() + 20
    while True:
        try:
            with urllib.request.urlopen(url, timeout=1) as response:  # noqa: S310 - owned loopback URL
                return response.read()
        except (
            urllib.error.URLError,
            TimeoutError,
            http.client.RemoteDisconnected,
            ConnectionError,
        ):
            if time.monotonic() >= deadline:
                pytest.fail(f"fixture not ready: {container.logs().decode()}")
            time.sleep(0.1)


def test_sandbox_full_fixture_topology_and_admin_isolation(tmp_path):
    client = require_docker(IMAGE, FIXTURES)
    scan = "t14-" + uuid.uuid4().hex[:12]
    try:
        with DockerEnv(scan, client=client, cache_dir=tmp_path) as env:
            fakehttp = env.start_fixture("fakehttp", api_aliases=["api.example.test"])
            canary = env.start_fixture("canary")
            wait_admin(env, fakehttp, "/_probe/state")
            wait_admin(env, canary, "/_probe/hits")
            for fixture, role, network in (
                (fakehttp, "fakehttp", "pub"),
                (canary, "canary", "priv"),
            ):
                fixture.reload()
                endpoints = fixture.attrs["NetworkSettings"]["Networks"]
                alias = f"probe-{role}-admin-{scan}"
                assert alias in endpoints[env.names["ctl"]]["Aliases"]
                assert alias not in endpoints[env.names[network]]["Aliases"]
                output = fixture.exec_run(
                    ["python", "-c", f"import socket; print(socket.gethostbyname({alias!r}))"]
                )
                assert output.exit_code == 0
                assert output.output.decode().strip() == endpoints[env.names["ctl"]]["IPAddress"]
            fake_ip = fakehttp.attrs["NetworkSettings"]["Networks"][env.names["pub"]]["IPAddress"]
            canary_ip = canary.attrs["NetworkSettings"]["Networks"][env.names["priv"]]["IPAddress"]
            assert ipaddress.ip_address(fake_ip).is_global
            assert ipaddress.ip_address(canary_ip).is_private
            output = run_script(
                env,
                f"""
import ipaddress, socket, urllib.request
assert ipaddress.ip_address(socket.gethostbyname('public.probe.test')).is_global
body = urllib.request.urlopen('http://public.probe.test/hello.txt', timeout=3).read()
assert body == b'probe-public-ok'
assert b'probe-canary' in urllib.request.urlopen('http://canary.probe.test/', timeout=3).read()
for host in [{fake_ip!r}, {canary_ip!r}]:
    try:
        socket.create_connection((host, 9090), timeout=1).close()
    except OSError:
        pass
    else:
        raise RuntimeError('admin reachable over data network')
for host in ['probe-fakehttp-admin-{scan}', 'probe-canary-admin-{scan}']:
    try:
        socket.create_connection((host, 9090), timeout=1).close()
    except OSError:
        pass
    else:
        raise RuntimeError('control alias reachable from target')
try:
    urllib.request.urlopen('http://public.probe.test/_probe/state', timeout=3)
except urllib.error.HTTPError as exc:
    assert exc.code == 404
else:
    raise RuntimeError('admin route exposed on public app')
print('isolated')
""",
            )
            assert "isolated" in output
    finally:
        assert_clean(client, scan)
        assert not list(tmp_path.glob("*.json"))


def test_sandbox_gc_real_owned_resources(tmp_path):
    client = require_docker(IMAGE)
    scan = "t14-" + uuid.uuid4().hex[:12]
    env = DockerEnv(scan, client=client, cache_dir=tmp_path)
    env.created = time.time() - 7200
    env.labels = labels(scan, env.created)
    try:
        env.create()
        target = env.create_target(IMAGE, command=["python", "-c", "import time; time.sleep(30)"])
        target.start()
        result = collect(client=client, cache_dir=tmp_path, scan_id=scan)
        assert not result.errors
        assert target.name in result.removed
        assert_clean(client, scan)
    finally:
        assert env.close() == []
        assert_clean(client, scan)


def test_sandbox_control_alias_binds_control_ip_at_process_start(tmp_path):
    """Networking gate independent of the fixtures runtime, using the same topology."""
    client = require_docker(IMAGE)
    scan = "t14-" + uuid.uuid4().hex[:12]
    try:
        with DockerEnv(scan, client=client, cache_dir=tmp_path) as env:
            alias = f"probe-fakehttp-admin-{scan}"
            script = f"""
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer
host = socket.gethostbyname({alias!r})
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(host.encode())
HTTPServer((host, 9090), Handler).serve_forever()
"""
            spec = target_spec(scan, IMAGE, command=["python", "-c", script])
            spec.pop("volumes")
            spec["ports"] = {"9090/tcp": ("127.0.0.1", None)}
            spec["networking_config"] = {
                env.names["pub"]: client.api.create_endpoint_config(aliases=["public.probe.test"])
            }
            fixture = env._container("fakehttp", spec)
            env.networks["ctl"].connect(fixture, aliases=[alias])
            fixture.start()
            response = wait_admin(env, fixture, "/")
            fixture.reload()
            endpoints = fixture.attrs["NetworkSettings"]["Networks"]
            control_ip = endpoints[env.names["ctl"]]["IPAddress"]
            assert response.decode() == control_ip
            public_ip = endpoints[env.names["pub"]]["IPAddress"]
            assert ipaddress.ip_address(public_ip).is_global
            output = run_script(
                env,
                f"""
import socket
for host in [{public_ip!r}, {control_ip!r}, {alias!r}]:
    try:
        socket.create_connection((host, 9090), timeout=1).close()
    except OSError:
        pass
    else:
        raise RuntimeError('control listener reachable from target')
print('control-isolated')
""",
            )
            assert "control-isolated" in output
    finally:
        assert_clean(client, scan)
        assert not list(tmp_path.glob("*.json"))
