import pytest

from probe.sandbox.docker_env import DockerEnv
from tests.sandbox.fakes import Client


def test_topology_and_exclusive_control_aliases(tmp_path):
    client = Client()
    with DockerEnv("topology", client=client, cache_dir=tmp_path) as env:
        nets = {n.name: n for n in client.networks.items}
        assert nets[env.names["pub"]].kwargs["internal"] is True
        assert nets[env.names["priv"]].kwargs["internal"] is True
        assert nets[env.names["ctl"]].kwargs["internal"] is False
        target = env.create_target("image")
        assert set(target.connections) == {env.names["pub"], env.names["priv"]}
        assert target.connections[env.names["priv"]] == ["target"]
        assert target.started is False
        fakehttp = env.start_fixture("fakehttp", api_aliases=["api.example.test"])
        assert fakehttp.connections[env.names["pub"]] == [
            "fakehttp",
            "public.probe.test",
            "api.example.test",
        ]
        assert fakehttp.connections[env.names["ctl"]] == ["probe-fakehttp-admin-topology"]
        assert fakehttp.kwargs["ports"] == {"9090/tcp": ("127.0.0.1", None)}
        assert fakehttp.kwargs["entrypoint"] == ["fixtures"]
        assert fakehttp.kwargs["command"] == [
            "fakehttp",
            "--host",
            "0.0.0.0",  # noqa: S104 - asserts fixture data listener
            "--port",
            "80",
            "--admin-host",
            "probe-fakehttp-admin-topology",
            "--admin-port",
            "9090",
        ]
        canary = env.start_fixture("canary")
        assert canary.connections[env.names["priv"]] == [
            "canary.probe.test",
            "metadata.google.internal",
            "metadata",
            "instance-data",
            "internal.probe.test",
        ]
        assert canary.connections[env.names["ctl"]] == ["probe-canary-admin-topology"]
        relay = env.start_fixture("relay", target_port=3000, target_host="172.16.0.2")
        assert relay.connections[env.names["ctl"]] == ["probe-relay-control-topology"]
        assert relay.kwargs["ports"] == {"8080/tcp": ("127.0.0.1", None)}
        assert relay.kwargs["command"] == [
            "relay",
            "--listen-host",
            "probe-relay-control-topology",
            "--listen-port",
            "8080",
            "--target-host",
            "172.16.0.2",
            "--target-port",
            "3000",
        ]
        for collection in (client.networks, client.volumes, client.containers):
            assert all(r.attrs["Labels"]["probe.scan"] == "topology" for r in collection.items)
            assert all(int(r.attrs["Labels"]["probe.created"]) > 0 for r in collection.items)
    assert not client.containers.list() and not client.networks.list() and not client.volumes.list()
    assert not list(tmp_path.glob("*.json"))


def test_attachment_failure_removes_created_objects_and_lease(tmp_path):
    client = Client()
    with (
        pytest.raises(RuntimeError, match="connect"),
        DockerEnv("failure", client=client, cache_dir=tmp_path) as env,
    ):
        client.fail_connect = True
        env.create_target("image")
    assert not client.containers.list() and not client.networks.list() and not client.volumes.list()
    assert not list(tmp_path.glob("*.json"))


def test_existing_volume_is_never_adopted_or_removed(tmp_path):
    client = Client()
    foreign = client.volumes.create(name="probe-data-collision", labels={})
    with pytest.raises(RuntimeError, match="exists"):
        DockerEnv("collision", client=client, cache_dir=tmp_path).create()
    assert not foreign.removed
    assert not client.networks.list()


def test_inspector_is_volume_only_and_readonly_by_default(tmp_path):
    client = Client()
    with DockerEnv("inspect", client=client, cache_dir=tmp_path) as env:
        inspector = env.create_inspector(["hash"])
        assert inspector.kwargs["network_mode"] == "none"
        assert "network" not in inspector.kwargs
        assert inspector.kwargs["volumes"] == {env.names["data"]: {"bind": "/data", "mode": "ro"}}
        assert inspector.kwargs["command"] == ["inspect", "--root", "/data", "hash"]
        reset = env.create_inspector(["reset", "--seed", "/seed"], writable=True)
        assert reset.kwargs["volumes"][env.names["data"]]["mode"] == "rw"


@pytest.mark.parametrize(
    "alias",
    [
        "probe-fakehttp-admin-x",
        "metadata",
        "localhost",
        "bad space",
        "-bad",
        "a" * 64,
        "public.probe.test",
    ],
)
def test_aliases_cannot_shadow_control_or_reserved_names(tmp_path, alias):
    with DockerEnv("x", client=Client(), cache_dir=tmp_path) as env, pytest.raises(ValueError):
        env.start_fixture("fakehttp", api_aliases=[alias])


def test_daemon_networks_without_ipam_are_ignored(tmp_path):
    client = Client()
    network = client.networks.create(name="host", labels={})
    network.attrs["IPAM"]["Config"] = None
    with DockerEnv("noipam", client=client, cache_dir=tmp_path) as env:
        assert env.ready


def test_network_creation_failure_rolls_back_and_releases(tmp_path, monkeypatch):
    client = Client()
    create = client.networks.create
    count = 0

    def fail_third(*args, **kwargs):
        nonlocal count
        count += 1
        if count == 3:
            raise RuntimeError("daemon create failed")
        return create(*args, **kwargs)

    monkeypatch.setattr(client.networks, "create", fail_third)
    with pytest.raises(RuntimeError, match="daemon create"):
        DockerEnv("partial", client=client, cache_dir=tmp_path).create()
    assert not client.networks.list()
    assert not list(tmp_path.glob("*.json"))


def test_cleanup_failure_retains_lease_for_retry(tmp_path, monkeypatch):
    client = Client()
    env = DockerEnv("retry", client=client, cache_dir=tmp_path).create()
    remove = env.volume.remove

    def fail_remove(**kwargs):
        raise RuntimeError("volume busy")

    monkeypatch.setattr(env.volume, "remove", fail_remove)
    assert "volume busy" in ";".join(env.close())
    assert (tmp_path / "retry.json").exists()
    monkeypatch.setattr(env.volume, "remove", remove)
    assert env.close() == []
    assert not list(tmp_path.glob("*.json"))


def test_initializer_has_only_chown_and_no_network_or_host_mount(tmp_path):
    client = Client()
    with DockerEnv("init", client=client, cache_dir=tmp_path) as env:
        env.initialize_data("image")
        helper = client.containers.items[-1]
        assert helper.removed
        assert helper.kwargs["user"] == "0:0"
        assert helper.kwargs["cap_drop"] == ["ALL"]
        assert helper.kwargs["cap_add"] == ["CHOWN"]
        assert helper.kwargs["network_mode"] == "none"
        assert helper.kwargs["volumes"] == {env.names["data"]: {"bind": "/data", "mode": "rw"}}
        assert helper.kwargs["command"][-1] == "import os; os.chown('/data', 10001, 10001)"


def test_control_url_requires_owned_loopback_binding(tmp_path):
    client = Client()
    with DockerEnv("url", client=client, cache_dir=tmp_path) as env:
        fixture = env.start_fixture("fakehttp")
        ports = {"9090/tcp": [{"HostIp": "127.0.0.1", "HostPort": "12345"}]}
        fixture.attrs["NetworkSettings"]["Ports"] = ports
        assert env.control_url(fixture) == "http://127.0.0.1:12345"
        ports["9090/tcp"][0]["HostIp"] = "0.0.0.0"  # noqa: S104 - rejected publication
        with pytest.raises(RuntimeError, match="loopback"):
            env.control_url(fixture)


def test_target_image_cannot_create_unlabeled_anonymous_volumes(tmp_path, monkeypatch):
    from types import SimpleNamespace

    client = Client()
    image = SimpleNamespace(attrs={"Config": {"Volumes": {"/unowned": {}}}})
    monkeypatch.setattr(client.images, "get", lambda ref: image)
    with DockerEnv("imagevol", client=client, cache_dir=tmp_path) as env:
        with pytest.raises(ValueError, match="volume"):
            env.create_target("untrusted")
        assert not client.containers.list()


def test_relay_uses_only_private_numeric_target_and_scaled_idle_timeout(tmp_path):
    with DockerEnv("relayguard", client=Client(), cache_dir=tmp_path) as env:
        relay = env.start_fixture(
            "relay", target_port=3000, target_host="172.16.0.2", idle_timeout=190
        )
        command = relay.kwargs["command"]
        assert command[command.index("--target-host") + 1] == "172.16.0.2"
        assert relay.kwargs["environment"]["PROBE_RELAY_TARGET_SUBNET"] == env.lease.private
        assert relay.kwargs["environment"]["PROBE_RELAY_IDLE_TIMEOUT"] == "190"
        with pytest.raises(ValueError, match="private"):
            env.start_fixture("relay", target_port=3000, target_host="8.8.8.8")


def test_old_docker_engine_is_refused_before_resources_are_created(tmp_path, monkeypatch):
    client = Client()
    monkeypatch.setattr(client, "version", lambda: {"Version": "25.0.5"}, raising=False)
    with pytest.raises(RuntimeError, match="26"):
        DockerEnv("olddocker", client=client, cache_dir=tmp_path).create()
    assert not client.networks.items and not client.volumes.items


def test_data_volume_has_a_size_limit(tmp_path):
    with DockerEnv("disklimit", client=Client(), cache_dir=tmp_path) as env:
        assert env.volume.kwargs["driver"] == "local"
        options = env.volume.kwargs["driver_opts"]
        assert options["type"] == "tmpfs"
        assert "size=256m" in options["o"]


def test_tmpfs_mount_survives_between_helpers(tmp_path):
    with DockerEnv("mountlife", client=Client(), cache_dir=tmp_path) as env:
        env.initialize_data("image")
        holder = env._data_holder
        assert holder.started and not holder.removed
        assert holder.kwargs["network_mode"] == "none"
        assert holder.kwargs["volumes"] == {env.names["data"]: {"bind": "/data", "mode": "rw"}}
        first = env.create_inspector(["hash"])
        env.remove_container(first)
        env.create_inspector(["hash"])
        assert env._data_holder is holder and not holder.removed
    assert holder.removed


def test_close_racing_inspector_creation_reclaims_volume_and_lease(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    client = Client()
    env = DockerEnv("inspect-race", client=client, cache_dir=tmp_path).create()
    entered, release, closing = Event(), Event(), Event()
    create = client.containers.create

    def delayed_create(**kwargs):
        entered.set()
        assert release.wait(5)
        return create(**kwargs)

    monkeypatch.setattr(client.containers, "create", delayed_create)
    with ThreadPoolExecutor(max_workers=2) as pool:
        inspector = pool.submit(env.create_inspector, ["hash"])
        assert entered.wait(2)

        def close():
            closing.set()
            return env.close()

        cleanup = pool.submit(close)
        assert closing.wait(2)
        release.set()
        inspector.result(timeout=5)
        assert cleanup.result(timeout=5) == []
    assert not client.containers.list()
    assert not client.volumes.list()
    assert not list(tmp_path.glob("*.json"))
    with pytest.raises(RuntimeError, match=r"clos|creat"):
        env.create_inspector(["hash"])
