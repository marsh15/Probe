from probe.sandbox.gc import collect, doctor
from tests.sandbox.fakes import Client


def test_gc_requires_matching_name_valid_scan_and_old_label(tmp_path):
    client = Client()
    old = {"probe.scan": "old", "probe.created": "1"}
    owned = [
        client.containers.create(name="probe-target-old-abcdef123456", labels=old),
        client.networks.create(name="probe-pub-old", labels=old),
        client.volumes.create(name="probe-data-old", labels=old),
    ]
    foreign = [
        client.containers.create(name="other", labels=old),
        client.networks.create(name="probe-pub-old", labels={}),
        client.volumes.create(
            name="probe-data-new", labels={"probe.scan": "new", "probe.created": "9999"}
        ),
        client.volumes.create(
            name="probe-data-bad", labels={"probe.scan": "bad", "probe.created": "nan"}
        ),
    ]
    result = collect(client=client, cache_dir=tmp_path, now=10000)
    assert len(result.removed) == 3
    assert not result.errors
    assert all(r.removed for r in owned)
    assert not any(r.removed for r in foreign)


def test_cleanup_rechecks_ownership(tmp_path):
    from probe.sandbox.docker_env import DockerEnv

    client = Client()
    env = DockerEnv("changed", client=client, cache_dir=tmp_path).create()
    target = env.create_target("image")
    target.attrs["Config"]["Labels"] = {}
    errors = env.close()
    assert not target.removed
    assert errors
    assert list(tmp_path.glob("*.json"))  # retain reservation until all resources are gone


def test_doctor_reports_basic_prerequisites():
    result = doctor(client=Client())
    assert result["daemon"] is True
    assert result["linux"] is True
    assert result["architecture"] == "aarch64"


def test_scoped_gc_never_releases_other_scans_lease(tmp_path):
    import json

    from probe.sandbox.docker_env import SubnetAllocator

    allocator = SubnetAllocator(tmp_path, clock=lambda: 1)
    allocator.reserve("other")
    path = tmp_path / "other.json"
    data = json.loads(path.read_text())
    data["pid"] = 2**30
    path.write_text(json.dumps(data))
    client = Client()
    client.networks.create(
        name="probe-pub-other", labels={"probe.scan": "other", "probe.created": "9900"}
    )
    result = collect(client=client, cache_dir=tmp_path, now=10000, scan_id="selected")
    assert not result.leases
    assert path.exists()


def test_gc_never_removes_resources_of_a_live_lease(tmp_path):
    from probe.sandbox.docker_env import SubnetAllocator

    allocator = SubnetAllocator(tmp_path, clock=lambda: 1)
    allocator.reserve("live")
    client = Client()
    meta = {"probe.scan": "live", "probe.created": "1"}
    resources = [
        client.containers.create(name="probe-target-live-abcdef123456", labels=meta),
        client.networks.create(name="probe-pub-live", labels=meta),
        client.volumes.create(name="probe-data-live", labels=meta),
    ]
    result = collect(client=client, cache_dir=tmp_path, now=10000, scan_id="live")
    assert not result.removed and not any(r.removed for r in resources)
    assert (tmp_path / "live.json").exists()


def test_doctor_refuses_unsupported_docker_engine(monkeypatch):
    client = Client()
    monkeypatch.setattr(client, "version", lambda: {"Version": "25.0.5"}, raising=False)
    assert "26" in doctor(client=client).get("error", "")
