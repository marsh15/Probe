"""Lease locking is exercised across processes, not only within one interpreter."""

import ipaddress
import json
import multiprocessing
import os

import pytest

from probe.sandbox.docker_env import SubnetAllocator, SubnetLease


def reserve_in_process(root, scan, queue):
    lease = SubnetAllocator(root).reserve(scan)
    queue.put((lease.public, lease.private))


def reject_nonregular_record(root, queue):
    try:
        SubnetAllocator(root).reserve("next-scan")
    except RuntimeError as exc:
        queue.put(str(exc))


def test_fifo_lease_is_preserved_and_cannot_block_reservation(tmp_path):
    fifo = tmp_path / "foreign.json"
    os.mkfifo(fifo, 0o600)
    ctx = multiprocessing.get_context("spawn")
    queue = ctx.Queue()
    process = ctx.Process(target=reject_nonregular_record, args=(tmp_path, queue))
    process.start()
    try:
        process.join(3)
        assert not process.is_alive(), "opening a nonregular lease blocked the allocator"
        assert process.exitcode == 0
        assert "ambiguous subnet lease" in queue.get(timeout=1)
        assert fifo.is_fifo()
    finally:
        if process.is_alive():
            process.kill()
            process.join(3)
        queue.close()


def test_concurrent_reservations_are_unique(tmp_path):
    ctx = multiprocessing.get_context("spawn")
    queue = ctx.Queue()
    processes = [
        ctx.Process(target=reserve_in_process, args=(tmp_path, f"s{i}", queue)) for i in range(4)
    ]
    for proc in processes:
        proc.start()
    pairs = [queue.get(timeout=15) for _ in processes]
    for proc in processes:
        proc.join(15)
        assert proc.exitcode == 0
    assert len({p[0] for p in pairs}) == len({p[1] for p in pairs}) == 4
    assert all(ipaddress.ip_network(p[0]).network_address.is_global for p in pairs)


def test_avoid_docker_subnets_release_and_exhaustion(tmp_path):
    allocator = SubnetAllocator(tmp_path, pool="11.250.0.0/23")
    first = allocator.reserve("first", used=["11.250.0.0/24", "172.16.0.0/24"])
    assert first.public == "11.250.1.0/24"
    assert first.private != "172.16.0.0/24"
    with pytest.raises(RuntimeError, match="exhausted"):
        allocator.reserve("second", used=["11.250.0.0/24"])
    allocator.release(first)
    assert not list(tmp_path.glob("*.json"))


@pytest.mark.parametrize(
    "pool",
    ["10.0.0.0/16", "127.0.0.0/24", "0.0.0.0/0", "::/64", "11.250.0.1/24", "11.250.0.0/25", "bad"],
)
def test_public_pool_requires_bounded_global_ipv4_ranges(tmp_path, pool):
    with pytest.raises(ValueError):
        SubnetAllocator(tmp_path, pool=pool)


def test_environment_pool_is_validated(tmp_path, monkeypatch):
    monkeypatch.setenv("PROBE_PUBLIC_SUBNET_POOL", "192.168.0.0/16")
    with pytest.raises(ValueError):
        SubnetAllocator(tmp_path)


def test_stale_leases_do_not_override_active_process_or_docker_scan(tmp_path):
    allocator = SubnetAllocator(tmp_path, pool="11.250.0.0/24", clock=lambda: 10000)
    lease = allocator.reserve("active")
    path = tmp_path / "active.json"
    data = json.loads(path.read_text())
    data["created"] = 1
    path.write_text(json.dumps(data))
    assert allocator.collect_stale(active_scans=set()) == []  # this process still owns it
    data["pid"] = 2**30
    path.write_text(json.dumps(data))
    assert allocator.collect_stale(active_scans={"active"}) == []
    assert allocator.collect_stale(active_scans=set()) == ["active"]
    replacement = allocator.reserve("active")
    allocator.release(lease)  # stale token must not remove its replacement
    assert path.exists()
    allocator.release(replacement)


def test_live_scan_id_cannot_be_reserved_twice(tmp_path):
    allocator = SubnetAllocator(tmp_path)
    allocator.reserve("live")
    with pytest.raises(RuntimeError, match="lease"):
        allocator.reserve("live")


def test_no_symlink_following_or_unowned_file_deletion(tmp_path):
    victim = tmp_path / "unowned"
    victim.write_text("keep")
    (tmp_path / "evil.json").symlink_to(victim)
    (tmp_path / "junk.json").write_text("{}")
    assert SubnetAllocator(tmp_path).collect_stale(active_scans=set()) == []
    assert victim.read_text() == "keep"
    assert (tmp_path / "evil.json").is_symlink()
    assert (tmp_path / "junk.json").exists()
    assert os.getpid() > 0


def test_young_dead_process_lease_is_preserved(tmp_path):
    allocator = SubnetAllocator(tmp_path, clock=lambda: 10000)
    allocator.reserve("young")
    path = tmp_path / "young.json"
    data = json.loads(path.read_text())
    data["pid"] = 2**30
    data["created"] = 9999
    path.write_text(json.dumps(data))
    assert allocator.collect_stale(active_scans=set()) == []
    assert path.exists()


def test_corrupt_reservation_is_fail_closed(tmp_path):
    (tmp_path / "unknown.json").write_text("{}")
    with pytest.raises(RuntimeError, match="ambiguous"):
        SubnetAllocator(tmp_path).reserve("new")


def interrupt_lease_write(root, phase):
    from probe.sandbox import docker_env

    def interrupted_dump(data, file):
        file.write("{")
        file.flush()
        os._exit(17)

    original_link = os.link

    def interrupted_link(*args, **kwargs):
        if phase == "after_publish":
            original_link(*args, **kwargs)
        os._exit(17)

    if phase == "write":
        docker_env.json.dump = interrupted_dump
    else:
        docker_env.os.link = interrupted_link
    SubnetAllocator(root).reserve("interrupted")


@pytest.mark.parametrize("phase", ["write", "before_publish", "after_publish"])
def test_process_interruption_never_publishes_partial_final_lease(tmp_path, phase):
    ctx = multiprocessing.get_context("spawn")
    child = ctx.Process(target=interrupt_lease_write, args=(tmp_path, phase))
    child.start()
    try:
        child.join(10)
        assert child.exitcode == 17
        final = tmp_path / "interrupted.json"
        if phase == "after_publish":
            interrupted = SubnetLease(**json.loads(final.read_text()))
        else:
            assert not list(tmp_path.glob("*.json"))
        allocator = SubnetAllocator(tmp_path)
        lease = allocator.reserve("later")
        assert json.loads((tmp_path / "later.json").read_text())["token"] == lease.token
        allocator.release(lease)
        if phase == "after_publish":
            allocator.release(interrupted)
        assert sorted(p.name for p in tmp_path.iterdir()) == [".lock"]
    finally:
        if child.is_alive():
            child.kill()
            child.join(5)


def test_lease_publish_collision_preserves_foreign_final_and_cleans_temporary(
    tmp_path, monkeypatch
):
    original_link = os.link
    final = tmp_path / "collision.json"

    def collide(*args, **kwargs):
        final.write_text("foreign record")
        return original_link(*args, **kwargs)

    monkeypatch.setattr("probe.sandbox.docker_env.os.link", collide)
    with pytest.raises(FileExistsError):
        SubnetAllocator(tmp_path).reserve("collision")
    assert final.read_text() == "foreign record"
    assert sorted(p.name for p in tmp_path.iterdir()) == [".lock", "collision.json"]
    with pytest.raises(RuntimeError, match="ambiguous"):
        SubnetAllocator(tmp_path).reserve("later")


def test_serialization_error_cleans_only_own_temporary_file(tmp_path, monkeypatch):
    unrelated = tmp_path / ".probe-lease-unrelated.tmp"
    unrelated.write_text("keep")

    def fail(data, file):
        file.write("{")
        raise OSError("write failed")

    monkeypatch.setattr("probe.sandbox.docker_env.json.dump", fail)
    with pytest.raises(OSError, match="write failed"):
        SubnetAllocator(tmp_path).reserve("failed")
    assert sorted(p.name for p in tmp_path.iterdir()) == [".lock", unrelated.name]
    assert unrelated.read_text() == "keep"


@pytest.mark.parametrize("kind", ["symlink", "public-file"])
def test_temporary_recovery_requires_owned_regular_private_file(tmp_path, kind):
    victim = tmp_path / "unrelated"
    victim.write_text("keep")
    artifact = tmp_path / f".probe-lease-{2**30}-{'a' * 32}.tmp"
    if kind == "symlink":
        artifact.symlink_to(victim)
    else:
        artifact.write_text("{")
        artifact.chmod(0o644)
    allocator = SubnetAllocator(tmp_path)
    with pytest.raises(RuntimeError, match="ambiguous"):
        allocator.reserve("later")
    with pytest.raises(RuntimeError, match="ambiguous"):
        allocator.collect_stale(active_scans=set())
    assert victim.read_text() == "keep"
    assert artifact.is_symlink() if kind == "symlink" else artifact.read_text() == "{"


def test_live_writer_temporary_is_not_recovered(tmp_path):
    artifact = tmp_path / f".probe-lease-{os.getpid()}-{'a' * 32}.tmp"
    artifact.write_text("{")
    artifact.chmod(0o600)
    allocator = SubnetAllocator(tmp_path)
    lease = allocator.reserve("later")
    assert artifact.read_text() == "{"
    allocator.release(lease)


def test_gc_recovers_only_dead_owned_temporary_artifacts(tmp_path):
    owned = tmp_path / f".probe-lease-{2**30}-{'a' * 32}.tmp"
    owned.write_text("{")
    owned.chmod(0o600)
    unrelated = tmp_path / ".probe-lease-unrelated.tmp"
    unrelated.write_text("keep")
    malformed = tmp_path / "unrelated.json"
    malformed.write_text("{")
    assert SubnetAllocator(tmp_path).collect_stale(active_scans=set()) == []
    assert not owned.exists()
    assert unrelated.read_text() == "keep"
    assert malformed.read_text() == "{"
