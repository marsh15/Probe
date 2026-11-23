"""Fixture orchestration logic without Docker."""

import io
import sqlite3
import tarfile

import pytest

from probe.config.profile import FixturesSection
from probe.sandbox.fixtures import FixtureSet, FixtureState, build_seed

TOKEN = "0123456789ab"


def section(**kwargs):
    return FixturesSection.model_validate(kwargs)


def unpack(config):
    with tarfile.open(fileobj=io.BytesIO(build_seed(config, token=TOKEN))) as archive:
        return {
            entry.name: (entry, archive.extractfile(entry).read() if entry.isfile() else None)
            for entry in archive
        }


def test_seed_archive_has_sentinels_and_user_files(tmp_path):
    (tmp_path / "custom.txt").write_text("custom")
    entries = unpack(section(fs={"seed_dir": str(tmp_path)}))
    assert entries["custom.txt"][1] == b"custom"
    assert entries["secret/SENTINEL"][1] == f"PROBE-SENTINEL-{TOKEN}".encode()
    assert len(entries["allowed/big.log"][1]) == 5 * 1024 * 1024
    assert entries["allowed/link_out"][0].issym()
    assert entries["allowed/link_out"][0].linkname == "../secret"
    assert entries["probe-canary"][0].isdir()
    assert entries["allowed_evil/evil.txt"][1]
    assert all(e.uid == e.gid == 10001 and not e.mode & 0o7000 for e, _ in entries.values())


@pytest.mark.parametrize("kind", ["escape", "chain", "privileged", "fifo"])
def test_unsafe_seed_is_rejected(tmp_path, kind):
    if kind == "escape":
        (tmp_path / "bad").symlink_to("../outside")
    elif kind == "chain":
        (tmp_path / "a").symlink_to("b")
        (tmp_path / "b").symlink_to("../outside")
    elif kind == "privileged":
        (tmp_path / "bad").write_text("bad")
        (tmp_path / "bad").chmod(0o4755)
    else:
        import os

        os.mkfifo(tmp_path / "bad")
    with pytest.raises(ValueError, match="seed"):
        build_seed(section(fs={"seed_dir": str(tmp_path), "sentinel": False}), token=TOKEN)


@pytest.mark.parametrize("path", ["/etc/app.db", "/data/../out", "../out", "a//b", "/data"])
def test_database_path_must_be_confined(path):
    with pytest.raises(ValueError, match="path"):
        build_seed(section(sqlite={"path": path}), token=TOKEN)


def test_sqlite_seed_is_a_real_database(tmp_path):
    sql = tmp_path / "seed.sql"
    sql.write_text("CREATE TABLE notes (text); INSERT INTO notes VALUES ('seeded');")
    entries = unpack(section(sqlite={"path": "/data/app.db", "seed_sql": str(sql)}))
    with sqlite3.connect(":memory:") as db:
        db.deserialize(entries["app.db"][1])
        assert db.execute("SELECT * FROM notes").fetchall() == [("seeded",)]


@pytest.mark.parametrize(
    "sql", ["ATTACH DATABASE '/tmp/no' AS bad", "bad SQL", "PRAGMA journal_mode=WAL"]
)
def test_unsafe_or_invalid_sql_fails(tmp_path, sql):
    source = tmp_path / "seed.sql"
    source.write_text(sql)
    with pytest.raises(ValueError, match="SQLite seed"):
        build_seed(section(sqlite={"path": "app.db", "seed_sql": str(source)}), token=TOKEN)


def test_seed_output_cannot_traverse_a_link(tmp_path):
    (tmp_path / "alias").symlink_to("real")
    (tmp_path / "real").mkdir()
    with pytest.raises(ValueError, match="symlink"):
        build_seed(
            section(
                fs={"seed_dir": str(tmp_path), "sentinel": False}, sqlite={"path": "alias/app.db"}
            ),
            token=TOKEN,
        )


def test_diff_tracks_paths_sqlite_collections_and_non_get_log_window():
    before = FixtureState(
        fs={"old": 1, "same": 2, "edit": 3},
        sqlite={"db": {"n": 1}},
        collections={"tasks": []},
        log_length=7,
    )
    after = FixtureState(
        fs={"new": 1, "same": 2, "edit": 4},
        sqlite={"db": {"n": 2}},
        collections={"tasks": [{"id": 1}]},
        log_length=10,
        requests=[
            {"sequence": 7, "method": "POST"},
            {"sequence": 8, "method": "GET"},
            {"sequence": 9, "method": "POST"},
            {"sequence": 11, "method": "DELETE"},
        ],
    )
    diff = FixtureSet.diff(before, after)
    assert diff.added == ["new"]
    assert diff.removed == ["old"]
    assert diff.changed == ["edit"]
    assert diff.sqlite_changed == ["db"]
    assert diff.collections_changed == ["tasks"]
    assert diff.backend_writes == [{"sequence": 9, "method": "POST"}]


def test_seed_volume_upload_is_networkless_and_cleanup_and_gc_own_it(tmp_path, monkeypatch):
    from probe.sandbox.docker_env import DockerEnv
    from probe.sandbox.gc import collect
    from tests.sandbox.fakes import Client, Resource

    uploads = []
    monkeypatch.setattr(
        Resource,
        "put_archive",
        lambda self, path, data: uploads.append((self, path, data)) or True,
        raising=False,
    )
    client = Client()
    with DockerEnv("seed-unit", client=client, cache_dir=tmp_path) as env:
        env.populate_seed(b"captured")
        helper, path, content = uploads[0]
        assert (path, content) == ("/seed", b"captured")
        assert helper.kwargs["network_mode"] == "none"
        assert helper.kwargs["volumes"] == {"probe-seed-seed-unit": {"bind": "/seed", "mode": "rw"}}
        assert helper.removed
        inspector = env.create_inspector(
            ["reset", "--seed", "/seed/data"], writable=True, seed=True
        )
        assert inspector.kwargs["volumes"][env.seed_name]["mode"] == "ro"
        assert inspector.kwargs["volumes"][env.names["data"]]["mode"] == "rw"
        volume = env.seed_volume
        with pytest.raises(RuntimeError, match="without a seed"):
            env.populate_seed(b"again")
    assert volume.removed
    assert not client.volumes.list()
    # GC recognizes exactly the new seed name; it can collect an abandoned seed too.
    orphan = client.volumes.create(
        name="probe-seed-abandoned", labels={"probe.scan": "abandoned", "probe.created": "1"}
    )
    result = collect(client=client, cache_dir=tmp_path, now=10000)
    assert not result.errors
    assert orphan.name in result.removed


def test_seed_upload_failure_remains_owned_for_cleanup(tmp_path, monkeypatch):
    from probe.sandbox.docker_env import DockerEnv
    from tests.sandbox.fakes import Client, Resource

    monkeypatch.setattr(Resource, "put_archive", lambda *args: False, raising=False)
    client = Client()
    with (
        DockerEnv("bad-upload", client=client, cache_dir=tmp_path) as env,
        pytest.raises(RuntimeError, match="upload failed"),
    ):
        env.populate_seed(b"captured")
    assert not client.containers.list()
    assert not client.volumes.list()
    assert not client.networks.list()


def test_http_route_body_capture_and_escape_rejection(tmp_path):
    from probe.sandbox.fixtures import build_routes

    route = tmp_path / "source.yaml"
    (tmp_path / "body.txt").write_text("body")
    route.write_text("routes: [{method: GET, path: /text, body_file: body.txt}]")
    with tarfile.open(fileobj=io.BytesIO(build_routes(str(route)))) as archive:
        assert archive.extractfile("http/body.txt").read() == b"body"
        assert archive.extractfile("http/routes.yaml").read() == route.read_bytes()
    for unsafe in ("../outside", "/etc/passwd"):
        route.write_text(f"routes: [{{method: GET, path: /text, body_file: '{unsafe}'}}]")
        with pytest.raises(ValueError, match="path"):
            build_routes(str(route))
    (tmp_path / "alias").symlink_to("body.txt")
    route.write_text("routes: [{method: GET, path: /text, body_file: alias}]")
    with pytest.raises(ValueError, match="symlink"):
        build_routes(str(route))


def test_git_bundle_clone_and_invalid_bundle(tmp_path):
    import subprocess

    def git(*args):
        command = ["git", *args]
        subprocess.run(command, check=True, capture_output=True)  # noqa: S603 - fixed test argv

    repo = tmp_path / "repo"
    git("init", str(repo))
    (repo / "readme").write_text("bundled")
    git("-C", str(repo), "add", ".")
    git(
        "-C",
        str(repo),
        "-c",
        "user.name=Probe",
        "-c",
        "user.email=probe@example.test",
        "commit",
        "-m",
        "Seed",
    )
    bundle = tmp_path / "seed.bundle"
    git("-C", str(repo), "bundle", "create", str(bundle), "HEAD")
    entries = unpack(section(git={"path": "/data/repo", "seed_bundle": str(bundle)}))
    assert entries["repo/readme"][1] == b"bundled"
    assert "repo/.git/HEAD" in entries
    bundle.write_text("bad bundle")
    with pytest.raises(ValueError, match="git seed"):
        build_seed(section(git={"path": "repo", "seed_bundle": str(bundle)}), token=TOKEN)


async def test_snapshot_log_cursor_survives_resets_and_deleted_sqlite(monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    fixtures = FixtureSet(SimpleNamespace(), section(sqlite={"path": "gone.db"}), token=TOKEN)
    fixtures._services = {"fakehttp": "http://127.0.0.1"}
    records = [{"sequence": 10, "method": "POST"}]

    async def admin(service, method, path):
        if path == "/_probe/state":
            return {"collections": {"tasks": []}}
        if path == "/_probe/reset":
            records.clear()
            return {"reset": True}
        return list(records)

    inspector = AsyncMock(return_value={})
    monkeypatch.setattr(fixtures, "_inspect", inspector)
    monkeypatch.setattr(fixtures, "_admin", admin)
    before = await fixtures.snapshot()
    assert before.log_length == 10
    assert before.sqlite == {}  # Deleted databases remain observable as removed filesystem paths.
    await fixtures.reset()
    baseline = await fixtures.snapshot()
    assert baseline.log_length == 10
    records.append({"sequence": 11, "method": "POST"})
    after = await fixtures.snapshot()
    assert fixtures.diff(baseline, after).backend_writes == records
    assert all(call.args[0][0] != "sqlite-checksum" for call in inspector.call_args_list)


async def test_failed_inspector_is_removed_and_reports_the_operation(tmp_path, monkeypatch):
    from probe.sandbox.docker_env import DockerEnv
    from tests.sandbox.fakes import Client, Resource

    client = Client()
    with DockerEnv("inspect-fail", client=client, cache_dir=tmp_path) as env:
        fixtures = FixtureSet(env, section(), token=TOKEN)
        monkeypatch.setattr(Resource, "wait", lambda *args, **kwargs: {"StatusCode": 2})
        with pytest.raises(RuntimeError, match="inspector hash failed"):
            await fixtures.snapshot()
        inspector = client.containers.items[-1]
        assert inspector.removed
        assert inspector.kwargs["network_mode"] == "none"
        assert inspector.kwargs["volumes"][env.names["data"]]["mode"] == "ro"
