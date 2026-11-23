"""FixtureSet acceptance gates on local images, without external network access."""

import json
import uuid

import pytest

from probe.config.profile import FixturesSection, Profile
from probe.engine.runscan import RunConfig, run_scan
from probe.runners.container import ContainerRunner, _docker
from probe.sandbox.docker_env import DockerEnv
from probe.sandbox.fixtures import FixtureSet
from probe.wire.session import Session
from tests.sandbox.test_docker import assert_clean, require_docker, run_script

pytestmark = pytest.mark.docker
TOKEN = "0123456789ab"


def fixture_config(tmp_path):
    seed = tmp_path / "seed"
    seed.mkdir()
    sql = tmp_path / "seed.sql"
    sql.write_text(
        "CREATE TABLE notes (id INTEGER PRIMARY KEY, text TEXT);"
        "INSERT INTO notes VALUES (1, 'seeded');"
    )
    routes = tmp_path / "routes.yaml"
    routes.write_text(
        "collections:\n  tasks:\n    id_field: id\n    seed: [{id: 1, title: seeded}]\n"
    )
    return FixturesSection.model_validate(
        {
            "fs": {"seed_dir": str(seed)},
            "sqlite": {"path": "/data/db/notes.db", "seed_sql": str(sql)},
            "http": {"routes": str(routes), "aliases": ["api.probe.test"]},
        }
    )


async def test_fixtures_snapshot_refserver_write_canary_and_reset(tmp_path):
    client = require_docker("probe-fixtures:dev", "probe-refserver:dev")
    scan = "t17-" + uuid.uuid4().hex[:12]
    env = DockerEnv(scan, client=client, cache_dir=tmp_path / "leases")
    fixtures = FixtureSet(env, fixture_config(tmp_path), token=TOKEN)
    runner = ContainerRunner(
        "probe-refserver:dev",
        sandbox=env,
        command=["refserver", "stdio"],
        env={"REFSERVER_DATA": "/data"},
        initialize_data=False,
    )
    try:
        await fixtures.start()
        initial = await fixtures.snapshot()
        assert initial.fs["allowed/link_out"] == {
            "type": "symlink",
            "target": "../secret",
            "mode": 0o777,
        }
        assert initial.sqlite["db/notes.db"]["notes"]["count"] == 1
        session = await Session.open(await runner.start(), era="legacy")
        result = await session.request(
            "tools/call",
            {"name": "write_file", "arguments": {"path": "notes/a.txt", "content": "changed"}},
        )
        assert not result.unwrap().get("isError"), result
        after = await fixtures.snapshot()
        diff = fixtures.diff(initial, after)
        assert diff.changed == ["allowed/notes/a.txt"]
        assert diff.added == diff.removed == diff.backend_writes == []
        rejected = await session.request(
            "tools/call", {"name": "read_file", "arguments": {"path": "link_out/SENTINEL"}}
        )
        assert rejected.unwrap()["isError"]
        assert TOKEN not in json.dumps(rejected.unwrap())

        # A direct request from a hardened sidecar on the private network proves the
        # canary observer works, independently of fetch_url's private-address policy.
        output = await _docker(
            lambda: run_script(
                env,
                """
import urllib.request
from pathlib import Path
print(Path('/data/secret/SENTINEL').read_text())
print(len(Path('/data/allowed/big.log').read_bytes()))
print(urllib.request.urlopen('http://canary.probe.test/t17', timeout=3).status)
""",
                network="priv",
            )
        )
        assert f"PROBE-SENTINEL-{TOKEN}" in output
        assert str(5 * 1024 * 1024) in output
        hits = await fixtures.canary_hits()
        assert len(hits) == 1 and hits[0]["path"] == "/t17"
        assert await fixtures.canary_hits(hits[0]["sequence"]) == []

        await _docker(
            lambda: run_script(
                env,
                """
import urllib.request
import sqlite3
request = urllib.request.Request('http://api.probe.test/c/tasks',
    data=b'{"title":"added"}', headers={'Content-Type':'application/json'}, method='POST')
print(urllib.request.urlopen(request, timeout=3).status)
with sqlite3.connect('/data/db/notes.db') as db:
    db.execute("INSERT INTO notes VALUES (2, 'added')")
""",
            )
        )
        written = await fixtures.snapshot()
        writes = fixtures.diff(after, written)
        assert writes.changed == ["db/notes.db"]
        assert writes.sqlite_changed == ["db/notes.db"]
        assert writes.collections_changed == ["tasks"]
        assert [(r["method"], r["path"]) for r in writes.backend_writes] == [("POST", "/c/tasks")]
        assert await fixtures.backend_log(written.log_length) == []
        await fixtures.reset()
        restored = await fixtures.snapshot()
        assert restored.fs == initial.fs
        assert restored.sqlite == initial.sqlite
        assert restored.collections == initial.collections
        assert not await fixtures.canary_hits()
        assert not await fixtures.backend_log()
        # The seed is mounted only into helpers/inspectors and fakehttp, always read-only
        # outside the upload helper. The reference target only sees /data.
        target = runner._main.container
        target.reload()
        assert {m["Destination"] for m in target.attrs["Mounts"] if m["Type"] == "volume"} == {
            "/data"
        }
        assert env.seed_volume.name == f"probe-seed-{scan}"
    finally:
        await runner.stop()
        assert_clean(client, scan)


async def test_fixtures_profile_scan_wires_stdio_and_http(tmp_path):
    require_docker("probe-fixtures:dev", "probe-refserver:dev")
    config = fixture_config(tmp_path)
    for transport in ("stdio", "http"):
        profile = Profile.model_validate(
            {
                "target": {
                    "image": "probe-refserver:dev",
                    "transport": transport,
                    "command": ["refserver", transport],
                    "env": {"REFSERVER_DATA": "/data"},
                },
                "fixtures": config.model_dump(),
            }
        )
        report = await run_scan(
            RunConfig(out_dir=tmp_path / transport, profile=profile, only=["proto.discover"])
        )
        assert report.scan.status == "completed", report.limitations
        assert_clean(require_docker(), report.scan.id)
