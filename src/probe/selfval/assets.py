"""What the sandboxed reference server needs around it: seeded data, a backend, a secret.

The checked-in profiles say how to start the server. Fixtures need files on disk (the data the
server reads, routes for the fake backend), so the runner writes those next to the scan output
and fills in the fixtures section of the profile before scanning.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from probe.config.profile import Profile

# The directories the fixture builder creates itself (with the scan's sentinel token).
_BUILDER_OWNED = ("allowed", "allowed_evil", "secret", "probe-canary")
BACKEND_ALIAS = "api.example.test"
ROUTES = "collections:\n  items:\n    id_field: id\n    seed: [{id: 1, title: seeded}]\n"
SEEDED_INPUTS: dict[str, list[dict[str, Any]]] = {
    "notes_get": [{"id": 1}],
    "notes_update": [{"id": 1, "body": "probe replay body"}],
    "notes_delete": [{"id": 5}],
    "call_backend": [{"item_id": 1}],
}


def prepare(root: Path, refserver_src: Path) -> tuple[Path, Path]:
    """(seed directory, routes file) under ``root``: the server's database and repository, and
    one backend collection. The sandbox adds its own sentinel layout, so the server's is dropped."""
    seed = root / "seed"
    shutil.rmtree(seed, ignore_errors=True)
    env = {**os.environ, "PYTHONPATH": str(refserver_src)}
    env.pop("PROBE_REF_BUGS", None)
    subprocess.run(  # noqa: S603 - fixed argv, this interpreter
        [sys.executable, "-m", "refserver", "seed", "--out", str(seed)],
        check=True,
        env=env,
        capture_output=True,
        timeout=180,
    )
    for name in _BUILDER_OWNED:
        shutil.rmtree(seed / name, ignore_errors=True)
    routes = root / "routes.yaml"
    routes.write_text(ROUTES)
    return seed, routes


def with_fixtures(profile: Profile, seed: Path, routes: Path) -> Profile:
    """``profile`` plus the files, backend and fake credential the safety checks need."""
    data = profile.model_dump(mode="json", exclude_none=True)
    data["fixtures"] = {
        "fs": {"seed_dir": str(seed), "allowed_roots": ["/data/allowed"], "sentinel": True},
        "http": {"routes": str(routes), "aliases": [BACKEND_ALIAS]},
    }
    target = data.setdefault("target", {})
    target.setdefault("env", {})["REFSERVER_BACKEND_URL"] = f"http://{BACKEND_ALIAS}"
    target.setdefault("secrets", {})["REFSERVER_BACKEND_TOKEN"] = {
        "value": "probe_fake_tok_{token}",
        "real": False,
    }
    data.setdefault("inputs", {}).update(SEEDED_INPUTS)
    return Profile.model_validate(data)
