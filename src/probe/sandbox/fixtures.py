"""Per-scan seeds, isolated fixture services and observable state.

Host inputs are captured into a bounded archive, never bind-mounted. Inspectors validate
and restore the pristine named seed volume without following target-controlled links.
"""

import asyncio
import io
import json
import os
import re
import sqlite3
import stat
import subprocess
import tarfile
import tempfile
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import yaml

from probe.config.profile import FixturesSection
from probe.runners.container import _docker
from probe.sandbox.docker_env import DockerEnv

MAX_SEED = 64 * 1024 * 1024
MAX_ENTRIES = 10000
Req = dict[str, Any]
Hit = dict[str, Any]


def data_path(value: str) -> str:
    """Accept relative data paths or absolute paths strictly below /data."""
    relative = value.removeprefix("/data/")
    if not relative or "\0" in relative or any(p in {"", ".", ".."} for p in relative.split("/")):
        raise ValueError("fixture path must stay below /data")
    return relative


def _regular(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_SEED or info.st_mode & 0o7000:
            raise ValueError("seed requires bounded regular files without privileged bits")
        content = source.read(MAX_SEED + 1)
        if len(content) > MAX_SEED:
            raise ValueError("seed file exceeds size limit")
        return content


def _validate_tree(root: Path) -> list[Path]:
    paths = sorted(root.rglob("*"))  # pathlib does not recurse into symlink directories
    if len(paths) > MAX_ENTRIES:
        raise ValueError("seed entry limit exceeded")
    size = 0
    for path in paths:
        info = path.lstat()
        if info.st_mode & 0o7000:
            raise ValueError("seed contains privileged permission bits")
        if len(path.relative_to(root).parts) > 64:
            raise ValueError("seed directory depth limit exceeded")
        if path.is_symlink():
            try:
                if Path(os.readlink(path)).is_absolute() or not path.resolve().is_relative_to(root):
                    raise ValueError("seed symlink escapes seed root")
            except (OSError, RuntimeError) as exc:
                raise ValueError("unsafe seed symlink chain") from exc
        elif stat.S_ISREG(info.st_mode):
            size += info.st_size
        elif not stat.S_ISDIR(info.st_mode):
            raise ValueError("seed contains unsupported filesystem entry")
    if size > MAX_SEED:
        raise ValueError("seed exceeds reset size limit")
    return paths


def _copy_seed(source: Path, destination: Path) -> None:
    if not source.is_dir():
        raise ValueError("seed_dir must be a directory")
    source = source.resolve()
    for path in _validate_tree(source):
        out = destination / path.relative_to(source)
        if path.is_symlink():
            out.symlink_to(os.readlink(path))
        elif path.is_dir():
            out.mkdir(mode=0o700)
        else:
            out.write_bytes(_regular(path))
            out.chmod(stat.S_IMODE(path.lstat().st_mode))
    # Set directory modes after copying, so read-only seed directories can be populated.
    for path in reversed(_validate_tree(source)):
        if path.is_dir() and not path.is_symlink():
            (destination / path.relative_to(source)).chmod(stat.S_IMODE(path.lstat().st_mode))


def _destination(root: Path, relative: str) -> Path:
    path = root / data_path(relative)
    for ancestor in [path, *path.parents]:
        if ancestor == root:
            break
        if ancestor.is_symlink():
            raise ValueError("seed output path contains a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _sqlite_seed(path: Path, sql: str | None) -> None:
    try:
        with sqlite3.connect(":memory:") as db:
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_SEED)
            db.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 1024 * 1024)
            steps = 0

            def progress() -> int:
                nonlocal steps
                steps += 1
                return int(steps > 10000)

            def authorize(action: int, arg1: str | None, arg2: str | None, *_: Any) -> int:
                if action in (
                    sqlite3.SQLITE_ATTACH,
                    sqlite3.SQLITE_DETACH,
                    sqlite3.SQLITE_PRAGMA,
                    sqlite3.SQLITE_CREATE_VTABLE,
                ) or (action == sqlite3.SQLITE_FUNCTION and arg2 == "load_extension"):
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK

            db.set_progress_handler(progress, 1000)
            db.set_authorizer(authorize)
            if sql is not None:
                db.executescript(_regular(Path(sql)).decode("utf-8"))
            db.commit()
            db.set_authorizer(None)
            with sqlite3.connect(path) as output:
                db.backup(output)
    except (sqlite3.Error, OSError, UnicodeError, ValueError) as exc:
        raise ValueError(f"SQLite seed failed: {exc}") from exc


def _git_seed(path: Path, bundle: str | None) -> None:
    if path.exists():
        raise ValueError("git seed destination already exists")
    # Discard user/system git configuration: no credential helpers, filters, hooks or URLs.
    env = {
        "PATH": os.defpath,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
    }
    command = [
        "git",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "protocol.allow=never",
        "-c",
        "protocol.file.allow=always",
        "-c",
        "init.templateDir=",
    ]
    if bundle is None:
        command += ["init", "--", str(path)]
    else:
        # Only a captured local bundle is given to git; never a URL or arbitrary repo path.
        captured = path.parent / ".probe-seed.bundle"
        if captured.exists() or captured.is_symlink():
            raise ValueError("git seed temporary path already exists")
        captured.write_bytes(_regular(Path(bundle)))
        command += ["clone", "--", str(captured), str(path)]
    try:
        subprocess.run(command, env=env, check=True, capture_output=True, timeout=30)  # noqa: S603
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError(
            "git seed failed to clone a local bundle or initialize repository"
        ) from exc
    finally:
        if bundle is not None:
            captured.unlink()


def _archive(root: Path, *, prefix: str = "") -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        paths = _validate_tree(root)
        if prefix:
            entry = tarfile.TarInfo(prefix)
            entry.type, entry.mode, entry.uid, entry.gid = tarfile.DIRTYPE, 0o755, 10001, 10001
            archive.addfile(entry)
        for path in paths:
            name = path.relative_to(root).as_posix()
            entry = tarfile.TarInfo(f"{prefix}/{name}" if prefix else name)
            entry.uid = entry.gid = 10001
            entry.mode = stat.S_IMODE(path.lstat().st_mode)
            if path.is_symlink():
                entry.type, entry.linkname = tarfile.SYMTYPE, os.readlink(path)
                archive.addfile(entry)
            elif path.is_dir():
                entry.type = tarfile.DIRTYPE
                archive.addfile(entry)
            else:
                content = _regular(path)
                entry.size = len(content)
                archive.addfile(entry, io.BytesIO(content))
    return buffer.getvalue()


def build_seed(config: FixturesSection, *, token: str, prefix: str = "") -> bytes:
    """Build data seed in a deleted temporary tree; output has only safe tar members."""
    if re.fullmatch(r"[a-f0-9]{12,16}", token) is None:
        raise ValueError("fixture token must be the per-scan hexadecimal profile token")
    with tempfile.TemporaryDirectory(prefix="probe-seed-") as directory:
        root = Path(directory).resolve()
        if config.fs is not None:
            _copy_seed(Path(config.fs.seed_dir), root)
            if config.fs.sentinel:
                for relative in (
                    "allowed",
                    "allowed/notes",
                    "allowed_evil",
                    "secret",
                    "probe-canary",
                ):
                    path = _destination(root, relative)
                    path.mkdir(exist_ok=True)
                files = {
                    "allowed/readme.md": b"Probe fixture files.\n",
                    "allowed/notes/a.txt": b"seeded\n",
                    "allowed/big.log": b"x" * (5 * 1024 * 1024),
                    "allowed_evil/evil.txt": b"outside allowed root\n",
                    "secret/SENTINEL": f"PROBE-SENTINEL-{token}".encode(),
                }
                for relative, content in files.items():
                    path = _destination(root, relative)
                    if path.exists():
                        raise ValueError(f"seed conflicts with sentinel path: {relative}")
                    path.write_bytes(content)
                _destination(root, "allowed/link_out").symlink_to("../secret")
        if config.sqlite is not None:
            path = _destination(root, config.sqlite.path)
            if path.exists():
                raise ValueError("SQLite seed destination already exists")
            _sqlite_seed(path, config.sqlite.seed_sql)
        if config.git is not None:
            _git_seed(_destination(root, config.git.path), config.git.seed_bundle)
        return _archive(root, prefix=prefix)


def build_routes(source: str) -> bytes:
    """Capture configured HTTP bodies without exposing their host directory to Docker."""
    path = Path(source).resolve()
    content = _regular(path)
    config = yaml.safe_load(content)
    if not isinstance(config, dict) or not isinstance(config.get("routes", []), list):
        raise ValueError("HTTP routes must be a mapping with a routes list")
    with tempfile.TemporaryDirectory(prefix="probe-routes-") as directory:
        root = Path(directory).resolve()
        (root / "routes.yaml").write_bytes(content)
        for route in config.get("routes", []):
            if isinstance(route, dict) and "body_file" in route:
                relative = data_path(route["body_file"])
                candidate = path.parent / relative
                if any(p.is_symlink() for p in [candidate, *candidate.parents] if p != path.parent):
                    raise ValueError("HTTP body_file contains a symlink")
                if relative == "routes.yaml":
                    raise ValueError("HTTP body_file conflicts with routes.yaml")
                _destination(root, relative).write_bytes(_regular(candidate))
        return _archive(root, prefix="http")


@dataclass(frozen=True)
class FixtureState:
    fs: dict[str, Any] = field(default_factory=dict)
    sqlite: dict[str, Any] = field(default_factory=dict)
    collections: dict[str, Any] = field(default_factory=dict)
    # Sequence cursor, not retained-array length: fixture histories are bounded and resettable.
    log_length: int = 0
    requests: list[Req] = field(default_factory=list, compare=False, repr=False)


@dataclass(frozen=True)
class StateDiff:
    changed: list[str]
    added: list[str]
    removed: list[str]
    backend_writes: list[Req]
    sqlite_changed: list[str] = field(default_factory=list)
    collections_changed: list[str] = field(default_factory=list)


class FixtureSet:
    def __init__(self, sandbox: DockerEnv, config: FixturesSection, *, token: str) -> None:
        self.sandbox, self.config, self.token = sandbox, config, token
        self._services: dict[str, str] = {}
        self._started = False
        self._log_cursor = 0
        self._canary: Any = None

    @property
    def canary_ip(self) -> str:
        """The canary's data address, never its control-network address."""
        if self._canary is None:
            raise RuntimeError("canary has not started")
        networks = self._canary.attrs["NetworkSettings"]["Networks"]
        return str(networks[self.sandbox.names["priv"]]["IPAddress"])

    async def start(self) -> None:
        if self._started:
            return
        archive = await _docker(lambda: build_seed(self.config, token=self.token, prefix="data"))
        http = self.config.http
        routes_path = http.routes if http is not None else None
        routes = await _docker(lambda: build_routes(routes_path)) if routes_path else None
        await _docker(self.sandbox.create)
        await _docker(lambda: self.sandbox.populate_seed(archive, routes=routes))
        await _docker(lambda: self.sandbox.initialize_data(self.sandbox.fixtures_image))
        if http is not None:
            container = await _docker(
                lambda: self.sandbox.start_fixture(
                    "fakehttp", api_aliases=http.aliases, seeded_routes=routes is not None
                )
            )
            self._services["fakehttp"] = await _docker(lambda: self.sandbox.control_url(container))
        # Canary is available for any fixture-backed safety scan, including fs-only profiles.
        container = await _docker(lambda: self.sandbox.start_fixture("canary"))
        self._services["canary"] = await _docker(lambda: self.sandbox.control_url(container))
        self._canary = container  # control_url refreshed its network addresses
        await self._ready()
        await self.reset()
        self._started = True

    async def _ready(self) -> None:
        deadline = time.monotonic() + 15
        for service, path in (("fakehttp", "/_probe/log"), ("canary", "/_probe/hits")):
            if service not in self._services:
                continue
            while True:
                try:
                    await self._admin(service, "GET", path)
                    break
                except httpx.HTTPError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError(f"{service} fixture did not become ready") from None
                    await asyncio.sleep(0.1)

    async def _admin(self, service: str, method: str, path: str) -> Any:
        async with httpx.AsyncClient(timeout=2, trust_env=False) as client:
            response = await client.request(method, self._services[service] + path)
            response.raise_for_status()
            return response.json()

    async def _inspect(self, args: Sequence[str], *, writable: bool = False) -> Any:
        def inspect() -> Any:
            container = self.sandbox.create_inspector(args, writable=writable, seed=writable)
            try:
                container.start()
                status = container.wait(timeout=30)["StatusCode"]
                if status:
                    raise RuntimeError(f"fixture inspector {args[0]} failed (exit {status})")
                return json.loads(container.logs(stdout=True, stderr=False))
            finally:
                self.sandbox.remove_container(container)

        return await _docker(inspect)

    async def snapshot(self) -> FixtureState:
        fs = await self._inspect(["hash"])
        sqlite = {}
        if self.config.sqlite:
            path = data_path(self.config.sqlite.path)
            if path in fs:
                sqlite[path] = await self._inspect(["sqlite-checksum", path])
        collections = {}
        requests = []
        if "fakehttp" in self._services:
            collections = (await self._admin("fakehttp", "GET", "/_probe/state"))["collections"]
            requests = await self.backend_log()
        return FixtureState(fs, sqlite, collections, self._log_cursor, requests)

    @staticmethod
    def diff(a: FixtureState, b: FixtureState) -> StateDiff:
        def changed(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
            return sorted(k for k in before.keys() | after.keys() if before.get(k) != after.get(k))

        return StateDiff(
            changed=sorted(k for k in a.fs.keys() & b.fs.keys() if a.fs[k] != b.fs[k]),
            added=sorted(b.fs.keys() - a.fs.keys()),
            removed=sorted(a.fs.keys() - b.fs.keys()),
            backend_writes=[
                r
                for r in b.requests
                if a.log_length < r["sequence"] <= b.log_length and r["method"] != "GET"
            ],
            sqlite_changed=changed(a.sqlite, b.sqlite),
            collections_changed=changed(a.collections, b.collections),
        )

    async def reset(self) -> None:
        await self._inspect(["reset", "--seed", "/seed/data"], writable=True)
        for service in self._services:
            await self._admin(service, "POST", "/_probe/reset")

    async def canary_hits(self, since: int = 0) -> list[Hit]:
        if "canary" not in self._services:
            return []
        return list(await self._admin("canary", "GET", f"/_probe/hits?since={since}"))

    async def backend_log(self, since: int = 0) -> list[Req]:
        if "fakehttp" not in self._services:
            return []
        records = list(await self._admin("fakehttp", "GET", f"/_probe/log?since={since}"))
        self._log_cursor = max(self._log_cursor, max((r["sequence"] for r in records), default=0))
        return records
