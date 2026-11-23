"""Owned per-scan Docker resources and process-safe subnet reservations."""

import contextlib
import fcntl
import ipaddress
import json
import os
import re
import stat
import time
import uuid
from collections.abc import Callable, Iterator, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Self

import docker  # type: ignore[import-untyped]

from probe.sandbox.spec import labels, names, owned, target_spec, validate_scan_id

DEFAULT_CACHE = Path.home() / ".cache" / "probe" / "subnets"
_PRIVATE = ipaddress.IPv4Network("172.16.0.0/12")
_PRIVATE_RANGES = tuple(
    ipaddress.IPv4Network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
CANARY_ALIASES = [
    "canary.probe.test",
    "metadata.google.internal",
    "metadata",
    "instance-data",
    "internal.probe.test",
]


@dataclass(frozen=True)
class SubnetLease:
    scan_id: str
    public: str
    private: str
    token: str
    pid: int
    created: float


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


class SubnetAllocator:
    """A flock serializes reservation/release across processes.

    Young orphaned leases are retained for one hour. Old leases are reclaimed only when
    their local process is dead AND Docker has no resources for that scan. Malformed or
    symlinked files are never deleted; reservations fail closed on ambiguous records.
    """

    def __init__(
        self,
        cache_dir: Path | str = DEFAULT_CACHE,
        *,
        pool: str | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.root = Path(cache_dir).expanduser()
        self.clock = clock
        value = (
            pool
            if pool is not None
            else os.environ.get("PROBE_PUBLIC_SUBNET_POOL", "11.250.0.0/16")
        )
        try:
            parsed = ipaddress.ip_network(value, strict=True)
            if not isinstance(parsed, ipaddress.IPv4Network) or not 16 <= parsed.prefixlen <= 24:
                raise ValueError("pool must be an IPv4 /16 through /24")
            # At most 256 subnets; also rejects pools straddling reserved ranges.
            if any(
                not ip.is_global
                for net in parsed.subnets(new_prefix=24)
                for ip in (net.network_address, net.broadcast_address)
            ):
                raise ValueError("pool addresses must be global")
        except ValueError as exc:
            raise ValueError(f"invalid public subnet pool: {value}") from exc
        self.pool = parsed

    @contextlib.contextmanager
    def _locked(self) -> Iterator[None]:
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(self.root / ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            self._recover_temps()
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _recover_temps(self) -> None:
        # The private cache and flock are the same trust boundary as final leases.
        # Only our exact temporary namespace, UID, private mode and a dead writer
        # authorize recovery; never follow a symlink or remove an arbitrary record.
        for path in self.root.glob(".probe-lease-*.tmp"):
            match = re.fullmatch(r"\.probe-lease-([1-9][0-9]*)-[a-f0-9]{32}\.tmp", path.name)
            if match is None:
                continue
            info = path.lstat()
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise RuntimeError(f"ambiguous temporary subnet lease: {path.name}")
            if not _alive(int(match[1])):
                path.unlink()

    def _read(self, path: Path) -> SubnetLease | None:
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "r") as file:
                if not stat.S_ISREG(os.fstat(file.fileno()).st_mode):
                    return None
                data = json.loads(file.read(4097))
            lease = SubnetLease(**data)
            validate_scan_id(lease.scan_id)
            if path.name != f"{lease.scan_id}.json":
                return None
            if not re.fullmatch(r"[a-f0-9]{32}", lease.token):
                return None
            if not isinstance(lease.pid, int) or lease.pid <= 0:
                return None
            if not isinstance(lease.created, int | float) or not 0 <= lease.created < 1e12:
                return None
            public = ipaddress.IPv4Network(lease.public)
            private = ipaddress.IPv4Network(lease.private)
            if public.prefixlen != 24 or not public.network_address.is_global:
                return None
            if private.prefixlen != 24 or not any(
                private.subnet_of(net) for net in _PRIVATE_RANGES
            ):
                return None
            return lease
        except (OSError, ValueError, TypeError):
            return None

    def reserve(self, scan_id: str, *, used: Sequence[str] = ()) -> SubnetLease:
        validate_scan_id(scan_id)
        blocked = [ipaddress.ip_network(value) for value in used]
        with self._locked():
            path = self.root / f"{scan_id}.json"
            if path.exists() or path.is_symlink():
                raise RuntimeError(f"subnet lease already exists for {scan_id}")
            for record in self.root.glob("*.json"):
                lease = self._read(record)
                if lease is None:
                    raise RuntimeError(f"ambiguous subnet lease: {record.name}")
                blocked.extend(
                    (ipaddress.ip_network(lease.public), ipaddress.ip_network(lease.private))
                )

            def free(pool: ipaddress.IPv4Network) -> str:
                for subnet in pool.subnets(new_prefix=24):
                    if all(not subnet.overlaps(other) for other in blocked if other.version == 4):
                        blocked.append(subnet)
                        return str(subnet)
                raise RuntimeError(f"subnet pool exhausted: {pool}")

            public = free(self.pool)
            private = free(_PRIVATE)
            lease = SubnetLease(
                scan_id, public, private, uuid.uuid4().hex, os.getpid(), self.clock()
            )
            temporary = self.root / f".probe-lease-{lease.pid}-{lease.token}.tmp"
            fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            try:
                with os.fdopen(fd, "w") as file:
                    json.dump(asdict(lease), file)
                    file.flush()
                    os.fsync(file.fileno())
                # A hard link publishes the complete inode atomically, and unlike
                # replace/rename cannot overwrite a final record created by a peer.
                os.link(temporary, path, follow_symlinks=False)
            finally:
                temporary.unlink()
            return lease

    def release(self, lease: SubnetLease) -> None:
        validate_scan_id(lease.scan_id)
        with self._locked():
            path = self.root / f"{lease.scan_id}.json"
            current = self._read(path)
            if current is not None and current.token == lease.token:
                path.unlink()

    def collect_stale(
        self, *, active_scans: set[str], age_s: float = 3600, scan_id: str | None = None
    ) -> list[str]:
        if scan_id is not None:
            validate_scan_id(scan_id)
        removed = []
        with self._locked():
            for path in self.root.glob("*.json"):
                lease = self._read(path)
                if lease is None or (scan_id is not None and lease.scan_id != scan_id):
                    continue
                if lease.scan_id in active_scans or _alive(lease.pid):
                    continue
                if self.clock() - lease.created <= max(3600, age_s):
                    continue
                path.unlink()
                removed.append(lease.scan_id)
        return removed


def docker_client() -> Any:
    """Finite SDK request timeout also bounds failure during cleanup."""
    return docker.from_env(timeout=10)


def docker_subnets(client: Any) -> list[str]:
    values = []
    for network in client.networks.list():
        for cfg in (network.attrs.get("IPAM") or {}).get("Config") or []:
            if cfg.get("Subnet"):
                values.append(cfg["Subnet"])
    return values


def remove_owned(resource: Any, scan_id: str | None = None, *, container: bool = False) -> None:
    try:
        resource.reload()
        if not owned(resource, scan_id):
            raise RuntimeError(f"refusing removal without ownership evidence: {resource.name}")
        resource.remove(force=True) if container else resource.remove()
    except docker.errors.NotFound:
        pass


class DockerEnv:
    """Synchronous Docker SDK lifecycle; the async runner calls it off the event loop.

    Use as a context manager, or call create/close from a caller's try/finally. Creation
    rolls back on failure. close returns errors and retains a lease on incomplete cleanup.
    This class does not populate fixtures or seeds (the FixtureSet layer owns that).
    """

    def __init__(
        self,
        scan_id: str,
        *,
        client: Any = None,
        cache_dir: Path | str = DEFAULT_CACHE,
        public_pool: str | None = None,
        fixtures_image: str = "probe-fixtures:dev",
    ) -> None:
        self.scan_id = validate_scan_id(scan_id)
        self.names = names(scan_id)
        self.client = docker_client() if client is None else client
        self.allocator = SubnetAllocator(cache_dir, pool=public_pool)
        self.fixtures_image = fixtures_image
        self.created = time.time()
        self.labels = labels(scan_id, self.created)
        self.lease: SubnetLease | None = None
        self.networks: dict[str, Any] = {}
        self.volume: Any = None
        self.seed_volume: Any = None
        self.seed_name = f"probe-seed-{self.scan_id}"
        self.containers: list[Any] = []
        self.ready = False

    def create(self) -> Self:
        if self.ready:
            return self
        if self.lease is not None:
            raise RuntimeError("sandbox has incomplete cleanup")
        try:
            # Volume create is an upsert in Docker: reject existing names BEFORE creating.
            try:
                self.client.volumes.get(self.names["data"])
            except docker.errors.NotFound:
                pass
            else:
                raise RuntimeError("sandbox data volume already exists")
            for net in self.client.networks.list():
                if net.name in self.names.values():
                    raise RuntimeError("sandbox network already exists")
            self.lease = self.allocator.reserve(self.scan_id, used=docker_subnets(self.client))
            for kind, subnet in (
                ("pub", self.lease.public),
                ("priv", self.lease.private),
                ("ctl", None),
            ):
                args: dict[str, Any] = {}
                if subnet is not None:
                    args["ipam"] = docker.types.IPAMConfig(
                        pool_configs=[docker.types.IPAMPool(subnet=subnet)]
                    )
                network = self.client.networks.create(
                    self.names[kind],
                    driver="bridge",
                    internal=kind != "ctl",
                    labels=self.labels,
                    **args,
                )
                self.networks[kind] = network
            self.volume = self.client.volumes.create(name=self.names["data"], labels=self.labels)
            self.volume.reload()
            if not owned(self.volume, self.scan_id):
                # A concurrent foreign upsert must never be adopted or removed.
                self.volume = None
                raise RuntimeError("data volume ownership mismatch")
            self.ready = True
            return self
        except BaseException as exc:
            for error in self.close():
                exc.add_note(error)
            raise

    def _container(self, role: str, spec: dict[str, Any]) -> Any:
        if not self.ready:
            raise RuntimeError("sandbox must be created first")
        image = self.client.images.get(spec["image"])
        declared = set(image.attrs.get("Config", {}).get("Volumes") or {})
        mounted = {config["bind"] for config in spec.get("volumes", {}).values()}
        if declared - mounted:
            raise ValueError("image declares volumes that would create unowned anonymous volumes")
        spec["image"] = image.id  # pin the inspected local image, avoiding tag replacement
        spec["name"] = f"probe-{role}-{self.scan_id}-{uuid.uuid4().hex[:12]}"
        container = self.client.containers.create(**spec)
        self.containers.append(container)
        return container

    def create_target(
        self,
        image: str,
        *,
        command: Sequence[str] | None = None,
        env: dict[str, str] | None = None,
        runtime: str | None = None,
    ) -> Any:
        spec = target_spec(
            self.scan_id, image, command=command, env=env, runtime=runtime, created=self.created
        )
        container = self._container("target", spec)
        try:
            self.networks["priv"].connect(container, aliases=["target"])
        except BaseException:
            self.remove_container(container)
            raise
        return container  # process has NOT started; both endpoints already exist

    def start_fixture(
        self,
        mode: str,
        *,
        api_aliases: Sequence[str] = (),
        target_port: int | None = None,
        seeded_routes: bool = False,
    ) -> Any:
        """Start a fixture with a listener bound to an alias present ONLY on ctl."""
        aliases = list(api_aliases)
        reserved = {"localhost", "fakehttp", "public.probe.test", "target", *CANARY_ALIASES}
        for alias in aliases:
            if (
                not isinstance(alias, str)
                or len(alias) > 253
                or alias.lower() != alias
                or alias in reserved
                or alias.startswith("probe-")
                or any(
                    re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p) is None
                    for p in alias.split(".")
                )
            ):
                raise ValueError("invalid or reserved API alias")
        if len(set(aliases)) != len(aliases):
            raise ValueError("duplicate API aliases")
        control = f"probe-{mode}-{'control' if mode == 'relay' else 'admin'}-{self.scan_id}"
        if mode == "fakehttp":
            net, data_aliases, port = "pub", ["fakehttp", "public.probe.test", *aliases], 9090
            argv = [
                "fixtures",
                "fakehttp",
                "--host",
                "0.0.0.0",  # noqa: S104 - fixture data listener inside isolated networks
                "--port",
                "80",
                "--admin-host",
                control,
                "--admin-port",
                "9090",
            ]
        elif mode == "canary":
            net, data_aliases, port = "priv", CANARY_ALIASES, 9090
            argv = [
                "fixtures",
                "canary",
                "--host",
                "0.0.0.0",  # noqa: S104 - fixture data listener inside isolated networks
                "--ports",
                "80,8080",
                "--admin-host",
                control,
                "--admin-port",
                "9090",
            ]
        elif mode == "relay":
            if (
                not isinstance(target_port, int)
                or isinstance(target_port, bool)
                or not 1 <= target_port <= 65535
            ):
                raise ValueError("relay target port must be 1-65535")
            net, data_aliases, port = "priv", [], 8080
            argv = [
                "fixtures",
                "relay",
                "--listen-host",
                control,
                "--listen-port",
                "8080",
                "--target-host",
                "target",
                "--target-port",
                str(target_port),
            ]
        else:
            raise ValueError("fixture mode must be fakehttp, canary, or relay")
        spec = target_spec(self.scan_id, self.fixtures_image, command=argv, created=self.created)
        spec.pop("volumes")
        if seeded_routes:
            if mode != "fakehttp" or self.seed_volume is None:
                raise ValueError("seeded routes require fakehttp and a populated seed volume")
            spec["command"] += ["--routes", "/seed/http/routes.yaml"]
            spec["volumes"] = {self.seed_name: {"bind": "/seed", "mode": "ro"}}
        spec["stdin_open"] = False
        spec["network"] = self.names[net]
        # High-level containers.create expects the raw endpoint mapping. Passing
        # api.create_networking_config here silently discards aliases in docker-py.
        spec["networking_config"] = {
            self.names[net]: self.client.api.create_endpoint_config(aliases=data_aliases)
        }
        spec["ports"] = {f"{port}/tcp": ("127.0.0.1", None)}
        container = self._container(mode, spec)
        try:
            self.networks["ctl"].connect(container, aliases=[control])
            container.start()
        except BaseException:
            self.remove_container(container)
            raise
        return container

    def create_inspector(
        self, args: Sequence[str], *, writable: bool = False, seed: bool = False
    ) -> Any:
        spec = target_spec(
            self.scan_id,
            self.fixtures_image,
            command=["fixtures", "inspect", "--root", "/data", *args],
            created=self.created,
        )
        spec.pop("network")
        spec["network_mode"] = "none"
        spec["stdin_open"] = False
        spec["volumes"][self.names["data"]]["mode"] = "rw" if writable else "ro"
        if seed:
            if self.seed_volume is None:
                raise RuntimeError("seed volume has not been populated")
            spec["volumes"][self.seed_name] = {"bind": "/seed", "mode": "ro"}
        return self._container("inspect", spec)

    def populate_seed(self, archive: bytes, *, routes: bytes | None = None) -> None:
        """Upload captured seeds once via a networkless helper, never a host bind mount."""
        if not self.ready or self.seed_volume is not None:
            raise RuntimeError("seed population requires a ready sandbox without a seed")
        try:
            self.client.volumes.get(self.seed_name)
        except docker.errors.NotFound:
            pass
        else:
            raise RuntimeError("sandbox seed volume already exists")
        self.seed_volume = self.client.volumes.create(name=self.seed_name, labels=self.labels)
        self.seed_volume.reload()
        if not owned(self.seed_volume, self.scan_id):
            self.seed_volume = None
            raise RuntimeError("seed volume ownership mismatch")
        spec = target_spec(
            self.scan_id,
            self.fixtures_image,
            command=["python", "-c", "import os; os.chown('/seed', 10001, 10001)"],
            created=self.created,
        )
        spec.pop("network")
        spec.update(network_mode="none", user="0:0", cap_add=["CHOWN"], stdin_open=False)
        spec["volumes"] = {self.seed_name: {"bind": "/seed", "mode": "rw"}}
        helper = self._container("init", spec)
        try:
            if not helper.put_archive("/seed", archive):
                raise RuntimeError("seed archive upload failed")
            if routes is not None and not helper.put_archive("/seed", routes):
                raise RuntimeError("routes archive upload failed")
            helper.start()
            if helper.wait(timeout=10)["StatusCode"] != 0:
                raise RuntimeError("seed volume initialization failed")
        finally:
            self.remove_container(helper)

    def initialize_data(self, image: str) -> None:
        """Give UID 10001 an empty named volume; never recursively touch target content.

        Only the volume root is chowned. This short-lived helper has no network, no host
        mounts, no DAC override, and only CAP_CHOWN; it is never the target container.
        """
        spec = target_spec(
            self.scan_id,
            image,
            command=["python", "-c", "import os; os.chown('/data', 10001, 10001)"],
            created=self.created,
        )
        spec.pop("network")
        spec.update(network_mode="none", user="0:0", cap_add=["CHOWN"], stdin_open=False)
        helper = self._container("init", spec)
        try:
            helper.start()
            result = helper.wait(timeout=10)
            if result["StatusCode"] != 0:
                raise RuntimeError("data volume initialization failed")
        finally:
            self.remove_container(helper)

    def remove_container(self, container: Any) -> None:
        remove_owned(container, self.scan_id, container=True)
        if container in self.containers:
            self.containers.remove(container)

    def control_url(self, container: Any, port: int = 9090) -> str:
        """Loopback URL for an existing published control endpoint; never a data IP."""
        container.reload()
        if not owned(container, self.scan_id) or container not in self.containers:
            raise ValueError("not an owned fixture")
        bindings = container.attrs.get("NetworkSettings", {}).get("Ports", {}).get(f"{port}/tcp")
        if not bindings or any(binding["HostIp"] != "127.0.0.1" for binding in bindings):
            raise RuntimeError("control port is not bound exclusively to loopback")
        return f"http://127.0.0.1:{int(bindings[0]['HostPort'])}"

    def close(self) -> list[str]:
        errors: list[str] = []
        for container in list(reversed(self.containers)):
            try:
                self.remove_container(container)
            except Exception as exc:
                errors.append(f"{container.name}: {exc}")
        for kind, network in list(reversed(self.networks.items())):
            try:
                remove_owned(network, self.scan_id)
                del self.networks[kind]
            except Exception as exc:
                errors.append(f"{network.name}: {exc}")
        if self.volume is not None:
            try:
                remove_owned(self.volume, self.scan_id)
                self.volume = None
            except Exception as exc:
                errors.append(f"{self.names['data']}: {exc}")
        if self.seed_volume is not None:
            try:
                remove_owned(self.seed_volume, self.scan_id)
                self.seed_volume = None
            except Exception as exc:
                errors.append(f"{self.seed_name}: {exc}")
        if not errors and self.lease is not None:
            self.allocator.release(self.lease)
            self.lease = None
        self.ready = False
        return errors

    def __enter__(self) -> Self:
        return self.create()

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        errors = self.close()
        if errors:
            if exc is not None:
                for error in errors:
                    exc.add_note(error)
            else:
                raise RuntimeError("sandbox cleanup incomplete: " + "; ".join(errors))
