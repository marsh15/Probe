"""Callable sandbox doctor/GC APIs; CLI registration belongs to the application."""

import math
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from probe.sandbox.docker_env import (
    DEFAULT_CACHE,
    SubnetAllocator,
    docker_client,
    remove_owned,
    require_safe_engine,
)
from probe.sandbox.spec import owned, validate_scan_id


@dataclass
class GCResult:
    removed: list[str] = field(default_factory=list)
    leases: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def collect(
    *,
    client: Any = None,
    cache_dir: Path | str = DEFAULT_CACHE,
    now: float | None = None,
    age_s: float = 3600,
    scan_id: str | None = None,
) -> GCResult:
    """Remove only proven-owned resources older than an hour, containers first.

    There is deliberately no prune call, broad name deletion, or image removal. A failed
    Docker listing aborts lease collection: absence must be proven, never guessed.
    """
    timestamp = time.time() if now is None else now
    if not math.isfinite(timestamp) or not math.isfinite(age_s) or age_s < 3600:
        raise ValueError("GC requires a finite age of at least one hour")
    client = docker_client() if client is None else client
    result = GCResult()
    if scan_id is not None:
        validate_scan_id(scan_id)
    resource_filter = "probe.scan" if scan_id is None else f"probe.scan={scan_id}"
    allocator = SubnetAllocator(cache_dir, clock=lambda: timestamp)
    live = allocator.live_scans()
    collections = (client.containers, client.networks, client.volumes)
    for index, collection in enumerate(collections):
        kwargs = {"all": True} if index == 0 else {}
        for resource in collection.list(filters={"label": resource_filter}, **kwargs):
            try:
                resource.reload()
                if not owned(resource, scan_id):
                    continue
                meta = resource.attrs.get("Config", {}).get("Labels", resource.attrs.get("Labels"))
                if meta["probe.scan"] in live or timestamp - int(meta["probe.created"]) <= age_s:
                    continue
                remove_owned(resource, container=index == 0)
                result.removed.append(resource.name)
            except Exception as exc:
                result.errors.append(f"{resource.name}: {exc}")
    active: set[str] = set()
    for index, collection in enumerate(collections):
        kwargs = {"all": True} if index == 0 else {}
        for resource in collection.list(filters={"label": resource_filter}, **kwargs):
            # Even a mismatched name still blocks release of the labeled scan's lease.
            meta = (
                resource.attrs.get("Config", {}).get("Labels", resource.attrs.get("Labels")) or {}
            )
            if isinstance(meta.get("probe.scan"), str):
                active.add(meta["probe.scan"])
    result.leases = allocator.collect_stale(active_scans=active, age_s=age_s, scan_id=scan_id)
    return result


def doctor(*, client: Any = None) -> dict[str, Any]:
    """Report prerequisites without starting containers, pulling images or mutating Docker."""
    result: dict[str, Any] = {"docker_cli": shutil.which("docker") is not None, "daemon": False}
    try:
        client = docker_client() if client is None else client
        result["daemon"] = bool(client.ping())
        require_safe_engine(client)
        info = client.info()
        result.update(
            linux=info.get("OSType") == "linux",
            architecture=info.get("Architecture"),
            runsc="runsc" in info.get("Runtimes", {}),
        )
        SubnetAllocator()  # validate configured public pool
        result["public_pool"] = True
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result
