"""Validated names and the single target hardening policy.

Only named Docker volumes cross the target boundary. Callers cannot supply arbitrary
Docker options; extending this policy requires an explicit change here.
"""

import math
import re
import time
from collections.abc import Mapping, Sequence
from typing import Any

_SCAN = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?", re.ASCII)
_ENV_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*", re.ASCII)
DEFAULT_ENV = {
    "HOME": "/home/probe",
    "TZ": "UTC",
    "LANG": "C.UTF-8",
    "PYTHONUNBUFFERED": "1",
    "PYTHONIOENCODING": "utf-8",
}


def validate_scan_id(scan_id: str) -> str:
    if not isinstance(scan_id, str) or _SCAN.fullmatch(scan_id) is None:
        raise ValueError(
            "scan id must be 1-40 lowercase letters/digits/hyphens, ending alphanumeric"
        )
    return scan_id


def names(scan_id: str) -> dict[str, str]:
    validate_scan_id(scan_id)
    return {kind: f"probe-{kind}-{scan_id}" for kind in ("pub", "priv", "ctl", "data")}


def labels(scan_id: str, created: float | None = None) -> dict[str, str]:
    validate_scan_id(scan_id)
    timestamp = time.time() if created is None else created
    if not math.isfinite(timestamp) or timestamp < 0:
        raise ValueError("creation time must be finite and nonnegative")
    return {"probe.scan": scan_id, "probe.created": str(int(timestamp))}


def owned(resource: Any, scan_id: str | None = None) -> bool:
    """Require both ownership labels and an exact Probe resource name after reload.

    Docker IDs are retained by the caller, so a replaced name cannot redirect teardown.
    Labels alone do not authorize removing arbitrary Docker objects.
    """
    attrs = resource.attrs
    meta = attrs.get("Config", {}).get("Labels") if "Config" in attrs else attrs.get("Labels")
    if not isinstance(meta, dict):
        return False
    scan = meta.get("probe.scan", "")
    try:
        validate_scan_id(scan)
        timestamp = meta["probe.created"]
        if not isinstance(timestamp, str) or not timestamp.isascii() or not timestamp.isdigit():
            return False
        if scan_id is not None and scan != scan_id:
            return False
    except (ValueError, KeyError, TypeError):
        return False
    name = resource.name
    if name in names(scan).values() or name == f"probe-seed-{scan}":
        return True
    return (
        re.fullmatch(
            rf"probe-(?:target|fakehttp|canary|relay|inspect|init)-{re.escape(scan)}-[a-f0-9]{{12}}",
            name,
        )
        is not None
    )


def target_spec(
    scan_id: str,
    image: str,
    *,
    command: Sequence[str] | None = None,
    env: Mapping[str, str] | None = None,
    runtime: str | None = None,
    created: float | None = None,
) -> dict[str, Any]:
    """Docker SDK create kwargs, with no host mounts or published ports.

    ``command`` is a complete executable argv, replacing both image ENTRYPOINT and CMD.
    Omit it to retain the image defaults. Mandatory environment values cannot be weakened.
    """
    resource_names = names(scan_id)
    if not image or "\0" in image or image.startswith("-"):
        raise ValueError("a valid image reference is required")
    if runtime not in (None, "runsc"):
        raise ValueError("the only optional sandbox runtime is runsc")
    environment = dict(DEFAULT_ENV)
    for key, value in (env or {}).items():
        if not _ENV_KEY.fullmatch(key) or not isinstance(value, str) or "\0" in value:
            raise ValueError("invalid environment key or value")
        if key in DEFAULT_ENV and value != DEFAULT_ENV[key]:
            raise ValueError(f"environment {key} is fixed by the sandbox policy")
        environment[key] = value
    spec: dict[str, Any] = {
        "image": image,
        "labels": labels(scan_id, created),
        "user": "10001:10001",
        "read_only": True,
        "tmpfs": {  # Private, per-container tmpfs; no host temporary directory.
            "/tmp": "rw,size=64m,mode=1777",  # noqa: S108
            "/home/probe": "rw,size=64m",
        },
        "environment": environment,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges"],
        "pids_limit": 256,
        "mem_limit": "1g",
        "memswap_limit": "1g",
        "nano_cpus": 1_000_000_000,
        "ulimits": [{"Name": "nofile", "Soft": 1024, "Hard": 1024}],
        "init": True,
        "network": resource_names["pub"],
        "volumes": {resource_names["data"]: {"bind": "/data", "mode": "rw"}},
        "use_config_proxy": False,  # do not leak Docker user proxy credentials into the target
        "stdin_open": True,
        "tty": False,
    }
    if command is not None:
        if (
            isinstance(command, str | bytes)
            or not command
            or any(not isinstance(part, str) or "\0" in part for part in command)
        ):
            raise ValueError("command must be a nonempty executable argv without NULs")
        if not command[0]:
            raise ValueError("command executable is empty")
        spec["entrypoint"] = [command[0]]
        spec["command"] = list(command[1:])
    if runtime is not None:
        spec["runtime"] = runtime
    return spec
