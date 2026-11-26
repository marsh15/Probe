"""Hashes that identify things: finding ids, scan keys, schema hashes."""

from collections.abc import Mapping
from hashlib import sha256
from typing import Any

from probe.util.canonical_json import canonical_bytes


def sha256_hex(data: str | bytes) -> str:
    raw = data if isinstance(data, bytes) else data.encode("utf-8", "surrogatepass")
    return sha256(raw).hexdigest()


def canonical_hash(value: Any) -> str:
    """SHA-256 of the canonical JSON encoding of ``value`` (profile hashes, schema hashes)."""
    return sha256(canonical_bytes(value)).hexdigest()


def finding_id(
    check_id: str,
    tool: str | None,
    case_id: str,
    target_identity: Mapping[str, Any],
) -> str:
    """Stable 16-hex id for a finding, identical across reruns of the same target.

    The inputs are hashed as a JSON list rather than joined with a separator, so no choice of
    ids can make two different findings collide, and "no tool" differs from an empty tool name.
    """
    return canonical_hash([check_id, tool, case_id, dict(target_identity)])[:16]


def scan_key(
    *,
    target_identity: Mapping[str, Any],
    probe_version: str,
    catalog_version: str,
    scoring_version: str,
    profile_hash: str,
    mode: str,
    seed: int,
    conformance: bool = True,
) -> str:
    """Content address of a scan: the same inputs always give the same key."""
    return canonical_hash(
        {
            "target_identity": dict(target_identity),
            "probe_version": probe_version,
            "catalog_version": catalog_version,
            "scoring_version": scoring_version,
            "profile_hash": profile_hash,
            "mode": mode,
            "seed": seed,
            "conformance": conformance,
        }
    )
