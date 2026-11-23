"""All protocol checks against the clean reference server: none may fail (false positives = 0).

The expected statuses were checked by hand: every PASS is a behavior the server really has, and
every NA is a precondition the scenario really lacks (wrong transport or era, no second instance).
"""

from pathlib import Path
from typing import Any

import probe.checks.protocol  # noqa: F401 - registers the checks
from probe.checks.registry import REGISTRY
from probe.engine.outcomes import Status
from probe.engine.scan import run_checks
from tests.checks.protocol.harness import Scan, stdio_scan, url_scan

P, NA = Status.PASS, Status.NA

STDIO_MODERN = {
    "protocol.deprecated_features": P,
    "protocol.discover_implemented": P,
    "protocol.era_parity": P,
    "protocol.unknown_method_error": P,
    "protocol.unsupported_version_error": P,
    "protocol.header_mismatch_rejected": NA,
    "protocol.malformed_jsonrpc_handled": P,
    "protocol.origin_validated": NA,
    "protocol.required_headers_enforced": NA,
    "protocol.error_code_ranges": P,
    "protocol.result_type_present": P,
    "protocol.stdout_clean": P,
}
STDIO_LEGACY = {
    **{check: NA for check in STDIO_MODERN},
    "protocol.discover_implemented": P,  # a modern request works AND discover does: no blame
    "protocol.unknown_method_error": P,
    "protocol.malformed_jsonrpc_handled": P,
    "protocol.error_code_ranges": P,
    "protocol.stdout_clean": P,
}
HTTP_MODERN = {
    "protocol.deprecated_features": P,
    "protocol.discover_implemented": P,
    "protocol.era_parity": NA,  # a URL target cannot start a second instance
    "protocol.unknown_method_error": P,
    "protocol.unsupported_version_error": P,
    "protocol.header_mismatch_rejected": P,
    "protocol.malformed_jsonrpc_handled": P,
    "protocol.origin_validated": P,
    "protocol.required_headers_enforced": P,
    "protocol.error_code_ranges": P,
    "protocol.result_type_present": P,
    "protocol.stdout_clean": NA,  # stdio only
}
HTTP_LEGACY = {
    **{check: NA for check in HTTP_MODERN},
    "protocol.discover_implemented": P,  # a new connection shows modern requests and discover work
    "protocol.unknown_method_error": P,
    "protocol.malformed_jsonrpc_handled": P,
    "protocol.origin_validated": P,
    "protocol.error_code_ranges": P,
}


async def statuses(scan: Scan) -> dict[str, Status]:
    checks = [c for c in REGISTRY if c.meta.family.value == "protocol"]
    results = await run_checks(scan.ctx, checks)
    failing = [(r.check_id, r.reason, [f.message for f in r.findings]) for r in results
               if r.status in (Status.FAIL, Status.ERROR)]  # fmt: skip
    assert not failing, failing
    return {r.check_id: r.status for r in results}


async def test_stdio_modern(stdio_command: Any, tmp_path: Path) -> None:
    argv, env = stdio_command
    async with stdio_scan(argv, tmp_path, env=env) as scan:
        assert scan.ctx.era.value == "modern"
        assert await statuses(scan) == STDIO_MODERN


async def test_stdio_legacy(stdio_command: Any, tmp_path: Path) -> None:
    argv, env = stdio_command
    async with stdio_scan(argv, tmp_path, env=env, era="legacy") as scan:
        assert scan.ctx.era.value == "legacy"
        assert await statuses(scan) == STDIO_LEGACY


async def test_http_modern(http_url: str, tmp_path: Path) -> None:
    async with url_scan(http_url, tmp_path) as scan:
        assert scan.ctx.era.value == "modern"
        assert await statuses(scan) == HTTP_MODERN


async def test_http_legacy(http_url: str, tmp_path: Path) -> None:
    async with url_scan(http_url, tmp_path, era="legacy") as scan:
        assert scan.ctx.era.value == "legacy"
        assert await statuses(scan) == HTTP_LEGACY
