"""All schema checks against the clean reference server: none may fail or error.

Expected statuses were checked by hand against the server's actual tool list.
"""

from pathlib import Path
from typing import Any

import probe.checks.schema  # noqa: F401 - registers the checks
from probe.checks.registry import REGISTRY
from probe.engine.outcomes import Status
from probe.engine.scan import run_checks
from tests.checks.protocol.harness import Scan, stdio_scan, url_scan, with_listing

P, NA = Status.PASS, Status.NA
MODERN = {
    "schema.tools_list_valid": P,
    "schema.input_schema_valid": P,
    "schema.refs_resolvable": P,
    "schema.tool_order_deterministic": P,
    "schema.cache_fields_present": P,
    "schema.cache_ttl_sane": P,
    "schema.tool_names_valid": P,
    "schema.descriptions_present": P,
    "schema.x_mcp_header_valid": P,
    "schema.input_schema_strict": P,  # passes with an information finding about loose schemas
    "schema.cache_scope_correct": NA,  # needs two identities (see test_cache_scope.py)
    "schema.output_conforms": P,
    "schema.structured_text_mirror": P,
}
LEGACY = {
    **MODERN,
    "schema.cache_fields_present": NA,  # modern-only fields
    "schema.cache_ttl_sane": NA,
    "schema.x_mcp_header_valid": NA,
    "schema.cache_scope_correct": NA,
}


async def statuses(scan: Scan) -> dict[str, Status]:
    await with_listing(scan)
    checks = [c for c in REGISTRY if c.meta.family.value == "schema"]
    results = await run_checks(scan.ctx, checks)
    bad = [(r.check_id, r.reason, [f.message for f in r.findings]) for r in results
           if r.status in (Status.FAIL, Status.ERROR)]  # fmt: skip
    assert not bad, bad
    return {r.check_id: r.status for r in results}


async def test_stdio_modern(stdio_command: Any, tmp_path: Path) -> None:
    argv, env = stdio_command
    async with stdio_scan(argv, tmp_path, env=env, mode="quick") as scan:
        assert await statuses(scan) == MODERN


async def test_stdio_legacy(stdio_command: Any, tmp_path: Path) -> None:
    argv, env = stdio_command
    async with stdio_scan(argv, tmp_path, env=env, era="legacy", mode="quick") as scan:
        assert await statuses(scan) == LEGACY


async def test_http_modern(http_url: str, tmp_path: Path) -> None:
    async with url_scan(http_url, tmp_path, mode="quick") as scan:
        assert await statuses(scan) == MODERN
