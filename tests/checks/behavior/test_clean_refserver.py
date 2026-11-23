"""The input-handling checks against the clean reference server: none may fail.

Quick mode keeps it short; slow_report sleeps by design, so a full campaign takes over a minute.
"""

from typing import Any

import probe.checks.behavior  # noqa: F401 - registers the checks
from probe.checks.registry import REGISTRY
from probe.engine.outcomes import Status
from probe.engine.scan import run_checks
from tests.checks.protocol.harness import stdio_scan, with_listing


async def test_clean_refserver_stdio(stdio_command: Any, tmp_path: Any) -> None:
    argv, env = stdio_command
    async with stdio_scan(argv, tmp_path, env=env, mode="quick") as scan:
        await with_listing(scan)
        checks = [c for c in REGISTRY if c.meta.family.value == "behavior"]
        results = await run_checks(scan.ctx, checks)
    got = {r.check_id: r.status for r in results}
    bad = [(r.check_id, r.reason, [f.message for f in r.findings]) for r in results
           if r.status in (Status.FAIL, Status.ERROR)]  # fmt: skip
    assert not bad, bad
    assert got["behavior.valid_input_accepted"] is Status.PASS
    assert got["behavior.invalid_input_rejected"] is Status.PASS
    assert got["behavior.survives_campaign"] is Status.PASS
