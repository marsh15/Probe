"""Each protocol check must catch its injected refserver bug (and only be satisfied without it).

The bugs are implemented by task T11 (b05, b06, b51 need the HTTP relay of T15). Until then the
server refuses to start with them, so these tests are strict xfails that name the bug: when a
bug lands the test XPASSes and fails the run, which is the cue to delete its xfail mark.
"""

import sys
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from probe.checks.base import Check
from probe.checks.protocol.deprecated import DeprecatedFeatures  # noqa: F401 - not bug-bearing
from probe.checks.protocol.discover import DiscoverImplemented
from probe.checks.protocol.http import (
    HeaderMismatchRejected,
    OriginValidated,
    RequiredHeadersEnforced,
)
from probe.checks.protocol.malformed import MalformedJsonrpcHandled
from probe.checks.protocol.parity import EraParity
from probe.checks.protocol.passive import ErrorCodeRanges, ResultTypePresent, StdoutClean
from probe.checks.protocol.unknown_method import UnknownMethodError
from probe.checks.protocol.version import UnsupportedVersionError
from probe.engine.outcomes import Status
from tests.checks.protocol.harness import Scan, stdio_scan, url_scan
from tests.conftest import launch_http, refserver_env

Prepare = Callable[[Scan], Awaitable[None]]


async def provoke_invalid_params(scan: Scan) -> None:
    """Passive checks read the trace, so make the server produce an invalid-params error."""
    await scan.ctx.exchange(
        "tools/call", {"name": "notes_get", "arguments": {"id": "not-a-number"}}
    )


@dataclass(frozen=True)
class Case:
    bug: str
    check: type[Check]
    transport: str  # "stdio" or "http"
    prepare: Prepare | None = None
    needs: str = "T11"


CASES = [
    Case("b01", DiscoverImplemented, "stdio"),
    Case("b02", UnsupportedVersionError, "stdio"),
    Case("b03", ResultTypePresent, "stdio"),
    Case("b04", ErrorCodeRanges, "stdio", provoke_invalid_params),
    Case("b05", HeaderMismatchRejected, "http", needs="T15"),
    Case("b06", OriginValidated, "http", needs="T15"),
    Case("b07", StdoutClean, "stdio"),
    Case("b08", MalformedJsonrpcHandled, "stdio"),
    Case("b50", EraParity, "stdio"),
    Case("b51", RequiredHeadersEnforced, "http", needs="T15"),
    Case("b52", UnknownMethodError, "stdio"),
]


def case_param(case: Case) -> Any:
    mark = pytest.mark.xfail(strict=True, reason=f"{case.bug} lands in {case.needs}")
    return pytest.param(case, id=f"{case.bug}-{case.check.meta.id}", marks=mark)


@pytest.mark.parametrize("case", [case_param(c) for c in CASES])
async def test_the_injected_bug_is_detected(case: Case, seeded_data: Path, tmp_path: Path) -> None:
    async def detect(scan: Scan) -> None:
        if case.prepare is not None:
            await case.prepare(scan)
        result = await scan.run(case.check)
        assert result.status is Status.FAIL, (result.status, result.reason)
        assert result.findings

    if case.transport == "stdio":
        argv = [sys.executable, "-m", "refserver", "stdio"]
        async with stdio_scan(argv, tmp_path, env=refserver_env(seeded_data, case.bug)) as scan:
            await detect(scan)
    else:
        with launch_http(seeded_data, case.bug) as url:
            async with url_scan(url, tmp_path) as scan:
                await detect(scan)
