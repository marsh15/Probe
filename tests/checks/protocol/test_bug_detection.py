"""Each protocol check must catch its injected refserver bug.

Every check has a clean-server test elsewhere, so a pass here means the check separates the bug
from the clean server rather than failing everything. The HTTP-only bugs (b05, b06, b51) run
against a local HTTP server; the sandboxed run of the same bugs comes with the relay in T15.
"""

import sys
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

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


@dataclass(frozen=True)
class Case:
    bug: str
    check: type[Check]
    transports: tuple[str, ...] = ("stdio",)
    prepare: Prepare | None = None


STDIO, HTTP, BOTH = ("stdio",), ("http",), ("stdio", "http")
# b08 also exists over HTTP, where it kills the server; Probe cannot restart a URL target, so
# that run needs the sandbox relay (T15).
CASES = [
    Case("b01", DiscoverImplemented, BOTH),
    Case("b02", UnsupportedVersionError, BOTH),
    Case("b03", ResultTypePresent, BOTH),
    Case("b04", ErrorCodeRanges, BOTH),  # the check provokes the error it judges
    Case("b05", HeaderMismatchRejected, HTTP),
    Case("b06", OriginValidated, HTTP),
    Case("b07", StdoutClean, STDIO),
    Case("b08", MalformedJsonrpcHandled, STDIO),
    Case("b50", EraParity, STDIO),
    Case("b51", RequiredHeadersEnforced, HTTP),
    Case("b52", UnknownMethodError, STDIO),
]
PARAMS = [
    pytest.param(c, t, id=f"{c.bug}-{c.check.meta.id}-{t}") for c in CASES for t in c.transports
]


@pytest.mark.parametrize(("case", "transport"), PARAMS)
async def test_the_injected_bug_is_detected(
    case: Case, transport: str, seeded_data: Path, tmp_path: Path
) -> None:
    async def detect(scan: Scan) -> None:
        if case.prepare is not None:
            await case.prepare(scan)
        result = await scan.run(case.check)
        assert result.status is Status.FAIL, (result.status, result.reason)
        assert result.findings

    if transport == "stdio":
        argv = [sys.executable, "-m", "refserver", "stdio"]
        async with stdio_scan(argv, tmp_path, env=refserver_env(seeded_data, case.bug)) as scan:
            await detect(scan)
    else:
        with launch_http(seeded_data, case.bug) as url:
            async with url_scan(url, tmp_path) as scan:
                await detect(scan)
