"""Pagination, result size, empty matches, concurrency, idempotency and output conformance,
each against the scripted tool server with and without its matching defect."""

import sys
from pathlib import Path
from typing import Any

import pytest

import probe.checks.behavior
import probe.checks.schema  # noqa: F401 - registers the checks
from probe.checks.behavior.concurrency import ConcurrencyConsistent
from probe.checks.behavior.idempotency import IdempotencyDeclared, ReplayIdempotent
from probe.checks.behavior.pagination import PaginationSound
from probe.checks.behavior.results import EmptyResultOk, OutputBounded
from probe.checks.context import ScanConfig
from probe.checks.schema.output import OutputConforms, StructuredTextMirror
from probe.engine.outcomes import Severity, Status
from probe.sandbox.fixtures import FixtureSet, FixtureState
from tests.checks.protocol.harness import stdio_scan, with_listing

SERVER = Path(__file__).parent / "tool_server.py"


def scan_of(tmp_path: Path, behavior: str = "clean", **env: str) -> Any:
    return stdio_scan(
        [sys.executable, str(SERVER)],
        tmp_path,
        env={"TOOL_EXTRA": "1", "EXTRA_BEHAVIOR": behavior, "PATH": "/usr/bin:/bin", **env},
        mode="standard",
    )


async def run(tmp_path: Path, check: Any, behavior: str = "clean", **env: str) -> Any:
    async with scan_of(tmp_path, behavior, **env) as scan:
        await with_listing(scan)
        return await scan.run(check)


CLEAN_PASSES = [
    PaginationSound,
    OutputBounded,
    EmptyResultOk,
    ConcurrencyConsistent,
    OutputConforms,
    StructuredTextMirror,
]


@pytest.mark.parametrize("check", CLEAN_PASSES)
async def test_the_clean_server_passes(check: Any, tmp_path: Path) -> None:
    result = await run(tmp_path, check)
    assert result.status is Status.PASS, (result.reason, [f.message for f in result.findings])


FAILURES = [
    (PaginationSound, "loop_cursor", "repeated"),
    (PaginationSound, "dup_pages", "duplicate"),
    (PaginationSound, "accept_bogus", "invalid cursor"),
    (OutputBounded, "big_output", "MiB"),
    (EmptyResultOk, "empty_error", "empty match"),
    (ConcurrencyConsistent, "racy", "differed"),
    (OutputConforms, "bad_output", "does not match"),
    (StructuredTextMirror, "no_mirror", "no text block"),
]


@pytest.mark.parametrize(("check", "behavior", "fragment"), FAILURES)
async def test_each_defect_is_caught(
    check: Any, behavior: str, fragment: str, tmp_path: Path
) -> None:
    result = await run(tmp_path, check, behavior)
    assert result.status is Status.FAIL, (result.status, result.reason)
    text = " ".join(f.title + " " + f.message for f in result.findings)
    assert fragment in text, text


async def test_missing_structured_content_is_an_output_failure(tmp_path: Path) -> None:
    async with scan_of(tmp_path, "no_mirror") as scan:
        await with_listing(scan)
        # Drop structuredContent entirely by pretending the schema demands another shape.
        scan.ctx.tools = [
            t.model_copy(update={"output_schema": {"type": "object", "required": ["nope"]}})
            if t.name == "list_items"
            else t
            for t in scan.ctx.tools
        ]
        result = await scan.run(OutputConforms)
    assert result.status is Status.FAIL


class CounterFixtures:
    """Fixture stand-in that watches the number of marks the server's add_item wrote."""

    def __init__(self, path: Path) -> None:
        self.path = path

    async def reset(self) -> None:
        self.path.write_text("")

    async def snapshot(self) -> FixtureState:
        return FixtureState(fs={"count": len(self.path.read_text())})

    def diff(self, a: Any, b: Any) -> Any:
        return FixtureSet.diff(a, b)


async def replay(tmp_path: Path, behavior: str, hint: str) -> Any:
    counter = tmp_path / "count"
    counter.write_text("")
    async with scan_of(
        tmp_path / "scan", behavior, TOOL_COUNT_FILE=str(counter), ADD_HINT=hint
    ) as scan:
        await with_listing(scan)
        scan.ctx.config = ScanConfig(mode="standard", allow_side_effects=True)
        scan.ctx.fixtures = CounterFixtures(counter)
        return await scan.run(ReplayIdempotent)


async def test_an_idempotent_tool_that_repeats_its_write_fails(tmp_path: Path) -> None:
    result = await replay(tmp_path, "not_idempotent", hint="1")
    assert result.status is Status.FAIL
    [finding] = result.findings
    assert finding.severity is Severity.HIGH and finding.tool == "add_item"


async def test_an_honest_idempotent_tool_passes(tmp_path: Path) -> None:
    assert (await replay(tmp_path, "clean", hint="1")).status is Status.PASS


async def test_repeating_without_a_promise_is_only_a_note(tmp_path: Path) -> None:
    result = await replay(tmp_path, "not_idempotent", hint="0")
    assert result.status is Status.PASS
    [finding] = result.findings
    assert finding.severity is Severity.INFO


async def test_a_write_tool_without_idempotent_hint_is_flagged(tmp_path: Path) -> None:
    async with scan_of(tmp_path) as scan:
        await with_listing(scan)
        scan.ctx.tools = [t.model_copy(update={"kind": "write"}) for t in scan.ctx.tools]
        result = await scan.run(IdempotencyDeclared)
    assert result.status is Status.FAIL
    assert {f.tool for f in result.findings} == {"get_greeting", "list_items", "add_item"}
