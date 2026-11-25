from unittest.mock import AsyncMock

import pytest

from probe.checks.behavior._campaign import SCRATCH_KEY, Campaign, Outcome, ToolPlan, outcomes
from probe.checks.context import ScanConfig
from probe.schema.cases import Case
from probe.wire.errors import RequestTimeout
from probe.wire.jsonrpc import ResultResponse
from probe.wire.session import Exchange
from tests.engine.fakes import DyingServer, FakeRunner, make_context, tool


async def test_crash_during_hang_retry_leaves_a_truncated_campaign() -> None:
    boom = tool("boom")
    first = Case(boom.name, "boundary", "first", 0, {})
    hung = Case(boom.name, "boundary", "hung", 0, {})
    skipped = Case(boom.name, "boundary", "skipped", 0, {})
    book = Campaign(plans=[ToolPlan(boom, boundary=[first, hung, skipped])])
    servers = iter([DyingServer(), DyingServer(), DyingServer(boom_crashes=False)])
    ctx, _ = await make_context(runner=FakeRunner(lambda: next(servers)), tools=[boom])
    ctx.scratch[SCRATCH_KEY] = book
    ctx.client.exchange = AsyncMock(
        side_effect=[Exchange(ResultResponse(1, {})), Exchange(None, timed_out=True)]
    )
    ctx.client.request = AsyncMock(side_effect=RequestTimeout(2, 5))

    seen = await outcomes(ctx, "boundary")
    assert [outcome.case for outcome in seen] == [first, hung]
    assert "boundary" in book.truncated
    assert await outcomes(ctx, "boundary") is seen


@pytest.mark.parametrize("scale", [0.5, 2])
async def test_campaign_scales_case_and_liveness_deadlines_and_records_case(scale) -> None:
    read = tool("read_it")
    case = Case(read.name, "valid", "minimal", 0, {})
    ctx, _ = await make_context(tools=[read], config=ScanConfig(timeout_scale=scale))
    ctx.scratch[SCRATCH_KEY] = Campaign(plans=[ToolPlan(read, valid=[case])])
    first_client = ctx.client
    first_client.exchange = AsyncMock(return_value=Exchange(None, timed_out=True))
    first_client.request = AsyncMock(side_effect=RequestTimeout(2, 5))

    [outcome] = await outcomes(ctx, "valid")
    assert outcome.hung and not outcome.reproduced
    assert (
        first_client.exchange.await_args.kwargs["timeout"],
        first_client.request.await_args.kwargs["timeout"],
        ctx.crashes.events[0].case_id,
    ) == (10 * scale, 5 * scale, case.id)


async def test_campaign_scales_the_per_tool_time_allowance(monkeypatch) -> None:
    read = tool("read_it")
    cases = [Case(read.name, "valid", "minimal", i, {}) for i in range(2)]
    ctx, _ = await make_context(tools=[read], config=ScanConfig(timeout_scale=2))
    ctx.scratch[SCRATCH_KEY] = Campaign(plans=[ToolPlan(read, valid=cases)])
    monkeypatch.setattr(
        "probe.checks.behavior._campaign.run_case",
        AsyncMock(side_effect=[Outcome(case, elapsed_ms=15_000) for case in cases]),
    )

    assert [outcome.case for outcome in await outcomes(ctx, "valid")] == cases
