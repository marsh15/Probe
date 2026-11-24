"""Operability verdicts against scripted wire peers and observed fixture state."""

import asyncio
from unittest.mock import AsyncMock

import pytest

from probe.checks.context import ScanConfig
from probe.checks.operability import (
    BurstResilient,
    CleanShutdown,
    LogsNoSecrets,
    MetaTolerated,
    StartupTime,
    TracePropagated,
)
from probe.engine.outcomes import Status, Transport
from probe.engine.scan import run_checks
from probe.wire.jsonrpc import Notification, encode, parse_line
from probe.wire.session import Exchange
from probe.wire.transport_base import CloseResult
from probe.wire.transport_http import RawHttpResult
from tests.engine.fakes import DyingServer, FakeRunner, make_context, tool
from tests.wire.fake_eras import EraServer, error, result


class Fixtures:
    token = "0123456789abcdef"

    def __init__(self):
        self.records = []
        self.faults = []

    async def reset(self):
        pass

    async def backend_log(self, since=0):
        return [r for r in self.records if r["sequence"] > since]

    async def backend_fault(self, route, *, count=1):
        self.faults.append((route, count))
        return True


class Peer(EraServer):
    def __init__(self, fixtures=None, *, trace="forward", reject=False, baseline=True):
        super().__init__()
        self.healthy_calls = None  # None: always; N: only the first N tools/call succeed
        self.calls = 0
        self.fixtures = fixtures
        self.trace = trace
        self.reject = reject
        self.baseline = baseline

    def handle(self, msg, headers):
        if msg.get("method") != "tools/call":
            return super().handle(msg, headers)
        self.received.append((msg, headers))
        meta = msg["params"].get("_meta", {})
        if not self.baseline or (self.reject and "com.example/x" in meta):
            return error(msg["id"], -32602, "metadata rejected")
        self.calls += 1
        if self.healthy_calls is not None and self.calls > self.healthy_calls:
            gone = [{"type": "text", "text": "note 1 not found"}]
            return result(msg["id"], {"resultType": "complete", "isError": True, "content": gone})
        if self.fixtures is not None and self.trace != "none":
            parent = meta.get("traceparent")
            if self.trace == "wrong":
                parent = "00-" + "a" * 32 + "-" + "b" * 16 + "-01"
            self.fixtures.records.append(
                {
                    "sequence": len(self.fixtures.records) + 1,
                    "path": "/c/items/1",
                    "headers": {"traceparent": parent},
                }
            )
        return result(msg["id"], {"resultType": "complete", "content": []})


async def verdict(check, **kwargs):
    ctx, runner = await make_context(**kwargs)
    [out] = await run_checks(ctx, [check])
    return out, ctx, runner


@pytest.mark.parametrize(
    "trace,status",
    [
        ("forward", Status.PASS),
        ("wrong", Status.FAIL),
        ("missing", Status.FAIL),
        ("none", Status.NA),
    ],
)
async def test_trace_window_and_id(trace, status):
    fixtures = Fixtures()
    fixtures.records.append({"sequence": 1, "headers": {}, "path": "/old"})
    peer = Peer(fixtures, trace=trace)
    if trace == "missing":
        peer.trace = "forward"
        original = peer.handle

        def strip(msg, headers):
            reply = original(msg, headers)
            if msg.get("method") == "tools/call":
                fixtures.records[-1]["headers"] = {}
            return reply

        peer.handle = strip
    out, ctx, _ = await verdict(TracePropagated, runner=FakeRunner(lambda: peer), fixtures=fixtures)
    assert out.status == status, out.reason
    if status == Status.FAIL:
        assert out.findings[0].evidence.observations["requests"]
    calls = [m for m, _ in peer.received if m.get("method") == "tools/call"]
    assert calls[0]["params"]["_meta"]["traceparent"].startswith("00-")
    assert ctx.calls >= 1


@pytest.mark.parametrize(
    "reject,baseline,status",
    [(False, True, Status.PASS), (True, True, Status.FAIL), (True, False, Status.NA)],
)
async def test_meta_compares_against_successful_baseline(reject, baseline, status):
    peer = Peer(reject=reject, baseline=baseline)
    out, _, _ = await verdict(MetaTolerated, runner=FakeRunner(lambda: peer))
    assert out.status == status, out.reason
    if baseline:
        meta = [m for m, _ in peer.received if m.get("method") == "tools/call"][-1]["params"][
            "_meta"
        ]
        assert {"traceparent", "tracestate", "baggage", "com.example/x"} <= meta.keys()


async def test_meta_does_not_blame_metadata_for_state_that_changed_since_the_baseline():
    """The scan's earlier calls may have deleted what the baseline read; a plain call that now
    fails too says nothing about metadata."""
    peer = Peer()
    peer.healthy_calls = 1
    ctx, _ = await make_context(runner=FakeRunner(lambda: peer))
    first = await ctx.establish_baseline(ctx.tools[0], {})
    assert first is not None
    [out] = await run_checks(ctx, [MetaTolerated])
    assert out.status == Status.NA, out.reason


@pytest.mark.parametrize("check", [TracePropagated, LogsNoSecrets])
async def test_fixture_checks_skip_without_fixtures(check):
    out, _, _ = await verdict(check)
    assert out.status == Status.SKIPPED


@pytest.mark.parametrize("mode,count", [("standard", 50), ("deep", 200)])
async def test_burst_is_simultaneous_and_budgeted(mode, count):
    ctx, _ = await make_context(config=ScanConfig(mode=mode))
    active = peak = 0
    gate = asyncio.Event()
    original = ctx.exchange

    async def exchange(*args, **kwargs):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        if active == count:
            gate.set()
        await asyncio.wait_for(gate.wait(), 2)
        reply = await original(*args, **kwargs)
        active -= 1
        return reply

    ctx.exchange = exchange
    [out] = await run_checks(ctx, [BurstResilient])
    assert out.status == Status.PASS
    assert peak == count
    assert ctx.calls == count + 1  # successful baseline and the complete burst


async def test_burst_shrinks_with_an_info_observation():
    out, ctx, _ = await verdict(BurstResilient, budget_calls=8)
    assert out.status == Status.PASS
    assert ctx.calls == 8
    assert out.findings[0].severity.value == "info"
    assert out.findings[0].evidence.observations["actual"] == 7


@pytest.mark.parametrize(
    "kind,status",
    [
        ("ok", Status.PASS),
        ("rate", Status.PASS),
        ("error", Status.FAIL),
        ("garbled", Status.FAIL),
        ("hang", Status.FAIL),
        ("5xx", Status.FAIL),
        ("429", Status.PASS),
        ("429-no-retry", Status.FAIL),
    ],
)
async def test_burst_response_shapes(kind, status):
    ctx, _ = await make_context()
    good = {"resultType": "complete", "content": []}
    from probe.wire.jsonrpc import ResultResponse

    response = ResultResponse(1, good)
    reply = Exchange(response)
    if kind in {"rate", "error"}:
        reply = Exchange(
            ResultResponse(
                1,
                {
                    **good,
                    "isError": True,
                    "content": [
                        {
                            "type": "text",
                            "text": "rate limit; retry" if kind == "rate" else "broken",
                        }
                    ],
                },
            )
        )
    elif kind == "garbled":
        reply = Exchange(ResultResponse(1, {"nonsense": True}))
    elif kind == "hang":
        reply = Exchange(None, timed_out=True)
    elif kind in {"5xx", "429", "429-no-retry"}:
        reply = Exchange(
            None,
            RawHttpResult(
                503 if kind == "5xx" else 429,
                {"retry-after": "2"} if kind == "429" else {},
                "",
                b"",
                0,
                (),
                0,
            ),
        )
    ctx.exchange = AsyncMock(return_value=reply)
    [out] = await run_checks(ctx, [BurstResilient])
    assert out.status == status, out.reason


@pytest.mark.parametrize("reproduce,status", [(True, Status.FAIL), (False, Status.ERROR)])
async def test_burst_repeats_the_whole_crashing_case(reproduce, status):
    # A simultaneous disconnect must be recorded once, rather than once per pending call.
    servers = iter(
        [
            DyingServer(boom_crashes=False),
            DyingServer(boom_crashes=reproduce),
            DyingServer(boom_crashes=False),
        ]
    )
    runner = FakeRunner(lambda: next(servers))
    ctx, _ = await make_context(runner=runner, tools=[tool("boom")])
    await ctx.establish_baseline(ctx.tools[0], {})
    runner.transports[0].server.boom_crashes = True
    [out] = await run_checks(ctx, [BurstResilient])
    assert out.status == status, out.reason
    assert len(ctx.crashes.events) == (2 if reproduce else 1)
    assert runner.restarts == (2 if reproduce else 1)


async def test_burst_quick_and_no_read_tools():
    out, _, _ = await verdict(BurstResilient, config=ScanConfig(mode="quick"))
    assert out.status == Status.SKIPPED
    out, _, _ = await verdict(BurstResilient, tools=[tool("write", "write")])
    assert out.status == Status.NA


@pytest.mark.parametrize("source", ["none", "stderr", "container", "notification"])
async def test_only_secret_sentinel_in_logs_fails(source):
    fixtures = Fixtures()
    sensitive = tool("read_secret", flags=["sensitive_param"])
    sensitive.param_roles["token"] = "sensitive_param"
    sensitive.input_schema = {"type": "object", "properties": {"token": {"type": "string"}}}
    ctx, runner = await make_context(tools=[sensitive], fixtures=fixtures)
    sentinel = f"probe-sensitive-{fixtures.token}"
    if source == "stderr":
        ctx.client.transport.stderr_tail = lambda n=4096: sentinel
    if source == "container":
        runner.logs = AsyncMock(return_value=sentinel)
    original = ctx.call

    async def call(name, arguments, **kwargs):
        assert arguments["token"] == sentinel
        reply = await original(name, arguments, **kwargs)
        if source == "notification":
            ctx.client.transport._receive(
                parse_line(
                    encode(Notification("notifications/message", {"data": sentinel}).to_obj())
                )
            )
        return reply

    ctx.call = call
    [out] = await run_checks(ctx, [LogsNoSecrets])
    assert out.status == (Status.PASS if source == "none" else Status.FAIL), out.reason
    if source != "none":
        assert sentinel in out.findings[0].evidence.excerpt


async def test_logs_na_without_sensitive_callable_parameters():
    out, _, _ = await verdict(LogsNoSecrets, fixtures=Fixtures())
    assert out.status == Status.NA


@pytest.mark.parametrize("killed,status", [(False, Status.PASS), (True, Status.FAIL)])
async def test_shutdown_uses_fresh_runner_probe(killed, status):
    runner = FakeRunner()
    runner.check_shutdown = AsyncMock(return_value=CloseResult(-9 if killed else 0, True, killed))
    out, _, _ = await verdict(CleanShutdown, runner=runner)
    assert out.status == status, out.reason
    runner.check_shutdown.assert_awaited_once_with()
    assert runner.running


async def test_shutdown_http_and_unsupported_are_na():
    out, _, _ = await verdict(CleanShutdown, runner=FakeRunner(kind=Transport.HTTP))
    assert out.status == Status.NA
    out, _, _ = await verdict(CleanShutdown, second_instance_supported=False)
    assert out.status == Status.NA


@pytest.mark.parametrize("milliseconds", [23.5, 30001])
async def test_startup_is_info_only(milliseconds):
    ctx, _ = await make_context()
    ctx.startup_ms = milliseconds
    [out] = await run_checks(ctx, [StartupTime])
    assert out.status == Status.PASS
    assert out.findings[0].severity.value == "info"
    assert out.findings[0].evidence.observations["startup_ms"] == milliseconds
    assert ("30 s" in out.findings[0].message) == (milliseconds > 30000)


async def test_startup_without_measurement_is_na():
    out, _, _ = await verdict(StartupTime)
    assert out.status == Status.NA


async def test_backend_fault_burst_and_cleanup():
    fixtures = Fixtures()
    peer = Peer(fixtures)
    out, ctx, _ = await verdict(BurstResilient, runner=FakeRunner(lambda: peer), fixtures=fixtures)
    assert out.status == Status.PASS, out.reason
    assert ctx.calls == 101
    assert fixtures.faults == [("/c/items/1", 50), (None, 1)]


async def test_backend_fault_is_cleared_when_burst_errors():
    from probe.checks.operability.burst import BurstResilient

    fixtures = Fixtures()
    peer = Peer(fixtures)
    ctx, _ = await make_context(runner=FakeRunner(lambda: peer), fixtures=fixtures)
    check = BurstResilient()
    check._burst = AsyncMock(side_effect=[[], RuntimeError("probe failure")])
    with pytest.raises(RuntimeError, match="probe failure"):
        await check.run(ctx)
    assert fixtures.faults[-1] == (None, 1)


async def test_metadata_timeout_is_a_failure_after_baseline():
    ctx, _ = await make_context()
    ctx.exchange = AsyncMock(return_value=Exchange(None, timed_out=True))
    [out] = await run_checks(ctx, [MetaTolerated])
    assert out.status == Status.FAIL
    assert out.findings[0].evidence.observations["timed_out"]


async def test_all_tool_checks_are_na_without_tools():
    for check in (TracePropagated, MetaTolerated, LogsNoSecrets, BurstResilient):
        out, _, _ = await verdict(check, tools=[], fixtures=Fixtures())
        assert out.status == Status.NA


async def test_cached_baseline_still_observes_backend_routes():
    fixtures = Fixtures()
    peer = Peer(fixtures)
    ctx, _ = await make_context(runner=FakeRunner(lambda: peer), fixtures=fixtures)
    results = await run_checks(ctx, [MetaTolerated, BurstResilient])
    assert all(r.status == Status.PASS for r in results)
    assert results[1].calls == 101
    assert fixtures.faults == [("/c/items/1", 50), (None, 1)]


async def test_backend_burst_budget_reduction_is_reported():
    fixtures = Fixtures()
    peer = Peer(fixtures)
    out, ctx, _ = await verdict(
        BurstResilient, runner=FakeRunner(lambda: peer), fixtures=fixtures, budget_calls=75
    )
    assert out.status == Status.PASS
    assert ctx.calls == 75
    assert out.findings[0].evidence.observations == {"requested": 50, "actual": 24}
    assert fixtures.faults == [("/c/items/1", 24), (None, 1)]


async def test_faults_are_rearmed_before_crash_reproduction():
    servers = iter([DyingServer(boom_crashes=False), DyingServer(boom_crashes=True), DyingServer()])
    fixtures = Fixtures()
    ctx, runner = await make_context(runner=FakeRunner(lambda: next(servers)), fixtures=fixtures)
    runner.transports[0].server.boom_crashes = True
    findings = await BurstResilient()._burst(
        ctx, tool("boom"), {}, 50, "fault-crash", fault_routes=("/c/items/1",)
    )
    assert findings[0].evidence.observations["reproduced_crash"]
    assert fixtures.faults == [("/c/items/1", 50)]
    assert len(ctx.crashes.events) == 2


async def test_burst_without_a_successful_baseline_is_na():
    out, _, _ = await verdict(BurstResilient, runner=FakeRunner(lambda: Peer(baseline=False)))
    assert out.status == Status.NA


@pytest.mark.parametrize("check", [MetaTolerated, BurstResilient])
async def test_baseline_timeout_is_na(check):
    from probe.wire.errors import RequestTimeout

    ctx, _ = await make_context()
    ctx.establish_baseline = AsyncMock(side_effect=RequestTimeout(1, 0.1))
    [out] = await run_checks(ctx, [check])
    assert out.status == Status.NA


async def test_large_successful_count_is_not_mistaken_for_http_500():
    from probe.checks.operability.burst import problem
    from probe.wire.jsonrpc import ResultResponse

    reply = Exchange(
        ResultResponse(
            1,
            {"resultType": "complete", "content": [{"type": "text", "text": "500 notes returned"}]},
        )
    )
    assert problem(reply, "2026-07-28") is None


async def test_burst_does_not_blame_the_burst_for_a_call_that_fails_alone():
    """A tool whose input was deleted earlier in the scan errors on every call, burst or not."""
    peer = Peer()
    peer.healthy_calls = 1
    ctx, _ = await make_context(runner=FakeRunner(lambda: peer))
    first = await ctx.establish_baseline(ctx.tools[0], {})
    assert first is not None
    [out] = await run_checks(ctx, [BurstResilient])
    assert out.status in (Status.PASS, Status.NA), (out.status, out.reason)
    assert not out.findings
