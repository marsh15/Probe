"""Recognizing a slow-capable tool from its schema, and the profile override."""

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, Mock

from probe.checks.behavior._slow import BLOCKING_SECONDS, CANCEL_SECONDS, _guess, slow_case
from probe.checks.behavior.slow import NoHeadOfLineBlocking
from probe.checks.context import ScanConfig
from probe.config.profile import Profile
from probe.engine.outcomes import Status, ToolInfo
from probe.engine.scan import run_checks
from tests.engine.fakes import DyingServer, FakeRunner, make_context


def tool_with(name: str, properties: dict[str, Any], required: list[str] | None = None) -> ToolInfo:
    schema: dict[str, Any] = {"type": "object", "properties": properties}
    if required is not None:
        schema["required"] = required
    return ToolInfo(
        name=name,
        title=None,
        description=None,
        input_schema=schema,
        output_schema=None,
        annotations={},
        kind="read",
        flags=set(),
        classification_source="heuristic",
        classification_reason="test",
        param_roles={},
    )


def test_a_seconds_parameter_gets_the_target_duration() -> None:
    tool = tool_with("slow_report", {"seconds": {"type": "number", "maximum": 30}}, ["seconds"])
    guess = _guess(tool, CANCEL_SECONDS)
    assert guess is not None and guess.arguments == {"seconds": CANCEL_SECONDS}


def test_a_milliseconds_parameter_is_scaled() -> None:
    guess = _guess(tool_with("sleep", {"delay_ms": {"type": "number"}}), BLOCKING_SECONDS)
    assert guess is not None and guess.arguments == {"delay_ms": BLOCKING_SECONDS * 1000}


def test_an_integer_parameter_is_rounded() -> None:
    guess = _guess(tool_with("wait_a_bit", {"seconds": {"type": "integer"}}), 1.6)
    assert guess is not None and guess.arguments == {"seconds": 2.0}


def test_a_limit_below_the_target_rules_the_tool_out() -> None:
    tool = tool_with("slow_report", {"seconds": {"type": "number", "maximum": 1}})
    assert _guess(tool, BLOCKING_SECONDS) is None


def test_names_and_parameters_that_do_not_look_slow_are_ignored() -> None:
    assert _guess(tool_with("notes_list", {"limit": {"type": "number"}}), 1.6) is None
    # "items" ends in "ms" but is not a duration
    assert _guess(tool_with("slow_thing", {"items": {"type": "number"}}), 1.6) is None
    assert _guess(tool_with("get_greeting", {"seconds": {"type": "number"}}), 1.6) is None


def test_two_numeric_parameters_are_too_ambiguous() -> None:
    both = {"seconds": {"type": "number"}, "count": {"type": "number"}}
    assert _guess(tool_with("slow_many", both), 1.6) is None


async def test_the_profile_names_a_slow_case() -> None:
    profile = Profile.model_validate(
        {"version": 1, "tools": {"export": {"slow_case": {"rows": 100000}}}}
    )
    ctx, _ = await make_context(tools=[tool_with("export", {"rows": {"type": "integer"}})])
    ctx.profile = profile
    found = slow_case(ctx)
    assert found is not None and found.arguments == {"rows": 100000}


async def test_head_of_line_scales_the_list_latency_limit(monkeypatch) -> None:
    class SlowPeer(DyingServer):
        def handle(self, msg, headers):
            if msg.get("method") == "tools/call":
                return None
            return super().handle(msg, headers)

    ctx, _ = await make_context(
        tools=[tool_with("slow_report", {"seconds": {"type": "number"}})],
        runner=FakeRunner(SlowPeer),
        config=ScanConfig(timeout_scale=2),
    )
    clock = SimpleNamespace(time=Mock(side_effect=[0, 3]))
    monkeypatch.setattr(
        "probe.checks.behavior.slow.asyncio",
        SimpleNamespace(get_running_loop=lambda: clock, sleep=AsyncMock()),
    )
    [result] = await run_checks(ctx, [NoHeadOfLineBlocking])
    assert result.status is Status.PASS, [f.message for f in result.findings]
