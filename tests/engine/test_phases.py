"""Which checks never run, and why: NA (cannot apply) versus SKIPPED (chosen not to)."""

from typing import Any

import pytest

from probe.checks.context import TASKS_EXTENSION, ScanConfig
from probe.engine.outcomes import Era, Status, Transport
from probe.engine.phases import gate
from tests.checks.helpers import make_meta
from tests.engine.fakes import FakeFixtures, FakeRunner, make_context, tool


async def decision(requires: set[str] | None = None, *, era: str = "modern", **kwargs: Any) -> Any:
    meta_fields = kwargs.pop("meta", {})
    ctx, _ = await make_context(era=era, **kwargs)
    meta = make_meta(requires=frozenset(requires or ()), **meta_fields)
    return gate(meta, ctx)


async def test_a_check_with_nothing_in_the_way_runs() -> None:
    assert await decision() is None


async def test_era_mismatch_is_na() -> None:
    g = await decision(meta={"eras": frozenset({Era.LEGACY})})
    assert (g.status, g.reason) == (
        Status.NA,
        "applies to legacy servers; this one negotiated modern",
    )
    assert await decision(era="legacy", meta={"eras": frozenset({Era.LEGACY})}) is None


async def test_transport_mismatch_is_na() -> None:
    g = await decision(meta={"transports": frozenset({Transport.HTTP})})
    assert g.status is Status.NA
    assert "http" in g.reason
    ok = await decision(
        meta={"transports": frozenset({Transport.HTTP})},
        runner=FakeRunner(kind=Transport.HTTP),
    )
    assert ok is None


async def test_min_version_is_compared_to_the_negotiated_version() -> None:
    g = await decision(era="legacy", meta={"min_version": "2026-07-28"})
    assert g.status is Status.NA
    assert "needs protocol 2026-07-28" in g.reason
    assert await decision(meta={"min_version": "2025-06-18"}) is None


@pytest.mark.parametrize(
    ("requirement", "tools", "reason"),
    [
        ("tools", [], "the server has no tools"),
        ("url_tools", [tool("a")], "no tool takes a URL parameter"),
        ("path_tools", [tool("a")], "no tool takes a path parameter"),
        ("write_tools", [tool("a")], "no tool writes anything"),
        ("paginated", [tool("a")], "no tool is paginated"),
    ],
)
async def test_missing_tool_properties_are_na(
    requirement: str, tools: list[Any], reason: str
) -> None:
    g = await decision({requirement}, tools=tools)
    assert (g.status, g.reason) == (Status.NA, reason)


@pytest.mark.parametrize(
    ("requirement", "tools"),
    [
        ("tools", [tool("a")]),
        ("url_tools", [tool("a", flags=["url_param"])]),
        ("path_tools", [tool("a", flags=["path_param"])]),
        ("write_tools", [tool("a", kind="write")]),
        ("write_tools", [tool("a", kind="destructive")]),
        ("write_tools", [tool("a", kind="exec")]),
        ("write_tools", [tool("a", kind="unknown")]),  # unknown is treated as write
        ("paginated", [tool("a", flags=["paginated"])]),
    ],
)
async def test_present_tool_properties_let_the_check_run(
    requirement: str, tools: list[Any]
) -> None:
    assert await decision({requirement}, tools=tools) is None


async def test_http_auth_tasks_and_second_instance_requirements() -> None:
    assert (await decision({"http"})).reason == "needs an HTTP target"
    assert await decision({"http"}, runner=FakeRunner(kind=Transport.HTTP)) is None
    assert (await decision({"auth_identities"})).reason == "no auth identities configured"
    assert await decision({"auth_identities"}, auth_identities=["alice", "bob"]) is None
    assert (await decision({"tasks_ext"})).status is Status.NA
    assert (
        await decision({"second_instance"}, second_instance_supported=False)
    ).status is Status.NA
    assert await decision({"second_instance"}) is None


async def test_tasks_extension_is_read_from_server_capabilities() -> None:
    ctx, _ = await make_context()
    ctx.client.server_capabilities = {"extensions": {TASKS_EXTENSION: {}}}
    assert gate(make_meta(requires=frozenset({"tasks_ext"})), ctx) is None


async def test_skipped_by_choice_or_environment() -> None:
    g = await decision({"fixtures"})
    assert (g.status, g.reason) == (Status.SKIPPED, "requires sandbox (fixtures)")
    assert await decision({"fixtures"}, fixtures=FakeFixtures()) is None
    assert (await decision({"llm"})).reason == "requires --llm"
    assert await decision({"llm"}, llm=object()) is None  # type: ignore[arg-type]


async def test_side_effect_checks_need_permission_or_a_sandbox() -> None:
    g = await decision({"side_effects"})
    assert (g.status, g.reason) == (Status.SKIPPED, "requires --allow-side-effects or a sandbox")
    allowed = ScanConfig(allow_side_effects=True)
    assert await decision({"side_effects"}, config=allowed) is None
    sandboxed = FakeRunner()
    sandboxed.sandboxed = True  # type: ignore[misc]
    assert await decision({"side_effects"}, runner=sandboxed) is None


async def test_not_applicable_is_decided_before_skipped() -> None:
    # Needs fixtures (would be SKIPPED) but also tools the server lacks (NA): NA wins.
    g = await decision({"fixtures", "tools"}, tools=[])
    assert g.status is Status.NA


async def test_mode_exclusion_beats_everything() -> None:
    g = await decision({"tools"}, tools=[], meta={"modes": frozenset({"deep"})})
    assert (g.status, g.reason) == (Status.SKIPPED, "not part of standard mode")
