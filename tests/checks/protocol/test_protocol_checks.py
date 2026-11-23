"""Each protocol check: a case that must pass and cases that must fail, on scripted targets."""

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from probe.checks.protocol import malformed as malformed_module
from probe.checks.protocol.deprecated import DeprecatedFeatures
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
from probe.engine.outcomes import Severity, Status
from probe.wire.jsonrpc import encode
from tests.checks.protocol.harness import (
    ToolsServer,
    http_scan,
    mini_argv,
    scripted_scan,
    stdio_scan,
)
from tests.wire.fake_eras import PV, EraServer, Reply, error
from tests.wire.fake_http import ServerState, serve


@pytest.fixture(autouse=True)
def short_reply_wait(monkeypatch: pytest.MonkeyPatch) -> None:
    """A server that ignores garbage never answers; do not wait the full production window."""
    monkeypatch.setattr(malformed_module, "_REPLY_WAIT_S", 0.4)


@pytest.fixture
async def http_fake() -> AsyncIterator[tuple[str, ServerState]]:
    async with serve() as running:
        yield running


def dual(**kwargs: Any) -> ToolsServer:
    return ToolsServer(legacy=True, advertise_legacy=True, **kwargs)


# --- protocol.discover_implemented -------------------------------------------------------


async def test_discover_passes_on_a_good_modern_server(tmp_path: Path) -> None:
    async with scripted_scan(ToolsServer, tmp_path) as scan:
        assert (await scan.run(DiscoverImplemented)).status is Status.PASS


async def test_discover_fails_when_required_fields_are_missing(tmp_path: Path) -> None:
    class Incomplete(ToolsServer):
        def _modern(self, id_: Any, method: str, *rest: Any) -> Any:
            reply = super()._modern(id_, method, *rest)
            if method == "server/discover":
                reply.body["result"].pop("ttlMs")
                reply.body["result"]["cacheScope"] = "everyone"
                reply.body["result"]["supportedVersions"] = []
            return reply

    async with scripted_scan(Incomplete, tmp_path) as scan:
        result = await scan.run(DiscoverImplemented)
    assert result.status is Status.FAIL
    message = result.findings[0].message
    assert "ttlMs" in message and "cacheScope" in message and "supportedVersions" in message


async def test_discover_fails_when_the_server_rejects_the_probe(tmp_path: Path) -> None:
    class Rejects(ToolsServer):
        def _modern(self, id_: Any, method: str, *rest: Any) -> Any:
            if method == "server/discover":
                return error(id_, -32020, "Header mismatch", status=400)
            return super()._modern(id_, method, *rest)

    async with scripted_scan(Rejects, tmp_path) as scan:
        result = await scan.run(DiscoverImplemented)
    assert result.status is Status.FAIL
    assert "no result" in result.findings[0].title


async def test_discover_missing_on_a_modern_capable_server_is_caught_on_a_fresh_instance(
    tmp_path: Path,
) -> None:
    class NoDiscover(ToolsServer):  # the bug: discover answers -32601 but modern requests work
        def _modern(self, id_: Any, method: str, *rest: Any) -> Any:
            if method == "server/discover":
                return error(id_, -32601, "Method not found")
            return super()._modern(id_, method, *rest)

    async with scripted_scan(lambda: NoDiscover(legacy=True), tmp_path) as scan:
        assert scan.ctx.era.value == "legacy"  # negotiation fell back, as clients would
        result = await scan.run(DiscoverImplemented)
    assert result.status is Status.FAIL
    assert "does not implement server/discover" in result.findings[0].title


async def test_discover_is_not_blamed_when_legacy_was_forced_on_a_good_server(
    tmp_path: Path,
) -> None:
    async with scripted_scan(dual, tmp_path, era="legacy") as scan:
        assert (await scan.run(DiscoverImplemented)).status is Status.PASS


async def test_discover_is_na_for_a_legacy_only_server(tmp_path: Path) -> None:
    async with scripted_scan(lambda: EraServer(modern=False, legacy=True), tmp_path) as scan:
        result = await scan.run(DiscoverImplemented)
    assert (result.status, result.reason) == (Status.NA, "the server speaks legacy MCP only")


# --- protocol.unsupported_version_error --------------------------------------------------


async def test_unsupported_version_passes_on_a_correct_server(tmp_path: Path) -> None:
    async with scripted_scan(ToolsServer, tmp_path) as scan:
        assert (await scan.run(UnsupportedVersionError)).status is Status.PASS


async def test_unsupported_version_fails_on_the_wrong_error_code(tmp_path: Path) -> None:
    class WrongCode(ToolsServer):
        def _modern(self, id_: Any, method: str, params: Any, meta: Any, headers: Any) -> Any:
            if meta[PV] not in self.modern_versions:
                return error(id_, -32602, "invalid params")
            return super()._modern(id_, method, params, meta, headers)

    async with scripted_scan(WrongCode, tmp_path) as scan:
        result = await scan.run(UnsupportedVersionError)
    assert result.status is Status.FAIL
    assert "-32602" in result.findings[0].message


async def test_unsupported_version_checks_the_http_status_and_data(
    tmp_path: Path, http_fake: tuple[str, ServerState]
) -> None:
    class WrongStatus(ToolsServer):
        def _modern(self, id_: Any, method: str, params: Any, meta: Any, headers: Any) -> Any:
            if meta[PV] not in self.modern_versions:
                return error(id_, -32022, "unsupported", {"supported": "2026-07-28"}, status=200)
            return super()._modern(id_, method, params, meta, headers)

    async with http_scan(http_fake, tmp_path, server=ToolsServer()) as scan:
        assert (await scan.run(UnsupportedVersionError)).status is Status.PASS
    async with http_scan(http_fake, tmp_path / "b", server=WrongStatus()) as scan:
        result = await scan.run(UnsupportedVersionError)
    assert result.status is Status.FAIL
    message = result.findings[0].message
    assert "not 400" in message and "data.supported" in message and "data.requested" in message


# --- protocol.result_type_present --------------------------------------------------------


async def test_result_type_passes_when_every_result_has_it(tmp_path: Path) -> None:
    async with scripted_scan(ToolsServer, tmp_path) as scan:
        await scan.ctx.exchange("tools/list")
        assert (await scan.run(ResultTypePresent)).status is Status.PASS


async def test_result_type_fails_and_names_the_methods(tmp_path: Path) -> None:
    class Strips(ToolsServer):
        def handle(self, msg: dict[str, Any], headers: Any) -> Any:
            reply = super().handle(msg, headers)
            if reply and reply.body and "result" in reply.body:
                reply.body["result"].pop("resultType", None)
            return reply

    async with scripted_scan(Strips, tmp_path) as scan:
        await scan.ctx.exchange("tools/list")
        result = await scan.run(ResultTypePresent)
    assert result.status is Status.FAIL
    assert result.findings[0].evidence.observations["methods"] == ["server/discover", "tools/list"]


async def test_result_type_ignores_traffic_of_side_instances(tmp_path: Path) -> None:
    # A legacy probe on a fresh instance has no resultType; it must not count against the
    # main (modern) instance.
    async with scripted_scan(dual, tmp_path) as scan:
        scan.ctx.client.transport.instance = None
        fresh = await scan.runner.second_instance()
        assert fresh is not None
        fresh.instance = "side"
        await fresh.send({"jsonrpc": "2.0", "method": "notifications/x"})
        fresh.push_raw(encode({"jsonrpc": "2.0", "id": 5, "result": {}}).strip())
        assert (await scan.run(ResultTypePresent)).status is Status.PASS


async def test_result_type_is_na_for_legacy_servers(tmp_path: Path) -> None:
    async with scripted_scan(lambda: EraServer(modern=False, legacy=True), tmp_path) as scan:
        assert (await scan.run(ResultTypePresent)).status is Status.NA


# --- protocol.error_code_ranges ----------------------------------------------------------


class OddCodes(ToolsServer):
    def handle(self, msg: dict[str, Any], headers: Any) -> Any:
        if msg.get("method") == "probe/reserved":
            return error(msg["id"], -32050)
        if msg.get("method") == "probe/legacy-not-found":
            return error(msg["id"], -32002)
        return super().handle(msg, headers)


async def test_error_codes_pass_with_standard_and_defined_codes(tmp_path: Path) -> None:
    async with scripted_scan(ToolsServer, tmp_path) as scan:
        await scan.ctx.exchange("tools/list", {"_meta": {PV: "1999-01-01"}})  # -32022
        assert (await scan.run(ErrorCodeRanges)).status is Status.PASS


async def test_error_codes_fail_for_a_reserved_code(tmp_path: Path) -> None:
    async with scripted_scan(OddCodes, tmp_path) as scan:
        await scan.ctx.exchange("probe/reserved")
        result = await scan.run(ErrorCodeRanges)
    assert result.status is Status.FAIL
    assert "reserved" in result.findings[0].message


async def test_error_32002_is_wrong_only_in_the_modern_era(tmp_path: Path) -> None:
    async with scripted_scan(OddCodes, tmp_path) as scan:
        await scan.ctx.exchange("probe/legacy-not-found")
        assert (await scan.run(ErrorCodeRanges)).status is Status.FAIL
    legacy = lambda: OddCodes(modern=False, legacy=True)  # noqa: E731
    async with scripted_scan(legacy, tmp_path / "b", era="legacy") as scan:
        await scan.ctx.exchange("probe/legacy-not-found")
        assert (await scan.run(ErrorCodeRanges)).status is Status.PASS


async def test_a_non_integer_error_code_fails(tmp_path: Path) -> None:
    async with scripted_scan(ToolsServer, tmp_path) as scan:
        scan.ctx.client.transport.push_raw(  # type: ignore[attr-defined]
            b'{"jsonrpc":"2.0","id":1,"error":{"code":1.5,"message":"x"}}'
        )
        result = await scan.run(ErrorCodeRanges)
    assert result.status is Status.FAIL
    assert "not an integer" in result.findings[0].message


# --- protocol.stdout_clean ---------------------------------------------------------------


async def test_stdout_clean_passes_and_fails_with_noise_in_the_stream(tmp_path: Path) -> None:
    async with scripted_scan(ToolsServer, tmp_path) as scan:
        assert (await scan.run(StdoutClean)).status is Status.PASS
        scan.ctx.client.transport.push_raw(b"Server listening on :3000")  # type: ignore[attr-defined]
        result = await scan.run(StdoutClean)
    assert result.status is Status.FAIL
    assert result.findings[0].evidence.observations["samples"] == ["Server listening on :3000"]


async def test_stdout_noise_from_a_real_process(tmp_path: Path) -> None:
    async with stdio_scan(mini_argv(), tmp_path) as scan:
        assert (await scan.run(StdoutClean)).status is Status.PASS
    async with stdio_scan(mini_argv("--noise"), tmp_path / "b") as scan:
        result = await scan.run(StdoutClean)
    assert result.status is Status.FAIL
    assert "hello from the server" in result.findings[0].evidence.observations["samples"]


async def test_stdout_clean_is_na_over_http(
    tmp_path: Path, http_fake: tuple[str, ServerState]
) -> None:
    async with http_scan(http_fake, tmp_path, server=ToolsServer()) as scan:
        assert (await scan.run(StdoutClean)).status is Status.NA


# --- protocol.header_mismatch_rejected / required_headers_enforced -----------------------


class Lenient(ToolsServer):
    """Trusts the body whatever the headers say."""

    def _header_mismatch(self, *args: Any) -> None:
        return None


async def test_header_mismatch_is_rejected_by_a_strict_server(
    tmp_path: Path, http_fake: tuple[str, ServerState]
) -> None:
    async with http_scan(http_fake, tmp_path, server=ToolsServer()) as scan:
        assert (await scan.run(HeaderMismatchRejected)).status is Status.PASS


async def test_header_mismatch_accepted_by_a_lenient_server_fails_both_cases(
    tmp_path: Path, http_fake: tuple[str, ServerState]
) -> None:
    async with http_scan(http_fake, tmp_path, server=Lenient()) as scan:
        result = await scan.run(HeaderMismatchRejected)
    assert result.status is Status.FAIL
    assert sorted(f.repro.case_id for f in result.findings) == [
        "header-mismatch:method",
        "header-mismatch:version",
    ]


async def test_header_checks_are_na_over_stdio(tmp_path: Path) -> None:
    async with scripted_scan(ToolsServer, tmp_path) as scan:
        for check in (HeaderMismatchRejected, RequiredHeadersEnforced, OriginValidated):
            result = await scan.run(check)
            assert result.status is Status.NA
            assert "http" in (result.reason or "").lower()


async def test_required_headers_are_enforced_by_a_strict_server(
    tmp_path: Path, http_fake: tuple[str, ServerState]
) -> None:
    async with http_scan(http_fake, tmp_path, server=ToolsServer()) as scan:
        assert (await scan.run(RequiredHeadersEnforced)).status is Status.PASS


async def test_missing_required_headers_accepted_by_a_lenient_server_fail(
    tmp_path: Path, http_fake: tuple[str, ServerState]
) -> None:
    async with http_scan(http_fake, tmp_path, server=Lenient()) as scan:
        result = await scan.run(RequiredHeadersEnforced)
    assert result.status is Status.FAIL
    assert sorted(f.repro.case_id for f in result.findings) == [
        "required-header:mcp-method",
        "required-header:mcp-protocol-version",
    ]
    assert all(f.severity is Severity.LOW for f in result.findings)


async def test_the_version_header_case_is_skipped_for_servers_that_support_older_clients(
    tmp_path: Path, http_fake: tuple[str, ServerState]
) -> None:
    server = Lenient(legacy=True, advertise_legacy=True, legacy_version="2025-03-26")
    async with http_scan(http_fake, tmp_path, server=server) as scan:
        result = await scan.run(RequiredHeadersEnforced)
    assert [f.repro.case_id for f in result.findings] == ["required-header:mcp-method"]


# --- protocol.origin_validated -----------------------------------------------------------


async def test_origin_is_validated_by_a_careful_server(
    tmp_path: Path, http_fake: tuple[str, ServerState]
) -> None:
    class Careful(ToolsServer):
        def handle(self, msg: dict[str, Any], headers: Any) -> Any:
            if headers and "origin" in headers:
                return Reply(status=403)
            return super().handle(msg, headers)

    async with http_scan(http_fake, tmp_path, server=Careful()) as scan:
        assert (await scan.run(OriginValidated)).status is Status.PASS


async def test_a_server_that_ignores_origin_fails_privately(
    tmp_path: Path, http_fake: tuple[str, ServerState]
) -> None:
    async with http_scan(http_fake, tmp_path, server=ToolsServer()) as scan:
        result = await scan.run(OriginValidated)
    assert result.status is Status.FAIL
    assert result.findings[0].disclosure.value == "private"
    assert result.findings[0].severity is Severity.HIGH
    origins = [s["headers"].get("origin") for s in http_fake[1].seen]
    assert "http://evil.probe.test" in origins


# --- protocol.malformed_jsonrpc_handled --------------------------------------------------


async def test_malformed_input_is_answered_by_a_well_behaved_process(tmp_path: Path) -> None:
    async with stdio_scan(mini_argv(), tmp_path) as scan:
        result = await scan.run(MalformedJsonrpcHandled)
    assert (result.status, result.reason) == (Status.PASS, None)


async def test_malformed_input_that_is_ignored_fails_every_case(tmp_path: Path) -> None:
    async with stdio_scan(mini_argv("--garbage", "ignore"), tmp_path) as scan:
        result = await scan.run(MalformedJsonrpcHandled)
    assert result.status is Status.FAIL
    assert sorted(f.repro.case_id for f in result.findings) == [
        "malformed:batch-array",
        "malformed:invalid-json",
        "malformed:missing-jsonrpc",
    ]


async def test_malformed_input_answered_with_a_wrong_code_fails(tmp_path: Path) -> None:
    async with stdio_scan(mini_argv("--garbage", "wrong-code"), tmp_path) as scan:
        result = await scan.run(MalformedJsonrpcHandled)
    assert result.status is Status.FAIL
    assert "-32000" in result.findings[0].message


async def test_a_server_that_dies_on_malformed_input_fails_when_it_reproduces(
    tmp_path: Path,
) -> None:
    async with stdio_scan(mini_argv("--garbage", "die"), tmp_path) as scan:
        result = await scan.run(MalformedJsonrpcHandled)
        assert scan.ctx.crashes.events  # the engine counted it too
    assert result.status is Status.FAIL
    assert result.findings[0].repro.case_id.endswith(":crash")


async def test_a_crash_that_does_not_reproduce_is_an_error_not_a_failure(tmp_path: Path) -> None:
    marker = tmp_path / "died-once"
    async with stdio_scan(
        mini_argv("--garbage", "die", "--die-once", str(marker)), tmp_path
    ) as scan:
        result = await scan.run(MalformedJsonrpcHandled)
    assert result.status is Status.ERROR
    assert "did not reproduce" in (result.reason or "")


async def test_malformed_input_over_http(
    tmp_path: Path, http_fake: tuple[str, ServerState]
) -> None:
    state = http_fake[1]
    state.garbage = "error"
    async with http_scan(http_fake, tmp_path, server=ToolsServer()) as scan:
        assert (await scan.run(MalformedJsonrpcHandled)).status is Status.PASS
    state.garbage = "ignore"
    async with http_scan(http_fake, tmp_path / "b", server=ToolsServer()) as scan:
        result = await scan.run(MalformedJsonrpcHandled)
    assert result.status is Status.FAIL
    assert len(result.findings) == 3


async def test_batches_are_not_tried_against_versions_that_allowed_them(tmp_path: Path) -> None:
    server = EraServer(modern=False, legacy=True, legacy_version="2025-03-26")
    async with scripted_scan(lambda: server, tmp_path, era="legacy") as scan:
        assert scan.ctx.negotiated_version == "2025-03-26"
    async with stdio_scan(mini_argv("--garbage", "ignore"), tmp_path / "b", era="legacy") as scan:
        result = await scan.run(MalformedJsonrpcHandled)
    # The mini server initializes as 2025-11-25, where batches are already gone.
    assert len(result.findings) == 3


# --- protocol.unknown_method_error -------------------------------------------------------


class Answers404(ToolsServer):
    def handle(self, msg: dict[str, Any], headers: Any) -> Any:
        if msg.get("method") == "probe/does_not_exist":
            return error(msg["id"], -32601, "Method not found", status=404)
        return super().handle(msg, headers)


async def test_unknown_method_passes_with_32601(
    tmp_path: Path, http_fake: tuple[str, ServerState]
) -> None:
    async with scripted_scan(Answers404, tmp_path) as scan:
        assert (await scan.run(UnknownMethodError)).status is Status.PASS
    async with http_scan(http_fake, tmp_path / "b", server=Answers404()) as scan:
        assert (await scan.run(UnknownMethodError)).status is Status.PASS


async def test_unknown_method_that_succeeds_fails(tmp_path: Path) -> None:
    async with scripted_scan(ToolsServer, tmp_path) as scan:  # answers any method with a result
        result = await scan.run(UnknownMethodError)
    assert result.status is Status.FAIL
    assert "returned a result" in result.findings[0].message


async def test_modern_http_needs_status_404(
    tmp_path: Path, http_fake: tuple[str, ServerState]
) -> None:
    class Status200(ToolsServer):
        def handle(self, msg: dict[str, Any], headers: Any) -> Any:
            if msg.get("method") == "probe/does_not_exist":
                return error(msg["id"], -32601, "Method not found", status=200)
            return super().handle(msg, headers)

    async with http_scan(http_fake, tmp_path, server=Status200()) as scan:
        result = await scan.run(UnknownMethodError)
    assert result.status is Status.FAIL
    assert "not 404" in result.findings[0].message


# --- protocol.era_parity -----------------------------------------------------------------

TOOL_A = {"name": "a", "inputSchema": {"type": "object"}}
TOOL_B = {"name": "b", "inputSchema": {"type": "object"}}
TOOL_A2 = {"name": "a", "inputSchema": {"type": "object", "properties": {"x": {}}}}


async def test_era_parity_passes_when_both_eras_agree(tmp_path: Path) -> None:
    async with scripted_scan(lambda: dual(tools=[TOOL_A, TOOL_B]), tmp_path) as scan:
        assert (await scan.run(EraParity)).status is Status.PASS


async def test_era_parity_reports_every_kind_of_difference(tmp_path: Path) -> None:
    server = dual(tools=[TOOL_A, TOOL_B], legacy_tools=[TOOL_A2])
    async with scripted_scan(lambda: server, tmp_path) as scan:
        result = await scan.run(EraParity)
    assert result.status is Status.FAIL
    observations = result.findings[0].evidence.observations
    assert observations["only_modern"] == ["b"]
    assert observations["schemas_differ"] == ["a"]


async def test_era_parity_is_na_for_modern_only_servers_and_skipped_outside_deep(
    tmp_path: Path,
) -> None:
    async with scripted_scan(ToolsServer, tmp_path) as scan:
        result = await scan.run(EraParity)
    assert (result.status, result.reason) == (
        Status.NA,
        "the server does not complete a legacy handshake",
    )
    async with scripted_scan(dual, tmp_path / "b", mode="standard") as scan:
        assert (await scan.run(EraParity)).status is Status.SKIPPED


# --- protocol.deprecated_features --------------------------------------------------------


async def test_deprecated_features_are_information_only(tmp_path: Path) -> None:
    class Logs(ToolsServer):
        def _modern(self, id_: Any, method: str, *rest: Any) -> Any:
            reply = super()._modern(id_, method, *rest)
            if method == "server/discover":
                reply.body["result"]["capabilities"]["logging"] = {}
            return reply

    async with scripted_scan(ToolsServer, tmp_path) as scan:
        clean = await scan.run(DeprecatedFeatures)
    assert (clean.status, clean.findings) == (Status.PASS, [])
    async with scripted_scan(Logs, tmp_path / "b") as scan:
        noted = await scan.run(DeprecatedFeatures)
    assert noted.status is Status.PASS  # info findings never fail a check
    assert [f.severity for f in noted.findings] == [Severity.INFO]
    assert "Logging" in noted.findings[0].title


async def test_http_plus_sse_endpoint_is_noted(
    tmp_path: Path, http_fake: tuple[str, ServerState]
) -> None:
    # The fake serves POST only, so a GET is answered 405 (as a modern server should): no note.
    async with http_scan(http_fake, tmp_path, server=ToolsServer()) as scan:
        clean = await scan.run(DeprecatedFeatures)
    assert (clean.status, clean.findings) == (Status.PASS, [])


async def test_a_dead_check_budget_does_not_crash_the_engine(tmp_path: Path) -> None:
    async with scripted_scan(ToolsServer, tmp_path) as scan:
        scan.ctx.budget.take(1000)
        result = await scan.run(UnknownMethodError)
    assert result.status is Status.ERROR
    assert "budget" in (result.reason or "")
    await asyncio.sleep(0)


# --- regressions from the M1 review ------------------------------------------------------


async def test_a_spent_budget_keeps_the_findings_already_made(tmp_path: Path) -> None:
    from probe.engine.budget import Budget

    async with stdio_scan(mini_argv("--garbage", "ignore"), tmp_path) as scan:
        scan.ctx.budget = Budget(1)  # enough for the first malformed case only
        result = await scan.run(MalformedJsonrpcHandled)
    assert result.status is Status.FAIL
    assert [f.repro.case_id for f in result.findings] == ["malformed:invalid-json"]


async def test_a_spent_budget_with_nothing_found_is_an_error_not_a_pass(tmp_path: Path) -> None:
    from probe.engine.budget import Budget

    async with stdio_scan(mini_argv(), tmp_path) as scan:
        scan.ctx.budget = Budget(1)
        result = await scan.run(MalformedJsonrpcHandled)
    assert result.status is Status.ERROR
    assert "budget" in (result.reason or "")


async def test_a_large_response_cannot_hide_a_missing_result_type(tmp_path: Path) -> None:
    class Strips(ToolsServer):
        def handle(self, msg: dict[str, Any], headers: Any) -> Any:
            reply = super().handle(msg, headers)
            if reply and reply.body and "result" in reply.body:
                reply.body["result"].pop("resultType", None)
            return reply

    # A body limit this small cuts every recorded message, as a huge tools/list would be.
    async with scripted_scan(Strips, tmp_path, body_max_bytes=40) as scan:
        await scan.ctx.exchange("tools/list")
        records = scan.ctx.trace_records()
        assert any(r.get("body_truncated") for r in records)  # the bodies really were cut
        result = await scan.run(ResultTypePresent)
    assert result.status is Status.FAIL
    assert result.findings[0].evidence.observations["methods"] == ["server/discover", "tools/list"]


async def test_a_large_response_cannot_hide_an_error_code(tmp_path: Path) -> None:
    async with scripted_scan(OddCodes, tmp_path, body_max_bytes=30) as scan:
        await scan.ctx.exchange("probe/reserved")
        result = await scan.run(ErrorCodeRanges)
    assert result.status is Status.FAIL and "reserved" in result.findings[0].message


async def test_error_code_check_sends_its_own_invalid_params_request(tmp_path: Path) -> None:
    async with scripted_scan(ToolsServer, tmp_path) as scan:
        result = await scan.run(ErrorCodeRanges)
        sent = [r["body"] for r in scan.ctx.trace_records() if r["dir"] == "c2s"]
    assert result.status is Status.PASS
    assert any(m.get("method") == "tools/call" and "name" not in m["params"] for m in sent)
