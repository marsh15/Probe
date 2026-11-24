"""The injected bugs as pure message rewrites, then end to end on both transports."""

from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from refserver import bugs, mutations
from refserver.config import Config
from refserver.mutations import MutationState, RequestInfo, mutate_response, request_info
from refserver.server import build_server, http_app

from tests.test_http import http_request, serving
from tests.test_stdio import META, MODERN

pytestmark = pytest.mark.anyio

MODERN_REQUEST = RequestInfo("tools/list", modern=True)
LEGACY_REQUEST = RequestInfo("tools/list", modern=False)


def tool(name: str, **props: Any) -> dict[str, Any]:
    return {
        "name": name,
        "description": f"{name} tool",
        "inputSchema": {
            "type": "object",
            "properties": {p: {"type": "string", "description": "d"} for p in (props or {"a": 1})},
            "required": list(props or {"a": 1}),
        },
    }


def listing(*names: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "resultType": "complete",
            "ttlMs": 60_000,
            "cacheScope": "public",
            "tools": [tool(n) for n in (names or ("a", "b", "c"))],
        },
    }


def apply(bug: str, message: dict[str, Any], info: RequestInfo | None = MODERN_REQUEST) -> Any:
    return mutate_response(frozenset({bug}), info, message, MutationState())


def test_every_implemented_bug_is_either_a_response_rewrite_or_has_its_own_hook() -> None:
    # request side, stdout, crashes, middleware, or the tool's own code
    own_hook = {
        "b05", "b06", "b07", "b08", "b14", "b17", "b18", "b19", "b20", "b22", "b24",
        "b25", "b26", "b27", "b28", "b30", "b31", "b32", "b33", "b34", "b35", "b36", "b38",
        "b39", "b40", "b41", "b42", "b43", "b44", "b45", "b46", "b47", "b48", "b49", "b51",
        "b57", "b58",
    }  # fmt: skip
    assert mutations.RESPONSE_BUGS | own_hook == bugs.IMPLEMENTED


def test_nothing_changes_without_active_bugs() -> None:
    message = listing()
    assert mutate_response(frozenset(), MODERN_REQUEST, message, MutationState()) is message


@pytest.mark.parametrize("bug", sorted(mutations.RESPONSE_BUGS))
def test_inputs_are_never_mutated_in_place(bug: str) -> None:
    for message, info in [
        (listing(), MODERN_REQUEST),
        ({"jsonrpc": "2.0", "id": 1, "error": {"code": -32602, "message": "x"}}, MODERN_REQUEST),
        ({"jsonrpc": "2.0", "id": 1, "result": {"resultType": "complete"}},
         RequestInfo("server/discover", modern=True)),
    ]:  # fmt: skip
        before = copy.deepcopy(message)
        apply(bug, message, info)
        assert message == before


def test_request_info_reads_method_and_era() -> None:
    assert request_info({"id": 1, "method": "tools/list", "params": {"_meta": META}}) == (
        RequestInfo("tools/list", modern=True)
    )
    legacy = request_info({"id": 1, "method": "tools/list"})
    assert legacy == RequestInfo("tools/list", modern=False)
    assert request_info({"method": "notifications/initialized"}) is None  # no id: not a request
    assert request_info([1]) is None and request_info("x") is None


def test_b01_discover_becomes_method_not_found() -> None:
    reply = {"jsonrpc": "2.0", "id": 4, "result": {"supportedVersions": [MODERN]}}
    out = apply("b01", reply, RequestInfo("server/discover", modern=True))
    error = {"code": -32601, "message": "Method not found"}
    assert out == {"jsonrpc": "2.0", "id": 4, "error": error}
    assert apply("b01", listing())["result"]["tools"]  # other methods untouched


def test_b02_and_b04_rewrite_specific_error_codes() -> None:
    def error(code: int) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": 1, "error": {"code": code, "message": "m", "data": {}}}

    assert apply("b02", error(-32022))["error"]["code"] == -32602
    assert apply("b02", error(-32602))["error"]["code"] == -32602
    assert apply("b04", error(-32602))["error"]["code"] == -32050
    assert apply("b04", error(-32022))["error"]["code"] == -32022


def test_b03_strips_result_type_from_every_result() -> None:
    assert "resultType" not in apply("b03", listing())["result"]
    bare = {"jsonrpc": "2.0", "id": 2, "result": {"resultType": "complete"}}
    assert "resultType" not in apply("b03", bare)["result"]


def test_b52_answers_unknown_methods_with_a_valid_empty_result() -> None:
    error = {"jsonrpc": "2.0", "id": 3, "error": {"code": -32601, "message": "Method not found"}}
    modern = apply("b52", error, RequestInfo("x/y", modern=True))
    assert modern["result"] == {"resultType": "complete"}
    assert apply("b52", error, RequestInfo("x/y", modern=False))["result"] == {}


def test_tool_definition_bugs() -> None:
    first = lambda bug: apply(bug, listing())["result"]["tools"][0]  # noqa: E731
    assert "inputSchema" not in first("b53")
    assert first("b10")["inputSchema"]["type"] == "obj"
    assert first("b11")["inputSchema"]["properties"]["ref"] == {"$ref": "#/$defs/missing"}
    assert "description" not in first("b16")
    names = [t["name"] for t in apply("b15", listing())["result"]["tools"]]
    assert names[0] == "bad name" and len(names) != len(set(names))
    tools = apply("b16", listing())["result"]["tools"]
    assert "description" not in tools[1]["inputSchema"]["properties"]["a"]  # a required parameter
    tagged = apply("b56", listing())["result"]["tools"][0]["inputSchema"]["properties"]["a"]
    assert tagged["x-mcp-header"] == "Bad Header"


def test_cache_bugs() -> None:
    assert "ttlMs" not in apply("b13", listing())["result"]
    assert apply("b55", listing())["result"]["ttlMs"] == 30 * 24 * 3600 * 1000


def test_b12_reorders_differently_on_consecutive_calls() -> None:
    # n tools have n-1 distinct non-identity rotations, so n-1 calls can never repeat an order.
    state = MutationState()
    active = frozenset({"b12"})

    def names(response: dict[str, Any]) -> tuple[str, ...]:
        return tuple(t["name"] for t in response["result"]["tools"])

    orders = [
        names(mutate_response(active, MODERN_REQUEST, listing(*"abcd"), state)) for _ in range(3)
    ]
    assert len(set(orders)) == 3
    assert all(sorted(o) == list("abcd") for o in orders)
    assert names(listing(*"abcd")) not in orders  # and none is the original order


def test_b50_adds_a_tool_only_for_legacy_requests() -> None:
    legacy = apply("b50", listing(), LEGACY_REQUEST)["result"]["tools"]
    modern = apply("b50", listing(), MODERN_REQUEST)["result"]["tools"]
    assert legacy[-1]["name"] == "legacy_only_debug"
    assert len(modern) == 3


# --- end to end ------------------------------------------------------------------------


def run_stdio(data_root: Path, bug: str, *lines: bytes) -> list[bytes]:
    env = {**os.environ, "REFSERVER_DATA": str(data_root), "PROBE_REF_BUGS": bug}
    proc = subprocess.run(
        [sys.executable, "-m", "refserver", "stdio"],
        input=b"".join(line + b"\n" for line in lines),
        capture_output=True,
        env=env,
        timeout=30,
        check=False,
    )
    run_stdio.returncode = proc.returncode  # type: ignore[attr-defined]
    return proc.stdout.splitlines()


def request(rid: int, method: str, **params: Any) -> bytes:
    body = {"jsonrpc": "2.0", "id": rid, "method": method, "params": {"_meta": META, **params}}
    return json.dumps(body).encode()


def test_b01_the_server_really_has_no_discover_and_still_does_legacy(data_root: Path) -> None:
    client = {"name": "t", "version": "0"}
    init = {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": client}
    lines = run_stdio(
        data_root,
        "b01",
        request(1, "server/discover"),
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": init}).encode(),
    )
    replies = [json.loads(line) for line in lines]
    assert replies[0]["error"]["code"] == -32601
    assert replies[1]["result"]["protocolVersion"] == "2025-11-25"  # not pinned to modern


def test_b07_prints_a_debug_line_before_each_response(data_root: Path) -> None:
    lines = run_stdio(data_root, "b07", request(1, "tools/list"))
    assert lines[0] == b"DEBUG: handling request"
    assert json.loads(lines[1])["id"] == 1


def test_b08_dies_on_unparseable_input_but_not_on_other_garbage(data_root: Path) -> None:
    run_stdio(data_root, "b08", b'{"jsonrpc": "2.0", "id": 1, "method": ')
    assert run_stdio.returncode == 3  # type: ignore[attr-defined]
    lines = run_stdio(data_root, "b08", b'{"id": 1}', request(2, "tools/list"))
    assert run_stdio.returncode == 0  # type: ignore[attr-defined]
    # An invalid request (as opposed to invalid JSON) does not crash it.
    assert json.loads(lines[-1])["id"] == 2


def modern_headers(method: str, **extra: str) -> dict[str, str]:
    return {
        "content-type": "application/json",
        "accept": "application/json, text/event-stream",
        "mcp-protocol-version": MODERN,
        "mcp-method": method,
        **extra,
    }


def post(url: str, method: str, headers: dict[str, str]) -> Any:
    body = json.loads(request(1, method))
    return http_request("POST", url + "/mcp", headers=headers, json=body)


@pytest.fixture
def bugged(cfg: Config, monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    def start(bug: str):  # type: ignore[no-untyped-def]
        monkeypatch.setenv(bugs.ENV_VAR, bug)
        bugs.load()
        return serving(http_app(build_server(cfg)))

    return start


async def test_clean_http_rejects_what_the_bugs_accept(cfg: Config) -> None:
    with serving(http_app(build_server(cfg))) as url:
        bad_origin = await post(
            url, "tools/list", modern_headers("tools/list", origin="http://evil.test")
        )
        mismatch = await post(url, "tools/list", modern_headers("tools/call"))
        no_version = modern_headers("tools/list")
        del no_version["mcp-protocol-version"]
        missing = await post(url, "tools/list", no_version)
    assert bad_origin.status_code == 403
    assert mismatch.status_code == 400 and mismatch.json()["error"]["code"] == -32020
    assert missing.status_code == 400


async def test_b06_ignores_a_hostile_origin(bugged: Any) -> None:
    with bugged("b06") as url:
        reply = await post(
            url, "tools/list", modern_headers("tools/list", origin="http://evil.test")
        )
    assert reply.status_code == 200 and reply.json()["result"]["tools"]


async def test_b05_trusts_the_body_over_wrong_headers_but_not_missing_ones(bugged: Any) -> None:
    with bugged("b05") as url:
        mismatch = await post(url, "tools/list", modern_headers("tools/call"))
        old = {**modern_headers("tools/list"), "mcp-protocol-version": "1999-01-01"}
        wrong_version = await post(url, "tools/list", old)
        no_method = modern_headers("tools/list")
        del no_method["mcp-method"]
        missing = await post(url, "tools/list", no_method)
    assert mismatch.status_code == 200 and wrong_version.status_code == 200
    assert missing.status_code == 400  # b05 repairs wrong headers; it does not invent missing ones


async def test_b51_accepts_a_missing_version_header_only(bugged: Any) -> None:
    with bugged("b51") as url:
        headers = modern_headers("tools/list")
        del headers["mcp-protocol-version"]
        accepted = await post(url, "tools/list", headers)
        mismatch = await post(url, "tools/list", modern_headers("tools/call"))
    assert accepted.status_code == 200
    assert mismatch.status_code == 400  # header mismatch is still rejected


async def test_response_bugs_apply_over_http_too(bugged: Any) -> None:
    with bugged("b03") as url:
        reply = await post(url, "tools/list", modern_headers("tools/list"))
    result = reply.json()["result"]
    assert "resultType" not in result and result["tools"]
    assert int(reply.headers["content-length"]) == len(reply.content)  # length was recomputed
