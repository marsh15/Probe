"""Protocol-level bug injection as pure functions over parsed JSON-RPC messages.

The stdio front proxy and the HTTP middleware both parse messages and call these, so a bug
behaves identically on both transports. Nothing here touches the SDK.

``request_info`` records what a client request was (its method, and whether it used the modern
per-request ``_meta`` or the legacy handshake). ``mutate_response`` rewrites the server's reply
for the bugs that are switched on. Responses are never mutated in place.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any

PROTOCOL_VERSION_META = "io.modelcontextprotocol/protocolVersion"
THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000
EXTRA_LEGACY_TOOL = {
    "name": "legacy_only_debug",
    "description": "A tool only legacy clients see.",
    "inputSchema": {"type": "object", "properties": {}},
}

# Bugs applied to server responses, in either transport.
RESPONSE_BUGS = frozenset(
    {"b01", "b02", "b03", "b04", "b10", "b11", "b12", "b13", "b15", "b16", "b50", "b52", "b53"}
    | {"b55", "b56"}
)


@dataclass(frozen=True)
class RequestInfo:
    method: str | None
    modern: bool  # the request carried per-request _meta with a protocol version


@dataclass
class MutationState:
    tools_list_calls: int = 0
    pending: dict[Any, RequestInfo] = field(default_factory=dict)  # stdio: id -> request


def request_info(message: Any) -> RequestInfo | None:
    """Describe a client *request* (it has an id and a method); None for anything else."""
    if (
        not isinstance(message, dict)
        or "id" not in message
        or not isinstance(message.get("method"), str)
    ):
        return None
    params = message.get("params")
    meta = params.get("_meta") if isinstance(params, dict) else None
    modern = isinstance(meta, dict) and PROTOCOL_VERSION_META in meta
    return RequestInfo(message["method"], modern)


def _error(code: int, message: str) -> dict[str, Any]:
    return {"code": code, "message": message}


def mutate_response(
    active: frozenset[str], info: RequestInfo | None, message: Any, state: MutationState
) -> Any:
    """The reply to deliver for ``message`` given the active bugs (a copy if changed)."""
    if not active & RESPONSE_BUGS or not isinstance(message, dict):
        return message
    if "error" in message and isinstance(message["error"], dict):
        return _mutate_error(active, info, message)
    if "result" in message and isinstance(message["result"], dict):
        return _mutate_result(active, info, message, state)
    return message


def _mutate_error(active: frozenset[str], info: RequestInfo | None, message: dict[str, Any]) -> Any:
    code = message["error"].get("code")
    out = copy.deepcopy(message)
    if code == -32601 and "b52" in active:  # unknown method: answer with an empty result
        empty = {"resultType": "complete"} if info is not None and info.modern else {}
        return {"jsonrpc": "2.0", "id": message.get("id"), "result": empty}
    if code == -32022 and "b02" in active:
        out["error"] = _error(-32602, "Invalid params")
    elif code == -32602 and "b04" in active:
        out["error"] = _error(-32050, "Invalid params")
    return out


def _mutate_result(
    active: frozenset[str], info: RequestInfo | None, message: dict[str, Any], state: MutationState
) -> Any:
    method = info.method if info else None
    if method == "server/discover" and "b01" in active:
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "error": _error(-32601, "Method not found"),
        }
    out = copy.deepcopy(message)
    result: dict[str, Any] = out["result"]
    if "b03" in active:
        result.pop("resultType", None)
    if method == "tools/list":
        _mutate_tools_list(active, info, result, state)
    return out


def _mutate_tools_list(
    active: frozenset[str], info: RequestInfo | None, result: dict[str, Any], state: MutationState
) -> None:
    tools = result.get("tools")
    state.tools_list_calls += 1
    if "b13" in active:
        result.pop("ttlMs", None)
    if "b55" in active:
        result["ttlMs"] = THIRTY_DAYS_MS
    if not isinstance(tools, list) or not tools:
        return
    if "b50" in active and info is not None and not info.modern:
        tools.append(copy.deepcopy(EXTRA_LEGACY_TOOL))
    if "b53" in active:
        tools[0].pop("inputSchema", None)
    if "b10" in active:
        tools[0].setdefault("inputSchema", {})["type"] = "obj"
    if "b11" in active:
        schema = tools[0].setdefault("inputSchema", {})
        schema.setdefault("properties", {})["ref"] = {"$ref": "#/$defs/missing"}
    if "b15" in active:
        tools[0]["name"] = "bad name"
        if len(tools) > 1:
            tools.append(copy.deepcopy(tools[1]))  # a duplicate name
    if "b16" in active:
        tools[0].pop("description", None)
        for tool in tools[1:]:
            schema = tool.get("inputSchema") or {}
            required = schema.get("required") or []
            if required:
                for name in required:
                    schema.get("properties", {}).get(name, {}).pop("description", None)
                break
    if "b56" in active:
        for tool in tools:
            props = (tool.get("inputSchema") or {}).get("properties") or {}
            target = next((p for p in props.values() if p.get("type") == "string"), None)
            if target is not None:
                target["x-mcp-header"] = "Bad Header"
                break
    if "b12" in active:  # a different order on every call (rotation by call count)
        shift = state.tools_list_calls % len(tools) or 1
        result["tools"] = tools[shift:] + tools[:shift]
