"""Protocol-level bug injection as pure functions over parsed JSON-RPC messages.

The stdio front proxy and the HTTP middleware both parse messages and call these, so a bug
behaves identically on both transports. Nothing here touches the SDK.

``request_info`` records what a client request was (its method, and whether it used the modern
per-request ``_meta`` or the legacy handshake). ``mutate_response`` rewrites the server's reply
for the bugs that are switched on. Responses are never mutated in place.
"""

from __future__ import annotations

import copy
import json
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
    | {"b09", "b21", "b23", "b29", "b54", "b55", "b56"}
)


@dataclass(frozen=True)
class RequestInfo:
    method: str | None
    modern: bool  # the request carried per-request _meta with a protocol version
    tool: str | None = None  # the tool name, for tools/call


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
    tool = (
        params.get("name")
        if isinstance(params, dict) and message["method"] == "tools/call"
        else None
    )
    return RequestInfo(message["method"], modern, tool if isinstance(tool, str) else None)


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
    if "b21" in active:
        out["error"]["message"] = "Error"  # the bug: no error says what went wrong
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
    if "b29" in active and result.get("resultType") == "input_required":
        requests = result.get("inputRequests")
        if isinstance(requests, dict) and requests:
            first = next(iter(requests.values()))
            if isinstance(first, dict):
                first.pop("method", None)  # the bug: an input request with no method
    if "b03" in active:
        result.pop("resultType", None)
    if method == "tools/list":
        _mutate_tools_list(active, info, result, state)
    if method == "tools/call":
        replaced = _mutate_tool_result(active, info, message, result)
        if replaced is not None:
            return replaced
    return out


def _mutate_tool_result(
    active: frozenset[str],
    info: RequestInfo | None,
    message: dict[str, Any],
    result: dict[str, Any],
) -> dict[str, Any] | None:
    """Tool-result bugs; returns a replacement message when the result becomes an error."""
    tool = info.tool if info else None
    structured = result.get("structuredContent")
    if "b09" in active and tool == "notes_get" and isinstance(structured, dict):
        # the bug: the id comes back as a string although the output schema says integer
        structured["id"] = str(structured.get("id"))
        _rewrite_mirror(result, structured)
    if "b54" in active and "structuredContent" in result:
        result["content"] = []  # the bug: no JSON text block next to structuredContent
    if "b21" in active and result.get("isError") is True:
        result["content"] = [{"type": "text", "text": "Error"}]
    if "b23" in active and tool == "search_notes" and _is_empty_search(result):
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "error": _error(-32603, "Internal error"),  # the bug: no match is an internal error
        }
    return None


def _rewrite_mirror(result: dict[str, Any], structured: dict[str, Any]) -> None:
    content = result.get("content")
    if isinstance(content, list) and content and isinstance(content[0], dict):
        content[0]["text"] = json.dumps(structured)


def _is_empty_search(result: dict[str, Any]) -> bool:
    content = result.get("content")
    if not isinstance(content, list) or not content or not isinstance(content[0], dict):
        return False
    try:
        found = json.loads(content[0].get("text", ""))
    except ValueError:
        return False
    return isinstance(found, dict) and found.get("items") == []


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
