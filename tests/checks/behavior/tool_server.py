"""A stdio MCP server (modern era) with one read tool whose handling of input can be broken.

Set TOOL_BEHAVIOR to one of:
  clean           validates against the schema and says what is wrong
  accept_invalid  never validates
  reject_valid    answers -32602 to everything
  crash_at_max    exits when ``name`` has a non-ASCII character (every time)
  crash_once      the same, but only the first time (FILE in TOOL_ONCE_FILE marks it)
  generic_errors  validates but every error text is just "Error"
  hang_at_max     stops answering when ``name`` has a non-ASCII character

With TOOL_EXTRA=1 two more tools exist: ``list_items`` (read, paged, structured output) and
``add_item`` (writes by appending to TOOL_COUNT_FILE). EXTRA_BEHAVIOR picks how they go wrong:
  loop_cursor   the next cursor never changes
  dup_pages     every page starts with the previous page's last item
  accept_bogus  an unknown cursor is accepted
  big_output    the largest page is 2 MiB of text
  empty_error   a search with no match is a JSON-RPC error
  bad_output    structuredContent does not satisfy outputSchema
  no_mirror     structuredContent has no JSON text block
  racy          the answer says how many calls were in flight (calls run on threads)
  not_idempotent add_item appends every time even with the same name; the default appends once
                per name
"""

import json
import os
import sys
import threading
import time
from typing import Any

from jsonschema import Draft202012Validator

BEHAVIOR = os.environ.get("TOOL_BEHAVIOR", "clean")
PV = "io.modelcontextprotocol/protocolVersion"
SCHEMA = {
    "type": "object",
    "properties": {
        "name": {"type": "string", "minLength": 1, "maxLength": 20},
        "times": {"type": "integer", "minimum": 1, "maximum": 5},
    },
    "required": ["name"],
    "additionalProperties": False,
}
TOOL = {
    "name": "get_greeting",
    "description": "Greet someone.",
    "inputSchema": SCHEMA,
    "annotations": {"readOnlyHint": True},
}
VALIDATOR = Draft202012Validator(SCHEMA)

EXTRA = os.environ.get("TOOL_EXTRA") == "1"
EXTRA_BEHAVIOR = os.environ.get("EXTRA_BEHAVIOR", "clean")
COUNT_FILE = os.environ.get("TOOL_COUNT_FILE", "")
ITEMS = [{"id": i, "title": f"item {i}"} for i in range(1, 8)]
PAGE = 3
LIST_SCHEMA = {
    "type": "object",
    "properties": {
        "cursor": {"type": "string"},
        "limit": {"type": "integer", "minimum": 1, "maximum": 50},
        "query": {"type": "string"},
    },
    "additionalProperties": False,
}
LIST_OUTPUT = {
    "type": "object",
    "properties": {"items": {"type": "array"}, "nextCursor": {"type": ["string", "null"]}},
    "required": ["items"],
}
ADD_SCHEMA = {
    "type": "object",
    "properties": {"name": {"type": "string", "minLength": 1, "maxLength": 20}},
    "required": ["name"],
    "additionalProperties": False,
}
EXTRA_TOOLS = [
    {
        "name": "list_items",
        "description": "List items.",
        "inputSchema": LIST_SCHEMA,
        "outputSchema": LIST_OUTPUT,
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "add_item",
        "description": "Add an item.",
        "inputSchema": ADD_SCHEMA,
        "annotations": ({"idempotentHint": True} if os.environ.get("ADD_HINT") == "1" else {}),
    },
]
INFLIGHT = 0
LOCK = threading.Lock()
SEEN_NAMES: set[str] = set()


def send(obj: object) -> None:
    print(json.dumps(obj), flush=True)


def result(id_: Any, value: dict[str, Any]) -> None:
    send({"jsonrpc": "2.0", "id": id_, "result": {**value, "resultType": "complete"}})


def error(id_: Any, code: int, message: str) -> None:
    send({"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}})


def list_items(id_: Any, arguments: dict[str, Any]) -> None:
    cursor, query = arguments.get("cursor"), arguments.get("query")
    if cursor not in (None, "c3", "c6") and EXTRA_BEHAVIOR != "accept_bogus":
        return error(id_, -32602, "Invalid cursor")
    start = {"c3": 3, "c6": 6}.get(cursor, 0)
    if query:
        items: list[Any] = []
        if EXTRA_BEHAVIOR == "empty_error":
            return error(id_, -32602, "nothing found")
        nxt = None
    else:
        if EXTRA_BEHAVIOR == "dup_pages" and start:
            start -= 1
        items = ITEMS[start : start + PAGE]
        end = {0: "c3", 3: "c6", 2: "c6", 6: None, 5: None}.get(start)
        nxt = "c3" if EXTRA_BEHAVIOR == "loop_cursor" else end
    structured: dict[str, Any] = {"items": items, "nextCursor": nxt}
    if EXTRA_BEHAVIOR == "bad_output":
        structured = {"items": "not a list"}
    text = json.dumps(structured)
    if EXTRA_BEHAVIOR == "big_output" and arguments.get("limit") == 50:
        text = "x" * (2 * 1024 * 1024)
    content = [] if EXTRA_BEHAVIOR == "no_mirror" else [{"type": "text", "text": text}]
    result(id_, {"content": content, "structuredContent": structured})


def add_item(id_: Any, arguments: dict[str, Any]) -> None:
    name = arguments["name"]
    if EXTRA_BEHAVIOR == "not_idempotent" or name not in SEEN_NAMES:
        with open(COUNT_FILE, "a") as handle:
            handle.write("x")
    SEEN_NAMES.add(name)
    result(id_, {"content": [{"type": "text", "text": f"added {name}"}]})


def racy_greeting(id_: Any, name: str) -> None:
    global INFLIGHT
    with LOCK:
        INFLIGHT += 1
        seen = INFLIGHT
    time.sleep(0.15)
    with LOCK:
        INFLIGHT -= 1
    result(id_, {"content": [{"type": "text", "text": f"hello {name} ({seen} in flight)"}]})


def extra(id_: Any, params: dict[str, Any]) -> bool:
    name, arguments = params.get("name"), params.get("arguments") or {}
    if name == "list_items":
        list_items(id_, arguments)
    elif name == "add_item":
        add_item(id_, arguments)
    else:
        return False
    return True


def call(id_: Any, arguments: Any) -> None:
    if BEHAVIOR == "reject_valid":
        return error(id_, -32602, "invalid params")
    problems = [e.message for e in VALIDATOR.iter_errors(arguments)]
    if problems and BEHAVIOR != "accept_invalid":
        if BEHAVIOR == "generic_errors":
            return result(id_, {"isError": True, "content": [{"type": "text", "text": "Error"}]})
        return error(id_, -32602, f"Invalid arguments: {problems[0]}")
    name = arguments.get("name") if isinstance(arguments, dict) else None
    if isinstance(name, str) and not name.isascii():
        if BEHAVIOR == "crash_at_max":
            sys.exit(7)
        if BEHAVIOR == "crash_once" and not os.path.exists(os.environ["TOOL_ONCE_FILE"]):
            open(os.environ["TOOL_ONCE_FILE"], "w").close()
            sys.exit(7)
        if BEHAVIOR == "hang_at_max":
            time.sleep(3600)
    if EXTRA_BEHAVIOR == "racy" and isinstance(name, str):
        return racy_greeting(id_, name)
    text = f"hello {name}"
    result(id_, {"content": [{"type": "text", "text": text}]})


for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue
    id_, method, params = msg["id"], msg.get("method"), msg.get("params") or {}
    meta = params.get("_meta") or {}
    if method == "server/discover":
        result(
            id_,
            {
                "supportedVersions": ["2026-07-28"],
                "capabilities": {"tools": {}},
                "ttlMs": 0,
                "cacheScope": "public",
            },
        )
    elif PV not in meta:
        error(id_, -32601, "modern requests only")
    elif method == "tools/list":
        tools = [TOOL, *EXTRA_TOOLS] if EXTRA else [TOOL]
        result(id_, {"tools": tools, "ttlMs": 0, "cacheScope": "public"})
    elif method == "tools/call" and EXTRA and extra(id_, params):
        pass
    elif method == "tools/call" and EXTRA_BEHAVIOR == "racy":
        threading.Thread(target=call, args=(id_, params.get("arguments")), daemon=True).start()
    elif method == "tools/call":
        call(id_, params.get("arguments"))
    else:
        error(id_, -32601, "method not found")
