"""A tiny stdio MCP server whose behavior on bad input can be switched.

Flags: --garbage error|ignore|die|wrong-code   what to do with malformed input
       --die-once FILE                          die on garbage only if FILE is absent (creates it)
       --noise                                  print a banner to stdout first
       --ansi-noise                             print a line with terminal escape codes first
       --legacy-only                            answer server/discover with -32601
"""

import argparse
import json
import os
import sys

parser = argparse.ArgumentParser()
parser.add_argument("--garbage", default="error")
parser.add_argument("--die-once", default=None)
parser.add_argument("--noise", action="store_true")
parser.add_argument("--ansi-noise", action="store_true")
parser.add_argument("--legacy-only", action="store_true")
args = parser.parse_args()

PV = "io.modelcontextprotocol/protocolVersion"


def send(obj: object) -> None:
    print(json.dumps(obj), flush=True)


def error(id_: object, code: int, message: str) -> None:
    send({"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}})


def garbage(code: int) -> None:
    if args.garbage == "ignore":
        return
    if args.garbage == "die":
        if args.die_once is not None:
            if os.path.exists(args.die_once):
                error(None, code, "bad input")
                return
            open(args.die_once, "w").close()
        sys.exit(3)
    error(None, -32000 if args.garbage == "wrong-code" else code, "bad input")


if args.noise:
    print("hello from the server", flush=True)
if args.ansi_noise:
    print("\x1b[2J\x1b[31mFAKE OUTPUT\x1b[0m\x07", flush=True)

for line in sys.stdin:
    try:
        msg = json.loads(line)
    except ValueError:
        garbage(-32700)
        continue
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
        garbage(-32600)
        continue
    if "id" not in msg:
        continue
    id_, method = msg["id"], msg.get("method")
    meta = (msg.get("params") or {}).get("_meta") or {}
    if method == "initialize":
        send(
            {
                "jsonrpc": "2.0",
                "id": id_,
                "result": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "mini", "version": "1"},
                },
            }
        )
    elif method == "server/discover" and not args.legacy_only:
        send(
            {
                "jsonrpc": "2.0",
                "id": id_,
                "result": {
                    "supportedVersions": ["2026-07-28", "2025-11-25"],
                    "capabilities": {"tools": {}},
                    "resultType": "complete",
                    "ttlMs": 0,
                    "cacheScope": "public",
                },
            }
        )
    elif PV in meta and args.legacy_only:
        error(id_, -32601, "unknown method")
    elif PV in meta and meta[PV] != "2026-07-28":
        send(
            {
                "jsonrpc": "2.0",
                "id": id_,
                "error": {
                    "code": -32022,
                    "message": "unsupported",
                    "data": {"supported": ["2026-07-28"], "requested": meta[PV]},
                },
            }
        )
    elif method == "tools/list":
        name = os.environ.get("PROBE_TOOL_NAME")  # lets a test make the server say anything
        result = {"tools": [{"name": name, "inputSchema": {"type": "string"}}] if name else []}
        if PV in meta:
            result["resultType"] = "complete"
        send({"jsonrpc": "2.0", "id": id_, "result": result})
    elif method == "probe/does_not_exist":
        error(id_, -32601, "method not found")
    else:
        send({"jsonrpc": "2.0", "id": id_, "result": {"resultType": "complete"}})
