"""Answers every request with its method and params; a few methods script extra behavior."""

import json
import sys


def write(obj: object) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg or "method" not in msg:
        continue
    method, params = msg["method"], msg.get("params", {})
    if method == "notify":
        write({"jsonrpc": "2.0", "method": "notifications/message", "params": params})
    elif method == "stderr":
        sys.stderr.write(params["text"] * params.get("repeat", 1))
        sys.stderr.flush()
    elif method == "unknown_id":
        write({"jsonrpc": "2.0", "id": "no-such-id", "result": {}})
    elif method == "deep":
        depth = params["depth"]
        sys.stdout.write("[" * depth + "]" * depth + "\n")
    elif method == "bad_shape":
        write({"jsonrpc": "2.0", "id": msg["id"], "result": {}, "error": {"code": 1}})
    write({"jsonrpc": "2.0", "id": msg["id"], "result": {"method": method, "params": params}})
