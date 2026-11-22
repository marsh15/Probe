"""On each client request, first asks the client for roots/list, then reports what it got."""

import json
import sys


def write(obj: object) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    msg = json.loads(line)
    server_id = f"srv-{msg['id']}"
    write({"jsonrpc": "2.0", "id": server_id, "method": "roots/list", "params": {}})
    reply = json.loads(sys.stdin.readline())
    write({"jsonrpc": "2.0", "id": msg["id"], "result": {"reply": reply}})
