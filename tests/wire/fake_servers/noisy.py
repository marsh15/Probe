"""Prints non-JSON lines and partial garbage around every valid response."""

import json
import sys

print("noisy server starting up", flush=True)
for line in sys.stdin:
    msg = json.loads(line)
    sys.stdout.write('{"jsonrpc": "2.0", "id": \n')
    sys.stdout.write("debug: handling request\n")
    sys.stdout.write("\n")
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {"ok": True}}) + "\n")
    sys.stdout.flush()
