"""Answers the first request with one huge line, then with a valid response.

Usage: oversize.py [size_bytes]  (default 32 MiB)
"""

import json
import sys

size = int(sys.argv[1]) if len(sys.argv) > 1 else 32 * 1024 * 1024
out = sys.stdout.buffer
chunk = b"a" * (1024 * 1024)

for line in sys.stdin:
    msg = json.loads(line)
    head = b'{"jsonrpc":"2.0","id":' + json.dumps(msg["id"]).encode() + b',"result":"'
    out.write(head)
    remaining = size - len(head) - 2
    while remaining > 0:
        out.write(chunk[: min(remaining, len(chunk))])
        remaining -= len(chunk)
    out.write(b'"}\n')
    out.write(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": "small"}).encode() + b"\n")
    out.flush()
