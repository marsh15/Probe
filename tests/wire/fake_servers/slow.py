"""Answers each request after ``params.delay`` seconds, concurrently (so out of order).

Flags: --linger keeps running after stdin closes; --ignore-term ignores SIGTERM.
"""

import json
import signal
import sys
import threading
import time

lock = threading.Lock()


def answer(msg: dict) -> None:
    time.sleep(msg.get("params", {}).get("delay", 0))
    with lock:
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": msg["id"]}))
        sys.stdout.write("\n")
        sys.stdout.flush()


if "--ignore-term" in sys.argv:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
print(json.dumps({"jsonrpc": "2.0", "method": "ready"}), flush=True)
for line in sys.stdin:
    threading.Thread(target=answer, args=(json.loads(line),)).start()
if "--linger" in sys.argv:
    while True:
        time.sleep(1)
