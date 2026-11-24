"""`refserver stdio | http --port 3000 | seed --out DIR`."""

from __future__ import annotations

import argparse
import atexit
import logging
import os
import shutil
import signal
import sys
import tempfile
import time
from pathlib import Path

import anyio

from refserver import bugs
from refserver.config import DEFAULT_DATA, Config
from refserver.seed.make_seed import make_seed

log = logging.getLogger("refserver")


def prepare_data() -> Path:
    """Locate the seeded data root, or seed a throwaway one for local runs without /data."""
    if env_root := os.environ.get("REFSERVER_DATA"):
        root = Path(env_root)
        if not (root / "db" / "notes.db").is_file():
            raise SystemExit(f"refserver: {root} is not seeded; run `refserver seed --out {root}`")
        return root
    if (DEFAULT_DATA / "db" / "notes.db").is_file():
        return DEFAULT_DATA
    root = Path(tempfile.mkdtemp(prefix="refserver-"))
    atexit.register(shutil.rmtree, root, ignore_errors=True)
    make_seed(root / "data", seed=int(os.environ.get("REFSERVER_SEED", "1")))
    print(f"refserver: no /data found; seeded a temporary copy at {root / 'data'}", file=sys.stderr)
    return root / "data"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="refserver", description="Probe reference MCP server")
    sub = parser.add_subparsers(dest="command", required=True)
    stdio = sub.add_parser("stdio", help="serve over stdin/stdout (NDJSON)")
    stdio.add_argument("--no-proxy", action="store_true", help=argparse.SUPPRESS)
    http = sub.add_parser("http", help="serve Streamable HTTP at /mcp")
    http.add_argument("--host", default="0.0.0.0")
    http.add_argument("--port", type=int, default=3000)
    seed = sub.add_parser("seed", help="write the deterministic seed")
    seed.add_argument("--out", type=Path, required=True)
    seed.add_argument("--seed", type=int, default=1)
    seed.add_argument("--token", default=None)
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
    if args.command == "seed":
        make_seed(args.out, args.seed, args.token)
        return 0

    try:
        bugs.load()
        cfg = Config.from_env(prepare_data())
    except (bugs.BugConfigError, ValueError) as exc:
        print(f"refserver: {exc}", file=sys.stderr)
        return 2

    from refserver.server import build_server, http_app
    from refserver.wire_bugs import run_stdio_proxy

    mcp = build_server(cfg)
    if args.command == "stdio" and bugs.is_on("b48"):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)  # the bug: SIGTERM is ignored
    if args.command == "stdio":
        if args.no_proxy:  # direct SDK transport; used by tests to prove the proxy is transparent
            anyio.run(mcp.run_stdio_async)
        else:
            anyio.run(run_stdio_proxy, mcp)
        if bugs.is_on("b48"):  # the bug: the server keeps running after stdin closes
            while True:
                time.sleep(3600)
        return 0

    import uvicorn

    uvicorn.run(http_app(mcp), host=args.host, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
