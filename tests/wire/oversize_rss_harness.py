"""Stream a 32 MiB line through StdioTransport and print this process's peak RSS as JSON.

Run by test_stdio.py in a fresh interpreter so the measured peak belongs to this scenario alone.
"""

import asyncio
import json
import resource
import sys
from pathlib import Path

from probe.wire.errors import OversizeMessage
from probe.wire.jsonrpc import Request
from probe.wire.transport_stdio import StdioTransport

SERVER = Path(__file__).parent / "fake_servers" / "oversize.py"


def peak_rss_bytes() -> int:
    if sys.platform == "linux":
        # Linux carries ru_maxrss across execve, so a child of a large pytest process would report
        # the parent's peak. VmHWM belongs to this process's own address space.
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith("VmHWM:"):
                return int(line.split()[1]) * 1024
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # ru_maxrss is bytes on macOS and KiB elsewhere.
    return peak if sys.platform == "darwin" else peak * 1024


async def main() -> None:
    transport = await StdioTransport.spawn([sys.executable, str(SERVER), str(32 * 1024 * 1024)])
    try:
        response = await transport.request(Request(1, "go").to_obj(), timeout=60)
    finally:
        await transport.close()
    [event] = [e for e in transport.events() if isinstance(e, OversizeMessage)]
    peak_bytes = peak_rss_bytes()
    result = response.unwrap()
    print(
        json.dumps(
            {"peak_rss_bytes": peak_bytes, "result": result, "oversize_length": event.length}
        )
    )


asyncio.run(main())
