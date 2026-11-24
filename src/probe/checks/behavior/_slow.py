"""Finding a call that takes a couple of seconds, and running it so it can be cancelled.

Cancellation and head-of-line checks need a request that is still in flight when Probe acts.
The profile can name one (``tools.<name>.slow_case``); otherwise Probe guesses from tools named
like ``slow``/``sleep``/``delay``/``wait`` that take one numeric duration.
"""

import asyncio
import contextlib
import re
from dataclasses import dataclass
from typing import Any

from probe.checks.context import ScanContext
from probe.engine.outcomes import ToolInfo
from probe.wire.errors import RequestTimeout, TransportClosed
from probe.wire.jsonrpc import Response
from probe.wire.transport_http import HttpTransport

PROFILE_SECONDS = 4.0  # what a profile slow_case is documented to take
CANCEL_SECONDS = 1.6  # long enough to be in flight when cancelled, short enough to wait out
BLOCKING_SECONDS = 4.0  # long enough that a blocked tools/list is clearly late
_NAME = re.compile(r"slow|sleep|delay|wait", re.IGNORECASE)
_SECONDS = re.compile(
    r"^(seconds?|secs?|duration|delay|timeout)(_s|_sec|_seconds)?$", re.IGNORECASE
)
_MILLIS = re.compile(r"(?i:(^|_)(ms|millis|milliseconds)$)|[a-z]Ms$")


@dataclass(frozen=True, slots=True)
class SlowCase:
    tool: ToolInfo
    arguments: dict[str, Any]
    seconds: float  # how long the call is expected to take


def _bounded(spec: dict[str, Any], value: float) -> float | None:
    low, high = spec.get("minimum"), spec.get("maximum")
    if isinstance(spec.get("type"), str) and spec["type"] == "integer":
        value = float(round(value))
    if isinstance(low, int | float) and value < low:
        value = float(low)
    if isinstance(high, int | float) and value > high:
        return None  # the tool cannot be made to run this long
    return value


def _guess(tool: ToolInfo, target: float) -> SlowCase | None:
    if not _NAME.search(tool.name):
        return None
    schema = tool.input_schema
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return None
    numeric = {
        n: s
        for n, s in properties.items()
        if isinstance(s, dict) and s.get("type") in ("number", "integer")
    }
    required = schema.get("required")
    if len(numeric) != 1 or (isinstance(required, list) and set(required) - set(numeric)):
        return None
    ((name, spec),) = numeric.items()
    if _MILLIS.search(name):
        value, seconds = _bounded(spec, target * 1000), target
    elif _SECONDS.match(name) or "second" in name.lower():
        value, seconds = _bounded(spec, target), target
    else:
        return None
    if value is None:
        return None
    return SlowCase(tool, {name: value}, seconds)


def slow_case(ctx: ScanContext, seconds: float = CANCEL_SECONDS) -> SlowCase | None:
    """A call that takes about ``seconds`` (a profile case: about four), or None when the
    server offers none Probe can recognize."""
    profile = ctx.profile
    for tool in ctx.callable_tools():
        override = profile.override_for(tool.name) if profile is not None else None
        if override is not None and override.slow_case is not None:
            return SlowCase(tool, dict(override.slow_case), PROFILE_SECONDS)
    for tool in ctx.callable_tools():
        if (guess := _guess(tool, seconds)) is not None:
            return guess
    return None


@dataclass(slots=True)
class RunningCall:
    """A request in flight whose answer has not been awaited yet."""

    message: dict[str, Any]
    task: "asyncio.Task[Response]"

    @property
    def request_id(self) -> Any:
        return self.message["id"]


async def start_call(ctx: ScanContext, case: SlowCase, *, timeout: float) -> RunningCall:  # noqa: ASYNC109
    """Send the slow call without waiting for its answer."""
    ctx.spend()
    message = ctx.client.build_request(
        "tools/call", {"name": case.tool.name, "arguments": case.arguments}
    )
    task = asyncio.create_task(ctx.client.transport.request(message, timeout))
    await asyncio.sleep(0)  # let the request go out before the caller starts timing
    return RunningCall(message, task)


async def cancel_call(ctx: ScanContext, call: RunningCall) -> None:
    """Cancel the way the transport says: close the response stream (HTTP) or notify (stdio)."""
    if isinstance(ctx.client.transport, HttpTransport):
        call.task.cancel()
        with contextlib.suppress(asyncio.CancelledError, RequestTimeout, TransportClosed):
            await call.task
        return
    await ctx.client.notify(
        "notifications/cancelled", {"requestId": call.request_id, "reason": "probe cancellation"}
    )


async def abandon(call: RunningCall) -> None:
    """Stop waiting for a call and swallow whatever it ends with."""
    if not call.task.done():
        call.task.cancel()
    with contextlib.suppress(asyncio.CancelledError, Exception):
        await call.task
