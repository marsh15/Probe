"""Everything a check can see and do during a scan.

The context owns the live session. Calls go through it so they are budgeted, counted, and so a
dying target is noticed, recorded, restarted and reconnected without each check handling it.
"""

import contextlib
import random
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from probe.engine.budget import Budget
from probe.engine.crash import CrashTracker, TargetCrashed, TargetUnstable
from probe.engine.discovery import ToolListing
from probe.engine.outcomes import CrashEvent, Mode, ToolInfo
from probe.engine.outcomes import Era as EraEnum
from probe.wire.errors import RequestTimeout, TransportClosed, WireEvent
from probe.wire.jsonrpc import ErrorResponse, Response, ResultResponse
from probe.wire.limits import request_timeout
from probe.wire.recorder import Recorder
from probe.wire.session import Exchange, Session
from probe.wire.transport_http import HttpRequestFailed, HttpTransport, RawHttpResult
from probe.wire.transport_stdio import StdioTransport

LIVENESS_TIMEOUT_S = 5.0
TASKS_EXTENSION = "io.modelcontextprotocol/tasks"
_STDERR_TAIL_BYTES = 4096


class Fixtures(Protocol):
    async def reset(self) -> None: ...


class Judge(Protocol):
    """The optional LLM judge (``--llm``); its interface is defined with the judge itself."""


@dataclass(frozen=True, slots=True)
class ScanConfig:
    mode: Mode = "standard"
    seed: int = 0
    allow_side_effects: bool = False
    timeout_scale: float = 1.0
    # Hashed into finding ids, so the same finding on the same target keeps its id.
    target_identity: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class CallResult:
    response: Response
    elapsed_ms: float

    @property
    def result(self) -> dict[str, Any] | None:
        if isinstance(self.response, ResultResponse) and isinstance(self.response.result, dict):
            return self.response.result
        return None

    @property
    def is_error(self) -> bool:
        """A JSON-RPC error, or a tool result flagged ``isError``."""
        if isinstance(self.response, ErrorResponse):
            return True
        result = self.result
        return result is not None and result.get("isError") is True

    @property
    def ok(self) -> bool:
        return isinstance(self.response, ResultResponse) and not self.is_error


class ScanContext:
    def __init__(
        self,
        *,
        session: Session,
        runner: Any,
        config: ScanConfig,
        tools: Sequence[ToolInfo],
        budget: Budget,
        fixtures: Fixtures | None = None,
        profile: Any = None,
        llm: Judge | None = None,
        trace: Recorder | None = None,
        auth_identities: Sequence[str] = (),
        second_instance_supported: bool = True,
        listing: ToolListing | None = None,
    ) -> None:
        self.client = session
        self.runner = runner
        self.config = config
        self.tools = list(tools)
        # The raw tools/list pages, for checks that validate the server's own output.
        self.listing = listing
        self.budget = budget
        self.fixtures = fixtures
        self.profile = profile
        self.llm = llm
        self.trace = trace
        self.auth_identities = tuple(auth_identities)
        self.second_instance_supported = second_instance_supported
        self.rng = random.Random(config.seed)  # noqa: S311 - reproducible cases, not security
        self.crashes = CrashTracker()
        self.current_check: str | None = None
        self.calls = 0  # calls made by the current check
        self._baselines: dict[str, CallResult | None] = {}
        self._dead_for_good = False
        self._retired: list[Any] = []  # transports of crashed instances, kept for their events

    # --- what was negotiated -----------------------------------------------------------

    @property
    def era(self) -> EraEnum:
        return EraEnum(self.client.era)

    @property
    def negotiated_version(self) -> str:
        return self.client.protocol_version

    @property
    def discover(self) -> dict[str, Any] | None:
        """The DiscoverResult (modern) or InitializeResult (legacy)."""
        return self.client.discover_result or self.client.initialize_result

    @property
    def server_extensions(self) -> frozenset[str]:
        extensions = self.client.server_capabilities.get("extensions")
        return frozenset(extensions) if isinstance(extensions, dict) else frozenset()

    @property
    def side_effects_allowed(self) -> bool:
        """Calls that may change state are fine in a sandbox or with --allow-side-effects."""
        return self.config.allow_side_effects or bool(self.runner.sandboxed)

    def callable_tools(self) -> list[ToolInfo]:
        """The tools checks may call: read tools always; the rest only if side effects are allowed.

        Unknown-kind tools count as writing tools.
        """
        if self.side_effects_allowed:
            return list(self.tools)
        return [t for t in self.tools if t.kind == "read"]

    def tool(self, name: str) -> ToolInfo | None:
        return next((t for t in self.tools if t.name == name), None)

    # --- making calls ------------------------------------------------------------------

    def begin_check(self, check_id: str) -> None:
        self.current_check = check_id
        self.calls = 0

    async def request(
        self,
        method: str,
        params: Mapping[str, Any] | None = None,
        *,
        timeout: float | None = None,  # noqa: ASYNC109 - the per-request deadline
        meta: Mapping[str, Any] | None = None,
        case_id: str | None = None,
    ) -> Response:
        """One budgeted request. A dead target is recorded and restarted, then TargetCrashed."""
        self.spend()
        deadline = timeout or request_timeout(self.config.mode, self.config.timeout_scale)
        try:
            return await self.client.request(method, params, timeout=deadline, meta=meta)
        except TransportClosed as exc:
            event = await self._handle_death(case_id, reason=exc.reason)
            raise TargetCrashed(event) from None

    async def call(
        self,
        tool: str,
        arguments: Mapping[str, Any] | None = None,
        *,
        timeout: float | None = None,  # noqa: ASYNC109 - the per-request deadline
        case_id: str | None = None,
    ) -> CallResult:
        started = time.monotonic()
        response = await self.request(
            "tools/call",
            {"name": tool, "arguments": dict(arguments or {})},
            timeout=timeout,
            case_id=case_id,
        )
        return CallResult(response, (time.monotonic() - started) * 1000)

    async def exchange(
        self,
        method: str,
        params: Mapping[str, Any] | None = None,
        *,
        timeout: float | None = None,  # noqa: ASYNC109 - the per-request deadline
        meta: Mapping[str, Any] | None = None,
        case_id: str | None = None,
    ) -> Exchange:
        """A budgeted request that reports the HTTP status and never raises for no answer."""
        self.spend()
        deadline = timeout or request_timeout(self.config.mode, self.config.timeout_scale)
        try:
            return await self.client.exchange(method, params, timeout=deadline, meta=meta)
        except TransportClosed as exc:
            raise TargetCrashed(await self._handle_death(case_id, reason=exc.reason)) from None

    async def raw_http(
        self,
        headers: Mapping[str, str],
        body: bytes,
        *,
        method: str = "POST",
        timeout: float = 10.0,  # noqa: ASYNC109 - the exchange deadline
    ) -> RawHttpResult:
        """Send exactly these headers and bytes (HTTP targets only); budgeted, still recorded."""
        transport = self.client.transport
        if not isinstance(transport, HttpTransport):
            raise TypeError("raw_http needs an HTTP target")
        self.spend()
        return await transport.raw_http(headers, body, method=method, timeout=timeout)

    async def raw_stdio(self, data: bytes, *, case_id: str | None = None) -> None:
        """Write exactly these bytes to the server's stdin (stdio targets only)."""
        transport = self.client.transport
        if not isinstance(transport, StdioTransport):
            raise TypeError("raw_stdio needs a stdio target")
        self.spend()
        try:
            await transport.raw_stdio_line(data)
        except TransportClosed as exc:
            raise TargetCrashed(await self._handle_death(case_id, reason=exc.reason)) from None

    def spend(self, n: int = 1) -> None:
        """Account for ``n`` calls made outside the context (e.g. on a fresh instance)."""
        if self._dead_for_good:
            raise TargetUnstable("target is unstable and cannot be restarted again")
        self.budget.take(n)
        self.calls += n

    def wire_events(self) -> list[WireEvent]:
        """Observations about server behavior from every instance of this scan, oldest first."""
        events: list[WireEvent] = []
        for transport in (*self._retired, self.client.transport):
            events.extend(transport.events())
        return events

    def trace_records(self) -> list[dict[str, Any]]:
        """The scan's recorded wire messages so far (empty without a recorder)."""
        return self.trace.records() if self.trace is not None else []

    # --- baselines (the main false-positive guard) -------------------------------------

    def baseline(self, tool: str) -> CallResult | None:
        """The first successful valid call of ``tool``, or None if there is none (yet)."""
        return self._baselines.get(tool)

    async def establish_baseline(
        self, tool: ToolInfo, arguments: Mapping[str, Any]
    ) -> CallResult | None:
        """Make one valid call; remember it if it succeeded. A failed attempt is not repeated."""
        if tool.name in self._baselines:
            return self._baselines[tool.name]
        result = await self.call(tool.name, arguments, case_id=f"{tool.name}:baseline")
        self._baselines[tool.name] = result if result.ok else None
        return self._baselines[tool.name]

    # --- crashes and liveness ----------------------------------------------------------

    async def reproduces_crash(
        self, method: str, params: Mapping[str, Any] | None, *, case_id: str | None = None
    ) -> bool:
        """Re-send the exact request that just crashed the target, on the restarted instance.

        Only a crash that happens again may be held against the server by checks whose fail
        criteria include crashing; call this right after catching ``TargetCrashed``.
        """
        try:
            await self.request(method, params, case_id=case_id)
        except TargetCrashed:
            return True
        except RequestTimeout:
            return False
        return False

    async def survives(self, action: Callable[[], Awaitable[object]]) -> bool:
        """Run ``action``; True if the target is still alive afterwards.

        For cases sent as raw bytes: run it on the restarted target after a crash to see whether
        the same input kills it again, which is what makes a crash attributable to that input.
        """
        try:
            await action()
        except TargetCrashed:
            return False
        return await self.liveness()

    async def liveness(self) -> bool:
        """Is the target still answering? Any reply, even an error, counts as alive.

        A dead or hung target is recorded as a crash and restarted. Not budgeted.
        """
        if self._dead_for_good:
            return False
        try:
            await self.client.request("tools/list", timeout=LIVENESS_TIMEOUT_S)
        except (TransportClosed, RequestTimeout, HttpRequestFailed) as exc:
            if isinstance(exc, HttpRequestFailed) and exc.status is not None:
                return True  # it answered over HTTP, just not with a JSON-RPC response
            await self._handle_death(None, reason=type(exc).__name__)
            return False
        return True

    async def restart_if_dead(self, reason: str = "found not running") -> None:
        """At a phase boundary: bring the target back if it is no longer running."""
        state = await self.runner.state()
        if not state.running and not self._dead_for_good:
            await self._handle_death(None, reason=reason)

    async def reconnect(self) -> None:
        transport = await self.runner.restart()
        old = self.client
        era = old.era
        self.client = await Session.open(
            transport,
            era=era,
            client_capabilities=old.client_capabilities,
            seed=self.config.seed,
            request_timeout=request_timeout(self.config.mode, self.config.timeout_scale),
            modern_version=old.protocol_version if era == "modern" else "2026-07-28",
            legacy_version=old.protocol_version if era == "legacy" else "2025-11-25",
        )
        self.client.register_tools(
            [{"name": t.name, "inputSchema": t.input_schema} for t in self.tools]
        )
        self._retired.append(old.transport)
        with contextlib.suppress(Exception):
            await old.transport.close()

    async def _handle_death(self, case_id: str | None, *, reason: str) -> CrashEvent:
        state = await self.runner.state()
        event = CrashEvent(
            check_id=self.current_check or "engine",
            case_id=case_id,
            exit_code=state.exit_code,
            oom_killed=state.oom_killed,
            stderr_tail=self.client.transport.stderr_tail(_STDERR_TAIL_BYTES) or reason,
        )
        self.crashes.record(event)
        if self.crashes.can_restart:
            self.crashes.restarts += 1
            await self.reconnect()
        else:
            self._dead_for_good = True
        return event
