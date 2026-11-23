"""Which MCP era a server speaks, and how to talk to it.

"Modern" (2026-07-28) is stateless: every request carries its version, identity and
capabilities in ``_meta`` (and, over HTTP, in headers). "Legacy" (2025-11-25 and earlier)
opens with an ``initialize`` handshake. ``Session.open`` runs the spec's detection
algorithm: probe ``server/discover``; a result or a recognized modern error means modern
(and never falls back); anything else, including silence, means legacy.
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Literal

from probe import __version__
from probe.wire.errors import JsonRpcError, RequestTimeout, WireError
from probe.wire.headers import (
    HeaderMirror,
    mirror_headers,
    parse_x_mcp_headers,
    standard_headers,
)
from probe.wire.jsonrpc import METHOD_NOT_FOUND, Notification, Request, Response, ResultResponse
from probe.wire.limits import DEFAULT_REQUEST_TIMEOUT_S, ERA_PROBE_TIMEOUT_S
from probe.wire.transport_base import Transport
from probe.wire.transport_http import HttpRequestFailed, HttpTransport

Era = Literal["modern", "legacy"]
EraChoice = Literal["auto", "modern", "legacy"]

MODERN_VERSION = "2026-07-28"
MODERN_VERSIONS = (MODERN_VERSION,)
LEGACY_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
# The MCP-Protocol-Version header exists from this legacy revision on.
_LEGACY_HEADER_SINCE = "2025-06-18"

META_VERSION = "io.modelcontextprotocol/protocolVersion"
META_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"
META_CLIENT_INFO = "io.modelcontextprotocol/clientInfo"

HEADER_MISMATCH = -32020
MISSING_CAPABILITY = -32021
UNSUPPORTED_PROTOCOL_VERSION = -32022
_MODERN_ERROR_CODES = frozenset({HEADER_MISMATCH, MISSING_CAPABILITY, UNSUPPORTED_PROTOCOL_VERSION})


@dataclass(frozen=True, slots=True)
class NegotiationStep:
    """One thing negotiation did and what came of it; evidence for protocol checks."""

    action: str
    outcome: str


class NegotiationFailed(WireError):
    def __init__(self, reason: str, steps: tuple[NegotiationStep, ...] = ()) -> None:
        super().__init__(reason)
        self.reason = reason
        self.steps = steps


class NoCommonVersion(NegotiationFailed):
    def __init__(self, supported: tuple[str, ...], steps: tuple[NegotiationStep, ...] = ()) -> None:
        super().__init__(f"no protocol version in common; server supports {list(supported)}", steps)
        self.supported = supported


@dataclass(frozen=True, slots=True)
class _Modern:
    result: Any
    version: str


@dataclass(frozen=True, slots=True)
class _ModernError:
    code: int
    data: Any


@dataclass(frozen=True, slots=True)
class _Legacy:
    why: str


class Session:
    """A negotiated connection. Build one with ``Session.open``; the caller owns the transport."""

    def __init__(
        self,
        transport: Transport,
        *,
        client_capabilities: Mapping[str, Any] | None,
        seed: int,
        request_timeout: float,
        probe_timeout: float,
        modern_version: str,
        legacy_version: str,
    ) -> None:
        self.transport = transport
        self.era: Era = "modern"
        self.protocol_version = modern_version
        self.client_capabilities: dict[str, Any] = dict(client_capabilities or {})
        self.client_info = {"name": "probe", "version": __version__}
        self.negotiation: list[NegotiationStep] = []
        self.server_capabilities: dict[str, Any] = {}
        self.server_info: dict[str, Any] = {}
        self.instructions: str | None = None
        self.supported_versions: tuple[str, ...] = ()
        self.discover_result: dict[str, Any] | None = None
        self.initialize_result: dict[str, Any] | None = None
        # Tools whose x-mcp-header annotations are invalid, with the reasons (all transports).
        self.x_mcp_header_errors: dict[str, tuple[str, ...]] = {}
        self._seed = seed
        self._request_timeout = request_timeout
        self._probe_timeout = probe_timeout
        self._modern_version = modern_version
        self._legacy_version = legacy_version
        self._counter = 0
        self._mirrors: dict[str, tuple[HeaderMirror, ...]] = {}
        # What headers to send right now: None while no era is established (e.g. initialize).
        self._wire: tuple[Era, str] | None = None
        if isinstance(transport, HttpTransport):
            transport.message_headers = self._headers_for

    @classmethod
    async def open(
        cls,
        transport: Transport,
        *,
        era: EraChoice = "auto",
        client_capabilities: Mapping[str, Any] | None = None,
        seed: int = 0,
        request_timeout: float = DEFAULT_REQUEST_TIMEOUT_S["standard"],
        probe_timeout: float = ERA_PROBE_TIMEOUT_S,
        modern_version: str = MODERN_VERSION,
        legacy_version: str = LEGACY_VERSIONS[0],
    ) -> "Session":
        if era not in ("auto", "modern", "legacy"):
            raise ValueError(f"era must be auto, modern or legacy, not {era!r}")
        session = cls(
            transport,
            client_capabilities=client_capabilities,
            seed=seed,
            request_timeout=request_timeout,
            probe_timeout=probe_timeout,
            modern_version=modern_version,
            legacy_version=legacy_version,
        )
        await session._negotiate(era)
        return session

    async def request(
        self,
        method: str,
        params: Mapping[str, Any] | None = None,
        *,
        timeout: float | None = None,  # noqa: ASYNC109 - the per-request deadline
        meta: Mapping[str, Any] | None = None,
    ) -> Response:
        """Send a request with a fresh id (modern ``_meta`` added) and wait for its response.

        On legacy HTTP, a 404 for a session the server forgot re-initializes once and retries.
        """
        deadline = self._request_timeout if timeout is None else timeout
        for attempt in (0, 1):
            message = self._build(method, params, meta)
            try:
                return await self.transport.request(message, deadline)
            except HttpRequestFailed as exc:
                if attempt == 1 or not self._session_expired(exc):
                    raise
            await self._reinitialize()
        raise AssertionError("unreachable")  # pragma: no cover

    async def notify(self, method: str, params: Mapping[str, Any] | None = None) -> None:
        await self.transport.send(Notification(method, dict(params) if params else None).to_obj())

    async def close(self) -> None:
        await self.transport.close()

    def build_meta(
        self, request_id: int, extra: Mapping[str, Any] | None = None, *, version: str | None = None
    ) -> dict[str, Any]:
        """The ``_meta`` for a modern request; ``traceparent`` is derived from seed and id."""
        digest = sha256(f"{self._seed}:{request_id}".encode()).digest()
        meta: dict[str, Any] = {
            META_VERSION: version or self.protocol_version,
            META_CLIENT_INFO: dict(self.client_info),
            META_CAPABILITIES: dict(self.client_capabilities),
            "traceparent": f"00-{digest[:16].hex()}-{digest[16:24].hex()}-01",
        }
        meta.update(extra or {})
        return meta

    def register_tools(self, tools: Iterable[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
        """Record each tool's ``x-mcp-header`` mirrors; return the tools usable on this transport.

        Over HTTP a tool with an invalid annotation must be excluded; over stdio annotations
        may be ignored, so every tool is kept. Invalid annotations are recorded either way.
        """
        usable: list[Mapping[str, Any]] = []
        over_http = isinstance(self.transport, HttpTransport)
        for tool in tools:
            name = tool.get("name")
            mirrors, errors = parse_x_mcp_headers(tool.get("inputSchema"))
            if isinstance(name, str):
                if errors:
                    self.x_mcp_header_errors[name] = errors
                    self._mirrors.pop(name, None)
                else:
                    self._mirrors[name] = mirrors
            if over_http and errors:
                continue
            usable.append(tool)
        return usable

    # --- negotiation -------------------------------------------------------------------

    async def _negotiate(self, era: EraChoice) -> None:
        if era == "legacy":
            self._step("era", "forced legacy; no discover probe")
            await self._initialize(self._legacy_version)
            return
        probe = await self._discover(self._modern_version)
        if isinstance(probe, _ModernError) and probe.code == UNSUPPORTED_PROTOCOL_VERSION:
            probe = await self._retry_with_supported(probe, era)
            if probe is None:
                return  # fell back to a legacy version the server listed
        if isinstance(probe, _Modern):
            self._adopt_modern(probe.result, probe.version)
        elif isinstance(probe, _ModernError):
            # -32020 / -32021 on our own probe: the server is modern but unhappy with it.
            self._step("discover", f"modern error {probe.code}; staying modern")
            self.transport.report_violation("discover_rejected", f"server/discover: {probe.code}")
            self._adopt_modern(None, self._modern_version)
        elif era == "modern":
            self._step("era", f"forced modern; ignoring legacy signal ({probe.why})")
            self._adopt_modern(None, self._modern_version)
        else:
            await self._initialize(self._legacy_version)

    async def _retry_with_supported(self, probe: _ModernError, era: EraChoice) -> Any:
        """Handle -32022: retry with a mutually supported version, or use a legacy one."""
        data = probe.data if isinstance(probe.data, Mapping) else {}
        listed = data.get("supported")
        if not isinstance(listed, list) or not all(isinstance(v, str) for v in listed):
            raise NegotiationFailed(
                "-32022 without a usable supported-versions list", tuple(self.negotiation)
            )
        supported = tuple(listed)
        modern = [v for v in MODERN_VERSIONS if v in supported]
        if modern:
            retry = await self._discover(modern[0])
            if isinstance(retry, _Modern):
                self._modern_version = modern[0]
                return retry
            raise NegotiationFailed(
                f"server rejected {modern[0]}, a version it advertised", tuple(self.negotiation)
            )
        legacy = [v for v in LEGACY_VERSIONS if v in supported]
        if legacy and era == "auto":
            self._step("era", f"server lists only legacy versions; using {legacy[0]}")
            await self._initialize(legacy[0])
            return None
        raise NoCommonVersion(supported, tuple(self.negotiation))

    async def _discover(self, version: str) -> _Modern | _ModernError | _Legacy:
        self._wire = ("modern", version)
        message = self._build("server/discover", None, None, version=version)
        try:
            response = await self.transport.request(message, self._probe_timeout)
        except RequestTimeout:
            self._step("discover", "timeout")
            return _Legacy("timeout")
        except HttpRequestFailed as exc:
            if exc.status is None:
                raise  # nothing answered at all: there is no era to find out
            self._step("discover", f"http {exc.status} without a modern error")
            return _Legacy(f"http {exc.status}")
        if isinstance(response, ResultResponse):
            self._step("discover", "result")
            return _Modern(response.result, version)
        code = response.error.code
        if code in _MODERN_ERROR_CODES:
            self._step("discover", f"modern error {code}")
            return _ModernError(code, response.error.data)
        self._step("discover", f"error {code}")
        return _Legacy(f"error {code}")

    def _adopt_modern(self, result: Any, version: str) -> None:
        self.era = "modern"
        self.protocol_version = version
        self._wire = ("modern", version)
        if isinstance(result, dict):
            self.discover_result = result
            supported = result.get("supportedVersions")
            if isinstance(supported, list) and all(isinstance(v, str) for v in supported):
                self.supported_versions = tuple(supported)
                if version not in supported:
                    detail = f"accepted {version} but lists {supported}"
                    self.transport.report_violation("discover_version_inconsistent", detail)
            else:
                self.transport.report_violation(
                    "discover_result_invalid", "supportedVersions is missing or not a string list"
                )
            self.server_capabilities = _mapping(result.get("capabilities"))
            self.server_info = _mapping(result.get("serverInfo"))
            instructions = result.get("instructions")
            self.instructions = instructions if isinstance(instructions, str) else None
        elif result is not None:
            self.transport.report_violation("discover_result_invalid", "result is not an object")
        self.transport.on_server_request(self._modern_server_request)

    async def _modern_server_request(self, request: Request) -> Any:
        self.transport.report_violation(
            "server_request_in_modern_era", f"server sent a {request.method!r} request"
        )
        raise JsonRpcError(METHOD_NOT_FOUND, "Method not found")

    async def _initialize(self, version: str) -> None:
        self._wire = None  # the handshake itself carries no version header
        params = {
            "protocolVersion": version,
            "capabilities": self.client_capabilities,
            "clientInfo": self.client_info,
        }
        message = Request(self._next_id(), "initialize", params).to_obj()
        try:
            response = await self.transport.request(message, self._request_timeout)
        except RequestTimeout as exc:
            self._step("initialize", "timeout")
            raise NegotiationFailed("no reply to initialize", tuple(self.negotiation)) from exc
        except HttpRequestFailed as exc:
            self._step("initialize", f"http {exc.status}: {exc.reason}")
            raise NegotiationFailed(
                f"initialize failed ({exc.reason})", tuple(self.negotiation)
            ) from exc
        if not isinstance(response, ResultResponse):
            error = response.error
            self._step("initialize", f"error {error.code}")
            raise NegotiationFailed(
                f"initialize rejected: {error.code} {error.message}", tuple(self.negotiation)
            )
        result = response.result
        chosen = result.get("protocolVersion") if isinstance(result, dict) else None
        if not isinstance(result, dict) or chosen not in LEGACY_VERSIONS:
            self._step("initialize", f"unsupported version {chosen!r}")
            raise NegotiationFailed(
                f"server chose protocol version {chosen!r}, which Probe does not speak as legacy",
                tuple(self.negotiation),
            )
        self._step("initialize", f"ok {chosen}")
        self.era = "legacy"
        self.protocol_version = chosen
        self.initialize_result = result
        self.server_capabilities = _mapping(result.get("capabilities"))
        self.server_info = _mapping(result.get("serverInfo"))
        instructions = result.get("instructions")
        self.instructions = instructions if isinstance(instructions, str) else None
        self._wire = ("legacy", chosen)
        await self.transport.send(Notification("notifications/initialized").to_obj())

    def _session_expired(self, exc: HttpRequestFailed) -> bool:
        return (
            self.era == "legacy"
            and exc.status == 404
            and isinstance(self.transport, HttpTransport)
            and self.transport.session_id is not None
        )

    async def _reinitialize(self) -> None:
        self._step("reinitialize", "404 for a session the server no longer knows")
        if isinstance(self.transport, HttpTransport):
            self.transport.session_id = None
        await self._initialize(self.protocol_version)

    # --- building messages -------------------------------------------------------------

    def _next_id(self) -> int:
        self._counter += 1
        return self._counter

    def _build(
        self,
        method: str,
        params: Mapping[str, Any] | None,
        meta: Mapping[str, Any] | None,
        *,
        version: str | None = None,
    ) -> dict[str, Any]:
        request_id = self._next_id()
        body = dict(params) if params is not None else None
        if self._wire is not None and self._wire[0] == "modern":
            body = body if body is not None else {}
            merged = self.build_meta(request_id, version=version or self._wire[1])
            merged.update(_mapping(body.get("_meta")))
            merged.update(meta or {})
            body["_meta"] = merged
        elif meta:
            body = body if body is not None else {}
            body["_meta"] = {**_mapping(body.get("_meta")), **meta}
        return Request(request_id, method, body).to_obj()

    def _headers_for(self, message: Mapping[str, Any]) -> dict[str, str]:
        """HTTP headers for one outgoing message in the current era (HTTP transports only)."""
        if self._wire is None:
            return {}
        era, version = self._wire
        if era == "legacy":
            return {"MCP-Protocol-Version": version} if version >= _LEGACY_HEADER_SINCE else {}
        headers = {"MCP-Protocol-Version": version}
        method = message.get("method")
        if isinstance(method, str):
            params = message.get("params")
            params = params if isinstance(params, Mapping) else None
            headers.update(standard_headers(method, params))
            if method == "tools/call" and params is not None:
                mirrors = self._mirrors.get(str(params.get("name")), ())
                arguments = params.get("arguments")
                headers.update(
                    mirror_headers(mirrors, arguments if isinstance(arguments, Mapping) else None)
                )
        return headers

    def _step(self, action: str, outcome: str) -> None:
        self.negotiation.append(NegotiationStep(action, outcome))


def _mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}
