"""Scripted MCP servers for era negotiation: modern, legacy or dual, with chosen failure modes.

``EraServer.handle`` is transport-agnostic: ``ScriptedTransport`` calls it in-process (stdio-like,
``headers=None``) and the fake HTTP app calls it with the request headers. Everything the server
receives is kept in ``received`` for assertions.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from probe.wire.errors import TransportClosed
from probe.wire.headers import decode_header_value
from probe.wire.jsonrpc import encode, parse_line
from probe.wire.transport_base import CloseResult, Transport

PV = "io.modelcontextprotocol/protocolVersion"
LegacyProbe = Literal["error", "silent", "http400", "http404", "http400-json", "http500"]


@dataclass
class Reply:
    body: dict[str, Any] | None = None
    status: int = 200
    headers: dict[str, str] = field(default_factory=dict)


def error(
    id_: Any, code: int, message: str = "error", data: Any = None, status: int = 200
) -> Reply:
    err: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return Reply({"jsonrpc": "2.0", "id": id_, "error": err}, status)


def result(id_: Any, value: dict[str, Any], headers: dict[str, str] | None = None) -> Reply:
    return Reply({"jsonrpc": "2.0", "id": id_, "result": value}, headers=headers or {})


class EraServer:
    def __init__(
        self,
        *,
        modern: bool = True,
        legacy: bool = False,
        modern_versions: tuple[str, ...] = ("2026-07-28",),
        legacy_version: str = "2025-11-25",
        advertise_legacy: bool = False,
        legacy_probe: LegacyProbe = "error",
        probe_error_code: int = -32601,
        initialize_error: bool = False,
        initialize_version: str | None = None,
    ) -> None:
        self.modern = modern
        self.legacy = legacy
        self.modern_versions = modern_versions
        self.legacy_version = legacy_version
        self.advertise_legacy = advertise_legacy
        self.legacy_probe = legacy_probe
        self.probe_error_code = probe_error_code
        self.initialize_error = initialize_error
        self.initialize_version = initialize_version
        self.received: list[tuple[dict[str, Any], dict[str, str] | None]] = []
        self.session_id: str | None = None
        self._sessions = 0
        self.initialized = False
        self.mirrors: dict[str, str] = {}  # header -> value the server expects on tools/call

    def forget_session(self) -> None:
        self.session_id = None

    def methods(self) -> list[str]:
        return [str(msg.get("method")) for msg, _ in self.received]

    def handle(self, msg: dict[str, Any], headers: dict[str, str] | None) -> Reply | None:
        self.received.append((msg, headers))
        if "id" not in msg or "method" not in msg:
            return Reply(status=202)
        id_, method = msg["id"], msg["method"]
        meta = (msg.get("params") or {}).get("_meta") or {}
        if method == "initialize":
            return self._initialize(id_, msg["params"])
        if PV in meta:
            return self._modern(id_, method, msg["params"], meta, headers)
        if self.legacy and self.initialized:
            return self._legacy(id_, method, headers)
        return error(id_, -32600, "send initialize first")

    def _supported(self) -> list[str]:
        extra = [self.legacy_version] if self.advertise_legacy else []
        return [*self.modern_versions, *extra]

    def _modern(
        self,
        id_: Any,
        method: str,
        params: dict[str, Any],
        meta: dict[str, Any],
        headers: dict[str, str] | None,
    ) -> Reply | None:
        if not self.modern:
            return self._probe_reply(id_)
        version = meta[PV]
        if version not in self.modern_versions:
            data = {"supported": self._supported(), "requested": version}
            return error(id_, -32022, "Unsupported protocol version", data, status=400)
        if headers is not None:
            mismatch = self._header_mismatch(method, params, version, headers)
            if mismatch:
                return error(id_, -32020, f"Header mismatch: {mismatch}", status=400)
        if method == "server/discover":
            return result(
                id_,
                {
                    "supportedVersions": self._supported(),
                    "capabilities": {"tools": {}},
                    "instructions": "scripted",
                    "ttlMs": 0,
                    "cacheScope": "public",
                },
            )
        return result(id_, {"resultType": "complete", "method": method})

    def _header_mismatch(
        self, method: str, params: dict[str, Any], version: str, headers: dict[str, str]
    ) -> str | None:
        if headers.get("mcp-protocol-version") != version:
            return "MCP-Protocol-Version"
        if headers.get("mcp-method") != method:
            return "Mcp-Method"
        if method == "tools/call":
            name = headers.get("mcp-name")
            if name is None or decode_header_value(name) != params["name"]:
                return "Mcp-Name"
            for header, expected in self.mirrors.items():
                value = headers.get(header.lower())
                if value is None or decode_header_value(value) != expected:
                    return header
        return None

    def _probe_reply(self, id_: Any) -> Reply | None:
        """A legacy-only server's answer to a modern request."""
        match self.legacy_probe:
            case "silent":
                return None
            case "http400":
                return Reply(status=400)
            case "http404":
                return Reply(status=404)
            case "http500":
                return Reply(status=500)
            case "http400-json":  # 400, JSON, but not a recognized modern error
                return error(id_, -32602, "bad request", status=400)
            case _:
                return error(id_, self.probe_error_code, "method not found")

    def _initialize(self, id_: Any, params: dict[str, Any]) -> Reply:
        if not self.legacy or self.initialize_error:
            data = {"supported": self._supported()}
            return error(id_, -32601, "Unknown method initialize; supports 2026-07-28", data)
        self._sessions += 1
        self.session_id = f"s-{self._sessions}"
        self.initialized = True
        version = self.initialize_version or self.legacy_version
        return result(
            id_,
            {
                "protocolVersion": version,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "legacy-fake", "version": "1"},
                "instructions": "legacy hello",
            },
            headers={"Mcp-Session-Id": self.session_id},
        )

    def _legacy(self, id_: Any, method: str, headers: dict[str, str] | None) -> Reply:
        if headers is not None:
            if headers.get("mcp-session-id") != self.session_id:
                return Reply(status=404)
            version = self.initialize_version or self.legacy_version
            sent = headers.get("mcp-protocol-version")
            if version >= "2025-06-18" and sent != version:
                return error(id_, -32600, "bad MCP-Protocol-Version", status=400)
            if version < "2025-06-18" and sent is not None:
                return error(id_, -32600, "unexpected MCP-Protocol-Version", status=400)
        return result(id_, {"method": method, "legacy": True})


class ScriptedTransport(Transport):
    """A stdio-like transport whose 'process' is an ``EraServer`` called in-process."""

    name = "stdio"

    def __init__(self, server: EraServer) -> None:
        super().__init__()
        self.server = server
        self._open = True

    async def send(self, obj: Mapping[str, Any]) -> None:
        reply = self.server.handle(dict(obj), None)
        if reply is not None and reply.body is not None:
            self._receive(parse_line(encode(reply.body)))

    def push(self, obj: Mapping[str, Any]) -> None:
        """Deliver a message the server sends unprompted."""
        self._receive(parse_line(encode(obj)))

    async def close(self) -> CloseResult:
        self._open = False
        self._mark_closed(TransportClosed(0, "closed by client"))
        return CloseResult(0)

    def alive(self) -> bool:
        return self._open

    def stderr_tail(self, n: int = 4096) -> str:
        return ""
