"""A standalone shell script that replays a finding's requests without Probe.

stdio targets get ``printf`` lines piped into the server (``docker run -i --rm <image>`` for a
sandboxed one); HTTP targets get one ``curl`` per request. The script shows what the server
answers; judging the answer (canary hits, state diffs) still takes ``probe repro``. Everything
that comes from the target or the scan is shell-quoted, and text placed in comments is cut to
one line so it cannot start a command.
"""

import json
import re
import shlex
from collections.abc import Mapping
from typing import Any

from probe.repro.bundle import ReproBundle
from probe.wire.headers import standard_headers
from probe.wire.session import (
    LEGACY_VERSIONS,
    META_CAPABILITIES,
    META_CLIENT_INFO,
    META_VERSION,
    MODERN_VERSION,
)

_CONTROL = re.compile(r"[\x00-\x1f\x7f]+")
_SECRET_PLACEHOLDER = re.compile(r"\{secret:([A-Za-z_][A-Za-z0-9_]*)\}")
_DOUBLE_QUOTED = re.compile(r'(["\\$`])')
_CLIENT_INFO = {"name": "probe-repro", "version": "1"}
_STDIO_LINGER_S = 3  # keep stdin open so the server can answer before it sees end of input


def _comment(text: object, limit: int = 300) -> str:
    one_line = _CONTROL.sub(" ", str(text)).strip()
    return one_line[:limit]


def _sh(text: str) -> str:
    """One shell word. A ``{secret:NAME}`` placeholder becomes ``"${NAME}"``, read from the
    user's environment when the script runs (and the script stops if it is not set); no secret
    value is ever written into the script."""
    if not _SECRET_PLACEHOLDER.search(text):
        return shlex.quote(text)
    parts: list[str] = []
    last = 0
    for match in _SECRET_PLACEHOLDER.finditer(text):
        parts.append(_DOUBLE_QUOTED.sub(r"\\\1", text[last : match.start()]))
        name = match.group(1)
        parts.append(f"${{{name}:?{name} is not set}}")
        last = match.end()
    parts.append(_DOUBLE_QUOTED.sub(r"\\\1", text[last:]))
    return '"' + "".join(parts) + '"'


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"))


def _version(bundle: ReproBundle) -> str:
    return bundle.run.negotiated_version or MODERN_VERSION


def _is_legacy(bundle: ReproBundle) -> bool:
    return _version(bundle) in LEGACY_VERSIONS


def _message(bundle: ReproBundle, request_id: int, step: Mapping[str, Any]) -> dict[str, Any]:
    params = dict(step.get("params") or {})
    if not _is_legacy(bundle):
        meta = {
            META_VERSION: _version(bundle),
            META_CLIENT_INFO: _CLIENT_INFO,
            META_CAPABILITIES: {},
        }
        existing = params.get("_meta")
        params["_meta"] = {**meta, **(existing if isinstance(existing, dict) else {})}
    return {"jsonrpc": "2.0", "id": request_id, "method": step["method"], "params": params}


def _legacy_handshake(bundle: ReproBundle) -> list[dict[str, Any]]:
    return [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": _version(bundle),
                "capabilities": {},
                "clientInfo": _CLIENT_INFO,
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
    ]


def _header(bundle: ReproBundle) -> list[str]:
    lines = [
        "#!/bin/sh",
        f"# Repro for finding {_comment(bundle.finding_id)}: {_comment(bundle.title)}",
        f"# Check {_comment(bundle.check_id)} (severity {_comment(bundle.severity)}), "
        f"tool {_comment(bundle.tool or '-')}, case {_comment(bundle.case_id)}",
        f"# Expected by Probe: {_comment(_json(bundle.expect), 500)}",
        "# This script sends the recorded requests and prints the replies, so you can see the",
        "# server's answer yourself. Effects Probe measures on the side (canary hits, files",
        "# changed, process crashes) need `probe repro report.json --finding "
        f"{_comment(bundle.finding_id)}`.",
    ]
    if bundle.run.allow_side_effects:
        lines.append("# The scan ran with side effects allowed: these requests may change data.")
    return lines


def _runnable_steps(bundle: ReproBundle, *, stdio: bool) -> tuple[list[dict[str, Any]], list[str]]:
    """The steps a script can send, and a comment for each one it has to leave out."""
    kept: list[dict[str, Any]] = []
    notes: list[str] = []
    for step in bundle.steps:
        kind = step.get("kind")
        usable = (
            (kind == "request" and isinstance(step.get("method"), str))
            or (kind == "raw_stdio" and stdio)
            or (kind == "raw_http" and not stdio)
        )
        if usable:
            kept.append(step)
        else:
            notes.append(f"# not reproduced here (needs Probe): {_comment(_json(step), 200)}")
    return kept, notes


def _nothing_to_send(bundle: ReproBundle, notes: list[str]) -> str:
    body = [
        *_header(bundle),
        "# No wire requests were recorded for this finding (it came from observing the whole",
        "# scan), so there is nothing to replay by hand. Use `probe repro` instead.",
        *notes,
        "exit 0",
    ]
    return "\n".join(body) + "\n"


def _target_env(bundle: ReproBundle) -> dict[str, str]:
    profile_target = bundle.profile.get("target") if isinstance(bundle.profile, dict) else None
    from_profile = profile_target.get("env", {}) if isinstance(profile_target, dict) else {}
    return {**from_profile, **bundle.run.target_env}


def _stdio_runner(bundle: ReproBundle) -> tuple[list[str], str | None]:
    """The comments and the command line that starts the target, or no command if unknown."""
    profile_target = bundle.profile.get("target") or {}
    image = bundle.target.image or profile_target.get("image")
    command = bundle.target.command or profile_target.get("command")
    env = _target_env(bundle)
    notes = []
    if bundle.run.secret_env:
        notes.append(f"# Set these secret variables yourself: {', '.join(bundle.run.secret_env)}")
    if image and bundle.target.sandbox is not False:
        pin = (
            f" (image id {_comment(bundle.target.image_digest)})"
            if bundle.target.image_digest
            else ""
        )
        notes.append(f"# Target image: {_comment(image)}{pin}")
        words = ["docker", "run", "-i", "--rm"]
        for key, value in sorted(env.items()):
            words += ["-e", f"{key}={value}"]
        for name in bundle.run.secret_env:  # `-e NAME` takes the value from the user's environment
            words += ["-e", name]
        return notes, " ".join(_sh(word) for word in [*words, image, *(command or [])])
    if command:
        assignments = [f"{k}={v}" for k, v in sorted(env.items())]
        return notes, " ".join(_sh(word) for word in ["env", *assignments, *command])
    return notes, None


def _stdio_script(bundle: ReproBundle) -> str:
    steps, skipped = _runnable_steps(bundle, stdio=True)
    if not steps:
        return _nothing_to_send(bundle, skipped)
    notes, runner = _stdio_runner(bundle)
    lines: list[str] = []
    next_id = 1
    if _is_legacy(bundle):
        lines += [_json(m) for m in _legacy_handshake(bundle)]
        next_id = 2
    for step in steps:
        if step["kind"] == "raw_stdio":
            lines.append(str(step.get("line", "")))
            continue
        lines.append(_json(_message(bundle, next_id, step)))
        next_id += 1
    if runner is None:
        return (
            "\n".join([*_header(bundle), *notes, "# The target command is not recorded.", "exit 2"])
            + "\n"
        )
    printf = "printf '%s\\n' " + " ".join(shlex.quote(line) for line in lines)
    return (
        "\n".join(
            [
                *_header(bundle),
                *notes,
                *skipped,
                "{",
                f"  {printf}",
                f"  sleep {_STDIO_LINGER_S}",
                f"}} | {runner}",
            ]
        )
        + "\n"
    )


_JSON_HEADERS = ["Content-Type: application/json", "Accept: application/json, text/event-stream"]
_SID_HEADER = '-H "Mcp-Session-Id: $SID"'  # $SID is set by the handshake in legacy scripts


def _curl(
    url: str,
    headers: list[str],
    body: str | None,
    method: str = "POST",
    *,
    show: str = "-i",
    with_session: bool = False,
) -> str:
    words = ["curl", "-sS", "-X", method, url]
    for header in headers:
        words += ["-H", header]
    if body is not None:
        words += ["--data-binary", body]
    line = shlex.join(words)
    extra = " ".join(part for part in (show, _SID_HEADER if with_session else "") if part)
    return line.replace("curl -sS", f"curl -sS {extra}".rstrip(), 1)


def _legacy_http_handshake(bundle: ReproBundle, url: str) -> list[str]:
    version = _version(bundle)
    headers = [*_JSON_HEADERS, f"MCP-Protocol-Version: {version}"]
    init = _json(_legacy_handshake(bundle)[0])
    initialized = _json(_legacy_handshake(bundle)[1])
    return [
        "HDRS=$(mktemp)",
        _curl(url, headers, init, show='-D "$HDRS"'),
        "SID=$(tr -d '\\r' < \"$HDRS\" | awk 'tolower($1)==\"mcp-session-id:\"{print $2}')",
        _curl(url, headers, initialized, show="-o /dev/null", with_session=True),
    ]


_MCP_HEADERS = ("mcp-protocol-version", "mcp-session-id", "mcp-method")


def _raw_http(step: Mapping[str, Any], mcp_url: str, version: str, legacy: bool) -> str:
    """One recorded raw request: to the URL it went to, with the live session in legacy scripts.

    The recorded headers are sent as they are (a check may have left one out on purpose). A step
    with no MCP header at all was recorded without them (older reports), so it gets the protocol
    version and, for a legacy target, the session from the handshake.
    """
    own_url = step.get("url")
    target = own_url if isinstance(own_url, str) and own_url else mcp_url
    recorded = {str(k): str(v) for k, v in (step.get("headers") or {}).items()}
    names = {name.lower() for name in recorded}
    method = str(step.get("method", "POST"))
    on_mcp_endpoint = target == mcp_url
    with_session = False
    if legacy and on_mcp_endpoint:
        with_session = "mcp-session-id" in names or not names & set(_MCP_HEADERS)
        recorded = {k: v for k, v in recorded.items() if k.lower() != "mcp-session-id"}
    if on_mcp_endpoint and method == "POST" and not names & set(_MCP_HEADERS):
        recorded["MCP-Protocol-Version"] = version
    headers = [f"{k}: {v}" for k, v in recorded.items()]
    return _curl(target, headers, str(step.get("body", "")), method, with_session=with_session)


def _http_script(bundle: ReproBundle) -> str:
    steps, skipped = _runnable_steps(bundle, stdio=False)
    url = bundle.target.url or ((bundle.profile.get("target") or {}).get("http") or {}).get("url")
    if not steps:
        return _nothing_to_send(bundle, skipped)
    if not url:
        return "\n".join([*_header(bundle), "# The target URL is not recorded.", "exit 2"]) + "\n"
    lines = [*_header(bundle), "# Only send these to a server you own or may test.", *skipped]
    if (bundle.profile.get("auth") or {}).get("type") == "bearer":
        lines.append("# The scan sent a bearer token; add your own Authorization header below.")
    legacy = _is_legacy(bundle)
    version = _version(bundle)
    next_id = 1
    if legacy:
        lines += _legacy_http_handshake(bundle, url)
        next_id = 2
    for step in steps:
        if step["kind"] == "raw_http":
            lines.append(_raw_http(step, url, version, legacy))
            continue
        message = _message(bundle, next_id, step)
        next_id += 1
        headers = [*_JSON_HEADERS, f"MCP-Protocol-Version: {version}"]
        if not legacy:
            standard = standard_headers(step["method"], step.get("params"))
            headers += [f"{k}: {v}" for k, v in standard.items()]
        lines.append(_curl(url, headers, _json(message), with_session=legacy))
    return "\n".join(lines) + "\n"


def export_script(bundle: ReproBundle) -> str:
    """The script text for ``bundle`` (POSIX sh)."""
    return _http_script(bundle) if bundle.target.transport == "http" else _stdio_script(bundle)
