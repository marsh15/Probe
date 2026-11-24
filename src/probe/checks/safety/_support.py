"""What the safety checks that call tools with hostile input have in common."""

import asyncio
import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from probe.checks.context import CallResult, ScanContext
from probe.checks.protocol._support import message_view
from probe.config.profile import Profile
from probe.engine.crash import TargetCrashed
from probe.engine.outcomes import ToolInfo
from probe.schema.valid_gen import generate_valid
from probe.wire.errors import RequestTimeout

DEFAULT_ALLOWED_ROOT = "/data/allowed"
CANARY_DIR = "probe-canary"


def allowed_roots(ctx: ScanContext) -> list[str]:
    """The directories tools may touch, from the profile (the sandbox layout by default)."""
    profile = ctx.profile
    fs = profile.fixtures.fs if isinstance(profile, Profile) else None
    return list(fs.allowed_roots) if fs is not None and fs.allowed_roots else [DEFAULT_ALLOWED_ROOT]


def data_root(ctx: ScanContext) -> str:
    """The directory that holds the allowed root, the secret directory and the canary directory."""
    return str(PurePosixPath(allowed_roots(ctx)[0]).parent)


def canary_dir(ctx: ScanContext) -> str:
    """A directory tools must never write into by themselves; Probe's own marker lands here."""
    return f"{data_root(ctx)}/{CANARY_DIR}"


def absolute(ctx: ScanContext, path: str) -> str:
    """A fixture-diff path made absolute (the sandbox reports paths relative to /data)."""
    return path if path.startswith("/") else f"{data_root(ctx)}/{path}"


def is_inside(path: str, roots: list[str]) -> bool:
    normal = str(PurePosixPath(path))
    return any(normal == r or normal.startswith(r.rstrip("/") + "/") for r in roots)


def params_with_role(tool: ToolInfo, role: str) -> list[str]:
    return [name for name, found in tool.param_roles.items() if found == role]


def tools_with_role(ctx: ScanContext, role: str) -> Iterator[tuple[ToolInfo, list[str]]]:
    for tool in ctx.callable_tools():
        if names := params_with_role(tool, role):
            yield tool, names


async def valid_arguments(ctx: ScanContext, tool: ToolInfo) -> dict[str, Any] | None:
    """Arguments the tool should accept (profile inputs first, else generated)."""
    generated = await asyncio.to_thread(
        generate_valid,
        tool,
        seed=ctx.config.seed,
        mode="quick",
        profile=ctx.profile if isinstance(ctx.profile, Profile) else None,
        allowed_roots=allowed_roots(ctx),
    )
    return next((c.arguments for c in generated.cases if isinstance(c.arguments, dict)), None)


async def safe_call(ctx: ScanContext, tool: str, arguments: dict[str, Any], case_id: str) -> Any:
    """The call's result, or None when the target died or did not answer (the engine records
    crashes; a hostile payload that only hangs the server is not this check's verdict)."""
    try:
        return await ctx.call(tool, arguments, case_id=case_id)
    except (TargetCrashed, RequestTimeout):
        return None


def output_text(result: CallResult | None) -> str:
    if result is None:
        return ""
    return json.dumps(result.response.to_obj(), ensure_ascii=False)


@dataclass(frozen=True, slots=True)
class ToolReply:
    """One answered ``tools/call`` as the trace holds it."""

    tool: str
    arguments: Any
    seq: int
    text: str  # everything a client would show or feed to a model: content, structured data, errors
    is_error: bool


def _reply_text(message: dict[str, Any]) -> str:
    error = message.get("error")
    if isinstance(error, dict):
        return str(error.get("message", ""))
    result = message.get("result")
    if not isinstance(result, dict):
        return ""
    parts: list[str] = []
    for block in result.get("content") or []:
        if isinstance(block, dict) and isinstance(block.get("text"), str):
            parts.append(block["text"])
    if "structuredContent" in result:
        parts.append(json.dumps(result["structuredContent"], ensure_ascii=False))
    return "\n".join(parts)


def tool_replies(ctx: ScanContext) -> list[ToolReply]:
    """Every answered tools/call on the main instance, in order (ids restart on restart, so a
    response is paired with the latest earlier request that has its id)."""
    sent: dict[Any, dict[str, Any]] = {}
    found: list[ToolReply] = []
    records = [r for r in ctx.trace_records() if "instance" not in r]
    for record in sorted(records, key=lambda r: r["seq"]):
        view = message_view(record)
        if view is None or "id" not in view:
            continue
        if record.get("dir") == "c2s" and view.get("method") == "tools/call":
            sent[view["id"]] = view.get("params") or {}
        elif record.get("dir") == "s2c" and view["id"] in sent:
            params = sent.pop(view["id"])
            result = view.get("result")
            is_error = "error" in view or (
                isinstance(result, dict) and result.get("isError") is True
            )
            found.append(
                ToolReply(
                    str(params.get("name")), params.get("arguments"), record["seq"],
                    _reply_text(view), is_error,
                )
            )  # fmt: skip
    return found


def excerpt(text: str, start: int, width: int = 80) -> str:
    """A short piece of ``text`` around ``start``, one line."""
    lo = max(0, start - width // 2)
    return text[lo : lo + width].replace("\n", " ")
