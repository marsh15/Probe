"""Phase order and the central rules that decide whether a check runs at all.

The engine, not each check, decides NA and SKIPPED from ``CheckMeta``:

* SKIPPED means Probe chose not to run it: not in this mode, no sandbox fixtures, side effects
  not allowed, no ``--llm``.
* NA means it cannot apply to this server: wrong era, transport or protocol version, or the
  server lacks what the check examines (tools, URL parameters, the Tasks extension...).

Not-in-mode wins over everything; then NA is judged before SKIPPED, because a check that can
never apply should say so rather than blame the run's settings.
"""

from dataclasses import dataclass
from typing import TYPE_CHECKING

from probe.checks.context import TASKS_EXTENSION
from probe.engine.outcomes import CheckMeta, Phase, Status
from probe.engine.outcomes import Transport as TransportKind

if TYPE_CHECKING:
    from probe.checks.context import ScanContext

ACTIVE_PHASES: frozenset[Phase] = frozenset(
    {"active.safe", "active.write", "active.adversarial", "active.stress"}
)
_WRITE_KINDS = frozenset({"write", "destructive", "exec", "unknown"})  # unknown counts as write


@dataclass(frozen=True, slots=True)
class Gate:
    status: Status  # NA or SKIPPED
    reason: str


def gate(meta: CheckMeta, ctx: "ScanContext") -> Gate | None:
    """None if the check should run; otherwise why it must not."""
    if ctx.config.mode not in meta.modes:
        return Gate(Status.SKIPPED, f"not part of {ctx.config.mode} mode")
    if (reason := _not_applicable(meta, ctx)) is not None:
        return Gate(Status.NA, reason)
    if (reason := _skipped(meta, ctx)) is not None:
        return Gate(Status.SKIPPED, reason)
    return None


def _not_applicable(meta: CheckMeta, ctx: "ScanContext") -> str | None:
    if ctx.era not in meta.eras:
        eras = "/".join(sorted(e.value for e in meta.eras))
        return f"applies to {eras} servers; this one negotiated {ctx.era.value}"
    if ctx.runner.transport_kind not in meta.transports:
        transports = "/".join(sorted(t.value for t in meta.transports))
        return f"applies to {transports} targets; this one is {ctx.runner.transport_kind.value}"
    if meta.min_version is not None and ctx.negotiated_version < meta.min_version:
        return f"needs protocol {meta.min_version} or later; negotiated {ctx.negotiated_version}"
    tools = ctx.tools
    needs = meta.requires
    if "tools" in needs and not tools:
        return "the server has no tools"
    if "url_tools" in needs and not any("url_param" in t.flags for t in tools):
        return "no tool takes a URL parameter"
    if "path_tools" in needs and not any("path_param" in t.flags for t in tools):
        return "no tool takes a path parameter"
    if "write_tools" in needs and not any(t.kind in _WRITE_KINDS for t in tools):
        return "no tool writes anything"
    if "paginated" in needs and not any("paginated" in t.flags for t in tools):
        return "no tool is paginated"
    if "http" in needs and ctx.runner.transport_kind is not TransportKind.HTTP:
        return "needs an HTTP target"
    if "auth_identities" in needs and not ctx.auth_identities:
        return "no auth identities configured"
    if "tasks_ext" in needs and TASKS_EXTENSION not in ctx.server_extensions:
        return "the server does not advertise the Tasks extension"
    if "second_instance" in needs and not ctx.second_instance_supported:
        return "this runner cannot start a second instance"
    return None


def _skipped(meta: CheckMeta, ctx: "ScanContext") -> str | None:
    needs = meta.requires
    if "fixtures" in needs and ctx.fixtures is None:
        return "requires sandbox (fixtures)"
    if "side_effects" in needs and not ctx.side_effects_allowed:
        return "requires --allow-side-effects or a sandbox"
    if "llm" in needs and ctx.llm is None:
        return "requires --llm"
    return None
