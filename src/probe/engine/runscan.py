"""One scan from configuration to a ``ScanReport`` (the lifecycle of the design, section 4.2).

Start the target, negotiate its era, discover and classify its tools, run the selected checks in
fixed order, then describe everything that happened. A target that cannot be started or never
answers still gets a report (status ``target_unavailable``) so a CI run leaves evidence.
"""

import contextlib
import fnmatch
import os
import platform
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import probe.checks.protocol
import probe.checks.schema  # noqa: F401 - registers the schema checks
from probe import __version__
from probe.checks.base import Check
from probe.checks.context import ScanConfig, ScanContext
from probe.checks.registry import PHASE_ORDER, REGISTRY
from probe.config.modes import settings_for
from probe.config.profile import (
    Profile,
    ProfileError,
    ResolvedProfile,
    resolve_profile,
    scan_token,
)
from probe.engine.budget import Budget
from probe.engine.discovery import list_tools, tool_infos
from probe.engine.outcomes import CheckResult, Mode, Status, Transport
from probe.engine.scan import run_checks
from probe.engine.versions import CATALOG_VERSION, SCORING_VERSION
from probe.report.json_out import (
    all_findings,
    interim_score,
    result_summaries,
    tool_summaries,
)
from probe.report.models import (
    EraInfo,
    ScanInfo,
    ScanReport,
    Stats,
    TargetInfo,
)
from probe.runners.base import Runner, TargetUnavailable
from probe.runners.local_stdio import LocalStdioRunner
from probe.runners.url import PermissionRequired, UrlRunner
from probe.util.hashing import scan_key
from probe.util.redact import Redactor
from probe.util.sanitize_console import sanitize_console
from probe.wire.errors import (
    MalformedMessage,
    OversizeMessage,
    ProtocolViolation,
    RequestTimeout,
    TransportClosed,
    UnmatchedResponse,
)
from probe.wire.jsonrpc import encode
from probe.wire.limits import ERA_PROBE_TIMEOUT_S, STARTUP_TIMEOUT_S, request_timeout
from probe.wire.recorder import Recorder
from probe.wire.session import LEGACY_VERSIONS, EraChoice, NegotiationFailed, Session
from probe.wire.transport_http import HttpRequestFailed

TRACE_FILE = "trace.jsonl"
_STDERR_TAIL = 2000


class UsageError(Exception):
    """The command line asked for something that cannot be done (exit code 2)."""


@dataclass(frozen=True)
class RunConfig:
    out_dir: Path
    command: Sequence[str] | None = None
    url: str | None = None
    profile: Profile = field(default_factory=Profile)
    mode: Mode = "standard"
    seed: int = 0
    era: EraChoice = "auto"
    allow_side_effects: bool = False
    only: Sequence[str] = ()
    skip: Sequence[str] = ()
    timeout_scale: float = 1.0
    i_have_permission: bool = False
    secret_env: Sequence[str] = ()
    target_env: dict[str, str] = field(default_factory=dict)
    environ: dict[str, str] | None = None  # where --secret-env values are looked up


def select_checks(
    only: Sequence[str], skip: Sequence[str], profile_skip: Mapping[str, str] | None = None
) -> tuple[list[type[Check]], dict[str, str]]:
    """The checks to run and why each of the others is left out (``id -> reason``).

    ``profile_skip`` maps a check id or glob to the reason the profile gives for skipping it.
    """
    selected: list[type[Check]] = []
    excluded: dict[str, str] = {}
    for check in REGISTRY:
        check_id = check.meta.id
        profile_reason = next(
            (r for g, r in (profile_skip or {}).items() if fnmatch.fnmatchcase(check_id, g)), None
        )
        if only and not any(fnmatch.fnmatchcase(check_id, g) for g in only):
            excluded[check_id] = "excluded by --only"
        elif any(fnmatch.fnmatchcase(check_id, g) for g in skip):
            excluded[check_id] = "excluded by --skip"
        elif profile_reason is not None:
            excluded[check_id] = f"skipped by the profile: {profile_reason}"
        else:
            selected.append(check)
    return selected, excluded


def _platform() -> str:
    return f"{platform.system().lower()}/{platform.machine()}"


def _make_runner(cfg: RunConfig, resolved: ResolvedProfile, recorder: Recorder) -> Runner:
    # A command after `--` wins; otherwise the profile's own command (local stdio) is used.
    command = cfg.command
    if command is None and cfg.url is None and resolved.profile.target.image is None:
        command = resolved.profile.target.command
    if cfg.url is not None and command is None:
        return UrlRunner(cfg.url, i_have_permission=cfg.i_have_permission, recorder=recorder)
    if command is not None and cfg.url is None:
        return LocalStdioRunner(command, env={**resolved.env, **cfg.target_env}, recorder=recorder)
    raise UsageError("give either --url or a target command after --, not both or neither")


def _resolve(cfg: RunConfig) -> tuple[ResolvedProfile, dict[str, str]]:
    """The profile with ``{token}`` and ``{secret:NAME}`` filled in, and the host environment."""
    environ = cfg.environ if cfg.environ is not None else dict(os.environ)
    try:
        token = scan_token(cfg.seed, cfg.profile.hash)
        return resolve_profile(cfg.profile, token=token, environ=environ), environ
    except ProfileError as exc:
        raise UsageError(str(exc)) from exc


def _secrets(cfg: RunConfig, resolved: ResolvedProfile, environ: Mapping[str, str]) -> list[str]:
    merged = {**environ, **resolved.env, **cfg.target_env}
    missing = [name for name in cfg.secret_env if name not in merged]
    if missing:
        raise UsageError(f"--secret-env names unset variables: {', '.join(missing)}")
    return [*(merged[name] for name in cfg.secret_env), *resolved.secrets]


def _target_name(cfg: RunConfig) -> str:
    if cfg.profile.name:
        return cfg.profile.name
    if cfg.url:
        return cfg.url
    return Path(cfg.command[0]).name if cfg.command else "target"


def _key(cfg: RunConfig, profile_hash: str) -> str:
    identity = {
        "command": list(cfg.command) if cfg.command else None,
        "url": cfg.url,
        "platform": _platform(),
    }
    return scan_key(
        target_identity=identity,
        probe_version=__version__,
        catalog_version=CATALOG_VERSION,
        scoring_version=SCORING_VERSION,
        profile_hash=profile_hash,
        mode=cfg.mode,
        seed=cfg.seed,
    )


async def run_scan(cfg: RunConfig) -> ScanReport:
    settings = settings_for(cfg.mode, cfg.timeout_scale)
    cfg.out_dir.mkdir(parents=True, exist_ok=True)
    resolved, environ = _resolve(cfg)
    secrets = _secrets(cfg, resolved, environ)
    recorder = Recorder(cfg.out_dir / TRACE_FILE, secrets=secrets)
    runner = _make_runner(cfg, resolved, recorder)
    started = datetime.now(UTC)
    ctx: ScanContext | None = None
    try:
        try:
            ctx = await _connect(
                cfg, resolved, runner, recorder, settings.scan_calls, settings.wall_clock_s
            )
        except PermissionRequired as exc:
            raise UsageError(str(exc)) from exc
        except (
            TargetUnavailable,
            NegotiationFailed,
            TransportClosed,
            HttpRequestFailed,
            RequestTimeout,
            OSError,
        ) as exc:
            return _redacted(_unavailable_report(cfg, started, str(exc), runner), secrets)
        return _redacted(await _scan(cfg, ctx, started), secrets)
    finally:
        with contextlib.suppress(Exception):
            await runner.stop()
        with contextlib.suppress(Exception):
            recorder.close()


def _redacted(report: ScanReport, secrets: Sequence[str]) -> ScanReport:
    """The report with every secret removed from every string and key.

    The trace is redacted as it is written, but the report is built from what the server said
    (tool names, errors, capabilities), so it needs the same treatment before it leaves here.
    """
    if not secrets:
        return report
    clean = Redactor(secrets).redact_json(report.model_dump(mode="json"))
    return ScanReport.model_validate(clean)


async def _connect(
    cfg: RunConfig,
    resolved: ResolvedProfile,
    runner: Runner,
    recorder: Recorder,
    calls: int,
    seconds: float,
) -> ScanContext:
    transport = await runner.start()
    stdio = runner.transport_kind is Transport.STDIO
    session = await Session.open(
        transport,
        era=cfg.era,
        seed=cfg.seed,
        # On stdio the first answer also waits for the server to boot.
        probe_timeout=STARTUP_TIMEOUT_S if stdio else ERA_PROBE_TIMEOUT_S,
        request_timeout=request_timeout(cfg.mode, cfg.timeout_scale),
    )
    listing = await list_tools(session, timeout=request_timeout(cfg.mode, cfg.timeout_scale))
    return ScanContext(
        session=session,
        runner=runner,
        config=ScanConfig(
            mode=cfg.mode,
            seed=cfg.seed,
            allow_side_effects=cfg.allow_side_effects,
            timeout_scale=cfg.timeout_scale,
            target_identity={"command": list(cfg.command or []), "url": cfg.url},
        ),
        tools=tool_infos(
            listing.tools,
            cfg.profile.classifier_view([str(t.get("name")) for t in listing.tools]),
        ),
        budget=Budget(calls, seconds),
        listing=listing,
        profile=resolved.profile,
        trace=recorder,
        second_instance_supported=not isinstance(runner, UrlRunner),
    )


async def _scan(cfg: RunConfig, ctx: ScanContext, started: datetime) -> ScanReport:
    selected, excluded = select_checks(cfg.only, cfg.skip, cfg.profile.checks.skip)
    results = await run_checks(ctx, selected)
    results += [
        CheckResult(check_id=check_id, status=Status.SKIPPED, reason=reason)
        for check_id, reason in excluded.items()
    ]
    results.sort(key=lambda r: (PHASE_ORDER.index(REGISTRY.get(r.check_id).meta.phase), r.check_id))
    finished = datetime.now(UTC)
    rows = result_summaries(results, REGISTRY)
    supported = list(ctx.client.supported_versions)
    kind: Literal["modern", "legacy", "dual"] = ctx.era.value
    if kind == "modern" and any(v in LEGACY_VERSIONS for v in supported):
        kind = "dual"
    profile_hash = cfg.profile.hash
    return ScanReport(
        probe_version=__version__,
        catalog_version=CATALOG_VERSION,
        scoring_version=SCORING_VERSION,
        scan=_scan_info(cfg, started, finished, "completed", profile_hash),
        target=TargetInfo(
            name=_target_name(cfg),
            transport=ctx.runner.transport_kind,
            era=EraInfo(
                kind=kind, negotiated_version=ctx.negotiated_version, supported_versions=supported
            ),
            server_info=ctx.client.server_info,
            package=None,
            image_digest=None,
            profile_hash=profile_hash,
            capabilities=ctx.client.server_capabilities,
            extensions=sorted(ctx.server_extensions),
        ),
        tools=tool_summaries(ctx.tools),
        results=rows,
        findings=all_findings(results),
        score=interim_score(rows),
        stats=_stats(ctx, results),
        limitations=_limitations(cfg, ctx, results),
    )


def _scan_info(
    cfg: RunConfig,
    started: datetime,
    finished: datetime,
    status: Literal["completed", "target_unavailable", "aborted"],
    profile_hash: str,
) -> ScanInfo:
    return ScanInfo(
        id=uuid.uuid4().hex[:12],
        scan_key=_key(cfg, profile_hash),
        status=status,
        started_at=started,
        finished_at=finished,
        duration_ms=int((finished - started).total_seconds() * 1000),
        mode=cfg.mode,
        seed=cfg.seed,
        sandboxed=False,
        platform=_platform(),
        runtime="none",
    )


def _stats(ctx: ScanContext, results: list[CheckResult]) -> Stats:
    events = ctx.wire_events()
    violations = (ProtocolViolation, MalformedMessage, OversizeMessage, UnmatchedResponse)
    phase_ms: dict[str, int] = {}
    for result in results:
        phase = REGISTRY.get(result.check_id).meta.phase
        phase_ms[phase] = phase_ms.get(phase, 0) + result.duration_ms
    sent = received = 0
    for record in ctx.trace_records():
        size = record.get("body_length") or len(encode(record.get("body")))
        if "instance" in record or record.get("dir") == "event":
            continue
        if record.get("dir") == "c2s":
            sent += size
        elif record.get("dir") == "s2c":
            received += size
    return Stats(
        calls=ctx.budget.used,
        protocol_errors=sum(isinstance(e, violations) for e in events),
        tool_errors=0,
        restarts=ctx.crashes.restarts,
        crashes=list(ctx.crashes.events),
        bytes_in=received,
        bytes_out=sent,
        phase_ms=phase_ms,
    )


def _limitations(cfg: RunConfig, ctx: ScanContext, results: list[CheckResult]) -> list[str]:
    notes: list[str] = []
    by_reason: dict[str, int] = {}
    for result in results:
        if result.status in (Status.SKIPPED, Status.NA) and result.reason:
            key = f"{result.status.value}: {result.reason}"
            by_reason[key] = by_reason.get(key, 0) + 1
    notes += [f"{count} check(s) {reason}" for reason, count in sorted(by_reason.items())]
    errors = [r.check_id for r in results if r.status is Status.ERROR]
    if errors:
        notes.append(f"{len(errors)} check(s) could not reach a verdict: {', '.join(errors)}")
    if not ctx.side_effects_allowed:
        skipped = [t.name for t in ctx.tools if t.kind != "read"]
        if skipped:
            notes.append(
                f"{len(skipped)} tool(s) that may write were not called (use --allow-side-effects "
                "or a sandbox)"
            )
    if ctx.listing is not None and not ctx.listing.complete:
        notes.append(f"tools/list was incomplete: {ctx.listing.error}")
    notes += [f"plugin {name} failed to load: {why}" for name, why in REGISTRY.plugin_errors]
    notes.append("scoring is not implemented in this build: no grade is reported")
    return notes


def _unavailable_report(
    cfg: RunConfig, started: datetime, reason: str, runner: Runner
) -> ScanReport:
    finished = datetime.now(UTC)
    profile_hash = cfg.profile.hash
    stderr = ""
    transport = getattr(runner, "_transport", None)
    if transport is not None:
        stderr = transport.stderr_tail(_STDERR_TAIL).strip()
    notes = [f"target unavailable: {sanitize_console(reason)}"]
    if stderr:
        notes.append(f"server stderr: {sanitize_console(stderr)}")
    return ScanReport(
        probe_version=__version__,
        catalog_version=CATALOG_VERSION,
        scoring_version=SCORING_VERSION,
        scan=_scan_info(cfg, started, finished, "target_unavailable", profile_hash),
        target=TargetInfo(
            name=_target_name(cfg),
            transport=runner.transport_kind,
            era=EraInfo(kind=None, negotiated_version=None, supported_versions=[]),
            server_info={},
            package=None,
            image_digest=None,
            profile_hash=profile_hash,
            capabilities={},
            extensions=[],
        ),
        tools=[],
        results=[],
        findings=[],
        score=interim_score([]),
        stats=Stats(
            calls=0,
            protocol_errors=0,
            tool_errors=0,
            restarts=0,
            crashes=[],
            bytes_in=0,
            bytes_out=0,
            phase_ms={},
        ),
        limitations=notes,
    )
