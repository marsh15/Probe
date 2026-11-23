"""Private-network and file URL checks use observed disclosures, never error text."""

import ipaddress
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from jsonschema import validate

from probe.checks.context import ScanConfig
from probe.checks.safety.urls import FileSchemeBlocked, SsrfBlocked
from probe.classify.tools import classify_tool
from probe.config.profile import Profile
from probe.engine.outcomes import Severity, Status, Transport
from probe.wire.errors import TransportClosed
from tests.engine.fakes import DyingServer, FakeRunner, make_context
from tests.wire.fake_eras import result

TOKEN = "a1b2c3d4e5f6"
CANARY = "172.20.4.2"
SCHEMA = {
    "type": "object",
    "properties": {
        "url": {"type": "string", "format": "uri"},
        "count": {"type": "integer", "minimum": 2, "maximum": 5},
    },
    "required": ["url", "count"],
    "additionalProperties": False,
}
TOOL = classify_tool("fetch_url", input_schema=SCHEMA, annotations={"readOnlyHint": True})
IP_HOSTS = {
    "ip-dotted": CANARY,
    "ip-decimal": str(int(ipaddress.IPv4Address(CANARY))),
    "ip-hex": hex(int(ipaddress.IPv4Address(CANARY))),
    "ip-octal": ".".join(f"0{int(part):o}" for part in CANARY.split(".")),
    "ip-mapped": f"::ffff:{CANARY}",
}


class Fixtures:
    token = TOKEN
    canary_ip = CANARY

    def __init__(self) -> None:
        self.hits: list[dict[str, Any]] = []
        self.sequence = 0

    async def reset(self) -> None:
        self.hits.clear()

    async def canary_hits(self, since: int = 0) -> list[dict[str, Any]]:
        return [h for h in self.hits if h["sequence"] > since]

    def hit(self, url: str) -> None:
        parts = urlsplit(url)
        self.sequence += 1
        self.hits.append(
            {
                "sequence": self.sequence,
                "host": parts.netloc,
                "path": parts.path,
                "query": parts.query,
            }
        )


class FetchServer(DyingServer):
    def __init__(
        self,
        fixtures: Fixtures,
        *,
        leak: str = "",
        crash: bool = False,
        baseline_ok: bool = True,
        misleading: str = "",
    ) -> None:
        super().__init__()
        self.fixtures = fixtures
        self.leak, self.crash = leak, crash
        self.baseline_ok, self.misleading = baseline_ok, misleading
        self.urls: list[str] = []

    def handle(self, msg: dict[str, Any], headers: Any) -> Any:
        if msg.get("method") != "tools/call":
            return super().handle(msg, headers)
        args = msg["params"]["arguments"]
        url = args["url"]
        self.urls.append(url)
        if url.startswith("http:"):
            validate(args, SCHEMA)  # The generator must fill the unrelated required argument.
        parts = urlsplit(url)
        if parts.hostname == "public.probe.test" and parts.path == "/hello.txt":
            return result(
                msg["id"],
                {
                    "content": [{"type": "text", "text": "probe-public-ok"}],
                    "isError": not self.baseline_ok,
                },
            )
        if self.crash and parts.hostname == CANARY:
            assert self.transport is not None
            self.transport._mark_closed(TransportClosed(139, "segfault"))
            return None
        if self.leak == "file" and parts.scheme == "file":
            text = f"PROBE-SENTINEL-{TOKEN}" if "SENTINEL" in url else "root:x:0:0:root"
            return result(msg["id"], {"content": [{"type": "text", "text": text}]})
        redirect = parts.hostname == "public.probe.test" and parts.path == "/redirect"
        if self.leak == "redirect" and redirect:
            self.fixtures.hit(parse_qs(parts.query)["to"][0])
        elif (
            self.leak == "all"
            or parts.hostname == IP_HOSTS.get(self.leak)
            or (self.leak == "metadata" and parts.hostname == "metadata.google.internal")
        ):
            self.fixtures.hit(url)
        elif self.leak == "unrelated":
            self.fixtures.hit(f"http://{CANARY}/another-scan")
        return result(
            msg["id"], {"isError": True, "content": [{"type": "text", "text": self.misleading}]}
        )


async def run(
    check: Any,
    *,
    kind: Transport = Transport.STDIO,
    mode: str = "standard",
    profile: Profile | None = None,
    **kwargs: Any,
) -> Any:
    from probe.engine.scan import run_checks

    fixtures = Fixtures()
    servers: list[FetchServer] = []

    def factory() -> FetchServer:
        server = FetchServer(fixtures, **kwargs)
        servers.append(server)
        return server

    ctx, runner = await make_context(
        runner=FakeRunner(factory, kind=kind),
        tools=[TOOL],
        fixtures=fixtures,
        profile=profile,
        config=ScanConfig(mode=mode),
    )
    runner.sandboxed = True
    try:
        [outcome] = await run_checks(ctx, [check])
        return outcome, [url for server in servers for url in server.urls], ctx
    finally:
        await runner.stop()


@pytest.mark.parametrize("check", [SsrfBlocked, FileSchemeBlocked])
async def test_clean_tool_passes(check: Any) -> None:
    outcome, urls, _ = await run(check)
    assert outcome.status is Status.PASS
    assert not outcome.findings
    assert urls[0] == "http://public.probe.test/hello.txt"


@pytest.mark.parametrize("payload", IP_HOSTS)
async def test_each_ip_encoding_has_its_own_evidence(payload: str) -> None:
    outcome, _, _ = await run(SsrfBlocked, leak=payload)
    assert outcome.status is Status.FAIL
    [finding] = outcome.findings
    assert finding.repro.case_id.endswith(payload)
    assert finding.severity is Severity.HIGH
    observations = finding.evidence.observations
    assert observations["canary_hit"]["host"].strip("[]") == IP_HOSTS[payload]
    assert TOKEN in observations["canary_hit"]["path"]
    assert observations["request"] == finding.repro.steps[-1]
    assert observations["payload_id"] == payload


async def test_redirect_only_bypass_is_attributed_to_redirect() -> None:
    outcome, _, _ = await run(SsrfBlocked, leak="redirect")
    assert outcome.status is Status.FAIL
    [finding] = outcome.findings
    assert finding.evidence.observations["payload_id"] == "redirect"
    assert "/redirect?to=" in finding.evidence.observations["request"]["params"]["arguments"]["url"]


async def test_query_only_canary_token_is_evidence() -> None:
    outcome, _, _ = await run(SsrfBlocked, leak="metadata")
    assert outcome.status is Status.FAIL
    [finding] = outcome.findings
    assert finding.evidence.observations["canary_hit"]["query"] == f"t={TOKEN}"


async def test_http_ssrf_is_critical() -> None:
    outcome, _, _ = await run(SsrfBlocked, kind=Transport.HTTP, leak="ip-dotted")
    assert outcome.findings[0].severity is Severity.CRITICAL


async def test_file_read_reports_both_disclosures() -> None:
    outcome, _, _ = await run(FileSchemeBlocked, leak="file")
    assert outcome.status is Status.FAIL
    assert {f.evidence.observations["payload_id"] for f in outcome.findings} == {
        "sentinel",
        "passwd",
    }
    assert all(f.severity is Severity.HIGH for f in outcome.findings)
    assert f"PROBE-SENTINEL-{TOKEN}" in outcome.findings[0].model_dump_json()


@pytest.mark.parametrize("check", [SsrfBlocked, FileSchemeBlocked])
async def test_unavailable_baseline_is_na(check: Any) -> None:
    outcome, urls, _ = await run(check, baseline_ok=False)
    assert outcome.status is Status.NA
    assert "cannot establish that the tool can fetch at all" in outcome.reason
    assert urls == ["http://public.probe.test/hello.txt"]


async def test_crash_is_recorded_without_an_ssrf_finding_and_campaign_continues() -> None:
    outcome, urls, ctx = await run(SsrfBlocked, crash=True, mode="quick")
    assert outcome.status is Status.PASS
    assert not outcome.findings
    assert ctx.crashes.events
    assert any("metadata.google.internal" in u for u in urls)
    assert any("/redirect?" in u for u in urls)


async def test_private_network_override_is_info_and_makes_no_calls() -> None:
    profile = Profile(tools={"fetch_*": {"allow_private_network": True}})
    outcome, urls, _ = await run(SsrfBlocked, profile=profile, leak="all")
    assert outcome.status is Status.PASS
    assert [f.severity for f in outcome.findings] == [Severity.INFO]
    assert not urls


@pytest.mark.parametrize("check", [SsrfBlocked, FileSchemeBlocked])
async def test_engine_gates_missing_tools_and_fixtures(check: Any) -> None:
    from probe.engine.scan import run_checks

    ctx, runner = await make_context(tools=[])
    try:
        [outcome] = await run_checks(ctx, [check])
        assert outcome.status is Status.NA
        ctx.tools = [TOOL]
        [outcome] = await run_checks(ctx, [check])
        assert outcome.status is Status.SKIPPED
    finally:
        await runner.stop()


@pytest.mark.parametrize("mode,count", [("quick", 3), ("standard", 9), ("deep", 9)])
async def test_mode_caps(mode: str, count: int) -> None:
    outcome, urls, _ = await run(SsrfBlocked, mode=mode)
    assert outcome.status is Status.PASS
    assert len(urls) == count + 1


async def test_unrelated_hits_and_echoed_canary_text_are_not_evidence() -> None:
    outcome, _, _ = await run(SsrfBlocked, leak="unrelated", misleading=f"probe-canary {TOKEN}")
    assert outcome.status is Status.PASS


async def test_wrong_scan_sentinel_is_not_a_disclosure() -> None:
    outcome, _, _ = await run(FileSchemeBlocked, misleading="PROBE-SENTINEL-other-scan")
    assert outcome.status is Status.PASS


@pytest.mark.parametrize("check", [SsrfBlocked, FileSchemeBlocked])
async def test_cached_unrelated_baseline_cannot_mask_a_failed_public_fetch(check: Any) -> None:
    from probe.checks.context import CallResult
    from probe.engine.scan import run_checks
    from probe.wire.jsonrpc import ResultResponse

    fixtures = Fixtures()
    server = FetchServer(fixtures, baseline_ok=False)
    ctx, runner = await make_context(
        runner=FakeRunner(lambda: server),
        tools=[TOOL],
        fixtures=fixtures,
    )
    runner.sandboxed = True
    ctx._baselines[TOOL.name] = CallResult(ResultResponse(0, {"content": []}), 0)
    try:
        [outcome] = await run_checks(ctx, [check])
        assert outcome.status is Status.NA
        assert server.urls == ["http://public.probe.test/hello.txt"]
    finally:
        await runner.stop()


@pytest.mark.parametrize("check", [SsrfBlocked, FileSchemeBlocked])
async def test_legacy_tools_are_checked(check: Any) -> None:
    from probe.engine.scan import run_checks

    fixtures = Fixtures()
    ctx, runner = await make_context(
        runner=FakeRunner(
            lambda: FetchServer(
                fixtures, leak="file" if check is FileSchemeBlocked else "ip-dotted"
            )
        ),
        tools=[TOOL],
        fixtures=fixtures,
        era="legacy",
    )
    runner.sandboxed = True
    try:
        [outcome] = await run_checks(ctx, [check])
        assert outcome.status is Status.FAIL
    finally:
        await runner.stop()


@pytest.mark.parametrize("check", [SsrfBlocked, FileSchemeBlocked])
async def test_cached_failed_baseline_does_not_prevent_public_fetch(check: Any) -> None:
    from probe.engine.scan import run_checks

    fixtures = Fixtures()
    server = FetchServer(fixtures)
    ctx, runner = await make_context(
        runner=FakeRunner(lambda: server),
        tools=[TOOL],
        fixtures=fixtures,
    )
    runner.sandboxed = True
    ctx._baselines[TOOL.name] = None
    try:
        [outcome] = await run_checks(ctx, [check])
        assert outcome.status is Status.PASS
        assert server.urls[0] == "http://public.probe.test/hello.txt"
    finally:
        await runner.stop()
