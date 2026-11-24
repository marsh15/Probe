"""no_secret_leak on a scripted server (the fault injection needs fakehttp, which only the Docker
sandbox has), and oauth_scopes_minimal on the real reference server over HTTP."""

from pathlib import Path
from typing import Any

import pytest

from probe.checks.safety.oauth import OauthScopesMinimal
from probe.checks.safety.secrets import NoSecretLeak
from probe.config.profile import Profile, parse_profile
from probe.engine.outcomes import Severity, Status
from tests.checks.protocol.harness import scripted_scan, url_scan
from tests.conftest import launch_http
from tests.engine.fakes import tool
from tests.wire.fake_eras import EraServer, Reply, result

SECRET = "probe_fake_tok_0123456789ab"


class FakeBackendFixtures:
    """The parts of the sandbox's fixtures that the check uses: a log of backend requests and a
    switch that makes the backend fail."""

    token = "0123456789abcdef"

    def __init__(self) -> None:
        self.armed = False
        self.requests: list[dict[str, Any]] = []

    async def reset(self) -> None:
        self.armed = False

    async def backend_log(self, since: int = 0) -> list[dict[str, Any]]:
        return [r for r in self.requests if r["sequence"] > since]

    async def backend_fault(self, route: str | None, *, count: int = 1) -> bool:
        self.armed = route is not None
        return True


class Backend(EraServer):
    """A tool that reads from a backend and, when the backend fails, says too much about it."""

    def __init__(self, fixtures: FakeBackendFixtures, leak: str) -> None:
        super().__init__()
        self.fixtures, self.leak = fixtures, leak

    def handle(self, msg: dict[str, Any], headers: dict[str, str] | None) -> Reply | None:
        if msg.get("method") != "tools/call":
            return super().handle(msg, headers)
        self.fixtures.requests.append({"sequence": len(self.fixtures.requests) + 1, "path": "/c/1"})
        if self.fixtures.armed:
            text = f"backend error (HTTP 429) {self.leak}"
            return result(
                msg["id"],
                {
                    "resultType": "complete",
                    "isError": True,
                    "content": [{"type": "text", "text": text}],
                },
            )
        body = [{"type": "text", "text": "item 1"}]
        return result(msg["id"], {"resultType": "complete", "content": body})


def profile() -> Profile:
    return parse_profile(
        f"version: 1\ntarget:\n  secrets:\n    API_TOKEN: {{value: {SECRET}, real: false}}\n"
    )


async def run_leak(tmp_path: Path, leak: str) -> Any:
    fixtures = FakeBackendFixtures()
    async with scripted_scan(lambda: Backend(fixtures, leak), tmp_path) as scan:
        scan.ctx.fixtures = fixtures  # type: ignore[assignment]
        scan.ctx.profile = profile()
        scan.ctx.tools = [tool("read_backend")]
        return await scan.run(NoSecretLeak)


async def test_an_error_that_echoes_the_injected_secret_is_a_high_finding(tmp_path: Path) -> None:
    out = await run_leak(tmp_path, f"headers: Authorization: Bearer {SECRET}")
    assert out.status is Status.FAIL
    [finding] = out.findings
    assert finding.severity is Severity.HIGH and finding.tool == "read_backend"
    assert SECRET in finding.evidence.observations["excerpt"]


async def test_a_generic_credential_pattern_is_a_medium_finding(tmp_path: Path) -> None:
    out = await run_leak(tmp_path, "key AKIAABCDEFGHIJKLMNOP")
    assert out.status is Status.FAIL
    assert {f.severity for f in out.findings} == {Severity.MEDIUM}


async def test_an_error_that_keeps_secrets_out_passes(tmp_path: Path) -> None:
    out = await run_leak(tmp_path, "try again later")
    assert out.status is Status.PASS, out.reason


TOKENS = "alice:probe_fake_alice_t,bob:probe_fake_bob_t"


async def run_oauth(seeded_data: Path, tmp_path: Path, bug: str) -> Any:
    with launch_http(seeded_data, bugs=bug, extra_env={"REFSERVER_TOKENS": TOKENS}) as url:
        headers = {"Authorization": "Bearer probe_fake_alice_t"}
        async with url_scan(url, tmp_path, headers=headers) as scan:
            return await scan.run(OauthScopesMinimal)


async def test_the_clean_server_publishes_narrow_scopes(seeded_data: Path, tmp_path: Path) -> None:
    out = await run_oauth(seeded_data, tmp_path, "")
    assert out.status is Status.PASS, (out.reason, [f.title for f in out.findings])
    # its authorization server is not on this machine, so Probe says it did not ask it
    assert {f.severity for f in out.findings} <= {Severity.INFO}


async def test_b43_wildcard_and_admin_scopes_are_caught(seeded_data: Path, tmp_path: Path) -> None:
    out = await run_oauth(seeded_data, tmp_path, "b43")
    assert out.status is Status.FAIL, (out.status, out.reason)
    assert "broad scopes" in out.findings[0].title


@pytest.mark.parametrize("kind", ["stdio"])
async def test_a_stdio_server_has_no_oauth_to_judge(kind: str, tmp_path: Path) -> None:
    async with scripted_scan(EraServer, tmp_path) as scan:
        out = await scan.run(OauthScopesMinimal)
    assert out.status is Status.NA
