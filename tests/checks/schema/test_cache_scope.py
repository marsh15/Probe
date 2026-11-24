"""schema.cache_scope_correct: clean and failing servers, using two bearer identities."""

from pathlib import Path
from typing import Any

import pytest

from probe.checks.schema.scope import CacheScopeCorrect
from probe.config.profile import Profile, parse_profile
from probe.engine.outcomes import Severity, Status
from tests.checks.protocol.harness import ToolsServer, http_scan, scripted_scan, url_scan
from tests.conftest import launch_http
from tests.wire.fake_http import serve

PROFILE_TEXT = """
version: 1
target: {transport: http}
auth:
  type: bearer
  identities:
    - {name: alice, token: probe_fake_alice_t}
    - {name: bob, token: probe_fake_bob_t}
"""
SHARED = {"name": "shared", "inputSchema": {"type": "object"}}
ONLY_ALICE = {"name": "alice_only", "inputSchema": {"type": "object"}}


def profile() -> Profile:
    return parse_profile(PROFILE_TEXT)


def identities() -> list[str]:
    return [i.name for i in profile().auth.identities]


class PerUser(ToolsServer):
    """Alice sees one more tool than bob; ``scope`` is what tools/list claims."""

    def __init__(self, scope: str, bob_differs: bool = True, **kwargs: Any) -> None:
        super().__init__(list_extra={"cacheScope": scope}, **kwargs)
        self.bob_differs = bob_differs

    def _modern(self, id_: Any, method: str, *rest: Any) -> Any:
        reply = super()._modern(id_, method, *rest)
        headers = rest[-1] or {}
        if method == "tools/list" and reply and reply.body and "result" in reply.body:
            bob = "bob" in headers.get("authorization", "")
            only_bob = bob and self.bob_differs
            reply.body["result"]["tools"] = [SHARED] if only_bob else [SHARED, ONLY_ALICE]
        return reply


async def run_scope(http_fake: Any, tmp_path: Path, server: ToolsServer) -> Any:
    async with http_scan(http_fake, tmp_path, server=server) as scan:
        scan.ctx.profile = profile()
        scan.ctx.auth_identities = tuple(identities())
        return await scan.run(CacheScopeCorrect)


@pytest.fixture
async def http_fake() -> Any:
    async with serve() as running:
        yield running


async def test_public_list_that_differs_per_user_fails(http_fake: Any, tmp_path: Path) -> None:
    result = await run_scope(http_fake, tmp_path, PerUser("public"))
    assert result.status is Status.FAIL
    [finding] = result.findings
    assert finding.severity is Severity.HIGH
    assert "tools/list" in finding.title
    seen = finding.evidence.observations["identities"]
    assert seen["alice"]["count"] == 2 and seen["bob"]["count"] == 1
    assert "probe_fake_alice_t" not in finding.model_dump_json()


async def test_private_list_that_differs_passes(http_fake: Any, tmp_path: Path) -> None:
    assert (await run_scope(http_fake, tmp_path, PerUser("private"))).status is Status.PASS


async def test_public_list_that_is_the_same_for_everyone_passes(
    http_fake: Any, tmp_path: Path
) -> None:
    server = PerUser("public", bob_differs=False)
    assert (await run_scope(http_fake, tmp_path, server)).status is Status.PASS


async def test_one_identity_is_not_applicable(http_fake: Any, tmp_path: Path) -> None:
    async with http_scan(http_fake, tmp_path, server=PerUser("public")) as scan:
        scan.ctx.auth_identities = ("alice",)
        result = await scan.run(CacheScopeCorrect)
    assert result.status is Status.NA


async def test_legacy_era_is_not_applicable(tmp_path: Path) -> None:
    async with scripted_scan(
        lambda: PerUser("public", legacy=True), tmp_path, era="legacy"
    ) as scan:
        scan.ctx.auth_identities = tuple(identities())
        result = await scan.run(CacheScopeCorrect)
    assert result.status is Status.NA


async def test_clean_refserver_passes(seeded_data: Path, tmp_path: Path) -> None:
    tokens = "alice:probe_fake_alice_t,bob:probe_fake_bob_t"
    with launch_http(seeded_data, extra_env={"REFSERVER_TOKENS": tokens}) as url:
        headers = {"Authorization": "Bearer probe_fake_alice_t"}
        async with url_scan(
            url, tmp_path, headers=headers, profile=profile(), auth_identities=identities()
        ) as scan:
            result = await scan.run(CacheScopeCorrect)
    assert result.status is Status.PASS, (result.reason, result.findings)


async def test_b14_refserver_is_caught(seeded_data: Path, tmp_path: Path) -> None:
    """b14: the per-user tool list is marked public."""
    tokens = "alice:probe_fake_alice_t,bob:probe_fake_bob_t"
    with launch_http(seeded_data, bugs="b14", extra_env={"REFSERVER_TOKENS": tokens}) as url:
        headers = {"Authorization": "Bearer probe_fake_alice_t"}
        async with url_scan(
            url, tmp_path, headers=headers, profile=profile(), auth_identities=identities()
        ) as scan:
            result = await scan.run(CacheScopeCorrect)
    assert result.status is Status.FAIL, (result.reason, result.findings)
