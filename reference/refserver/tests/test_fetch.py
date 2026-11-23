from __future__ import annotations

import httpx
import pytest
from mcp import Client
from mcp.server.mcpserver.exceptions import ToolError
from refserver.tools.fetch import Fetcher

from tests.helpers import call

pytestmark = pytest.mark.anyio

PUBLIC_IP = "11.250.0.10"  # the sandbox's public-looking subnet; is_global is True

BLOCKED_LITERALS = [
    "http://127.0.0.1/",
    "http://127.0.0.1:8080/x",
    "http://localhost/",
    "http://LOCALHOST./",
    "http://foo.localhost/",
    "http://[::1]/",
    "http://10.0.0.1/",
    "http://172.16.5.4/",
    "http://192.168.1.1/",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata/",
    "http://instance-data/",
    "http://2130706433/",  # decimal 127.0.0.1
    "http://0x7f000001/",  # hex
    "http://0177.0.0.1/",  # octal
    "http://127.1/",  # short form
    "http://0/",
    "http://[::ffff:127.0.0.1]/",  # IPv4-mapped IPv6
    "http://[::ffff:7f00:1]/",
    "http://[fe80::1]/",
    "http://[fd00::1]/",
    "http://100.64.0.1/",  # carrier-grade NAT
]
BAD_SCHEMES = [
    "file:///etc/passwd",
    "ftp://example.com/",
    "gopher://127.0.0.1:70/",
    "dict://x/",
    "javascript:alert(1)",
]


@pytest.mark.parametrize("url", BLOCKED_LITERALS + BAD_SCHEMES + ["http://user:pw@example.com/"])
async def test_tool_blocks_without_network(client: Client, url: str) -> None:
    is_error, text = await call(client, "fetch_url", {"url": url})
    assert is_error, url
    assert "blocked" in text or "scheme" in text or "credentials" in text


def resolver(table: dict[str, list[str]]):
    async def resolve(host: str, port: int) -> list[str]:
        return table[host]

    return resolve


class Recorder:
    """httpx transport that answers from a script and records what was sent."""

    def __init__(self, responses: dict[str, httpx.Response]) -> None:
        self.responses = responses
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.responses[f"{request.url.host}{request.url.path}"]


async def test_public_host_connects_to_vetted_ip_with_host_header() -> None:
    rec = Recorder({f"{PUBLIC_IP}/hello.txt": httpx.Response(200, text="probe-public-ok")})
    fetcher = Fetcher(resolver({"public.probe.test": [PUBLIC_IP]}), httpx.MockTransport(rec))
    out = await fetcher.fetch("http://public.probe.test/hello.txt")
    assert out["status"] == 200 and out["body"] == "probe-public-ok"
    sent = rec.requests[0]
    assert sent.url.host == PUBLIC_IP
    assert sent.headers["host"] == "public.probe.test"


async def test_https_keeps_sni_hostname() -> None:
    rec = Recorder({f"{PUBLIC_IP}/": httpx.Response(200, text="ok")})
    fetcher = Fetcher(resolver({"public.probe.test": [PUBLIC_IP]}), httpx.MockTransport(rec))
    await fetcher.fetch("https://public.probe.test/")
    assert rec.requests[0].extensions["sni_hostname"] == "public.probe.test"


@pytest.mark.parametrize(
    "answers", [["10.1.2.3"], [PUBLIC_IP, "127.0.0.1"], ["::1"], ["169.254.169.254"]]
)
async def test_hostname_resolving_to_private_is_blocked(answers: list[str]) -> None:
    rec = Recorder({})
    fetcher = Fetcher(resolver({"evil.test": answers}), httpx.MockTransport(rec))
    with pytest.raises(ToolError, match="blocked"):
        await fetcher.fetch("http://evil.test/")
    assert rec.requests == []


async def test_redirect_to_private_is_blocked() -> None:
    rec = Recorder(
        {
            f"{PUBLIC_IP}/redirect": httpx.Response(
                302, headers={"location": "http://127.0.0.1/admin"}
            )
        }
    )
    fetcher = Fetcher(resolver({"public.probe.test": [PUBLIC_IP]}), httpx.MockTransport(rec))
    with pytest.raises(ToolError, match="blocked"):
        await fetcher.fetch("http://public.probe.test/redirect")
    assert len(rec.requests) == 1


async def test_redirect_to_private_hostname_is_blocked() -> None:
    rec = Recorder(
        {f"{PUBLIC_IP}/r": httpx.Response(307, headers={"location": "http://internal.test/x"})}
    )
    fetcher = Fetcher(
        resolver({"public.probe.test": [PUBLIC_IP], "internal.test": ["192.168.0.5"]}),
        httpx.MockTransport(rec),
    )
    with pytest.raises(ToolError, match="blocked"):
        await fetcher.fetch("http://public.probe.test/r")


async def test_up_to_three_redirects_followed_then_refused() -> None:
    hops = {
        f"{PUBLIC_IP}/{i}": httpx.Response(302, headers={"location": f"/{i + 1}"}) for i in range(4)
    }
    hops[f"{PUBLIC_IP}/4"] = httpx.Response(200, text="done")
    fetcher = Fetcher(
        resolver({"public.probe.test": [PUBLIC_IP]}), httpx.MockTransport(Recorder(hops))
    )
    assert (await fetcher.fetch("http://public.probe.test/1"))["body"] == "done"  # 3 redirects
    with pytest.raises(ToolError, match="too many redirects"):
        await fetcher.fetch("http://public.probe.test/0")  # 4 redirects


async def test_redirect_to_file_scheme_is_blocked() -> None:
    rec = Recorder(
        {f"{PUBLIC_IP}/r": httpx.Response(302, headers={"location": "file:///etc/passwd"})}
    )
    fetcher = Fetcher(resolver({"public.probe.test": [PUBLIC_IP]}), httpx.MockTransport(rec))
    with pytest.raises(ToolError, match="scheme"):
        await fetcher.fetch("http://public.probe.test/r")
