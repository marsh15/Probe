from __future__ import annotations

import json

from mcp import Client


async def call(
    client: Client, name: str, args: dict[str, object] | None = None
) -> tuple[bool, str]:
    """Call a tool and return (is_error, first text block)."""
    result = await client.call_tool(name, args or {})
    return result.is_error, result.content[0].text if result.content else ""


async def call_json(client: Client, name: str, args: dict[str, object] | None = None) -> object:
    is_error, text = await call(client, name, args)
    assert not is_error, text
    return json.loads(text)
