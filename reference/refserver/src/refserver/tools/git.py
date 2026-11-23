"""git_log over the seeded repository, safe against argument injection."""

from __future__ import annotations

import asyncio
import json
import os
import re
from typing import TYPE_CHECKING, Annotated

from mcp.server.mcpserver.exceptions import ToolError
from pydantic import Field

from refserver.tools import READ

if TYPE_CHECKING:
    from pathlib import Path

    from mcp.server.mcpserver import MCPServer

    from refserver.config import Config

REF_RE = re.compile(r"^[A-Za-z0-9._/-]+$")
TIMEOUT = 10.0


def validate_ref(ref: str) -> str:
    if not REF_RE.match(ref) or ref.startswith("-"):
        raise ToolError(
            f"invalid ref {ref!r}; use a branch, tag or commit id such as 'main' or 'v1.0'"
        )
    return ref


async def git_log_entries(repo: Path, ref: str, max_count: int) -> list[dict[str, str]]:
    validate_ref(ref)
    # --end-of-options makes git treat the ref as a revision even if validation were bypassed;
    # the trailing "--" stops it from being read as a path.
    argv = [
        "git", "-C", str(repo), "log", f"--max-count={max_count}",
        "--format=%H%x1f%an%x1f%aI%x1f%s", "--end-of-options", ref, "--",
    ]  # fmt: skip
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "GIT_CONFIG_NOSYSTEM": "1",
        "HOME": str(repo),
    }
    proc = await asyncio.create_subprocess_exec(
        *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), TIMEOUT)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        raise ToolError("git log timed out") from None
    if proc.returncode != 0:
        if b"unknown revision" in err or b"bad revision" in err or b"ambiguous argument" in err:
            raise ToolError(f"unknown ref {ref!r}; try 'main', 'v1.0' or 'feature/notes'")
        raise ToolError(f"git log failed (exit {proc.returncode})")
    entries = []
    for line in out.decode(errors="replace").splitlines():
        commit, author, date, subject = line.split("\x1f", 3)
        entries.append({"commit": commit, "author": author, "date": date, "subject": subject})
    return entries


def register(mcp: MCPServer, cfg: Config) -> None:
    repo = cfg.repo_path

    @mcp.tool(structured_output=False, annotations=READ)
    async def git_log(
        ref: Annotated[
            str,
            Field(
                min_length=1, max_length=200, description="Branch, tag or commit id, e.g. 'main'."
            ),
        ] = "main",
        max_count: Annotated[int, Field(ge=1, le=50, description="Number of commits (1-50).")] = 10,
    ) -> str:
        """List commits reachable from a ref in the demo repository, newest first."""
        return json.dumps(await git_log_entries(repo, ref, max_count))
