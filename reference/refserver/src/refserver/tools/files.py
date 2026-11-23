"""read_file / write_file, contained under the allowed root.

Containment is decided on fully resolved paths (`os.path.realpath`, which
follows every symlink) with `os.path.commonpath`, never on string prefixes,
so `../`, absolute paths, symlinks out and the `allowed_evil` prefix sibling
are all rejected. Opens use O_NOFOLLOW so a symlink swapped in after the
check is refused rather than followed.
"""

from __future__ import annotations

import json
import os
import stat
from typing import TYPE_CHECKING, Annotated

from mcp.server.mcpserver.exceptions import ToolError
from pydantic import Field

from refserver.tools import READ, hints

if TYPE_CHECKING:
    from pathlib import Path

    from mcp.server.mcpserver import MCPServer

    from refserver.config import Config

MAX_READ = 1024 * 1024
MAX_WRITE = 1024 * 1024

PathArg = Annotated[
    str,
    Field(
        min_length=1,
        max_length=1024,
        description="Path relative to the allowed root, e.g. notes/a.txt.",
    ),
]


def resolve_contained(root: Path, path: str) -> str:
    """Return the real path for `path` under `root`, or raise ToolError if it escapes."""
    if "\x00" in path:
        raise ToolError("path must not contain NUL bytes")
    real_root = os.path.realpath(root)
    candidate = os.path.realpath(os.path.join(real_root, path))
    if os.path.commonpath([real_root, candidate]) != real_root:
        raise ToolError(f"path {path!r} is outside the allowed root; use a path relative to it")
    return candidate


def read_contained(root: Path, path: str) -> dict[str, object]:
    real = resolve_contained(root, path)
    try:
        fd = os.open(real, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        raise ToolError(f"file {path!r} does not exist") from None
    except IsADirectoryError:
        raise ToolError(f"{path!r} is a directory, not a file") from None
    except OSError as exc:
        raise ToolError(f"cannot open {path!r}: {exc.strerror}") from None
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        os.close(fd)
        raise ToolError(f"{path!r} is a directory or special file, not a regular file")
    with os.fdopen(fd, "rb") as fh:
        size = info.st_size
        data = fh.read(MAX_READ)
    return {
        "path": os.path.relpath(real, os.path.realpath(root)),
        "size": size,
        "content": data.decode("utf-8", errors="replace"),
        "truncated": size > MAX_READ,
    }


def write_contained(root: Path, path: str, content: str) -> dict[str, object]:
    data = content.encode()
    if len(data) > MAX_WRITE:
        raise ToolError(f"content is {len(data)} bytes; the limit is {MAX_WRITE}")
    real = resolve_contained(root, path)
    if real == os.path.realpath(root):
        raise ToolError("path must name a file, not the allowed root")
    if not os.path.isdir(os.path.dirname(real)):
        raise ToolError(f"parent directory of {path!r} does not exist")
    try:
        fd = os.open(real, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
    except IsADirectoryError:
        raise ToolError(f"{path!r} is a directory, not a file") from None
    except OSError as exc:
        raise ToolError(f"cannot write {path!r}: {exc.strerror}") from None
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    return {"path": os.path.relpath(real, os.path.realpath(root)), "bytes_written": len(data)}


def register(mcp: MCPServer, cfg: Config) -> None:
    root = cfg.allowed_root

    @mcp.tool(structured_output=False, annotations=READ)
    def read_file(path: PathArg) -> str:
        """Read a text file under the allowed root (first 1 MiB)."""
        return json.dumps(read_contained(root, path))

    @mcp.tool(
        structured_output=False,
        annotations=hints(read_only=False, destructive=True, idempotent=True),
    )
    def write_file(
        path: PathArg,
        content: Annotated[
            str, Field(max_length=MAX_WRITE, description="Full new file content (UTF-8).")
        ],
    ) -> str:
        """Create or overwrite a file under the allowed root. Idempotent."""
        return json.dumps(write_contained(root, path, content))
