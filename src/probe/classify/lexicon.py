"""Fixed token vocabulary; order expresses risk, never server-specific exceptions."""

import re

from probe.engine.outcomes import ToolKind

# Explicit word forms, not a stemmer: adding a suffix must not invent a match.
DESTRUCTIVE_TOKENS = frozenset(
    [
        "delete",
        "remove",
        "rm",
        "drop",
        "destroy",
        "purge",
        "truncate",
        "kill",
        "terminate",
        "reset",
        "revoke",
        "overwrite",
        "wipe",
        "force",
        "unlink",
        "archive",
        "deletes",
        "deleted",
        "deleting",
        "deletion",
        "deletions",
        "dismiss",
        "dismisses",
        "dismissed",
        "dismissing",
        "dismissal",
        "dismissals",
        "archives",
        "archived",
        "archiving",
    ]
)

KIND_LEXICONS: tuple[tuple[ToolKind, frozenset[str]], ...] = (
    (
        "exec",
        frozenset(
            [
                "exec",
                "execute",
                "run",
                "shell",
                "command",
                "cmd",
                "eval",
                "spawn",
                "script",
                "bash",
                "terminal",
            ]
        ),
    ),
    ("destructive", DESTRUCTIVE_TOKENS),
    (
        "write",
        frozenset(
            [
                "create",
                "add",
                "insert",
                "update",
                "set",
                "put",
                "post",
                "write",
                "save",
                "upload",
                "send",
                "publish",
                "push",
                "commit",
                "merge",
                "move",
                "rename",
                "append",
                "edit",
                "patch",
                "assign",
                "close",
                "open",
                "comment",
                "label",
                "star",
                "fork",
                "transfer",
                "approve",
            ]
        ),
    ),
    (
        "read",
        frozenset(
            [
                "get",
                "list",
                "read",
                "search",
                "find",
                "fetch",
                "query",
                "describe",
                "show",
                "view",
                "lookup",
                "browse",
                "count",
                "check",
                "inspect",
                "info",
                "status",
                "download",
                "retrieve",
            ]
        ),
    ),
)


def tokenize(text: str) -> tuple[str, ...]:
    """Split identifiers and prose, including camelCase and acronym boundaries."""
    text = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", text)
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    return tuple(word.lower() for word in re.findall(r"[A-Za-z0-9]+", text))
