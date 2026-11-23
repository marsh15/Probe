"""Classify supplied metadata without calling tools or interpreting schema references."""

import re
from collections.abc import Mapping
from copy import deepcopy
from typing import Any, Literal, cast, get_args

from probe.classify.lexicon import DESTRUCTIVE_TOKENS, KIND_LEXICONS, tokenize
from probe.engine.outcomes import ToolFlag, ToolInfo, ToolKind

_URL_NAME = re.compile(
    r"^(url|uri|href|link|endpoint|webhook|callback|src_url|target_url|.*_url)$", re.IGNORECASE
)
_PATH_NAME = re.compile(
    r"^(path|file|filename|filepath|file_path|dir|directory|folder|root|dest|destination|source|src|"
    r"target_path|.*_path)$",
    re.IGNORECASE,
)
_SQL_NAME = re.compile(r"^(sql|query|statement)$", re.IGNORECASE)
_COMMAND_NAME = re.compile(
    r"^(command|cmd|args|argv|script|ref|rev|revision|branch|commit)$", re.IGNORECASE
)
_SENSITIVE_NAME = re.compile(
    r"password|passwd|secret|token|api_?key|credential|auth|private_?key", re.IGNORECASE
)
_URL_FORMATS = frozenset({"uri", "uri-reference", "iri", "url"})
_SQL_CONTEXT = frozenset({"sql", "database", "db", "postgres", "sqlite", "mysql"})
_COMMAND_CONTEXT = frozenset({"git", "shell", "command", "cli"})
_INPUT_PAGING = frozenset({"cursor", "page", "page_token", "offset"})
_OUTPUT_PAGING = frozenset({"nextCursor", "next_page"})
# All matches remain in flags; this order selects the one primary role per property.
_ROLE_PRIORITY: tuple[ToolFlag, ...] = (
    "sensitive_param",
    "command_param",
    "sql_param",
    "path_param",
    "url_param",
)


def _profile_kind(name: str, profile: Mapping[str, Any] | None) -> ToolKind | None:
    if profile is None or "tools" not in profile:
        return None
    tools = profile["tools"]
    if not isinstance(tools, Mapping):
        raise ValueError("profile tools must be a mapping")
    if name not in tools:
        return None
    entry = tools[name]
    if not isinstance(entry, Mapping):
        raise ValueError(f"profile tools.{name} must be a mapping")
    if "kind" not in entry:
        return None
    kind = entry["kind"]
    if not isinstance(kind, str) or kind not in get_args(ToolKind):
        raise ValueError(
            f"profile tools.{name}.kind must be one of {', '.join(get_args(ToolKind))}"
        )
    return cast(ToolKind, kind)


def _heuristic_kind(name: str, description: str | None) -> tuple[ToolKind, str]:
    first_sentence = re.split(r"[.!?](?:\s|$)", description or "", maxsplit=1)[0]
    for source, text in (
        ("name", name),
        ("first description sentence", first_sentence),
    ):
        tokens = tokenize(text)
        for kind, vocabulary in KIND_LEXICONS:
            for token in tokens:
                if token in vocabulary:
                    if source == "name" and kind == "write":
                        for capability in tokenize(first_sentence):
                            if capability in DESTRUCTIVE_TOKENS:
                                return (
                                    "destructive",
                                    f"name token '{token}' matches write vocabulary; "
                                    f"first description sentence token '{capability}' "
                                    "raises write to destructive (risk priority)",
                                )
                    return (
                        kind,
                        f"{source} token '{token}' matches {kind} vocabulary (risk priority)",
                    )
    return (
        "unknown",
        "No recognized token in name or first description sentence; unknown gates as write",
    )


def _annotation_kind(annotations: Mapping[str, Any]) -> tuple[ToolKind, str]:
    if annotations.get("readOnlyHint") is True:
        return "read", "readOnlyHint is strictly true"
    read_reason = "readOnlyHint is not strictly true"
    if annotations.get("destructiveHint") is False:
        return "write", f"{read_reason}; destructiveHint is strictly false"
    if "destructiveHint" not in annotations:
        return "destructive", f"{read_reason}; destructiveHint absent defaults to true"
    if annotations["destructiveHint"] is True:
        return "destructive", f"{read_reason}; destructiveHint is strictly true"
    return "destructive", f"{read_reason}; malformed destructiveHint treated conservatively as true"


def _properties(schema: Mapping[str, Any] | None) -> Mapping[str, Any]:
    properties = schema.get("properties") if schema is not None else None
    return properties if isinstance(properties, Mapping) else {}


def _parameter_roles(
    name: str,
    description: str | None,
    kind: ToolKind,
    input_schema: Mapping[str, Any],
    output_schema: Mapping[str, Any] | None,
) -> tuple[set[ToolFlag], dict[str, str]]:
    context = set(tokenize(name)) | set(tokenize(description or ""))
    sql_context = bool(context & _SQL_CONTEXT)
    command_context = kind == "exec" or bool(context & _COMMAND_CONTEXT)
    properties = _properties(input_schema)
    flags: set[ToolFlag] = set()
    roles: dict[str, str] = {}
    for param, definition in properties.items():
        if not isinstance(param, str):
            continue
        details = definition if isinstance(definition, Mapping) else {}
        matches: set[ToolFlag] = set()
        fmt = details.get("format")
        description_value = details.get("description")
        if (
            (isinstance(fmt, str) and fmt in _URL_FORMATS)
            or _URL_NAME.fullmatch(param)
            or (
                isinstance(description_value, str)
                and re.search(r"\bURL\b", description_value, re.IGNORECASE)
            )
        ):
            matches.add("url_param")
        if _PATH_NAME.fullmatch(param):
            matches.add("path_param")
        if sql_context and _SQL_NAME.fullmatch(param):
            matches.add("sql_param")
        if command_context and _COMMAND_NAME.fullmatch(param):
            matches.add("command_param")
        if _SENSITIVE_NAME.search(param):
            matches.add("sensitive_param")
        if matches:
            flags.update(matches)
            roles[param] = next(role for role in _ROLE_PRIORITY if role in matches)
    if _INPUT_PAGING.intersection(properties) or _OUTPUT_PAGING.intersection(
        _properties(output_schema)
    ):
        flags.add("paginated")
    return flags, roles


def classify_tool(
    name: str,
    input_schema: dict[str, Any],
    *,
    title: str | None = None,
    description: str | None = None,
    output_schema: dict[str, Any] | None = None,
    annotations: Mapping[str, Any] | None = None,
    profile: Mapping[str, Any] | None = None,
) -> ToolInfo:
    """Return an independent ToolInfo using profile, annotation, then token evidence.

    ``profile`` is a mapping with optional ``tools.<exact name>.kind`` entries. An
    explicitly supplied invalid kind raises ValueError. Only top-level properties
    contribute roles/pagination; supplied schemas and annotations are copied intact.
    """
    annotation_data = dict(annotations) if annotations is not None else {}
    override = _profile_kind(name, profile)
    source: Literal["profile", "annotations", "heuristic"]
    if override is not None:
        kind, source, reason = (
            override,
            "profile",
            f"profile tools.{name}.kind explicitly sets {override}",
        )
    elif annotation_data:
        kind, reason = _annotation_kind(annotation_data)
        source = "annotations"
    else:
        kind, reason = _heuristic_kind(name, description)
        source = "heuristic"
    flags, roles = _parameter_roles(name, description, kind, input_schema, output_schema)
    return ToolInfo(
        name=name,
        title=title,
        description=description,
        input_schema=deepcopy(input_schema),
        output_schema=deepcopy(output_schema),
        annotations=deepcopy(annotation_data),
        kind=kind,
        flags=flags,
        classification_source=source,
        classification_reason=reason,
        param_roles=roles,
    )
