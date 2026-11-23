"""Behavior contracts for the standalone classifier (no server or schema resolver)."""

from copy import deepcopy
from typing import Any

import pytest

from probe.classify import classify_tool
from probe.engine.outcomes import ToolInfo
from probe.engine.phases import gate
from tests.checks.helpers import make_meta
from tests.engine.fakes import make_context

LEXICONS = {
    "exec": "exec execute run shell command cmd eval spawn script bash terminal",
    "destructive": (
        "delete remove rm drop destroy purge truncate kill terminate reset revoke overwrite "
        "wipe force unlink archive"
    ),
    "write": (
        "create add insert update set put post write save upload send publish push commit merge "
        "move rename append edit patch assign close open comment label star fork transfer approve"
    ),
    "read": (
        "get list read search find fetch query describe show view lookup browse count check "
        "inspect info status download retrieve"
    ),
}


@pytest.mark.parametrize(
    ("kind", "token"),
    [(kind, token) for kind, words in LEXICONS.items() for token in words.split()],
)
def test_every_exact_lexicon_token(kind: str, token: str) -> None:
    info = classify_tool(f"widgets_{token}", {})
    assert isinstance(info, ToolInfo)
    assert info.kind == kind
    assert info.classification_source == "heuristic"
    assert token in info.classification_reason
    assert "name" in info.classification_reason


@pytest.mark.parametrize(
    "name", ["get_items", "get-items", "items.get", "getItems", "HTTPGetItems"]
)
def test_name_token_boundaries(name: str) -> None:
    assert classify_tool(name, {}).kind == "read"


@pytest.mark.parametrize("name", ["target", "setting", "payload", "forget", "runner", "evaluate"])
def test_substrings_are_not_lexicon_tokens(name: str) -> None:
    info = classify_tool(name, {})
    assert info.kind == "unknown"
    assert info.classification_reason


@pytest.mark.parametrize(
    ("name", "kind"),
    [
        ("get_delete_run", "exec"),
        ("run_delete_get", "exec"),
        ("get_update_delete", "destructive"),
        ("delete_update_get", "destructive"),
        ("get_update", "write"),
        ("update_get", "write"),
    ],
)
def test_risk_priority_beats_token_position(name: str, kind: str) -> None:
    assert classify_tool(name, {}).kind == kind


@pytest.mark.parametrize(
    ("description", "kind"),
    [
        ("Read the current widget.", "read"),
        ("Please LIST widgets! Then delete them.", "read"),
        ("A widget helper. Delete all widgets.", "unknown"),
        ("A widget helper? Run shell commands.", "unknown"),
        ("Read and then delete widgets.", "destructive"),
        ("getItems from storage", "read"),
        ("The setting and payload belong to a target.", "unknown"),
        ("", "unknown"),
        (None, "unknown"),
    ],
)
def test_only_first_description_sentence_is_a_fallback(description: str | None, kind: str) -> None:
    info = classify_tool("widgets", {}, description=description)
    assert info.kind == kind
    assert "description" in info.classification_reason or kind == "unknown"


def test_read_name_keeps_description_fallback_behavior() -> None:
    assert classify_tool("get_widgets", {}, description="Delete all widgets.").kind == "read"


@pytest.mark.parametrize(
    "capability",
    ["delete", "revoke", "wipe", "truncate", "archive", "deletion", "dismissal", "archiving"],
)
def test_write_name_escalates_on_first_sentence_destructive_capability(capability: str) -> None:
    info = classify_tool(
        "update_catalog",
        {},
        description=f"Maintain a catalog with optional {capability} of entries.",
    )
    assert (info.kind, info.classification_source) == ("destructive", "heuristic")
    assert "first description sentence" in info.classification_reason
    assert capability in info.classification_reason
    assert "write" in info.classification_reason


@pytest.mark.parametrize(
    "word",
    [
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
    ],
)
def test_explicit_destructive_word_forms_use_token_boundaries(word: str) -> None:
    assert classify_tool(f"catalog_{word}", {}).kind == "destructive"
    assert (
        classify_tool("catalog", {}, description=f"Supports {word} of entries.").kind
        == "destructive"
    )
    assert (
        classify_tool("edit_catalog", {}, description=f"Supports {word} of entries.").kind
        == "destructive"
    )


@pytest.mark.parametrize(
    ("name", "description", "kind"),
    [
        ("edit_catalog", "Maintain entries. Supports deletion of entries.", "write"),
        ("edit_catalog", "Read entries without changing anything.", "write"),
        ("edit_catalog", "Run a validation script.", "write"),
        ("edit_catalog", "Maintain undeleted entries with an archiver.", "write"),
        ("edit_catalog", "Maintain dismissalish metadata and unarchiving preferences.", "write"),
        ("edit_catalog", "Maintain entries without deletion.", "destructive"),
        ("get_catalog", "Supports dismissal and deletion of entries.", "read"),
        ("run_catalog", "Supports deletion of entries.", "exec"),
        ("delete_catalog", "Read entries.", "destructive"),
        ("catalog_undeleted", None, "unknown"),
        ("catalog_archiver", None, "unknown"),
        ("catalog_dismissalish", None, "unknown"),
    ],
)
def test_destructive_refinement_limits_and_conservative_ambiguity(
    name: str, description: str | None, kind: str
) -> None:
    assert classify_tool(name, {}, description=description).kind == kind


@pytest.mark.parametrize(
    ("annotations", "kind"),
    [({"readOnlyHint": True}, "read"), ({"destructiveHint": False}, "write")],
)
def test_destructive_description_cannot_override_annotations(
    annotations: dict[str, Any], kind: str
) -> None:
    info = classify_tool(
        "edit_catalog", {}, description="Supports deletion of entries.", annotations=annotations
    )
    assert (info.kind, info.classification_source) == (kind, "annotations")


def test_destructive_description_cannot_override_profile() -> None:
    info = classify_tool(
        "edit_catalog",
        {},
        description="Supports deletion of entries.",
        annotations={"destructiveHint": True},
        profile={"tools": {"edit_catalog": {"kind": "read"}}},
    )
    assert (info.kind, info.classification_source) == ("read", "profile")


@pytest.mark.parametrize(
    ("annotations", "kind"),
    [
        ({}, "read"),
        ({"readOnlyHint": True}, "read"),
        ({"readOnlyHint": True, "destructiveHint": True}, "read"),
        ({"readOnlyHint": True, "destructiveHint": "false"}, "read"),
        ({"readOnlyHint": False}, "destructive"),
        ({"destructiveHint": True}, "destructive"),
        ({"destructiveHint": False}, "write"),
        ({"readOnlyHint": False, "destructiveHint": False}, "write"),
        ({"title": "Read widgets"}, "destructive"),
        ({"openWorldHint": False}, "destructive"),
        ({"idempotentHint": True}, "destructive"),
        ({"readOnlyHint": "true"}, "destructive"),
        ({"readOnlyHint": 1}, "destructive"),
        ({"readOnlyHint": None}, "destructive"),
        ({"readOnlyHint": []}, "destructive"),
        ({"readOnlyHint": {"value": True}}, "destructive"),
        ({"destructiveHint": 0}, "destructive"),
        ({"destructiveHint": 1}, "destructive"),
        ({"destructiveHint": "false"}, "destructive"),
        ({"destructiveHint": None}, "destructive"),
        ({"destructiveHint": []}, "destructive"),
        ({"readOnlyHint": "true", "destructiveHint": False}, "write"),
    ],
)
def test_annotations_override_heuristics_with_strict_boolean_defaults(
    annotations: dict[str, Any], kind: str
) -> None:
    info = classify_tool("get_widgets", {}, annotations=annotations)
    assert info.kind == kind
    assert info.classification_source == ("annotations" if annotations else "heuristic")
    assert info.classification_reason
    if annotations:
        assert "Hint" in info.classification_reason


@pytest.mark.parametrize("kind", ["read", "write", "destructive", "exec", "unknown"])
def test_profile_override_has_highest_priority(kind: str) -> None:
    info = classify_tool(
        "delete_widgets",
        {},
        annotations={"readOnlyHint": True},
        profile={"tools": {"delete_widgets": {"kind": kind}}},
    )
    assert info.kind == kind
    assert info.classification_source == "profile"
    assert "tools.delete_widgets.kind" in info.classification_reason


@pytest.mark.parametrize("kind", [None, True, 1, "READ", "erase", "", [], {}])
def test_invalid_override_kind_is_rejected(kind: Any) -> None:
    with pytest.raises(ValueError, match=r"tools.get_widgets.kind"):
        classify_tool("get_widgets", {}, profile={"tools": {"get_widgets": {"kind": kind}}})


@pytest.mark.parametrize(
    "profile", [{}, {"tools": {}}, {"tools": {"other": {"kind": "exec"}}}, {"tools": {"get": {}}}]
)
def test_unset_override_allows_annotations(profile: dict[str, Any]) -> None:
    info = classify_tool("get", {}, annotations={"destructiveHint": False}, profile=profile)
    assert (info.kind, info.classification_source) == ("write", "annotations")


async def test_unknown_is_compatible_with_existing_write_gate() -> None:
    info = classify_tool("mystery", {})
    assert info.kind == "unknown"
    ctx, _ = await make_context(tools=[info])
    assert gate(make_meta(requires=frozenset({"write_tools"})), ctx) is None


@pytest.mark.parametrize("fmt", ["uri", "uri-reference", "iri", "url"])
def test_url_formats(fmt: str) -> None:
    info = classify_tool("get", {"properties": {"address": {"format": fmt}}})
    assert info.param_roles == {"address": "url_param"}
    assert info.flags == {"url_param"}


@pytest.mark.parametrize(
    "name",
    [
        "url",
        "uri",
        "href",
        "link",
        "endpoint",
        "webhook",
        "callback",
        "src_url",
        "target_url",
        "image_url",
        "URL",
    ],
)
def test_url_names(name: str) -> None:
    info = classify_tool("get", {"properties": {name: {}}})
    assert info.param_roles == {name: "url_param"}


def test_url_description_is_case_insensitive_and_uses_word_boundaries() -> None:
    info = classify_tool(
        "get", {"properties": {"address": {"description": "The destination URL."}, "curl": {}}}
    )
    assert info.param_roles == {"address": "url_param"}


@pytest.mark.parametrize(
    "name",
    [
        "path",
        "file",
        "filename",
        "filepath",
        "file_path",
        "dir",
        "directory",
        "folder",
        "root",
        "dest",
        "destination",
        "source",
        "src",
        "target_path",
        "repo_path",
        "PATH",
    ],
)
def test_path_names(name: str) -> None:
    assert classify_tool("get", {"properties": {name: {}}}).param_roles == {name: "path_param"}


@pytest.mark.parametrize("context", ["sql", "database", "db", "postgres", "sqlite", "mysql"])
@pytest.mark.parametrize("name", ["sql", "query", "statement", "SQL"])
def test_sql_roles_require_tool_context(context: str, name: str) -> None:
    schema = {"properties": {name: {}}}
    assert classify_tool(f"{context}_helper", schema).param_roles == {name: "sql_param"}
    assert classify_tool("helper", schema, description=f"A {context} helper.").param_roles == {
        name: "sql_param"
    }


@pytest.mark.parametrize(
    "context", [None, "Search text", "dogit dbx mysqlish", "A widget databaseish"]
)
def test_query_name_and_property_description_alone_do_not_imply_sql(context: str | None) -> None:
    schema = {"properties": {"query": {"description": "A SQL query"}}}
    assert classify_tool("search", schema, description=context).param_roles == {}


@pytest.mark.parametrize("context", ["git", "shell", "command", "cli"])
@pytest.mark.parametrize(
    "name",
    ["command", "cmd", "args", "argv", "script", "ref", "rev", "revision", "branch", "commit"],
)
def test_command_roles_require_context_or_exec_kind(context: str, name: str) -> None:
    schema = {"properties": {name: {}}}
    assert classify_tool(f"{context}_helper", schema).param_roles == {name: "command_param"}
    assert classify_tool("helper", schema, description=f"A {context} helper.").param_roles == {
        name: "command_param"
    }
    assert classify_tool("run", schema).param_roles == {name: "command_param"}
    assert classify_tool(
        "helper", schema, profile={"tools": {"helper": {"kind": "exec"}}}
    ).flags == {"command_param"}


def test_command_role_does_not_infer_context_from_parameter_name_or_substring() -> None:
    assert classify_tool("get", {"properties": {"command": {}, "branch": {}}}).param_roles == {}
    assert classify_tool("digit", {"properties": {"ref": {}}}).param_roles == {}


@pytest.mark.parametrize(
    "name",
    [
        "password",
        "passwd",
        "client_secret",
        "access_token",
        "api_key",
        "apikey",
        "credential",
        "auth",
        "private_key",
        "privatekey",
        "API_KEY",
    ],
)
def test_sensitive_name_patterns(name: str) -> None:
    assert classify_tool("get", {"properties": {name: {}}}).param_roles == {name: "sensitive_param"}


def test_combined_flags_keep_sensitive_primary_and_all_detected_roles() -> None:
    info = classify_tool(
        "run_sql",
        {
            "properties": {
                "token_path": {"format": "uri"},
                "query": {"description": "A URL containing SQL"},
                "command": {"format": "url"},
                "path": {"format": "uri"},
            }
        },
    )
    assert info.flags == {
        "sensitive_param",
        "url_param",
        "path_param",
        "sql_param",
        "command_param",
    }
    assert info.param_roles == {
        "token_path": "sensitive_param",
        "query": "sql_param",
        "command": "command_param",
        "path": "path_param",
    }


@pytest.mark.parametrize("name", ["cursor", "page", "page_token", "offset"])
def test_input_pagination_names(name: str) -> None:
    assert "paginated" in classify_tool("get", {"properties": {name: {}}}).flags


@pytest.mark.parametrize("name", ["nextCursor", "next_page"])
def test_output_pagination_names(name: str) -> None:
    assert "paginated" in classify_tool("get", {}, output_schema={"properties": {name: {}}}).flags


def test_only_top_level_properties_are_used_without_reference_resolution() -> None:
    schema = {
        "$ref": "#/$defs/Input",
        "$defs": {"Input": {"properties": {"url": {}}}},
        "properties": {"nested": {"properties": {"cursor": {}, "password": {}}}},
    }
    info = classify_tool(
        "get", schema, output_schema={"properties": {"nested": {"nextCursor": {}}}}
    )
    assert info.param_roles == {}
    assert info.flags == set()
    assert "paginated" not in classify_tool("get", {"properties": {"page_size": {}}}).flags


@pytest.mark.parametrize("properties", [None, [], True, "url", 42])
def test_malformed_properties_container_is_ignored(properties: Any) -> None:
    info = classify_tool(
        "get", {"properties": properties}, output_schema={"properties": properties}
    )
    assert info.flags == set()
    assert info.param_roles == {}


def test_malformed_property_definitions_keep_name_signals_without_crashing() -> None:
    info = classify_tool(
        "get",
        {
            "properties": {
                "url": False,
                "file": [],
                "password": None,
                "other": 42,
                "x": {"format": [], "description": {"url": True}},
            }
        },
    )
    assert info.param_roles == {
        "url": "url_param",
        "file": "path_param",
        "password": "sensitive_param",
    }


def test_returned_info_preserves_metadata_without_mutating_or_aliasing_caller_data() -> None:
    schema = {"properties": {"url": {"format": "uri", "examples": ["https://example.test"]}}}
    output = {"properties": {"nextCursor": {"type": "string"}}}
    annotations = {"readOnlyHint": True, "extra": {"values": [1]}}
    profile = {"tools": {"get": {"kind": "read"}}}
    original = deepcopy((schema, output, annotations, profile))
    info = classify_tool(
        "get",
        schema,
        title="Widget lookup",
        description="Read widget.",
        output_schema=output,
        annotations=annotations,
        profile=profile,
    )
    assert (schema, output, annotations, profile) == original
    assert info.input_schema == schema
    assert info.output_schema == output
    assert info.annotations == annotations
    assert (info.name, info.title, info.description) == ("get", "Widget lookup", "Read widget.")
    again = classify_tool(
        "get",
        schema,
        title="Widget lookup",
        description="Read widget.",
        output_schema=output,
        annotations=annotations,
        profile=profile,
    )
    assert info.model_dump_json() == again.model_dump_json()
    info.input_schema["properties"]["url"]["examples"].append("changed")
    assert info.output_schema is not None
    info.output_schema["properties"]["nextCursor"]["type"] = "number"
    info.annotations["extra"]["values"].append(2)
    assert (schema, output, annotations, profile) == original


@pytest.mark.parametrize("profile", [{"tools": []}, {"tools": {"get": None}}])
def test_malformed_override_container_is_rejected(profile: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="profile tools"):
        classify_tool("get", {}, profile=profile)


@pytest.mark.parametrize("name", ["install", "scale", "navigate", "log", "screenshot", "click"])
def test_no_additional_verbs_are_invented(name: str) -> None:
    assert classify_tool(name, {}).kind == "unknown"


def test_annotations_beat_exec_name_and_description() -> None:
    info = classify_tool(
        "run", {}, description="Delete data.", annotations={"destructiveHint": False}
    )
    assert (info.kind, info.classification_source) == ("write", "annotations")


def test_description_context_for_roles_can_come_from_later_sentences() -> None:
    info = classify_tool(
        "get",
        {"properties": {"query": {}, "ref": {}}},
        description="Read metadata. The backend uses a SQL database and Git CLI.",
    )
    assert info.param_roles == {"query": "sql_param", "ref": "command_param"}


def test_url_description_requires_the_url_word_and_formats_are_exact() -> None:
    info = classify_tool(
        "get",
        {"properties": {"first": {"description": "curl options"}, "second": {"format": "URI"}}},
    )
    assert info.param_roles == {}
