"""Header value encoding, standard headers and x-mcp-header handling (spec: streamable HTTP)."""

import pytest

from probe.wire.headers import (
    HeaderMirror,
    decode_header_value,
    encode_header_value,
    mirror_headers,
    parse_x_mcp_headers,
    standard_headers,
)

# The encoding table from the spec, verbatim.
SPEC_EXAMPLES = [
    ("us-west1", "us-west1"),
    ("Hello, 世界", "=?base64?SGVsbG8sIOS4lueVjA==?="),
    (" padded ", "=?base64?IHBhZGRlZCA=?="),
    ("line1\nline2", "=?base64?bGluZTEKbGluZTI=?="),
    ("=?base64?literal?=", "=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?="),
]


@pytest.mark.parametrize(("value", "encoded"), SPEC_EXAMPLES)
def test_spec_encoding_examples(value: str, encoded: str) -> None:
    assert encode_header_value(value) == encoded
    assert decode_header_value(encoded) == value


@pytest.mark.parametrize("value", ["", "a b", "x" * 300, "~!@#$%^&*()", "=?base64?x"])
def test_plain_ascii_is_left_alone(value: str) -> None:
    assert encode_header_value(value) == value
    assert decode_header_value(value) == value


@pytest.mark.parametrize("value", ["tab\there", "\x00", "del\x7f", "é", "trailing "])
def test_unsafe_values_are_base64_and_round_trip(value: str) -> None:
    encoded = encode_header_value(value)
    assert encoded.startswith("=?base64?")
    assert decode_header_value(encoded) == value


def test_bad_base64_in_a_sentinel_is_rejected() -> None:
    with pytest.raises(ValueError):
        decode_header_value("=?base64?***?=")


def test_standard_headers() -> None:
    assert standard_headers("tools/list", {}) == {"Mcp-Method": "tools/list"}
    assert standard_headers("tools/call", {"name": "get_weather"}) == {
        "Mcp-Method": "tools/call",
        "Mcp-Name": "get_weather",
    }
    assert standard_headers("resources/read", {"uri": "file:///a b"})["Mcp-Name"] == "file:///a b"
    assert standard_headers("prompts/get", {"name": "héllo"})["Mcp-Name"].startswith("=?base64?")


def test_task_requests_are_named_by_their_task_id() -> None:
    for method in ("tasks/get", "tasks/update", "tasks/cancel"):
        assert standard_headers(method, {"taskId": "t-1"}) == {
            "Mcp-Method": method,
            "Mcp-Name": "t-1",
        }


def test_standard_headers_without_a_usable_name() -> None:
    assert standard_headers("tools/call", None) == {"Mcp-Method": "tools/call"}
    assert standard_headers("tools/call", {"name": 7}) == {"Mcp-Method": "tools/call"}
    assert "Mcp-Name" not in standard_headers("ping", {"name": "x"})


def schema(**props: object) -> dict[str, object]:
    return {"type": "object", "properties": props}


def test_valid_annotations_are_collected_including_nested_ones() -> None:
    mirrors, errors = parse_x_mcp_headers(
        schema(
            region={"type": "string", "x-mcp-header": "Region"},
            opts={"type": "object", "properties": {"n": {"type": "integer", "x-mcp-header": "N"}}},
            plain={"type": "string"},
            flag={"type": "boolean", "x-mcp-header": "Flag"},
        )
    )
    assert errors == ()
    assert mirrors == (
        HeaderMirror("Mcp-Param-Region", ("region",)),
        HeaderMirror("Mcp-Param-N", ("opts", "n")),
        HeaderMirror("Mcp-Param-Flag", ("flag",)),
    )


@pytest.mark.parametrize(
    ("prop", "reason"),
    [
        ({"type": "string", "x-mcp-header": ""}, "empty"),
        ({"type": "string", "x-mcp-header": "Bad Name"}, "token"),
        ({"type": "string", "x-mcp-header": "Bad:Name"}, "token"),
        ({"type": "string", "x-mcp-header": "A\r\nB"}, "token"),
        ({"type": "string", "x-mcp-header": 5}, "string"),
        ({"type": "number", "x-mcp-header": "N"}, "primitive"),
        ({"type": "array", "x-mcp-header": "N"}, "primitive"),
        ({"type": ["string", "null"], "x-mcp-header": "N"}, "primitive"),
        ({"x-mcp-header": "N"}, "primitive"),
    ],
)
def test_invalid_annotations_are_reported(prop: dict[str, object], reason: str) -> None:
    _, errors = parse_x_mcp_headers(schema(p=prop))
    assert len(errors) == 1
    assert reason in errors[0]


def test_names_must_be_unique_ignoring_case() -> None:
    _, errors = parse_x_mcp_headers(
        schema(
            a={"type": "string", "x-mcp-header": "Region"},
            b={"type": "string", "x-mcp-header": "region"},
        )
    )
    assert len(errors) == 1
    assert "unique" in errors[0]


@pytest.mark.parametrize(
    "bad_schema",
    [
        # reachable only through array items, composition, conditionals or $ref
        schema(xs={"type": "array", "items": {"type": "string", "x-mcp-header": "X"}}),
        schema(o={"oneOf": [{"type": "string", "x-mcp-header": "X"}]}),
        schema(o={"anyOf": [{"type": "string", "x-mcp-header": "X"}]}),
        schema(o={"allOf": [{"type": "string", "x-mcp-header": "X"}]}),
        schema(o={"not": {"type": "string", "x-mcp-header": "X"}}),
        schema(o={"if": {"type": "string", "x-mcp-header": "X"}}),
        {"type": "object", "$defs": {"d": {"type": "string", "x-mcp-header": "X"}}},
        {"type": "object", "x-mcp-header": "Root"},
    ],
)
def test_annotations_off_the_properties_chain_are_invalid(bad_schema: dict[str, object]) -> None:
    mirrors, errors = parse_x_mcp_headers(bad_schema)
    assert mirrors == ()
    assert len(errors) == 1
    assert "reachable" in errors[0]


def test_annotation_named_data_inside_enum_or_default_is_not_an_annotation() -> None:
    mirrors, errors = parse_x_mcp_headers(
        schema(p={"type": "string", "default": {"x-mcp-header": ""}, "enum": ["a"]})
    )
    assert (mirrors, errors) == ((), ())


def test_non_object_schema_has_no_mirrors() -> None:
    assert parse_x_mcp_headers(None) == ((), ())
    assert parse_x_mcp_headers({}) == ((), ())


def test_mirror_headers_convert_encode_and_omit_missing_values() -> None:
    mirrors, _ = parse_x_mcp_headers(
        schema(
            region={"type": "string", "x-mcp-header": "Region"},
            n={"type": "integer", "x-mcp-header": "N"},
            flag={"type": "boolean", "x-mcp-header": "Flag"},
            text={"type": "string", "x-mcp-header": "Text"},
            gone={"type": "string", "x-mcp-header": "Gone"},
            o={"type": "object", "properties": {"d": {"type": "string", "x-mcp-header": "Deep"}}},
        )
    )
    arguments = {
        "region": "us-west1",
        "n": -7,
        "flag": False,
        "text": " padded ",
        "o": {"d": "x"},
    }
    assert mirror_headers(mirrors, arguments) == {
        "Mcp-Param-Region": "us-west1",
        "Mcp-Param-N": "-7",
        "Mcp-Param-Flag": "false",
        "Mcp-Param-Text": "=?base64?IHBhZGRlZCA=?=",
        "Mcp-Param-Deep": "x",
    }


def test_mirror_headers_skip_values_of_the_wrong_type_and_odd_arguments() -> None:
    mirrors, _ = parse_x_mcp_headers(schema(n={"type": "integer", "x-mcp-header": "N"}))
    assert mirror_headers(mirrors, {"n": 1.5}) == {}
    assert mirror_headers(mirrors, {"n": None}) == {}
    assert mirror_headers(mirrors, {"n": [1]}) == {}
    assert mirror_headers(mirrors, None) == {}
    assert mirror_headers(mirrors, {"o": 1}) == {}
