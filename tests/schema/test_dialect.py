"""Dialect selection is explicit and defaults to 2020-12."""

import pytest

from probe.schema.dialect import detect_dialect


@pytest.mark.parametrize("schema", [{}, True, False])
def test_absent_schema_defaults_to_2020_12(schema):
    result = detect_dialect(schema)
    assert result.name == "2020-12"
    assert result.notes == ()


@pytest.mark.parametrize(
    "uri",
    [
        "http://json-schema.org/draft-07/schema#",
        "https://json-schema.org/draft-07/schema",
        "https://json-schema.org/draft-07/schema#",
    ],
)
def test_draft_7_is_recognized(uri):
    assert detect_dialect({"$schema": uri}).name == "draft-07"
    assert detect_dialect({"$schema": uri}).notes == ()


def test_declared_2020_12_is_recognized():
    assert detect_dialect({"$schema": "https://json-schema.org/draft/2020-12/schema"}).notes == ()


@pytest.mark.parametrize("uri", ["https://example.test/unknown", "draft-07", None, 12])
def test_unknown_dialect_is_noted(uri):
    result = detect_dialect({"$schema": uri})
    assert result.name == "2020-12"
    assert len(result.notes) == 1
    assert str(uri) in result.notes[0]
