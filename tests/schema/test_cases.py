"""Case identity."""

import pytest

from probe.schema.cases import Case, case_id


def test_case_ids_follow_the_documented_format() -> None:
    assert case_id("notes_get", "valid", "minimal", 0) == "notes_get:valid:minimal:0"
    case = Case("fetch", "malformed", "missing-url", 2, {})
    assert case.id == "fetch:malformed:missing-url:2"


def test_cases_are_immutable_and_comparable() -> None:
    a = Case("t", "valid", "example", 0, {"x": 1})
    assert a == Case("t", "valid", "example", 0, {"x": 1})
    with pytest.raises(AttributeError):
        a.index = 3  # type: ignore[misc]
