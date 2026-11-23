"""Generate through draft 7, then validate against all original corpus schemas."""

import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest
from hypothesis import HealthCheck, Phase, given, seed, settings
from hypothesis_jsonschema import from_schema
from jsonschema import Draft7Validator, Draft202012Validator

from probe.schema.dialect import detect_dialect
from probe.schema.normalize import normalize

from .synthetic import SCHEMAS

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "schemas"
CASES = [(path.stem, json.loads(path.read_text())) for path in sorted(FIXTURES.glob("*.json"))]
CASES.extend(SCHEMAS.items())


def generated_valid_values(schema, normalized, name):
    """A test-only deterministic draw loop; T21 owns the production generator."""
    validator_class = (
        Draft7Validator if detect_dialect(schema).name == "draft-07" else (Draft202012Validator)
    )
    validator = validator_class(schema)
    valid = []
    fixed_seed = int.from_bytes(hashlib.sha256(name.encode()).digest()[:8])

    @seed(fixed_seed)
    @settings(
        database=None,
        derandomize=True,
        max_examples=5,
        deadline=None,
        phases=[Phase.generate],
        suppress_health_check=list(HealthCheck),
    )
    @given(from_schema(normalized))
    def draw(value):
        if validator.is_valid(value):
            valid.append(value)

    draw()
    return valid, validator


def test_corpus_has_sixty_real_and_fifteen_synthetic_schemas():
    assert len(list(FIXTURES.glob("*.json"))) == 60
    assert len(SCHEMAS) == 15


@pytest.mark.timeout(3)
@pytest.mark.parametrize(("name", "schema"), CASES, ids=[name for name, _ in CASES])
def test_generated_then_validated_values_obey_original_schema(name, schema):
    original = deepcopy(schema)
    result = normalize(schema)
    assert schema == original
    Draft7Validator.check_schema(result.schema)
    assert normalize(result.schema).schema == result.schema
    values, validator = generated_valid_values(schema, result.schema, name)
    # All 75 schemas are satisfiable: each must actually yield a valid candidate.
    assert values, name
    assert all(validator.is_valid(value) for value in values)


def test_draws_are_repeatable_and_invalid_candidates_are_dropped():
    original = {"const": 1}
    normalized = {"enum": [0, 1]}
    first, _ = generated_valid_values(original, normalized, "filtering")
    second, _ = generated_valid_values(original, normalized, "filtering")
    assert first == second == [1]


def test_schema_dependency_required_names_generate_without_a_separate_dependent_required():
    schema = {
        "type": "object",
        "properties": {"a": {"type": "integer"}, "b": {"type": "integer"}},
        "required": ["a"],
        "dependentSchemas": {"a": {"required": ["b"], "properties": {"b": {"minimum": 1}}}},
        "additionalProperties": False,
    }
    result = normalize(schema)
    values, validator = generated_valid_values(schema, result.schema, "required-dependency")
    assert values
    assert all(validator.is_valid(value) and value["b"] >= 1 for value in values)
    assert normalize(result.schema).schema == result.schema
