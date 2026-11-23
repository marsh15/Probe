"""Evaluate frozen semantic labels; never generate labels from classifier predictions."""

import json
from pathlib import Path
from typing import Any

import yaml

from probe.classify import classify_tool

CORPUS = Path(__file__).resolve().parents[2] / "fixtures" / "schemas"
LABELS = Path(__file__).with_name("expected.yaml")
MISSES = Path(__file__).with_name("known_misses.yaml")


def test_corpus_evaluation_uses_one_metadata_policy_without_answer_overrides() -> None:
    labels = yaml.safe_load(LABELS.read_text())
    for filename, label in labels.items():
        assert "profile" not in label, f"{filename}: expected kinds cannot be classifier inputs"
        assert "annotations" not in label, (
            f"{filename}: this corpus evaluates name/description rules"
        )


def test_all_sixty_schemas_have_independent_filename_associated_labels() -> None:
    labels = yaml.safe_load(LABELS.read_text())
    assert set(labels) == {path.name for path in CORPUS.glob("*.json")}
    assert len(labels) == 60
    for filename, label in labels.items():
        assert label["name"] == filename.removesuffix(".json").split("__", 1)[1]
        assert label["description"]
        assert label["source"].startswith("https://github.com/")
        assert label["kind"] in {"read", "write", "destructive", "exec", "unknown"}


def test_corpus_kind_agreement_is_at_least_95_percent_and_every_miss_is_documented() -> None:
    labels: dict[str, Any] = yaml.safe_load(LABELS.read_text())
    known_misses: dict[str, Any] = yaml.safe_load(MISSES.read_text()) or {}
    actual_misses = {}
    for filename, label in labels.items():
        info = classify_tool(
            label["name"],
            json.loads((CORPUS / filename).read_text()),
            description=label["description"],
        )
        if info.kind != label["kind"]:
            actual_misses[filename] = {"expected": label["kind"], "actual": info.kind}
    assert set(actual_misses) == set(known_misses), actual_misses
    for filename, miss in actual_misses.items():
        assert miss == {key: known_misses[filename][key] for key in ("expected", "actual")}
        assert known_misses[filename]["reason"].strip()
    assert (len(labels) - len(actual_misses)) / len(labels) >= 0.95, actual_misses
