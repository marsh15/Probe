"""The self-validation expectations are well formed and cover exactly the implemented bugs."""

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

EXPECTED = yaml.safe_load((Path(__file__).parent / "expected.yaml").read_text())
CHECK_ID = re.compile(r"[a-z]+\.[a-z0-9_.]+")
IMPLEMENTED = {f"b{n:02d}" for n in (*range(1, 31), *range(50, 59))}  # b01-b30, b50-b58


def test_covers_the_clean_baseline_and_exactly_the_implemented_bugs() -> None:
    assert set(EXPECTED) == {"clean", *IMPLEMENTED}


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_entries_are_well_formed(name: str) -> None:
    entry: dict[str, Any] = EXPECTED[name]
    assert set(entry["transports"]) <= {"stdio", "http"} and entry["transports"]
    for check in [*entry["primary"], *entry.get("allowed_collateral", [])]:
        assert CHECK_ID.fullmatch(check), check
    if name == "clean":
        assert entry["primary"] == []
        return
    assert len(entry["primary"]) >= 1
    collateral = set(entry["allowed_collateral"])
    assert set(entry.get("justification", {})) == collateral  # every collateral is explained
    assert not collateral & set(entry["primary"])
    assert all(entry.get("justification", {}).values())


def test_http_only_bugs_are_the_header_origin_and_cache_scope_bugs() -> None:
    http_only = {n for n, e in EXPECTED.items() if e["transports"] == ["http"]}
    assert http_only == {"b05", "b06", "b14", "b51"}
