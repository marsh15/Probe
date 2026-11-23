"""Small builders for dummy checks used by framework tests."""

from typing import Any

from probe.engine.outcomes import (
    CheckMeta,
    DisclosureTier,
    Era,
    Evidence,
    Family,
    ReproCase,
    Severity,
    Transport,
)


def make_meta(check_id: str = "protocol.dummy", **overrides: Any) -> CheckMeta:
    fields: dict[str, Any] = {
        "id": check_id,
        "family": Family(check_id.split(".")[0]),
        "title": "Dummy",
        "severity": Severity.MEDIUM,
        "eras": frozenset(Era),
        "transports": frozenset(Transport),
        "requires": frozenset(),
        "modes": frozenset({"quick", "standard", "deep"}),
        "phase": "static",
        "spec_refs": [],
        "disclosure": DisclosureTier.PUBLIC,
        "rationale": "because",
        "remediation": "fix it",
    }
    fields.update(overrides)
    return CheckMeta(**fields)


def evidence(summary: str = "saw it") -> Evidence:
    return Evidence(summary=summary, request_refs=[], response_refs=[], observations={})


def repro(case_id: str = "case:1") -> ReproCase:
    return ReproCase(case_id=case_id, steps=[], expect={}, command="probe repro")
