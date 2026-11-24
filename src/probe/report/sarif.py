"""SARIF 2.1.0 for code-scanning dashboards (GitHub, VS Code).

One run; every check in the catalog is a rule. Only findings from failing checks become
results (info observations are not alerts). Findings are behavioral, so each result is
anchored on a file the caller names (``--sarif-anchor``, default README.md) and carries the
tool as a logical location.
"""

from typing import Any

import probe.checks.behavior
import probe.checks.operability
import probe.checks.protocol
import probe.checks.safety
import probe.checks.schema  # noqa: F401 - registers the checks that become rules
from probe.checks.registry import REGISTRY
from probe.engine.outcomes import Severity
from probe.report.models import ScanReport

SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
HELP_BASE = "https://probe-mcp.github.io/checks/"
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
}
_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _rules() -> list[dict[str, Any]]:
    rules = []
    for check in sorted(REGISTRY, key=lambda c: c.meta.id):
        meta = check.meta
        properties: dict[str, Any] = {"tags": [meta.family.value]}
        if meta.severity in _SECURITY_SEVERITY:
            properties["security-severity"] = _SECURITY_SEVERITY[meta.severity]
        rules.append(
            {
                "id": meta.id,
                "shortDescription": {"text": meta.title},
                "fullDescription": {"text": meta.rationale},
                "help": {"text": meta.remediation, "markdown": meta.remediation},
                "helpUri": f"{HELP_BASE}{meta.id}/",
                "defaultConfiguration": {"level": _LEVEL[meta.severity]},
                "properties": properties,
            }
        )
    return rules


def to_sarif(report: ScanReport, anchor: str = "README.md") -> dict[str, Any]:
    rules = _rules()
    index = {rule["id"]: i for i, rule in enumerate(rules)}
    results = []
    for finding in report.findings:
        if finding.severity is Severity.INFO:
            continue
        subject = f" (tool {finding.tool})" if finding.tool else ""
        location: dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {"uri": anchor},
                "region": {"startLine": 1},
            }
        }
        if finding.tool:
            location["logicalLocations"] = [{"name": finding.tool, "kind": "function"}]
        result: dict[str, Any] = {
            "ruleId": finding.check_id,
            "level": _LEVEL[finding.severity],
            "message": {
                "text": f"{finding.title}{subject}: {finding.message} "
                f"Reproduce: {finding.repro.command}"
            },
            "locations": [location],
            "partialFingerprints": {"probeFindingId": finding.finding_id},
            "properties": {"severity": finding.severity.value, "family": finding.family.value},
        }
        if finding.check_id in index:
            result["ruleIndex"] = index[finding.check_id]
        results.append(result)
    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "probe",
                        "version": report.probe_version,
                        "informationUri": "https://probe-mcp.github.io/",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
