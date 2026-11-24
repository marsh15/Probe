"""The HTML report: structure, escaping, CSP, size and snapshots (clean and buggy refserver)."""

import base64
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from syrupy.assertion import SnapshotAssertion

from probe.report.html import render_html
from probe.report.models import ScanReport

DATA = Path(__file__).parent / "data"


def load(name: str) -> ScanReport:
    return ScanReport.model_validate_json((DATA / f"{name}.json").read_text())


def mutate(name: str, edit: Any) -> ScanReport:
    data = json.loads((DATA / f"{name}.json").read_text())
    edit(data)
    return ScanReport.model_validate(data)


def test_clean_report_has_every_section_and_the_grade() -> None:
    page = render_html(load("clean"))
    for anchor in ("summary", "families", "findings", "tools", "checks", "limits", "metadata"):
        assert f'id="{anchor}"' in page
    assert 'class="grade"' in page and ">A<" in page and "100.0" in page
    assert "2026-07-28" in page
    assert "No issues found by Probe v1.0 checks is not a security guarantee." in page


def test_buggy_report_groups_findings_by_severity_with_repro_commands() -> None:
    report = load("buggy")
    page = render_html(report)
    for finding in report.findings:
        assert finding.finding_id in page
        assert f"probe repro report.json --finding {finding.finding_id}" in page
    assert page.index("sev-high") < page.index("sev-medium") if "sev-high" in page else True
    assert "How to fix" in page and "Why it matters" in page
    assert "<details" in page and "copy" in page.lower()


def test_page_is_self_contained_with_a_matching_csp() -> None:
    page = render_html(load("buggy"))
    assert "http://" not in re.sub(r"https?://(www\.)?w3\.org/\d+/svg", "", page)
    assert "<link " not in page and 'src="http' not in page
    csp = re.search(r'Content-Security-Policy" content="([^"]+)"', page)
    assert csp is not None
    policy = csp.group(1)
    assert "default-src 'none'" in policy and "unsafe-eval" not in policy
    scripts = re.findall(r"<script>(.*?)</script>", page, re.S)
    assert len(scripts) == 1
    digest = base64.b64encode(hashlib.sha256(scripts[0].encode()).digest()).decode()
    assert f"script-src 'sha256-{digest}'" in policy
    assert not re.search(r"<[a-z]+ [^>]*\son[a-z]+=", page)  # no inline event handlers


def test_hostile_server_text_is_escaped_everywhere() -> None:
    hostile = "<img src=x onerror=alert(1)>"

    def edit(data: dict[str, Any]) -> None:
        data["tools"][0]["name"] = hostile
        data["target"]["name"] = hostile
        data["target"]["server_info"]["name"] = hostile
        data["findings"][0]["message"] = hostile
        data["findings"][0]["tool"] = hostile
        data["findings"][0]["evidence"]["excerpt"] = hostile
        data["findings"][0]["evidence"]["observations"] = {"x": hostile}
        data["limitations"] = [hostile]

    page = render_html(mutate("buggy", edit))
    assert hostile not in page and "&lt;img src=x onerror=alert(1)&gt;" in page
    assert "<img" not in page


def test_report_stays_under_the_size_budget_even_with_many_findings() -> None:
    def edit(data: dict[str, Any]) -> None:
        base = data["findings"][0]
        data["findings"] = [
            {
                **base,
                "finding_id": f"{i:016x}",
                "evidence": {**base["evidence"], "excerpt": "x" * 2048},
            }
            for i in range(1500)
        ]

    page = render_html(mutate("buggy", edit))
    assert len(page.encode()) < 1_500_000
    assert "more findings" in page  # the cut is announced, not silent


def test_ungraded_report_says_so(tmp_path: Path) -> None:
    def edit(data: dict[str, Any]) -> None:
        data["score"].update(overall=None, grade=None, coverage=0)
        for fam in data["score"]["families"].values():
            fam.update(score=None, applicable_weight=0, failed_weight=0)

    page = render_html(mutate("clean", edit))
    assert "Not graded" in page


def test_snapshots(snapshot: SnapshotAssertion) -> None:
    assert render_html(load("clean")) == snapshot(name="clean")
    assert render_html(load("buggy")) == snapshot(name="buggy")


def test_llm_panel_appears_only_when_the_experiment_ran() -> None:
    assert 'id="llm"' not in render_html(load("clean"))

    def edit_llm(data: dict[str, Any]) -> None:
        data["llm"] = {
            "model": "m", "recovery_rate": 66.7, "lift": 33.3, "cases": 3,
            "cache_hits": 1, "cost_usd": 0.0123,
        }  # fmt: skip

    page = render_html(mutate("clean", edit_llm))
    assert 'id="llm"' in page and "66.7%" in page and "+33.3" in page and "$0.0123" in page
