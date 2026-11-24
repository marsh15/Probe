"""The release helper and the release workflow's shape."""

import importlib.util
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location(
    "release_notes", ROOT / "scripts" / "release_notes.py"
)
assert spec is not None and spec.loader is not None
notes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(notes)

CHANGELOG = """# Changelog

## [Unreleased]

### Added
- next thing

## [0.9.0] - 2026-12-12

### Added
- a
- b

## [0.8.0] - 2026-11-01

- old
"""


def test_section_returns_only_that_versions_text() -> None:
    assert notes.section(CHANGELOG, "0.9.0") == "### Added\n- a\n- b\n"
    assert notes.section(CHANGELOG, "0.8.0") == "- old\n"


def test_missing_or_empty_sections_are_errors() -> None:
    with pytest.raises(ValueError, match="no section"):
        notes.section(CHANGELOG, "1.0.0")
    with pytest.raises(ValueError, match="empty"):
        notes.section("## [1.0.0]\n\n## [0.9.0]\n- a\n", "1.0.0")


def test_a_tag_must_match_the_package_version() -> None:
    notes.check_tag("v0.9.0", "0.9.0")
    with pytest.raises(ValueError, match="does not match"):
        notes.check_tag("v0.9.1", "0.9.0")


def test_the_real_changelog_has_an_unreleased_section() -> None:
    assert notes.section((ROOT / "CHANGELOG.md").read_text(), "Unreleased")


def load_workflow() -> dict:
    data = yaml.safe_load((ROOT / ".github" / "workflows" / "release.yml").read_text())
    data["on"] = data.pop(True, data.get("on"))  # YAML reads a bare `on` as True
    return data


def test_release_runs_only_on_version_tags_and_publishes_with_trusted_publishing() -> None:
    wf = load_workflow()
    assert wf["on"]["push"]["tags"] == ["v*"]
    publish = wf["jobs"]["publish-pypi"]
    assert publish["permissions"]["id-token"] == "write" and publish["environment"] == "pypi"
    assert "password" not in str(publish)  # no stored token: trusted publishing only


def test_release_builds_multi_arch_images_to_ghcr() -> None:
    wf = load_workflow()
    names = {entry["name"] for entry in wf["jobs"]["images"]["strategy"]["matrix"]["include"]}
    assert names == {"refserver", "fixtures"}
    text = (ROOT / ".github" / "workflows" / "release.yml").read_text()
    assert "linux/amd64,linux/arm64" in text and "ghcr.io" in text
    # nothing is published unless the package built and its version matched the tag
    assert wf["jobs"]["publish-pypi"]["needs"] == "build"
    assert "build" in wf["jobs"]["images"]["needs"]


# --- the GitHub Action (integrations/github-action) --------------------------------------

ACTION = ROOT / "integrations" / "github-action"


def load_action() -> dict:
    return yaml.safe_load((ACTION / "action.yml").read_text())


def test_action_has_the_documented_inputs_and_outputs() -> None:
    action = load_action()
    assert {
        "command", "url", "image", "profile", "mode", "fail-on", "min-score", "sandbox", "sarif",
        "sarif-anchor", "badge", "badge-branch", "probe-version", "compare-base", "llm",
        "target-env",
    } <= set(action["inputs"])  # fmt: skip
    assert action["inputs"]["mode"]["default"] == "quick"
    assert action["inputs"]["fail-on"]["default"] == "high"
    assert set(action["outputs"]) == {"grade", "score", "exit-code"}
    assert action["runs"]["using"] == "composite"


def test_action_never_interpolates_inputs_into_a_script() -> None:
    for step in load_action()["runs"]["steps"]:
        script = step.get("run", "")
        assert "${{" not in script, f"step {step.get('name')} interpolates into the script"
        for shell_step in (step,) if "run" in step else ():
            assert shell_step["shell"] == "bash"


def test_action_fails_the_job_only_after_uploading_and_uses_probes_exit_code() -> None:
    steps = load_action()["runs"]["steps"]
    names = [s.get("name") or s.get("uses") for s in steps]
    assert names.index("Scan") < names.index("Fail the job if Probe did") == len(steps) - 1
    assert "set +e" in next(s for s in steps if s.get("name") == "Scan")["run"]


def test_selftest_expects_clean_to_pass_and_buggy_to_fail() -> None:
    wf = yaml.safe_load((ACTION / ".github" / "workflows" / "selftest.yml").read_text())
    assert set(wf["jobs"]) == {"clean", "buggy"}
    assert "PROBE_REF_BUGS=b31,b17" in str(wf["jobs"]["buggy"])
    assert wf["jobs"]["buggy"]["steps"][1]["continue-on-error"] is True
