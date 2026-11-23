"""A whole scan, from configuration to report, against the small scripted stdio server."""

import gzip
import json
import sys
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from probe.config.profile import parse_profile
from probe.engine.outcomes import Status
from probe.engine.runscan import RunConfig, UsageError, run_scan, select_checks
from probe.report.models import ScanReport
from tests.checks.protocol.harness import mini_argv

REPORT_SCHEMA = json.loads(
    (Path(__file__).parents[2] / "schemas" / "report.schema.json").read_text()
)


def config(tmp_path: Path, *flags: str, **kwargs: Any) -> RunConfig:
    return RunConfig(out_dir=tmp_path / "out", command=mini_argv(*flags), **kwargs)


def statuses(report: ScanReport) -> dict[str, Status]:
    return {r.check_id: r.status for r in report.results}


async def test_a_scan_produces_a_valid_complete_report(tmp_path: Path) -> None:
    report = await run_scan(config(tmp_path, mode="deep", seed=7))
    jsonschema.validate(json.loads(report.model_dump_json()), REPORT_SCHEMA)
    assert report.scan.status == "completed"
    assert (report.scan.mode, report.scan.seed, report.scan.sandboxed) == ("deep", 7, False)
    assert report.target.transport.value == "stdio"
    assert report.target.era.kind == "dual"  # the mini server lists a legacy version too
    assert report.target.era.negotiated_version == "2026-07-28"
    assert report.stats.calls > 0 and report.stats.bytes_in > 0 and report.stats.bytes_out > 0
    assert report.score.grade is None  # scoring is not part of this build
    assert any("scoring" in note for note in report.limitations)
    assert len(report.results) == 22  # every registered check is accounted for


async def test_results_are_in_phase_then_id_order_and_findings_match(tmp_path: Path) -> None:
    report = await run_scan(config(tmp_path))
    ids = [r.check_id for r in report.results]
    assert ids[0].startswith(("protocol.", "schema.")) and len(ids) == len(set(ids))
    finding_ids = {f.finding_id for f in report.findings}
    listed = {i for r in report.results for i in r.finding_ids}
    assert listed == finding_ids  # every finding belongs to exactly the result that names it
    failing = {r.check_id for r in report.results if r.status is Status.FAIL}
    assert failing == {f.check_id for f in report.findings if f.severity.value != "info"}


async def test_the_trace_and_stderr_artifacts_are_written(tmp_path: Path) -> None:
    await run_scan(config(tmp_path))
    assert (tmp_path / "out" / "trace.jsonl.gz").is_file()
    assert (tmp_path / "out" / "stderr.log").is_file()


async def test_only_and_skip_select_checks_and_say_why_the_others_were_left_out(
    tmp_path: Path,
) -> None:
    report = await run_scan(config(tmp_path, only=["protocol.*"], skip=["protocol.stdout_clean"]))
    by_id = {r.check_id: r for r in report.results}
    assert by_id["protocol.stdout_clean"].reason == "excluded by --skip"
    assert by_id["schema.tools_list_valid"].reason == "excluded by --only"
    assert by_id["protocol.discover_implemented"].status is Status.PASS
    assert all(
        r.status is Status.SKIPPED for r in report.results if r.check_id.startswith("schema")
    )


async def test_the_profile_can_skip_checks_and_override_tool_kinds(tmp_path: Path) -> None:
    profile = parse_profile("name: demo\nchecks: {skip: {'schema.*': 'not relevant here'}}")
    report = await run_scan(config(tmp_path, profile=profile))
    assert report.target.name == "demo"
    assert report.target.profile_hash == profile.hash
    assert all(
        r.reason == "skipped by the profile: not relevant here"
        for r in report.results
        if r.check_id.startswith("schema")
    )


async def test_the_era_can_be_forced(tmp_path: Path) -> None:
    report = await run_scan(config(tmp_path, "--legacy-only"))
    assert report.target.era.kind == "legacy"
    assert report.target.era.negotiated_version == "2025-11-25"
    forced = await run_scan(config(tmp_path / "x", era="legacy"))
    assert forced.target.era.kind == "legacy"


async def test_limitations_explain_what_was_not_exercised(tmp_path: Path) -> None:
    report = await run_scan(config(tmp_path))
    text = " ".join(report.limitations)
    assert "not part of standard mode" in text  # the deep-only check
    assert "applies to" in text  # era/transport mismatches


async def test_scan_keys_are_stable_and_depend_on_the_inputs(tmp_path: Path) -> None:
    a = await run_scan(config(tmp_path / "a", seed=1))
    b = await run_scan(config(tmp_path / "b", seed=1))
    c = await run_scan(config(tmp_path / "c", seed=2))
    assert a.scan.scan_key == b.scan.scan_key != c.scan.scan_key
    assert a.scan.id != b.scan.id  # ids are per run


async def test_a_target_that_cannot_start_still_gets_a_report(tmp_path: Path) -> None:
    cfg = RunConfig(out_dir=tmp_path / "out", command=["/no/such/binary"])
    report = await run_scan(cfg)
    jsonschema.validate(json.loads(report.model_dump_json()), REPORT_SCHEMA)
    assert report.scan.status == "target_unavailable"
    assert report.target.era.kind is None and report.results == []
    assert "could not start" in report.limitations[0]


async def test_a_target_that_dies_at_once_reports_its_stderr(tmp_path: Path) -> None:
    script = tmp_path / "die.py"
    script.write_text("import sys\nsys.stderr.write('boom: bad config\\n')\nsys.exit(5)\n")
    report = await run_scan(
        RunConfig(out_dir=tmp_path / "out", command=[sys.executable, str(script)])
    )
    assert report.scan.status == "target_unavailable"
    assert any("boom: bad config" in note for note in report.limitations)


async def test_misuse_is_a_usage_error(tmp_path: Path) -> None:
    with pytest.raises(UsageError, match="either --url or"):
        await run_scan(RunConfig(out_dir=tmp_path))
    with pytest.raises(UsageError, match="either --url or"):
        await run_scan(RunConfig(out_dir=tmp_path, command=["x"], url="http://localhost/mcp"))
    with pytest.raises(UsageError, match="local or private"):
        await run_scan(RunConfig(out_dir=tmp_path / "r", url="https://8.8.8.8/mcp"))
    with pytest.raises(UsageError, match="unset variables"):
        await run_scan(config(tmp_path / "s", secret_env=["NO_SUCH_VAR_FOR_PROBE"], environ={}))


async def test_secret_env_values_are_redacted_in_artifacts(tmp_path: Path) -> None:
    secret = "s3cret-value-1234"
    cfg = config(tmp_path, target_env={"MY_TOKEN": secret}, secret_env=["MY_TOKEN"])
    await run_scan(cfg)
    with gzip.open(tmp_path / "out" / "trace.jsonl.gz", "rt") as fh:
        trace = fh.read()
    assert secret not in trace and secret not in (tmp_path / "out" / "stderr.log").read_text()


def test_select_checks_matches_globs_exactly() -> None:
    selected, excluded = select_checks(["protocol.discover_*"], [])
    assert [c.meta.id for c in selected] == ["protocol.discover_implemented"]
    assert len(excluded) == 21
    none_selected, _ = select_checks(["nope.*"], [])
    assert none_selected == []
    skipped, why = select_checks([], ["schema.*", "protocol.stdout_clean"])
    assert "protocol.stdout_clean" in why and not any(
        c.meta.id.startswith("schema") for c in skipped
    )


# --- regressions from the M1 review ------------------------------------------------------


async def test_a_secret_the_server_echoes_never_reaches_the_report(tmp_path: Path) -> None:
    """The secret comes back as a tool name; findings and the report are built from it."""
    secret = "s3cret-tool-name-1234"
    cfg = config(tmp_path, target_env={"PROBE_TOOL_NAME": secret}, secret_env=["PROBE_TOOL_NAME"])
    report = await run_scan(cfg)
    text = report.model_dump_json()
    assert secret not in text and "[REDACTED]" in text
    assert any(f.check_id == "schema.input_schema_valid" for f in report.findings)  # it was used


async def run_checks_for_restart(ctx: Any) -> list[Any]:
    from probe.checks.base import Check, CheckOutcome
    from probe.engine.crash import TargetCrashed
    from probe.engine.outcomes import Severity
    from probe.engine.scan import run_checks
    from tests.checks.helpers import evidence, make_meta, repro

    class AFinding(Check):
        meta = make_meta("behavior.a_finding", phase="active.safe")

        async def run(self, ctx: Any) -> CheckOutcome:
            finding = self.finding(
                ctx, severity=Severity.MEDIUM, title="t", message="m", evidence=evidence(),
                repro=repro(),
            )  # fmt: skip
            return CheckOutcome([finding])

    class BCrash(Check):
        meta = make_meta("behavior.b_crash", phase="active.safe")

        async def run(self, ctx: Any) -> CheckOutcome:
            try:
                await ctx.call("boom")
            except TargetCrashed:
                raise
            return CheckOutcome()

    class CLater(Check):
        meta = make_meta("behavior.c_later", phase="active.safe")

        async def run(self, ctx: Any) -> CheckOutcome:
            return CheckOutcome()

    return await run_checks(ctx, [AFinding, BCrash, CLater])


async def test_a_target_that_cannot_be_restarted_keeps_the_findings_so_far(
    tmp_path: Path,
) -> None:
    from probe.runners.base import TargetUnavailable
    from tests.engine.fakes import FakeRunner, make_context

    runner = FakeRunner()
    runner.restart_error = TargetUnavailable("the host is gone")
    ctx, _ = await make_context(runner=runner)
    results = await run_checks_for_restart(ctx)
    by_id = {r.check_id: r for r in results}
    assert by_id["behavior.a_finding"].status is Status.FAIL  # not lost
    assert by_id["behavior.b_crash"].status is Status.ERROR
    assert (by_id["behavior.c_later"].status, by_id["behavior.c_later"].reason) == (
        Status.ERROR,
        "target_unstable",
    )
    assert ctx.crashes.abandoned


# --- the full profile in a scan ----------------------------------------------------------


def with_profile(tmp_path: Path, yaml_text: str, **kwargs: Any) -> RunConfig:
    return RunConfig(out_dir=tmp_path / "out", profile=parse_profile(yaml_text), **kwargs)


async def test_the_profile_command_is_used_when_none_is_given(tmp_path: Path) -> None:
    import json as _json

    command = _json.dumps(mini_argv())
    report = await run_scan(
        with_profile(tmp_path, f"name: from-profile\ntarget: {{command: {command}}}")
    )
    assert report.scan.status == "completed" and report.target.name == "from-profile"


async def test_a_command_after_the_dashes_beats_the_profile_command(tmp_path: Path) -> None:
    cfg = with_profile(tmp_path, 'target: {command: ["/no/such/binary"]}', command=mini_argv())
    assert (await run_scan(cfg)).scan.status == "completed"


async def test_the_token_reaches_the_server_and_stays_visible_as_a_fake(tmp_path: Path) -> None:
    profile = 'target: {env: {PROBE_TOOL_NAME: "fake_{token}"}}'
    report = await run_scan(with_profile(tmp_path, profile, command=mini_argv()))
    names = [t.name for t in report.tools]
    assert len(names) == 1 and names[0].startswith("fake_") and len(names[0]) > len("fake_")


async def test_a_host_secret_in_the_profile_is_redacted_everywhere(tmp_path: Path) -> None:
    secret = "host-secret-value-77"
    profile = 'target: {env: {PROBE_TOOL_NAME: "{secret:DEMO_HOST_SECRET}"}}'
    cfg = with_profile(tmp_path, profile, command=mini_argv(), environ={"DEMO_HOST_SECRET": secret})
    report = await run_scan(cfg)
    assert secret not in report.model_dump_json() and "[REDACTED]" in report.model_dump_json()
    with gzip.open(tmp_path / "out" / "trace.jsonl.gz", "rt") as fh:
        assert secret not in fh.read()


async def test_the_scan_key_ignores_the_token_but_not_the_profile(tmp_path: Path) -> None:
    profile = 'target: {env: {PROBE_TOOL_NAME: "t_{token}"}}'
    a = await run_scan(with_profile(tmp_path / "a", profile, command=mini_argv()))
    b = await run_scan(with_profile(tmp_path / "b", profile, command=mini_argv()))
    c = await run_scan(
        with_profile(tmp_path / "c", profile + "\nnotes: changed", command=mini_argv())
    )
    assert a.scan.scan_key == b.scan.scan_key != c.scan.scan_key
    assert a.target.profile_hash == b.target.profile_hash


async def test_profile_problems_are_usage_errors(tmp_path: Path) -> None:
    with pytest.raises(UsageError, match="NOT_SET"):
        await run_scan(
            with_profile(
                tmp_path, "target: {env: {A: '{secret:NOT_SET}'}}", command=mini_argv(), environ={}
            )
        )
    with pytest.raises(UsageError, match="either --url or"):  # an image-only profile has no command
        await run_scan(with_profile(tmp_path / "x", "target: {image: probe-refserver:dev}"))


async def test_tool_override_globs_reach_the_classifier(tmp_path: Path) -> None:
    profile = "tools: {'delete_*': {kind: read}}"
    cfg = with_profile(
        tmp_path, profile, command=mini_argv(), target_env={"PROBE_TOOL_NAME": "delete_thing"}
    )
    tool = (await run_scan(cfg)).tools[0]
    assert (tool.kind, tool.classification_source) == ("read", "profile")
