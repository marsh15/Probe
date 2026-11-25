"""The full profile model: validation, interpolation and overrides."""

import copy
from pathlib import Path
from typing import Any

import pytest

from probe.config.profile import (
    Profile,
    ProfileError,
    load_profile,
    parse_profile,
    resolve_profile,
    scan_token,
)

FULL = """
version: 1
name: demo-server
target:
  transport: stdio
  image: probe-target/demo:1.0
  command: ["demo-server", "/data/allowed", "--token", "{token}"]
  env: {LOG_LEVEL: debug, API_BASE: "http://x/{token}"}
  secrets:
    API_TOKEN: {value: "probe_fake_tok_{token}", real: false}
    REAL_KEY: {value: "{secret:DEMO_REAL_KEY}", real: true}
  startup_timeout_s: 20
fixtures:
  fs: {seed_dir: fixtures/fs/basic, allowed_roots: ["/data/allowed"], sentinel: true}
  http: {routes: fixtures/http/github.yaml, env_base_urls: {GITHUB_API_URL: "http://fakehttp/github"}}
  sqlite: {path: /data/app.db, seed_sql: fixtures/db/notes.sql}
  git: {path: /data/allowed/repo, seed_bundle: fixtures/git/small.bundle}
tools:
  write_file: {kind: write, idempotent: true}
  run_command: {kind: exec, intended_exec: true}
  fetch: {allow_private_network: false}
  "get_*": {kind: read}
inputs:
  read_file: [{path: /data/allowed/readme.md}]
elicitation_answers:
  - {match: {message_regex: "(?i)confirm"}, response: {action: accept, content: {confirm: true}}}
  - {match: {key: delete}, response: {action: decline}}
auth:
  type: bearer
  identities:
    - {name: alice, token: "probe_fake_alice_{token}"}
    - {name: bob, token: "probe_fake_bob_{token}"}
checks:
  skip: {operability.burst_resilient: "upstream documents no rate limiting"}
notes: free text shown in the report
"""


def test_an_empty_profile_is_valid_and_has_a_stable_hash() -> None:
    assert parse_profile("").hash == parse_profile("{}").hash == Profile().hash
    assert len(Profile().hash) == 64
    assert Profile().target.transport == "stdio" and Profile().version == 1


def test_the_full_example_from_the_design_parses() -> None:
    profile = parse_profile(FULL)
    assert profile.name == "demo-server"
    assert profile.target.startup_timeout_s == 20
    assert profile.target.secrets["REAL_KEY"].real is True
    assert profile.fixtures.fs is not None and profile.fixtures.fs.allowed_roots == [
        "/data/allowed"
    ]
    assert profile.fixtures.sqlite is not None and profile.fixtures.sqlite.path == "/data/app.db"
    assert profile.tools["run_command"].intended_exec is True
    assert profile.inputs["read_file"] == [{"path": "/data/allowed/readme.md"}]
    assert profile.elicitation_answers[1].response.action == "decline"
    assert [i.name for i in profile.auth.identities] == ["alice", "bob"]
    assert "burst_resilient" in next(iter(profile.checks.skip))


def test_the_hash_depends_on_content_not_key_order() -> None:
    a = parse_profile("target: {env: {A: '1', B: '2'}}")
    b = parse_profile("target: {env: {B: '2', A: '1'}}")
    assert a.hash == b.hash != parse_profile("target: {env: {A: '1'}}").hash


@pytest.mark.parametrize(
    ("text", "fragment"),
    [
        ("targt: {}", "targt"),  # a typo must not silently do nothing
        ("version: 2", "version"),
        ("target: {env: {A: 1}}", "target.env.A"),
        ("target: {transport: carrier-pigeon}", "target.transport"),
        ("target: {secrets: {'bad name': {value: x}}}", "environment variable"),
        ("target: {transport: stdio, http: {port: 80}}", "transport: http"),
        ("target: {transport: http, http: {port: 0}}", "target.http.port"),
        ("target: {transport: http, http: {path: mcp}}", "must start with /"),
        ("target: {startup_timeout_s: 0}", "startup_timeout_s"),
        ("tools: {x: {kind: big}}", "tools.x.kind"),
        ("tools: {x: {surprise: 1}}", "tools.x.surprise"),
        ("inputs: {x: {a: 1}}", "inputs.x"),  # must be a list of argument objects
        ("fixtures: {fs: {}}", "seed_dir"),
        ("elicitation_answers: [{match: {}, response: {action: accept}}]", "needs key"),
        (
            "elicitation_answers: [{match: {message_regex: '('}, response: {action: accept}}]",
            "not a valid regex",
        ),
        (
            "elicitation_answers: [{match: {key: k}, response: {action: decline, content: {}}}]",
            "only allowed with action: accept",
        ),
        ("auth: {type: bearer}", "at least one identity"),
        ("auth: {type: none, identities: [{name: a, token: t}]}", "need type: bearer"),
        (
            "auth: {type: bearer, identities: [{name: a, token: t}, {name: a, token: u}]}",
            "must be unique",
        ),
        ("checks: {skip: {safety.x: '  '}}", "need a reason"),
        ("checks: {skip: [safety.x]}", "checks.skip"),  # a bare list has no reasons
        ("- a\n- b", "top level"),
        ("a: [unclosed", "not valid YAML"),
    ],
)
def test_invalid_profiles_are_rejected_with_where(text: str, fragment: str) -> None:
    with pytest.raises(ProfileError, match="profile") as info:
        parse_profile(text)
    assert fragment in str(info.value)


def test_a_http_target_gets_the_default_port_and_path() -> None:
    http = parse_profile("target: {transport: http}").target.http
    assert http is not None and (http.port, http.path) == (3000, "/mcp")


# --- tool overrides ----------------------------------------------------------------------


def test_an_exact_override_beats_a_glob_and_the_first_glob_wins() -> None:
    profile = parse_profile(
        "tools: {'get_*': {kind: read}, get_secret: {kind: destructive}, '*_all': {kind: exec},"
        " '*': {idempotent: true}}"
    )
    assert profile.override_for("get_secret").kind == "destructive"  # type: ignore[union-attr]
    assert profile.override_for("get_note").kind == "read"  # type: ignore[union-attr]
    assert profile.override_for("delete_all").kind == "exec"  # type: ignore[union-attr]
    assert profile.override_for("other").idempotent is True  # type: ignore[union-attr]
    assert parse_profile("tools: {a: {}}").override_for("b") is None


def test_the_classifier_view_expands_globs_against_the_real_tool_names() -> None:
    profile = parse_profile(
        "tools: {'get_*': {kind: read}, run: {kind: exec}, odd: {idempotent: true}}"
    )
    view = profile.classifier_view(["get_a", "get_b", "run", "odd", "unrelated"])
    assert view == {
        "tools": {"get_a": {"kind": "read"}, "get_b": {"kind": "read"}, "run": {"kind": "exec"}}
    }
    assert profile.classifier_view() == {"tools": {}}


# --- interpolation -----------------------------------------------------------------------


def resolved(text: str = FULL, **environ: str) -> Any:
    profile = parse_profile(text)
    return resolve_profile(
        profile, token="TOK123", environ={"DEMO_REAL_KEY": "hunter2xx", **environ}
    )


def test_the_token_is_resolved_once_and_shared_by_env_secrets_and_auth() -> None:
    out = resolved()
    target = out.profile.target
    assert target.command == ["demo-server", "/data/allowed", "--token", "TOK123"]
    assert target.env["API_BASE"] == "http://x/TOK123"
    assert target.secrets["API_TOKEN"].value == "probe_fake_tok_TOK123"
    assert [i.token for i in out.profile.auth.identities] == [
        "probe_fake_alice_TOK123",
        "probe_fake_bob_TOK123",
    ]
    assert "{token}" not in out.profile.model_dump_json()


def test_the_env_a_server_starts_with_includes_its_secrets() -> None:
    env = resolved().env
    assert env["LOG_LEVEL"] == "debug" and env["API_TOKEN"] == "probe_fake_tok_TOK123"
    assert env["REAL_KEY"] == "hunter2xx"


def test_host_secrets_and_real_secrets_are_returned_for_redaction_but_fakes_are_not() -> None:
    out = resolved()
    assert out.secrets == ("hunter2xx",)  # fake tokens are evidence, so they stay visible
    only_real = resolved("target: {secrets: {K: {value: plain-real-value, real: true}}}")
    assert only_real.secrets == ("plain-real-value",)


def test_a_missing_host_secret_is_an_error_that_names_it() -> None:
    profile = parse_profile("target: {env: {X: '{secret:NOT_SET_ANYWHERE}'}}")
    with pytest.raises(ProfileError, match=r"target\.env\.X.*NOT_SET_ANYWHERE"):
        resolve_profile(profile, token="t", environ={})


def test_unknown_placeholders_and_plain_braces_are_left_alone() -> None:
    out = resolved('target: {env: {A: \'{"json": true}\', B: "{other}", C: "{secret:}"}}')
    assert out.profile.target.env == {"A": '{"json": true}', "B": "{other}", "C": "{secret:}"}


def test_resolving_does_not_change_the_profile_it_was_given() -> None:
    profile = parse_profile(FULL)
    before = copy.deepcopy(profile.model_dump())
    resolve_profile(profile, token="t", environ={"DEMO_REAL_KEY": "k" * 8})
    assert profile.model_dump() == before


def test_the_scan_token_is_stable_per_seed_and_profile() -> None:
    h = Profile().hash
    assert scan_token(1, h) == scan_token(1, h) != scan_token(2, h)
    assert scan_token(1, h) != scan_token(1, parse_profile("name: x").hash)
    assert len(scan_token(1, h)) == 12


def test_the_profile_hash_ignores_the_token_so_reports_stay_reproducible() -> None:
    profile = parse_profile(FULL)
    assert profile.hash == parse_profile(FULL).hash  # the hash is of the file, not of a resolution


# --- files -------------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["refserver", "refserver-http", "refserver-local"])
def test_the_shipped_reference_profiles_are_valid(name: str) -> None:
    path = Path(__file__).parents[2] / "profiles" / f"{name}.yaml"
    profile = load_profile(path)
    assert profile.name == "refserver"
    resolve_profile(profile, token="t", environ={})  # no host secrets needed


def test_the_http_reference_profile_shares_one_token_between_server_and_identities() -> None:
    path = Path(__file__).parents[2] / "profiles" / "refserver-http.yaml"
    out = resolve_profile(load_profile(path), token="abc123", environ={})
    tokens = out.profile.target.env["REFSERVER_TOKENS"]
    for identity in out.profile.auth.identities:
        assert f"{identity.name}:{identity.token}" in tokens.split(",")
    assert len(out.profile.auth.identities) >= 2  # enough for the cache-scope check


def test_a_missing_profile_file_is_a_profile_error(tmp_path: Path) -> None:
    with pytest.raises(ProfileError, match="cannot read"):
        load_profile(tmp_path / "nope.yaml")


def test_empty_resolved_secret_is_a_profile_error():
    profile = parse_profile(
        "auth: {type: bearer, identities: [{name: user, token: '{secret:EMPTY}'}]}"
    )
    with pytest.raises(ProfileError, match=r"auth.identities.0.token"):
        resolve_profile(profile, token="test", environ={"EMPTY": ""})
