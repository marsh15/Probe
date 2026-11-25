# WP1 scanner security validation

Completed in the existing `fix/wp1-scanner-security` worktree, based on
`b8ae5432b7ad0609216207e20ec6457a7029148c`. No push, main checkout edit, full-suite
run, Docker test, or CATALOG_VERSION change was performed.

## Finding outcomes

All 13 WP1 findings are fixed and their review checkboxes are ticked. No finding
was skipped. Regression names below are relative to the repository root unless
prefixed with `fixtures_runtime/`.

| Finding | Regression tests |
| --- | --- |
| OAuth issuer SSRF/path manipulation | `tests/checks/safety/test_secrets_and_oauth.py::test_untrusted_oauth_issuer_is_never_requested`, `test_same_origin_oauth_issuer_uses_joined_metadata_url` |
| Relay DNS fallback | `fixtures_runtime/tests/test_relay.py::test_relay_rejects_target_name_before_any_dns_lookup`, `test_relay_never_accepts_dns_targets_or_external_addresses`; `tests/runners/test_container_http_security.py::test_http_restarts_replace_relay_with_current_private_ip` |
| Relay idle timeout | `tests/runners/test_container_http_security.py::test_scaled_request_timeout_reaches_http_runner`; `fixtures_runtime/tests/test_relay.py::test_relay_cli_gets_lease_and_timeout_without_changing_flags` |
| URL permission gate | `tests/runners/test_url.py::test_shared_and_transition_addresses_require_permission`, `test_localhost_subdomains_are_resolved` |
| Secret excerpts | `tests/checks/safety/test_secrets_and_oauth.py::test_generic_credential_excerpts_mask_all_matches`, `test_injected_evidence_does_not_expose_nearby_generic_credentials`, `test_private_key_excerpt_masks_key_material` |
| Repro redaction | `tests/repro/test_repro.py::test_bundle_redacts_secrets_in_command_url_env_and_export` |
| LLM redaction | `tests/llm/test_judge.py::test_run_scan_passes_real_secrets_to_judge`, `test_judge_redacts_inputs_before_api_and_disk_cache`, `test_judge_redacts_before_json_encoding_schema_and_response` |
| LLM fencing | `tests/llm/test_judge.py::test_all_server_controlled_prompt_text_is_fenced` |
| Markdown mentions/autolinks | `tests/report/test_text.py::test_hostile_markdown_cannot_mention_or_autolink` |
| Action badge publishing | `tests/unit/test_action_security.py::test_badge_publishing_is_default_branch_only_in_temporary_clone` |
| GC live PID guard | `tests/sandbox/test_gc.py::test_gc_never_removes_resources_of_a_live_lease` |
| Docker Engine <26 | `tests/sandbox/test_docker_env.py::test_old_docker_engine_is_refused_before_resources_are_created`; `tests/sandbox/test_gc.py::test_doctor_refuses_unsupported_docker_engine` |
| Disk/log limits | `tests/sandbox/test_docker_env.py::test_data_volume_has_a_size_limit`, `test_tmpfs_mount_survives_between_helpers`; `tests/sandbox/test_spec.py::test_target_logs_have_bounded_rotation` |

## Scope and decisions

- Retained `runscan.py` for the scaled relay timeout and scan-secret injection
  into the judge. Retained `factory.py` and `anthropic_judge.py` to carry the
  redactor through the real API/cache path.
- Retained `container_http.py` to inspect the current target's private numeric IP
  and replace its pinned relay on restart.
- Reverted the in-progress additions of public fixture CLI flags
  `--target-subnet` and `--idle-timeout`. The existing CLI flags are unchanged;
  DockerEnv supplies internal `PROBE_RELAY_TARGET_SUBNET` and
  `PROBE_RELAY_IDLE_TIMEOUT` environment values instead.
- Removed the in-progress new `engine_version` doctor JSON field. The existing
  doctor error path reports unsupported engines without adding a field.
- The relay allows only numeric loopback addresses standalone, or addresses in
  the supplied RFC1918 /24. DockerEnv validates the inspected address against
  its lease before launch. Idle timeout is the larger of effective request and
  startup timeouts, plus 10 seconds; finite positive scaled timeouts can exceed
  the old one-hour constructor cap.
- Bounded /data uses a 256 MiB local tmpfs volume; a networkless holder keeps its
  contents mounted between helpers and target restarts. Logs rotate at 10 MiB
  with three files. The seed volume remains scanner-owned and target-read-only.
- Completed private-key masking through the footer or end of truncated input.
  Redaction of LLM schemas and responses now precedes JSON encoding, including
  credentials containing quotes.
- Badge publication requires a full default-branch ref, excluding same-named
  tags, and performs destructive Git operations only inside a temporary clone.
- Updated the existing Docker smoke caller to use its inspected numeric target
  address and the relay environment contract, and updated the relevant docs.
  The Docker smoke itself was not run, as instructed.
- No public Probe CLI flag, exit-code meaning, report schema, or catalog version
  changed. No unrelated implementation edits were found beyond the removed
  CLI additions and doctor field.
- Baseline proof used temporary copies of b8ae543 source and current selected
  regressions under this worktree; these copies were removed afterward.
  Root baseline: 25 expected failures, 1 pass. Fixture baseline: 2 expected
  failures. The NAT64 parameter `64:ff9b::a00:1` already required permission
  on this Python 3.14 interpreter; the CGNAT/Teredo/special-use and localhost
  regressions reproduced the permission-gate finding.
- No test timed out. Fixture tests emitted one existing Starlette/httpx
  deprecation warning. All disk checks reported 6.5 GiB available, above 1.5 GiB.

## Commands and exit codes

Working directory for root commands was
`/Users/santoshkumar/.t3/worktrees/Probe/t3-eb8affed-93665bc515924963`.
Fixture commands ran from its `fixtures_runtime` project directory.

The focused root command (F) was:
```sh
uv run pytest tests/checks/safety/test_secrets_and_oauth.py tests/llm/test_judge.py tests/repro/test_repro.py tests/runners/test_url.py tests/runners/test_container_http_security.py tests/report/test_text.py tests/unit/test_action_security.py tests/sandbox/test_docker_env.py tests/sandbox/test_gc.py tests/sandbox/test_spec.py -q -p no:cacheprovider -o tmp_path_retention_policy=failed -m 'not docker'
```

| Command/run | Exit | Result |
| --- | ---: | --- |
| F, initial inherited diff | 1 | 132 passed; private-key-body regression failed |
| `uv run pytest tests/checks/safety/test_secrets_and_oauth.py::test_private_key_excerpt_masks_key_material -q -p no:cacheprovider -o tmp_path_retention_policy=failed` | 1 | Confirmed exposed private key body before fix |
| `uv run pytest tests/unit/test_action_security.py -q -p no:cacheprovider -o tmp_path_retention_policy=failed` | 1 | Full branch ref guard absent before fix |
| Fixture: `uv run pytest tests/test_relay.py::test_relay_cli_gets_lease_and_timeout_without_changing_flags -q -p no:cacheprovider -o tmp_path_retention_policy=failed` | 1 | In-progress required new flag broke unchanged CLI invocation |
| `uv run ruff check .`, first run | 1 | One long line in new action test |
| `uv run ruff format --check .`, first run | 1 | Two new test files needed formatting |
| `uv run ruff format tests/llm/test_judge.py tests/unit/test_action_security.py` | 0 | Formatted those two files |
| `python3` baseline-snapshot script (`git archive b8ae543`, copy selected test tree) | 0 | Worktree-local baseline created |
| Root baseline command below | 1 | 25 expected failures, 1 pass, 106 deselected |
| Fixture baseline command below | 1 | 2 expected failures, 4 deselected |
| Fixture: `uv run pytest tests/test_relay.py -q -p no:cacheprovider -o tmp_path_retention_policy=failed` | 0 | 6 passed |
| `uv run pytest tests/llm/test_judge.py::test_judge_redacts_before_json_encoding_schema_and_response -q -p no:cacheprovider -o tmp_path_retention_policy=failed` | 1 | Quoted secret exposed before encoding-order fix |
| Fixture: `uv run pytest tests -q -p no:cacheprovider -o tmp_path_retention_policy=failed` | 0 | 67 passed; one existing warning |
| `uv run pytest tests/llm/test_judge.py -q -p no:cacheprovider -o tmp_path_retention_policy=failed` | 0 | 14 passed after encoding-order fix |
| `python3` baseline cleanup script | 0 | Removed only this worktree's temporary snapshot |
| F, final | 0 | 135 passed |
| `uv run ruff check .`, after fixes and again after smoke caller update | 0 | All checks passed both times |
| `uv run ruff format --check .`, after fixes and again after smoke caller update | 0 | 374 files formatted both times |
| `uv run mypy src` | 0 | No issues in 152 source files |
| `git diff --check`, repeated | 0 | No whitespace errors |
| `python3` scope assertions | 0 | Exactly 13 checkbox-only changes, expected branch, no public CLI/schema/catalog path changes |
| `df -h /System/Volumes/Data`, before big runs and at completion | 0 | 6.5 GiB available on every check |

Baseline root command, run from the temporary baseline root with
`PYTHONPATH=<worktree>/.wp1-validation/baseline/src`:
```sh
uv run --project <worktree> pytest tests/checks/safety/test_secrets_and_oauth.py tests/llm/test_judge.py tests/repro/test_repro.py tests/runners/test_url.py tests/report/test_text.py tests/unit/test_action_security.py tests/sandbox/test_docker_env.py tests/sandbox/test_gc.py tests/sandbox/test_spec.py -k 'untrusted_oauth or generic_credential_excerpts or injected_evidence_does or same_origin_oauth or private_key_excerpt or all_server_controlled or run_scan_passes_real or bundle_redacts or shared_and_transition or localhost_subdomains or hostile_markdown or badge_publishing or old_docker_engine or data_volume_has or gc_never_removes or doctor_refuses or target_logs' -q -p no:cacheprovider -o tmp_path_retention_policy=failed --tb=short
```

Baseline fixture command, run from the temporary baseline fixture root with
`PYTHONPATH=<worktree>/.wp1-validation/baseline/fixtures_runtime/src`:
```sh
uv run --project <worktree>/fixtures_runtime pytest tests/test_relay.py -k 'rejects_target_name or relay_cli_gets' -q -p no:cacheprovider -o tmp_path_retention_policy=failed --tb=short
```

Read-only inspection used `pwd`, `git status --short`, `git diff --stat`,
`git diff --numstat`, scoped `git diff -- <paths>`, `git log -1 --format='%H %s'`,
`git branch --show-current`, `cat <source/test/config paths>`,
`sed -n <ranges> <source/test/doc paths>`, and `rg -n <patterns> <paths>`;
these completed with exit 0. The worktree-wide
`rg --files --hidden -g AGENTS.md -g '!**/.git/**'` returned exit 1 (no matching
AGENTS.md). File discovery `rg --files -g AGENTS.md -g '*test*' -g pyproject.toml -g '*review*'`
returned exit 0.

