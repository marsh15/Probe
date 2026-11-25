# WP2 completion evidence

Base: `b8ae543`; branch: `fix/wp2-crashes`. Work was confined to the existing WP2 worktree.

All eleven assigned review entries are fixed. The ten inherited checked entries were audited;
the previously unchecked deep-JSON entry is now also checked. Other review entries remain open.

| Finding | Regression tests | Failure on b8ae543 |
| --- | --- | --- |
| Unhashable JSON-RPC IDs | `test_unhashable_id_scan_writes_report` (array and object) | TypeError in `response_methods`, aborting the scan |
| Huge integer TTLs and compared values | `test_huge_ttl_scan_records_finding_and_writes_report`, `test_huge_compared_integer_is_preserved` | OverflowError; TTL check becomes ERROR instead of a finding |
| Deep JSON text | `test_deep_json_text_does_not_abort_mirror_check`, `test_deep_server_text_scan_writes_report`, `test_oversize_json_text_is_not_parsed` | RecursionError; mirror check becomes ERROR instead of a finding |
| Report redaction | `test_short_secrets_do_not_corrupt_report_metadata`, `test_http_transport_survives_a_secret_named_http`, `test_secret_matching_a_tool_flag_preserves_typed_flag` | ValidationError from corrupted datetimes, enums, literal fields or model keys |
| Recorder leak | `test_runner_creation_failure_closes_recorder` | The file remains open after UsageError |
| Empty profile secret | `test_empty_resolved_secret_is_a_profile_error` | Unconverted pydantic ValidationError |
| Post-scan I/O exits | `test_output_io_errors_exit_internal`, `test_output_path_errors_exit_usage`, `test_output_directory_is_a_file_exits_usage`, `test_export_io_error_is_usage_error`, `test_export_disk_failure_is_internal_error` | Escaping OSError gives exit 1; an occupied output directory gives exit 4 |
| Inspector read-only directories and hostile entries | `test_reset_repeats_readonly_seed_directories`, `test_hostile_tree_snapshot_and_reset_are_bounded` | PermissionError on the second reset; unsupported entry rejects snapshot |
| Fixture reset and deleted inodes | `test_fixture_reset_restores_only_while_target_is_stopped`, `test_fixture_reset_stops_all_targets_before_restore_and_restarts`, `test_scan_connect_prepares_fixtures_and_shares_the_profile_token` | Restoration runs while the target is still running |
| Inspector creation versus deadline teardown | `test_close_racing_inspector_creation_reclaims_volume_and_lease` | A container remains after close |
| Container SIGTERM and extras cleanup | `test_shutdown_reports_attachment_sigterm_as_forced_exit`, `test_shutdown_tolerates_deadline_clearing_extras` | SIGTERM is misreported as clean EOF; list.remove raises ValueError |

The baseline regression run temporarily restored only implementation files inside this worktree,
with all modified contents saved in memory and restored in a `finally` block. It produced 36
expected failures and four passes in the main project (exit 1), plus two expected inspector
failures in the fixtures project (exit 1). Some parameterized redaction values do not corrupt
metadata on this particular scan; the failing parameters cover the reported issue. The tool-flag
test was added afterward, observed failing with the old `_redacted` function (ValidationError
at `tools.0.flags.0`, pytest exit 1), and passes with the inherited typed-field preservation.

`output.py` needed a fix: Python 3.14's C JSON decoder accepts the 20,000-level text, while the
installed Python 3.12 decoder raises RecursionError. The regression uses the stdlib's recursive
Python decoder as well as the default decoder, so it exercises the failure on both interpreter
families. A separate Python 3.12 check executed the actual old and new `_mirrors` function bodies:
old raises RecursionError, new returns False. Mirror text longer than the existing
`MAX_MESSAGE_BYTES` constant is skipped before decoding; parsing and comparison both catch
RecursionError.

Fixture restoration stops/removes every target instance before replacing data, restores fixtures,
starts a fresh main instance, and opens a new session on its transport. Fixture services and
volumes survive this operation. The `checks/context.py` change allows that already-started
transport to be supplied to `reconnect`, avoiding another runner restart. Initial seed setup
still precedes target startup. This uses the restart approach permitted by the review.

Exit meanings match `docs/cli.md`: internal/storage I/O failures return 4; invalid, missing,
occupied, non-directory, directory-as-file and permission-denied user paths return 2. Both scan
outputs and exported repro scripts use the same mapping. No CLI flags, report fields, documented
exit meanings, or catalog version changed.

No unrelated inherited edits were found or reverted. The HTTP transport finding and relay
timeout remain outside WP2 and untouched. No full suite, `make check`, Docker-marked tests, push,
or changes to main were performed. Free space remained approximately 6.5 GiB during validation.

## Validation

- Changed root test files: 187 passed (exit 0). The subsequently added tool-flag regression also
  passed alone (exit 0).
- Related schema, protocol, context, fixture and hostile-input tests: 172 passed (exit 0), including
  the tool-flag regression.
- Inspector test file, run from `fixtures_runtime`: 12 passed (exit 0).
- `uv run ruff check .`: passed after formatting the new tool-flag test (exit 0).
- `uv run ruff format --check .`: 372 files already formatted (exit 0).
- `uv run mypy src`: 152 source files passed (exit 0).

The preceding agent's transcript did not preserve the name of its timed-out scan test. To cover
that uncertainty, every test in `tests/engine/test_runscan.py` was run in its own pytest process:
27 passed (each exit 0), and
`test_an_injected_judge_fills_the_llm_block_and_leaves_the_score_alone` exceeded pytest's 120-second
timeout (exit 1). That exact test was then run alone with all modified Probe implementation files
temporarily restored to `b8ae543`; it again timed out at 120 seconds (exit 1). The failure is
pre-existing, and no unrelated change was made to address it. The saved WP2 files were restored
in a `finally` block. The deep complete-report test also passed alone before the per-test run.

The complete shell invocation log, including expected regression failures and isolated scan
commands, is in [2026-11-25-wp2-commands.md](2026-11-25-wp2-commands.md). Shell grouping exit codes
refer to the complete invocation. Baseline subprocess exit codes are called out separately.
