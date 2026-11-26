# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `protocol.official.conformance` runs the official MCP conformance suite (pinned image under `images/conformance`) against HTTP servers in the sandbox and reports each failed scenario check; `--no-conformance` turns it off, a failure in the suite's own harness is an error and never a finding
- A tag-triggered release workflow (PyPI trusted publishing, multi-architecture GHCR images, GitHub release from the changelog; `docs/releasing.md`) and a GitHub Action with SARIF upload, job summary, base-branch diff and an optional badge, drafted under `integrations/github-action/`
- README quickstart, a command-line reference, limitations and FAQ pages, and `scripts/check_cli_docs.py` (part of `make docs-check`), which fails when a command or option is not documented
- Optional `--llm` experiment `behavior.agent_recovery`: a cached, budgeted model call measures whether the server's error messages help an agent fix malformed calls (recovery rate and lift, no score weight); `--llm-budget-usd`, `--llm-cache` (see docs/llm.md)
- SARIF 2.1.0, a shields badge and a markdown summary (`--format sarif,md,badge`, `--sarif-anchor`, `--badge-style`), `probe report REPORT --format F` to write one from a finished report, and `probe diff BASE HEAD` for score change, new and fixed findings
- `probe run` writes a self-contained `report.html` (grade, families, findings with evidence and repro command, tools, checks, limits) by default; server text is escaped, a strict CSP allows no network, and axe finds no serious problems in light or dark at phone and desktop widths (see docs/report.md)
- `probe repro REPORT --finding ID` runs one finding's check again on a fresh target and prints REPRODUCED or NOT REPRODUCED, `--export-script` writes a standalone shell script of the recorded requests, and `probe run` writes a repro bundle per finding next to the report (see docs/repro.md)
- Ten more safety checks (`path_contained`, `no_command_injection`, `readonly_enforced`, `no_secret_leak`, `no_stack_traces`, `no_hidden_instructions`, `annotations_truthful`, `destructive_annotated`, `request_state_integrity`, `oauth_scopes_minimal`) and the remaining reference-server bugs b31-b49, so all 58 catalog bugs now exist; `probe selfval` builds the sandbox fixtures (seeded data, fake backend, fake credential) for the reference profile
- `probe selfval` scans the reference server clean and with each injected bug (sandbox or `--local`), reports detection, false positives and unexpected failures, and exits non-zero on any miss; `make selfval-fast` runs a dozen bugs without Docker in pull-request CI, and a nightly workflow runs every bug in the sandbox (see docs/selfval.md)
- `operability.meta_tolerated` and `operability.burst_resilient` no longer blame the metadata or the burst for a call that fails on its own because earlier scan calls changed the data
- Reference-server bugs b09, b14, b17-b24, b27, b54, b57 and b58 with a detection test for each; `concurrency_consistent` now tries up to three tools; the reference profiles carry known-good ids for `notes_get` and `notes_update`
- Behavior checks `cancellation_honored`, `no_head_of_line_blocking`, `stateless_consistent`, `mrtr_wellformed` and `tasks_lifecycle`, with a wire-level multi round-trip loop and Tasks client; the profile can name a slow call with `tools.<name>.slow_case`; the reference server now serves the Tasks extension and has bugs b25, b26, b28, b29 and b30
- Behavior checks `output_bounded`, `empty_result_ok`, `pagination_sound`, `concurrency_consistent`, `idempotency_declared`, `replay_idempotent` and schema checks `output_conforms`, `structured_text_mirror`; verified against the clean server in the sandbox with fixtures
- Behavior checks `valid_input_accepted`, `invalid_input_rejected`, `boundary_robust`, `errors_actionable` and `survives_campaign`, built on a shared generated-input campaign that runs each case once, repeats crashes to tell reproducible ones from one-offs, and never counts a merely slow tool as hung
- Sandbox SSRF and file-scheme safety checks with public-fetch baselines, canary-hit evidence, private-network profile overrides, and mode-specific payloads
- Six operability checks for trace propagation, metadata tolerance, concurrent bursts and backend rate limits, secret-free logs, graceful shutdown, and startup latency
- `schema.cache_scope_correct`: lists a server marks `cacheScope: public` must be identical for every profile identity; `probe run --url` now sends the first identity's bearer token
- Deterministic valid input generation with fixture-aware values, original-schema validation, mode caps, and killable per-tool budgets
- Deterministic boundary and malformed schema mutators with mode caps, sampling diagnostics, bounded work, and original-dialect validation of every malformed case
- Per-scan FixtureSet orchestration with isolated pristine seeds, sentinel layout, filesystem/SQLite/backend diffs, canary observation and phase resets
- Offline schema dialect detection, bounded reference inlining, and draft-7 normalization with approximation diagnostics and generation checks against 60 real and 15 synthetic schemas
- Initial project bootstrap
- CLI structure with version command
- Project documentation and governance files
- JSON-RPC stdio client with bounded shutdown, queues and server-request handling
- Redacted, size-limited traces and stderr artifacts
- Regression tests for hostile server output, late replies and trace-write failures
- Corpus of 60 MCP tool input schemas with pinned sources and upstream license texts
- Streamable HTTP client with an incremental SSE parser, size and event limits, and raw HTTP access for negative tests
- `probe run --image` / profile `target.image` run the target in the sandbox, including HTTP servers reached through a loopback-only relay (exit code 5 when Docker is unavailable); HTTP bug tests run end to end in Docker
- Full profile model with `{token}` and `{secret:NAME}` interpolation, tool-override globs and justified check skips, `probe profile validate/init`, the three reference-server profiles and `schemas/profile.schema.json` (see docs/profiles.md)
- `probe checks list/show` and `docs/checks.md`, generated from the checks' own metadata and kept honest by a staleness test and a CI step
- `probe run`: scans a stdio command or a URL, writes `report.json`, the redacted trace and the server's stderr, prints a per-family summary and the findings, and exits 0/1/2/3/4 (see docs/running-probe.md)
- Fixes from the M1 review: secrets are removed from the whole report and the console (not only the trace), a failed restart keeps the findings gathered so far, discovery is bounded in total size, a spent budget keeps findings already made, truncated trace bodies keep a summary so passive checks cannot be blinded by large responses, and server text can no longer inject console markup
- Twenty injectable reference-server bugs (protocol, schema and HTTP header bugs, b01-b08, b10-b13, b15, b16, b50-b53, b55, b56) as message rewrites shared by the stdio proxy and the HTTP middleware, with the self-validation expectations in `tests/selfval/expected.yaml`
- Ten schema checks (tools/list conformance, input schema validity, references, names, descriptions, cache fields, tool order, header annotations) with offline JSON Schema tooling and a tool-discovery step
- Twelve protocol checks: discover, unsupported version, result type, error codes, header and Origin validation, stdout cleanliness, malformed input, unknown method, era parity, deprecated features
- Check framework and scan engine: registry with plugin loading, status rules, phase gating, budget, baselines, crash and restart policy, liveness probe
- Local stdio and URL runners; URL targets must be local or private unless permission is asserted; calls to writing tools need `--allow-side-effects` or a sandbox
- Oracle tests comparing Probe's client with the official SDK client on the reference server
- Session layer: modern/legacy era detection, `_meta` and HTTP header building, `x-mcp-header` mirroring
- Standalone tool classifier with profile and annotation precedence, parameter-role detection, and risk heuristics evaluated on 60 schema fixtures
- Standalone Docker fixture runtime with fake HTTP collections and faults, private canary, TCP relay, and confined filesystem/SQLite inspection and reset
- Bounded fixture listeners, atomic rejected writes, monotonic collection IDs, and fixture tests included in `make check`
- Hardened per-scan Docker networks, data volumes, and stdio container runner with deadline enforcement and cancellation-safe cleanup
- Atomic subnet reservations, ownership-checked garbage collection, and `probe sandbox doctor` / `probe sandbox gc` commands
- Weighted scan scores, transport coverage, grade caps, and full/public-interim scoring profiles that exclude private checks and private finding caps from interim scores
- Grade, score and coverage in reports and console output, with finite `--min-score` thresholds and documented ungraded-scan behavior
