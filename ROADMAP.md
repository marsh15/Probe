# Probe roadmap and stage tracker

Probe is a behavioral, safety and operability test suite for MCP servers.
The detailed design is a private planning document kept by the owner (not in this repo). This file is the short public version:
five stages, each with a clear "done" test, so the project always has an end in sight.

**Rule:** a stage is finished when its gate passes. When it does, we move on.
If we fall behind, we cut features only in the order of the plan's cut list (section 23).
We never cut: sandbox, fixtures, self-validation, safety checks, repro, scoring, disclosure.

## How work is done

- Work goes straight to `main` in small commits. Each commit does one understandable thing.
- Tests come first for core code. A task is done only when its acceptance commands pass after the last edit.
- Roles: the lead agent (Sonnet 5.5) builds core logic and reviews everything.
  Hard tasks go to Opus 5.5 (medium effort). Simple, repetitive tasks go to Haiku 4.5.
  A GPT-6.1 Codex reviewer cross-checks the work at the end of each stage.
- Outward actions (sending disclosures, filing issues or PRs on other people's repos, publishing) are drafted by agents and sent by the owner.

## Stages

| Stage | Dates (2026) | Goal | Gate: it is done when |
|---|---|---|---|
| **M1** Foundations | Nov 23 - Nov 29 | Project skeleton, wire client, reference server, protocol and schema checks, `probe run` | Reference server scanned in both protocol eras. 17 stdio bugs detected. JSON report validates. `make check` green. |
| **M2** Sandbox and behavior | Nov 30 - Dec 6 | Docker sandbox, fixtures, input generation, behavior checks, self-validation | Sandbox works. Generator is deterministic. 39/39 implemented bugs detected. 0 false positives. |
| **M3** Safety, scoring, reports | Dec 7 - Dec 13 | Safety and operability checks, scoring, HTML report, SARIF, GitHub Action, LLM judge, v0.9.0 | Self-validation at least 90% overall and 80% per family, 0 false positives. v0.9.0 on PyPI. Action works. |
| **M4** Corpus and disclosure | Dec 14 - Dec 20 | Scan 45 open-source servers, triage, send private reports | At least 40 servers scanned. All findings at or above medium triaged. Private reports sent by Dec 18. At least 10 public issues filed. |
| **M5** Release | Dec 21 - Dec 27 | Upstream PRs, site, docs, video, v1.0.0 | At least 6 PRs opened. Docs complete. v1.0.0 on PyPI. Coverage at least 85%. |

After the build: follow-ups and bugfix releases only, report published 2027-02-01, study closed 2027-03-22.

## Task status

Task IDs match section 20 of the plan. Update this table in the same commit that finishes a task.

| Task | Title | Status |
|---|---|---|
| T00 | Bootstrap (package, CI, docs, spec snapshots) | done |
| T01 | Core models and utilities | done |
| T02 | Wire: JSON-RPC, stdio transport, recorder | done |
| T03 | Wire: HTTP transport and SSE | done |
| T04 | Session and era negotiation | done |
| T05 | Reference server (clean) and bug framework | done (Docker build and both stdio eras verified) |
| T06 | Oracle tests against the official SDK | done |
| T07 | Check framework and scan engine | done |
| T08 | Runners: local stdio and URL | done |
| T09 | Protocol checks | done |
| T10 | Schema checks | done |
| T11 | Reference server bugs, batch 1 (20) | done (b08 over HTTP needs the T15 relay) |
| T12 | `probe run` CLI and JSON report | done |
| T13 | `probe checks list/show` and generated docs | todo |
| T14 | Hardened Docker sandbox and container runner | done (98 unit/CLI tests; eight Docker gates passed) |
| T16 | Fixture services and inspector runtime | done (63 tests; Docker build, size and service smoke gates passed) |
| T19a | Collect 60 real tool schemas (independent preparation for M2) | done |
| T19b | Tool classifier (independent preparation for M2) | done (57/60 corpus agreement; three misses documented) |

Remaining later tasks are added here when their stage starts.
