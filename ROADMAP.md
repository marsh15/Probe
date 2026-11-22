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
| T02 | Wire: JSON-RPC, stdio transport, recorder | todo |
| T03 | Wire: HTTP transport and SSE | todo |
| T04 | Session and era negotiation | todo |
| T05 | Reference server (clean) and bug framework | todo |
| T06 | Oracle tests against the official SDK | todo |
| T07 | Check framework and scan engine | todo |
| T08 | Runners: local stdio and URL | todo |
| T09 | Protocol checks | todo |
| T10 | Schema checks | todo |
| T11 | Reference server bugs, batch 1 (20) | todo |
| T12 | `probe run` CLI and JSON report | todo |
| T13 | `probe checks list/show` and generated docs | todo |

Later tasks (T14 onward) are added here when their stage starts.
