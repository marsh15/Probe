# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Offline schema dialect detection, bounded reference inlining, and draft-7 normalization with approximation diagnostics and generation checks against 60 real and 15 synthetic schemas
- Initial project bootstrap
- CLI structure with version command
- Project documentation and governance files
- JSON-RPC stdio client with bounded shutdown, queues and server-request handling
- Redacted, size-limited traces and stderr artifacts
- Regression tests for hostile server output, late replies and trace-write failures
- Corpus of 60 MCP tool input schemas with pinned sources and upstream license texts
- Streamable HTTP client with an incremental SSE parser, size and event limits, and raw HTTP access for negative tests
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
