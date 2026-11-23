# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial project bootstrap
- CLI structure with version command
- Project documentation and governance files
- JSON-RPC stdio client with bounded shutdown, queues and server-request handling
- Redacted, size-limited traces and stderr artifacts
- Regression tests for hostile server output, late replies and trace-write failures
- Corpus of 60 MCP tool input schemas with pinned sources and upstream license texts
- Streamable HTTP client with an incremental SSE parser, size and event limits, and raw HTTP access for negative tests
- Twelve protocol checks: discover, unsupported version, result type, error codes, header and Origin validation, stdout cleanliness, malformed input, unknown method, era parity, deprecated features
- Check framework and scan engine: registry with plugin loading, status rules, phase gating, budget, baselines, crash and restart policy, liveness probe
- Local stdio and URL runners; URL targets must be local or private unless permission is asserted; calls to writing tools need `--allow-side-effects` or a sandbox
- Oracle tests comparing Probe's client with the official SDK client on the reference server
- Session layer: modern/legacy era detection, `_meta` and HTTP header building, `x-mcp-header` mirroring
- Standalone tool classifier with profile and annotation precedence, parameter-role detection, and risk heuristics evaluated on 60 schema fixtures
- Standalone Docker fixture runtime with fake HTTP collections and faults, private canary, TCP relay, and confined filesystem/SQLite inspection and reset
- Bounded fixture listeners, atomic rejected writes, monotonic collection IDs, and fixture tests included in `make check`
