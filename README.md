# Probe: MCP Server Test Suite

A behavioral, safety and operability test suite for MCP servers. Probe calls a server's tools
the way an agent (or an attacker) would, inside a sandbox when you give it an image, and
reports what it found with evidence and **one command that reproduces each finding**. Its own
accuracy is measured too: it is run against a reference server with known injected bugs, and
the detection rate and false-positive count are published.

**Status: pre-alpha.** No issues found by Probe is not a security guarantee; see
[limitations.md](docs/limitations.md).

## Quickstart

```text
uv tool install probe-mcp          # or: pipx install probe-mcp

# a local stdio server: put its command after --
probe run --out probe-out -- npx -y @modelcontextprotocol/server-everything

# a running HTTP server you own
probe run --url http://127.0.0.1:3000/mcp

# a server in the sandbox (needs Docker)
probe run --image my-server:latest
```

You get a console summary, `probe-out/report.json` and `probe-out/report.html` (a single file
you can open or attach to a bug report). The exit code is 1 if there is a finding at
`--fail-on` (default `high`) or above.

```text
probe repro probe-out/report.json --finding <id>      # run one finding again
probe report probe-out/report.json --format sarif     # code-scanning output
probe diff before/report.json after/report.json       # what changed
```

## Where to read more

- [docs/cli.md](docs/cli.md): every command and option.
- [docs/profiles.md](docs/profiles.md): tell Probe about your server (tool kinds, known-good inputs, fixtures).
- [docs/scoring.md](docs/scoring.md): how the grade and coverage are computed.
- [docs/report.md](docs/report.md), [docs/repro.md](docs/repro.md), [docs/llm.md](docs/llm.md).
- [docs/checks.md](docs/checks.md): every check, with why it matters and how to fix it.
- [docs/selfval.md](docs/selfval.md): how Probe measures its own accuracy.
- [docs/faq.md](docs/faq.md) and [docs/limitations.md](docs/limitations.md).

## Development

See [ROADMAP.md](ROADMAP.md) for the stages and what "done" means for each, and
[CHANGELOG.md](CHANGELOG.md) for changes.
