# Profiles

A profile tells Probe what it cannot discover on its own: how the server is started, which tools
need a different classification, which arguments are known to work, and who the test users are.
Everything is optional. `probe run --profile FILE` uses one; `probe profile validate FILE...`
checks them; `probe profile init [--from-report report.json]` scaffolds one.

Unknown keys are errors (a typo never silently does nothing), and every skipped check needs a
written reason.

```yaml
version: 1
name: mcp-server-filesystem
target:
  transport: stdio                    # stdio | http
  image: probe-target/server:1.0      # sandbox mode (not used by `probe run` yet)
  command: ["mcp-server-filesystem", "/data/allowed"]   # used when nothing follows `--`
  http: {port: 3000, path: /mcp}      # http only (defaults shown)
  env: {LOG_LEVEL: debug}
  secrets:                            # injected as environment variables
    API_TOKEN: {value: "probe_fake_tok_{token}", real: false}
  startup_timeout_s: 30
fixtures:                             # needs the sandbox
  fs: {seed_dir: fixtures/fs/basic, allowed_roots: ["/data/allowed"], sentinel: true}
  http: {routes: fixtures/http/github.yaml, env_base_urls: {GITHUB_API_URL: "http://fakehttp/github"}}
  sqlite: {path: /data/app.db, seed_sql: fixtures/db/notes.sql}
  git: {path: /data/allowed/repo, seed_bundle: fixtures/git/small.bundle}
tools:                                # overrides; keys may be globs
  write_file: {kind: write, idempotent: true}
  run_command: {kind: exec, intended_exec: true}
  "get_*": {kind: read}
inputs:                               # known-good arguments, tried first
  read_file: [{path: /data/allowed/readme.md}]
elicitation_answers:
  - {match: {message_regex: "(?i)confirm"}, response: {action: accept, content: {confirm: true}}}
auth:
  type: bearer                        # none | bearer
  identities:                         # two or more enable schema.cache_scope_correct
    - {name: alice, token: "probe_fake_alice_{token}"}
    - {name: bob, token: "probe_fake_bob_{token}"}
checks:
  skip: {operability.burst_resilient: "upstream documents no rate limiting"}
notes: Free text shown in the report.
```

## Placeholders

- `{token}` is one value per scan, shared by `target.command`, `target.env`, `target.secrets` and
  `auth.identities`, so the server's configuration and Probe's credentials always agree. It is
  derived from the seed and the profile, so the same scan gets the same token.
- `{secret:NAME}` takes the value from Probe's own environment. It is never written to an
  artifact: it is redacted from the trace, the report and the console. If `NAME` is not set the
  scan stops with a usage error that names it.

Anything else in braces is left as written, so JSON in a value is safe.

## Secrets

`target.secrets` values are passed to the server as environment variables. Mark a value
`real: true` when it is a real credential: it is then redacted from every artifact. Fake values
(the default) stay visible, because a fake secret appearing in a log or an error is evidence.

## Tool overrides

An exact name beats a glob, and the first matching glob (in file order) wins. `kind` replaces the
classifier's guess (`read`, `write`, `destructive`, `exec`, `unknown`); Probe will only call a
tool that may write when side effects are allowed. A profile classification is reported as
`classification_source: profile`.

## Skipping checks

`checks.skip` maps a check id (or glob) to the reason. The check appears in the report as
skipped with `skipped by the profile: <reason>`, so a reader sees what was left out and why.

## Schema

`schemas/profile.schema.json` describes the file for editors; it is generated from the model
(`uv run python scripts/export_schemas.py`) and CI fails if it is stale.
