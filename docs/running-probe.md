# Running Probe

```
probe run [options] -- <command that starts your MCP server over stdio>
probe run [options] --url http://localhost:3000/mcp
```

All probe options go **before** `--`; everything after it is the server command. A URL target
must be local or private unless you pass `--i-have-permission` (Probe sends malformed, oversized
and hostile requests, so only test servers you own or may test).

| Option | Meaning |
|---|---|
| `--mode quick\|standard\|deep` | How much to spend (default standard). Deep adds checks such as `protocol.era_parity`. |
| `--era auto\|modern\|legacy` | `auto` probes `server/discover` and falls back to `initialize`. |
| `--only GLOB`, `--skip GLOB` | Select checks by id, e.g. `--skip 'schema.*'`. Left-out checks appear in the report as skipped. |
| `--profile FILE` | A YAML profile (see [profiles.md](profiles.md)). Its `target.command` is used when nothing follows `--`. |
| `--target-env KEY=VALUE` | Set an environment variable for the server (merged over the profile). |
| `--secret-env NAME` | Treat this variable's value as a secret: it is redacted from every artifact. |
| `--image REF`, `--sandbox/--no-sandbox` | Run the target in the hardened Docker sandbox (default when an image is given, here or in the profile). An HTTP profile is reached through a loopback-only relay. |
| `--allow-side-effects` | Also call tools that may write. Without it only read tools are called. |
| `--fail-on critical\|high\|medium\|low\|none` | The lowest finding severity that makes the run fail (default high). |
| `--min-score NUMBER` | Require an overall score from 0 through 100. An ungraded scan fails any requested minimum. |
| `--out DIR` | Where artifacts go (default `./probe-out`). |
| `--seed`, `--timeout-scale` | Reproducibility and slow servers. |
| `-v`, `-q` | List every check result, or only the summary table. |

## Output

`--out` receives `report.json` (validates against `schemas/report.schema.json`), `trace.jsonl.gz`
(every message, redacted) and `stderr.log` (the server's stderr). The console shows grade,
overall score, coverage, grade caps, pass/fail/n/a/skipped/error counts per family, and findings.
Strings from the server are
stripped of terminal control codes before they are printed.

Scores use catalog severity weights and count each failed check once. Coverage measures how
much of the registered catalog was judged for the target transport. A high grade with low
coverage offers limited evidence; a scan with no applicable weighted checks stays ungraded.
See [scoring.md](scoring.md) for formulas, grade caps and disclosure profiles.

`--min-score` compares the reported overall score with the requested minimum; equality passes.
It accepts finite numbers from 0 through 100. A null score fails even a minimum of 0.
Either an unmet score minimum or a finding at or above `--fail-on` produces exit 1.
Usage, target, internal and sandbox errors retain their exit codes below.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No finding at or above `--fail-on`, and any requested score minimum was met. |
| 1 | At least one finding at or above `--fail-on`, or the requested score minimum was not met. |
| 2 | Usage or configuration error (nothing was scanned). |
| 3 | The target could not be started or never answered. A report with status `target_unavailable` is still written. |
| 4 | Internal Probe error. |
| 5 | A sandboxed scan was requested but Docker is unavailable. |

A check that cannot reach a verdict ends in `error` and is listed in the report; it never counts
as a finding against the server and does not itself change the exit code.

## Reproducing a finding

Each finding in the report names a one-line command, `probe repro report.json --finding <id>`,
and `probe run` writes the bundle it needs to `<out>/repro/`. See [repro.md](repro.md).
