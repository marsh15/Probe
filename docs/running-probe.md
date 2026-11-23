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
| `--profile FILE` | A YAML profile: `target.name`, `target.env`, `checks.skip`, `tools.<name>.kind`. |
| `--target-env KEY=VALUE` | Set an environment variable for the server (merged over the profile). |
| `--secret-env NAME` | Treat this variable's value as a secret: it is redacted from every artifact. |
| `--allow-side-effects` | Also call tools that may write. Without it only read tools are called. |
| `--fail-on critical\|high\|medium\|low\|none` | The lowest finding severity that makes the run fail (default high). |
| `--out DIR` | Where artifacts go (default `./probe-out`). |
| `--seed`, `--timeout-scale` | Reproducibility and slow servers. |
| `-v`, `-q` | List every check result, or only the summary table. |

## Output

`--out` receives `report.json` (validates against `schemas/report.schema.json`), `trace.jsonl.gz`
(every message, redacted) and `stderr.log` (the server's stderr). The console shows pass, fail,
n/a, skipped and error counts per family and then the findings. Strings from the server are
stripped of terminal control codes before they are printed.

Scoring and grades are not part of this build: `score.grade` is `null`, so `--min-score` is
refused with a usage error rather than silently ignored.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No finding at or above `--fail-on`. |
| 1 | At least one finding at or above `--fail-on`. |
| 2 | Usage or configuration error (nothing was scanned). |
| 3 | The target could not be started or never answered. A report with status `target_unavailable` is still written. |
| 4 | Internal Probe error. |

A check that cannot reach a verdict ends in `error` and is listed in the report; it never counts
as a finding against the server and does not change the exit code.
