# Command-line reference

All options of `probe run` go **before** `--`; everything after `--` is the server command.
Exit codes for `run`: 0 ok, 1 a finding at or above `--fail-on` or `--min-score` not met
(including an ungraded scan), 2 usage error, 3 target did not start or answer, 4 internal error,
5 sandbox unavailable.

## `probe run`

Scan one server: a command (local stdio), `--url` (a running HTTP server) or `--image` (the
sandbox).

| Option | Meaning |
| --- | --- |
| `--url URL` | Scan a running server. Non-local, non-private hosts also need `--i-have-permission`. |
| `--image REF` | Run the server in the sandbox from this image (Docker). `--sandbox` / `--no-sandbox` overrides the default of "on when an image is given". |
| `--profile FILE` | A profile ([profiles.md](profiles.md)). |
| `--mode quick\|standard\|deep` | How much to run. Default `standard`. |
| `--seed N` | Seed for every random choice; the same seed reproduces the same cases. |
| `--era auto\|modern\|legacy` | Which protocol era to speak. |
| `--allow-side-effects` | Also call tools that may write (outside a sandbox). |
| `--only GLOB`, `--skip GLOB` | Select checks by id. Repeatable. |
| `--timeout-scale X` | Multiply every timeout. |
| `--out DIR` | Output directory, default `probe-out`. |
| `--format LIST` | `json,html,sarif,md,badge`; default `json,html`. See [report.md](report.md). |
| `--sarif-anchor FILE`, `--badge-style grade\|coverage` | See [report.md](report.md). |
| `--fail-on SEVERITY` | `critical`, `high` (default), `medium`, `low` or `none`. |
| `--min-score N` | Fail if the overall score is below N or the scan is ungraded. |
| `--target-env KEY=VALUE` | Environment for the target. Repeatable. |
| `--secret-env NAME` | A variable whose value must never appear in any artifact. Repeatable. |
| `--i-have-permission` | Allow a target that is not local or private. |
| `--llm`, `--llm-budget-usd`, `--llm-cache` | The optional experiment in [llm.md](llm.md). |
| `-v`, `-q` (`--verbose`, `--quiet`) | List every check, or print only the summary. |

## `probe repro REPORT --finding ID`

Run a finding's check again on a fresh target, or export it. See [repro.md](repro.md).
`--export-script PATH`, `--no-run`, `--image REF`, `--target-env KEY=VALUE`, `-v` / `--verbose`.

## `probe report REPORT --format F` and `probe diff BASE HEAD`

Write one output format from a finished report, and compare two reports. See
[report.md](report.md).

## `probe checks`

- `probe checks list [--family F] [--format table|md|json]`: the catalog in run order.
- `probe checks show ID`: what a check tests, why it matters and how to fix a failure.
  The full catalog is [checks.md](checks.md).

## `probe profile`

- `probe profile init [--from-report REPORT] [--out PATH] [--force]`: scaffold a profile that
  lists every tool from a previous scan with its inferred kind. `--force` overwrites `--out`.
- `probe profile validate PATH...`: exit 2 if any profile is invalid. See
  [profiles.md](profiles.md).

## `probe sandbox`

- `probe sandbox doctor`: is Docker reachable, and is the sandbox configured.
- `probe sandbox gc [--scan-id ID] [--older-than SECONDS] [--cache-dir DIR]`: remove expired
  Probe resources. See [sandbox-core.md](sandbox-core.md).

## `probe selfval`

Scan the reference server clean and with each injected bug and report detection, false
positives and unexpected failures. Options: `--bugs`, `--seeds`, `--workers`, `--mode`,
`--out`, `--expected`, `--profiles`, `--refserver-src`, `--transports`, `--local`, `--fast`.
See [selfval.md](selfval.md).

## `probe version`

Print the Probe version.
