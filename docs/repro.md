# Reproducing a finding

Every finding carries a one-line command in the report:

```text
probe repro report.json --finding 3f9a1c0d5b7e2a64
```

`probe run` writes a bundle for each finding next to the report, at
`<out>/repro/<finding_id>/repro.json` (plus `trace-excerpt.jsonl` when the finding points at
trace records). Keep the `repro/` directory beside `report.json`; the command reads it.

## What a bundle holds

How the target was started (command, URL or image), the scan settings that matter (mode,
seed, era, side effects, timeout scale, the profile), the wire steps the check recorded and
what it expected. Secrets never go in. `--secret-env` values are left out (the names are kept
and `probe repro` reads the values from your environment again), and the profile is stored with
its `{secret:NAME}` placeholders unresolved.

## `probe repro`

Starts a fresh target, runs **only the finding's check** with the same mode, seed, era and
profile, and reports:

| Output | Meaning | Exit |
| --- | --- | --- |
| `REPRODUCED` | the check reported a finding for the same check, tool and case | 0 |
| `NOT REPRODUCED` | the check ran and did not report it | 1 |
| `TARGET UNAVAILABLE` | the target did not start or answer | 3 |
| `INCONCLUSIVE` | the check could not run (not applicable, error, skipped) | 6 |

Exit 2 is a usage error (unknown finding, unreadable report), 4 an internal error, 5 an
unavailable sandbox.

Findings are matched by check, tool and case, not by finding id, because the id includes the
target's identity and a rebuilt or fixed target has a different one. To test a fix, point the
replay at it:

```text
probe repro report.json --finding 3f9a1c0d5b7e2a64 --image my-server:fixed
probe repro report.json --finding 3f9a1c0d5b7e2a64 --target-env FEATURE_X=off
```

## `--export-script`

```text
probe repro report.json --finding 3f9a1c0d5b7e2a64 --export-script repro.sh --no-run
```

Writes a POSIX shell script that sends the recorded requests without Probe and prints the
replies, so a maintainer can see the server's answer. stdio targets are fed with `printf`
(`docker run -i --rm <image>` for a sandboxed one); HTTP targets get one `curl` per request,
with the session handshake for legacy servers. Modern requests include the `_meta` the
2026-07-28 protocol requires. The script header names the check, the case and what Probe
expected.

The script shows the answer; it cannot judge effects Probe measures on the side (canary hits,
files changed, crashes). A finding that came from watching the whole scan has no recorded
requests, so its script says so. Values from the target are shell-quoted and header text is
cut to one comment line, so a hostile tool name cannot add commands. Only send the requests
to servers you own or may test.
