# Self-validation

Probe tests itself the way it tests servers: `reference/refserver` is a small, correct MCP server
with bugs that can be switched on one at a time (`PROBE_REF_BUGS=b17`). `probe selfval` scans it
clean and with each bug on, then checks that

- every bug makes the check built for it **fail** (on every seed and every transport the bug runs on),
- the clean server fails **nothing** (no false positives), and
- no other check fails unless `tests/selfval/expected.yaml` allows it, with a one-line reason
  (a crash that the whole scan records, for example).

```
probe selfval --bugs all --seeds 1,2,3 --workers 4        # in the Docker sandbox, deep mode
probe selfval --fast                                      # no Docker: clean + 12 bugs, ~5 minutes
probe selfval --local --bugs b17,b19 --mode standard      # chosen bugs, no Docker
```

The exit code is 0 only when every bug is detected and nothing unexpected failed. Reports are
written to `<out>/selfval/report.md` and `report.json`; each scan's own report is under
`<out>/jobs/`.

A local run (`--local`, or `--fast`) starts the server as a plain process. Checks that need the
sandbox's fixtures are skipped there, so a local pass is quick feedback, not the full result:
the nightly workflow (`.github/workflows/selfval-nightly.yml`) runs the sandbox version.

## Adding a bug

1. Implement it behind `bugs.is_on("bNN")` in `reference/refserver` and list it in
   `bugs.IMPLEMENTED`.
2. Add an entry to `tests/selfval/expected.yaml`: the transports it runs on, the check that must
   fail, and any other check that may fail because of it (with the reason).
3. Add a detection test next to the check's other tests.

## The official suite is not part of the accuracy gate

`probe selfval` runs every scan with `--no-conformance`: it measures Probe's own checks, which
are deterministic. The nightly workflow runs the official suite against the clean reference
server in a separate job and uploads the result for reading.
