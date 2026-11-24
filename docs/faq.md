# FAQ

**Is it safe to point Probe at my server?** Probe calls tools. Read tools are always tried;
tools that may write are only tried with `--allow-side-effects` or in the sandbox, and
destructive tools only in the sandbox against its fixtures. Do not point it at a server that
holds real data you cannot lose, and do not scan servers you do not own or may not test.

**Why did my scan skip so many checks?** Without Docker the safety checks that need canaries
and file diffs cannot run. `probe run -v` lists every check and why it was skipped.

**What does the grade mean?** See [scoring.md](scoring.md). A critical finding caps the grade
at D and a high finding at B, whatever the score.

**A finding looks wrong.** Run `probe repro report.json --finding ID` to see whether it
happens again; the report and [repro.md](repro.md) show the exact requests. If Probe is wrong,
that is a bug in Probe: please open an issue with the repro command.

**Can I run it in CI?** Yes: `probe run --fail-on high --format json,sarif`. Exit code 1 means
a finding at or above the threshold. See [report.md](report.md) for SARIF and the summary.

**Does Probe send my data anywhere?** No, unless you pass `--llm`, which sends tool metadata
and error messages to the model provider ([llm.md](llm.md)).
