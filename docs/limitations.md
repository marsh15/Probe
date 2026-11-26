# What Probe does not tell you

- **Not a guarantee.** "No issues found" means none of Probe's checks found one on this run.
  The grade and coverage are separate: a high grade with low coverage is limited evidence.
- **Black box.** Probe drives the server through its protocol. It does not read source code,
  dependencies or configuration, so it cannot find a flaw that no input reaches.
- **Only what it can reach.** Auth-gated tools need a profile with identities. Tools that need
  real third-party accounts are exercised against fakes in the sandbox, not the real service.
- **Checks that need a sandbox are skipped without one.** Path escapes, SSRF, command
  injection and secret leaks are judged from canaries and file diffs that only the sandbox can
  observe. A scan without Docker reports them as skipped, and coverage drops accordingly.
- **Generated input is finite.** Cases are derived from the tool's schema, seeded and capped
  by mode (`quick`, `standard`, `deep`). A different seed or a deeper mode can find more.
- **Timing checks are approximate.** Head-of-line blocking, cancellation and burst checks
  depend on a slow call, named in the profile or guessed from parameter names.
- **The optional LLM experiment** sends tool metadata to a model provider and is not part of
  the score ([llm.md](llm.md)).
- **Protocol eras.** Probe speaks the 2026-07-28 stateless protocol and the legacy
  initialize-based versions. Era-specific checks stay in the coverage denominator, so a
  legacy-only server has lower coverage by design.
- **Official conformance.** The official MCP suite runs against sandboxed HTTP servers in
  standard and deep mode (`protocol.official.conformance`). Profiles with bearer auth are
  ineligible because the pinned suite versions cannot take a baseline token. Harness and
  Host errors do not count as findings. Use `--no-conformance` to skip the suite.
