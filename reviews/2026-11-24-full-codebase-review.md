# Probe: full codebase review

Read-only review of the whole repository as of commit `683598d` plus the uncommitted T36
(official conformance) work. No code was changed. Done area by area with the `code-review`
skill at `high`; each entry names the file and line, what is wrong, a concrete way it fails,
and a suggested fix.

Severity: **important** = a bug this code has (most are false positives, crashes or wrong
verdicts), **pre-existing** = an older bug found while reviewing, **nit** = minor.

Use the checkboxes to track fixes.

## Summary

| Area | Important | Pre-existing | Nit | Status |
| --- | ---: | ---: | ---: | --- |
| 1. Wire client (`src/probe/wire`) | 5 | 0 | 5 | reviewed |
| 2. Engine, config, scoring, schema, classify, util | 5 | 3 | 2 | reviewed |
| 3. Check framework, protocol and schema checks | 10 | 0 | 0 | reviewed |
| 4. Behavior and operability checks | 10 | 0 | 0 | reviewed |
| 5. Safety checks, official conformance (T36), LLM judge | 16 | 0 | 4 | reviewed |
| 6. Sandbox, runners, fixtures, images | 9 | 0 | 1 | reviewed |
| 7. Reports, repro, CLI, selfval, scripts, CI, Action | 10 | 0 | 0 | reviewed |
| 8. Reference server | 5 | 0 | 5 | reviewed |
| **Total** | **70** | **3** | **17** | 90 findings |

Themes:

- **False positives on clean servers** are the largest group (legacy servers judged by modern
  rules, missing control requests, volatile fields not masked, rate limiting treated as a
  failure, write tools repeated). Each one would also break the "0 false positives" selfval gate
  on real servers.
- **Hostile-server crashes**: unhashable ids, huge integers, deep JSON nesting and non-ASCII
  header values can end a check, or the whole scan, with an exception.
- **Timeouts that ignore `--timeout-scale` and the scan budget** (campaign, slow checks, tasks,
  conformance).
- **Safety of the scanner itself**: a few paths let a hostile server steer Probe's own requests at other hosts (OAuth issuer fetch, relay DNS fallback, a loose permission gate), and some secrets reach artifacts or the LLM.
- **T36 is not ready to commit** (section 5a).

---

## 1. Wire client (`src/probe/wire`)

- [ ] **important** `transport_http.py:329`: an HTTP request times out even though its response already arrived, if the server keeps the SSE stream open (keepalive pings). `send()` → `_read_sse` reads until the stream closes, and `request()` waits for `send()` before the future. *Fails:* the server answers, then sends `: ping` every 15 s; after 30 s Probe raises RequestTimeout and scores the server as hanging. *Fix:* stop reading once the matching response is delivered, or race the future against `send()`.
- [ ] **important** `session.py:205`: `Session.exchange` reads the shared `transport.last_result`, which any concurrent send overwrites (reply POSTs from `_answer`, other checks). *Fails:* a legacy tools/call stream carrying a sampling request; the reply's 202 overwrites the result and the check judges the wrong exchange. *Fix:* return the `RawHttpResult` from `send`, or key it by request id.
- [ ] **important** `transport_http.py:255`: a non-ASCII header value raises UnicodeEncodeError from httpx `build_request`, which is not caught (only HTTPError/OSError/RuntimeError are), after the c2s trace record is already written. *Fails:* `exchange("tools/çall")` or a configured accented header crashes the check, and the trace shows a request that was never sent. *Fix:* catch ValueError around `build_request`, and encode `Mcp-Method` with `encode_header_value`.
- [ ] **important** `transport_base.py:227`: queue eviction in `_receive` can pop the `None` end-of-stream sentinel, so `notifications()` blocks forever after close. *Fails:* a stdio server's grandchild floods stdout after the parent exits; the sentinel is evicted at 10,000 items. *Fix:* stop accepting notifications once closed, or never evict the sentinel.
- [ ] **important** `session.py:321`: a modern server that rejects `server/discover` with a modern code (-32020..-32022) on a non-2xx status with a null id is treated as legacy, because `_discover` maps any HTTP error to legacy without reading `exc.result.responses`. *Fix:* look for a modern error in the HTTP failure's responses before falling back.
- [ ] **nit** `session.py:418`: legacy session-expiry recovery isn't serialized. Concurrent 404s each re-initialize, and `_wire = None` during the handshake drops `MCP-Protocol-Version` from in-flight requests (permanently if initialize fails). *Fix:* a lock; restore `_wire` on failure.
- [ ] **nit** `transport_http.py:324`: non-JSON bodies are cut to 64 KiB before redaction, so a secret straddling the cut leaks its prefix (also in `RawHttpResult.body`). *Fix:* redact before truncating.
- [ ] **nit** `transport_http.py:316`: an empty 202 with `Content-Type: application/json` is reported as a malformed message. *Fix:* test for an empty body first.
- [ ] **nit** `tasks.py:162`: `wait_for_terminal` never answers a second input request that reuses a key, so the task polls until timeout. *Fix:* track what was answered per round, not per key.
- [ ] **nit** `session.py:253`: `register_tools` never clears `x_mcp_header_errors` for a tool that becomes valid on re-listing. *Fix:* pop the entry in the clean branch.

## 2. Engine, config, scoring, schema, classify, util

- [ ] **important** `engine/runscan.py:420` (T36): the conformance suite gets no bearer token, so auth-protected servers fail every scenario (high for auth ones, capping the grade at B). *Fix:* pass the baseline identity, or NA under bearer auth.
- [ ] **important** `engine/runscan.py:123` (T36): the default image `probe-conformance:dev` is never published, and images are never pulled, so installed users get ERROR on every sandboxed HTTP scan. *Fix:* default to the released versioned tag and pull it, NA when missing, add `--conformance-image`.
- [ ] **important** `engine/runscan.py:410` (T36): the suite timeout (300 s) ignores the scan budget, the mode's wall clock and `--timeout-scale`, and can double a standard scan. *Fix:* cap it at the remaining budget.
- [ ] **important** `engine/scan.py:48` (T36): post-phase checks still run after the target is declared unstable, so the conformance suite reports connection failures as findings. *Fix:* ERROR `target_unstable` for post-phase checks that drive the target.
- [ ] **important** `engine/versions.py:4` (T36): a new check was added without bumping `CATALOG_VERSION`, and `--no-conformance` is not part of `scan_key`, so corpus results with different check sets share a key. *Fix:* bump the version and add the setting to the key.
- [ ] **pre-existing** `config/profile.py:278`: a profile secret that resolves to an empty string raises pydantic ValidationError, which isn't converted to ProfileError, so `probe run` exits 4 (internal error) instead of 2 with a profile message. *Fix:* catch ValidationError in `resolve_profile`.
- [ ] **pre-existing** `engine/runscan.py:344`: `_redacted` replaces secrets in every string, including enum, literal and datetime fields, then re-validates. A short secret such as `2026` or `http` corrupts `started_at` or `transport`, validation fails, and no report is written. *Fix:* redact free-text fields only, or fall back on validation failure.
- [ ] **pre-existing** `engine/runscan.py:308`: the Recorder (opens `trace.jsonl`) is created before `_make_runner`, which can raise UsageError or SandboxUnavailable outside the `try`/`finally`, so the file handle leaks. *Fix:* create the runner inside the `try`, or the recorder after it.
- [ ] **nit** `schema/normalize.py:65`: `minContains == 0` is also true for `false`, silently dropping `contains`. *Fix:* type-check the int.
- [ ] **nit** `schema/valid_gen.py:373`: when the generation worker crashes (EOF), the note says the draws timed out. *Fix:* a separate note.

## 3. Check framework, protocol and schema checks

- [ ] **important** `checks/protocol/_support.py:93`: an array or object JSON-RPC id from the server raises TypeError in `response_methods` (unhashable). `CacheFieldsPresent.applicable` calls it outside the engine's try, so **the whole scan aborts with no report**. *Fix:* ignore ids that aren't str, int or None.
- [ ] **important** `checks/protocol/discover.py:121`: legacy-only servers get a HIGH false positive "modern-capable server does not implement server/discover", because the forced-modern fresh session counts any server that answers `tools/list` without `initialize` (TS SDK stdio, stateless HTTP) as modern-capable. *Fix:* require a modern-only signal (a correct -32022, modern `_meta`/resultType) before judging; otherwise NA.
- [ ] **important** `checks/protocol/passive.py:123`: `error_code_ranges` applies the 2026-07-28 reserved range in legacy mode too, where -32000..-32099 are implementation-defined (and 2025-11-25 defines -32042). *Fix:* modern era only.
- [ ] **important** `checks/protocol/malformed.py:115`: when the restart budget is already spent, the retry raises TargetUnstable before anything is re-sent, and that is reported as "reproduced on a fresh instance". *Fix:* treat TargetUnstable as not reproduced (ERROR).
- [ ] **important** `checks/protocol/http.py:93`: the version-mismatch case accepts only 400 with -32020. A clean server that validates the header version first correctly answers 400 with -32022 and is failed. *Fix:* also accept -32022, or use a supported version for the mismatch.
- [ ] **important** `checks/schema/cache.py:149` and `checks/normalize_volatile.py:51`: a huge integer `ttlMs` (or any big int in compared results) raises OverflowError when converted to float. *Fix:* guard the magnitude, format big ints with `str()`.
- [ ] **important** `checks/schema/output.py:112`: `json.loads` of deeply nested server text raises RecursionError, which isn't caught. *Fix:* catch RecursionError and cap length or depth.
- [ ] **important** `checks/schema/cache.py:154`: several pages with different TTLs give several findings with the **same finding id** (the case id has no page or ttl), which breaks `probe repro --finding` and diff. *Fix:* put the page in the case id, or one finding per method.
- [ ] **important** `checks/protocol/http.py:198` (also `:151` RequiredHeadersEnforced): `origin_validated` (HIGH) passes whenever the tampered request isn't accepted, with no control request, so a 401, 5xx or timeout counts as "Origin validated". *Fix:* send the untampered request first and NA unless it is accepted.
- [ ] **important** `checks/normalize_volatile.py:15`: volatile fields such as `createdAt`, `elapsedMs`, `durationMs` and epoch *seconds* aren't masked, so the order, stateless and concurrency checks report nondeterminism on clean servers. *Fix:* match camelCase and unit-suffixed keys; mask epoch seconds too.

## 4. Behavior and operability checks

- [ ] **important** `checks/operability/logs.py:59`: one shared sentinel and logs that are never reset, so after one tool leaks every later tool is also blamed. *Fix:* a per-tool sentinel, or only search log output that arrived after the call.
- [ ] **important** `checks/behavior/_campaign.py:255`: `changed_anything` counts any non-GET backend request as a state change, giving HIGH false positives in ReplayIdempotent (an idempotent `PUT`) and InvalidInputRejected (a refused call that sent a POST). *Fix:* judge from collection, SQLite and file diffs, not backend writes.
- [ ] **important** `checks/operability/metadata.py:98`: MetaTolerated repeats a successful write call with `_meta`; non-repeatable tools (create, insert) fail the second time and the metadata is blamed. *Fix:* read or idempotent tools only, or confirm by repeating without `_meta`.
- [ ] **important** `checks/behavior/_campaign.py:231`: the hang-repeat exchange isn't guarded for TargetCrashed, so the check ERRORs with a wrong reason and a partial outcome list is cached as complete for later checks. *Fix:* catch it and mark the kind truncated or unstable in a `finally`.
- [ ] **important** `checks/behavior/input_handling.py:155` (also `:267`): InvalidInputRejected and ErrorsActionable PASS when the malformed campaign stopped early (budget, instability); `truncated` and `unstable` are never read. *Fix:* route through `conclude()` and handle truncated kinds.
- [ ] **important** `checks/behavior/_campaign.py:227`: per-case and liveness timeouts (10 s, 5 s), `_SLOW_TOOL_S`, `_LIST_LIMIT_S` and the task deadline cap ignore `--timeout-scale`. A slow-but-healthy tool on a serial stdio server is recorded as a reproduced crash (and the crash has `case_id=None`). *Fix:* scale them, and record the case id.
- [ ] **important** `checks/behavior/concurrency.py:141`: correct rate limiting (429 or a "rate limited" error) is reported as concurrent calls disagreeing, which contradicts BurstResilient. *Fix:* skip rate-limit replies.
- [ ] **important** `checks/behavior/results.py:231`: EmptyResultOk blames an "empty match" on tools that fail on every call (no baseline is established first). *Fix:* require a successful baseline call with the base arguments.
- [ ] **important** `checks/behavior/agent_recovery.py:82`: each attempt spends budget twice (`budget.take()` plus `ctx.call`), and BudgetExhausted or TargetCrashed are not caught, so the experiment and its paid LLM results are discarded. *Fix:* drop the extra `take()` and catch both as skipped cases.
- [ ] **important** `checks/operability/burst.py:44`: the backend-5xx regex runs on successful results, so a log-search tool returning `status=503` text is flagged. *Fix:* error results only, or compare with the baseline.

## 5. Safety checks, official conformance (T36), LLM judge

### 5a. Official conformance (uncommitted T36): first-pass review

T36 must not be committed until these are fixed. It also has 5 failing tests: the clean-refserver
protocol expectations, and `--conformance` is undocumented.

- [ ] **important** `sandbox/conformance.py:37`: the container is named `probe-conformance-…`, but `owned()` in `sandbox/spec.py` accepts only target, fakehttp, canary, relay, inspect and init, so teardown refuses to remove it. The network and lease are left behind and "sandbox cleanup incomplete" is raised. *Fix:* add `conformance` to `owned()`.
- [ ] **important** `runners/container_http.py:70`: the suite calls `http://target:<port>`, so its requests carry the host name `target`. DNS-rebinding protection (the refserver's `_allowed_hosts`, the SDK defaults) rejects it, giving FAILs on clean servers. *Fix:* send the suite's traffic through the relay with a localhost Host, or treat 421/403 Host rejections as ERROR.
- [ ] **important** `checks/official/conformance.py:142`: no auth is passed to the suite (see 2).
- [ ] **important** `checks/official/conformance.py:32`: the timeout is outside the scan budget (see 2).
- [ ] **important** `checks/official/conformance.py:189`: no liveness check before running the suite (see 2).
- [ ] **important** `engine/runscan.py:123`: the `:dev` image is never published (see 2).
- [ ] **important** `checks/official/conformance.py:196`: one unreadable `checks.json` (or any `@@PROBE-ERROR@@`) turns the result into ERROR and drops real failures from the other scenarios. *Fix:* emit findings for what parsed; ERROR only if nothing parsed.
- [ ] **nit** `sandbox/conformance.py:36`: HOME is `/home/probe`, which the replaced tmpfs no longer mounts on a read-only root. *Fix:* HOME=/tmp.
- [ ] **nit** `checks/official/conformance.py:178`: `--no-conformance` is reported as NA when it should be SKIPPED.
- [ ] **nit** `checks/official/conformance.py:147`: any scenario name containing "auth" (for example "author") becomes HIGH. *Fix:* match on a token boundary.

### 5b. Safety checks and LLM judge

- [x] **important** `checks/safety/oauth.py:155`: **the server under test can make Probe GET any private or link-local address from the scanner host**. A target-supplied `authorization_servers[0]` is trusted when it is private (which includes 169.254.0.0/16), and the URL is built by string concatenation, so a query string controls the path. The response goes into the trace and finding. *Fails:* on a cloud runner, `http://169.254.169.254/latest/meta-data/iam/security-credentials/role?x=` leaks credentials into artifacts. *Fix:* only fetch issuers on the target's own origin (or loopback for local targets); reject link-local and query/fragment issuers; build the URL with urljoin.
- [ ] **important** `checks/safety/_support.py:41`: `data_root()` comes from the first allowed root's parent, but the sandbox always places secret/, allowed_evil/ and probe-canary/ directly under /data. With `allowed_roots: [/data/allowed/notes]` you get a false CRITICAL path escape **and** missed command injection (the marker dir doesn't exist). *Fix:* use the fixed `/data` sandbox root.
- [ ] **important** `checks/safety/annotations.py:148`: `destructive_annotated` flags destructive-sounding tools with *no* annotations, but the spec default is already destructiveHint=true. *Fix:* only flag an explicit `destructiveHint: false` or `readOnlyHint: true`.
- [ ] **important** `checks/safety/outputs.py:105`: `no_hidden_instructions` flags ZWJ/ZWNJ (emoji, Persian, Indic) and LRM/RLM (RTL text), and the bare phrase "system prompt". *Fix:* exclude those characters, require imperative context.
- [ ] **important** `checks/safety/injection.py:253`: `readonly_enforced` (CRITICAL) blames the payload for any state change, with no benign control call, so access logs, SQLite WAL/SHM or cache files become false positives. *Fix:* diff a baseline call first; report only changes unique to the payload.
- [x] **important** `checks/safety/secrets.py:62`: generic-pattern matches (AWS keys, GitHub tokens, `sk-`, private keys) are stored **in full** in the excerpt and so reach report.json, SARIF, HTML and markdown. *Fix:* mask the matched span.
- [x] **important** `llm/judge.py:58`: `failed_args` and `error_text` go to Anthropic (and to the on-disk cache) without redaction, so real secrets echoed by the server leave the machine. *Fix:* pass the scan's Redactor into `build_prompt`.
- [ ] **important** `checks/safety/secrets.py:136`: the 6-tool fault-injection budget is spent on tools that never touch the backend, so backend-calling tools are never tested. *Fix:* count only tools whose baseline hit the backend.
- [ ] **important** `checks/safety/paths.py:35`: `_EVIL_MARKER` matches refusal wording ("outside the allowed root"); a refusal returned as normal content becomes a HIGH path escape. *Fix:* match the exact seeded file content or a token marker.
- [x] **nit** `llm/judge.py:76`: only the error text is fenced; the tool description and schema (server-controlled, up to 2000 chars) go in unfenced, and the docstring claims the system prompt says to treat input as data, which it doesn't. *Fix:* fence them too and add the instruction.

## 6. Sandbox, runners, fixtures

- [x] **important** `fixtures_runtime/.../relay.py:62`: the relay re-resolves `target` per connection and sits on the non-internal `ctl` network. When the target is down, Docker DNS falls back to the host's resolvers and search domains, so **hostile traffic and the bearer token can go to a real host called `target`**. *Fix:* connect only to addresses in the lease's private /24 (or the target's private IP); no external DNS for the relay.
- [ ] **important** `fixtures_runtime/.../inspector.py:303`: after the first reset, later resets fail on read-only seed dirs (0555 restored, then EACCES), and `inventory()` raises on sockets, FIFOs, files over 64 MiB or more than 10,000 entries. Every fixture-backed check then errors for the rest of the scan. *Fix:* chmod u+rwx before descending; delete without a hashable inventory.
- [x] **important** `sandbox/gc.py:51`: `probe sandbox gc` can force-remove a **running** scan's resources (age comes from a construction-time label; no liveness check). Long deep scans pass the 1 h threshold. *Fix:* skip scans whose lease has a live pid.
- [ ] **important** `sandbox/fixtures.py:404`: `reset()` recreates files under /data while the target holds them open; writes then go to deleted inodes and snapshots miss real side effects (SQLite servers). *Fix:* stop or restart the target around reset, or restore in place.
- [x] **important** `runners/url.py:37`: the permission gate passes unresolved `*.localhost` names and every non-global address, including CGNAT 100.64/10 (Tailscale peers), NAT64 and Teredo, all of which reach other people's machines. *Fix:* resolve `.localhost`; allow loopback, RFC1918/ULA and link-local only.
- [x] **important** `sandbox/docker_env.py:306`: on Docker Engine older than 26, internal networks still forward DNS to the host, so a target can exfiltrate data over DNS. `doctor` doesn't check the engine version. *Fix:* refuse old engines, or give targets an unroutable resolver.
- [x] **important** `fixtures_runtime/.../relay.py:68`: the relay's 60 s idle cut is hard-coded and ignores `--timeout-scale`, so long calls are cut mid-flight and the target is blamed. *Fix:* pass the effective timeout plus a margin.
- [ ] **important** `sandbox/docker_env.py:553`: deadline teardown races inspector creation, leaking the data volume and lease. *Fix:* a closing flag under a lock that refuses new containers.
- [x] **important** `sandbox/spec.py:103`: no disk limits. The /data volume and the json-file container log are unbounded, so a hostile target can fill the host disk. *Fix:* `log_config` max-size and max-file, and a size-limited data volume.
- [ ] **nit** `runners/container.py:206`: SIGTERM to `docker start -ai` passes through to the container, so a server that ignores EOF but handles SIGTERM is recorded as a clean EOF exit; also an unguarded `_extras.remove`.

## 7. Reports, repro, CLI, selfval, scripts, CI, Action

- [x] **important** `repro/bundle.py:86`: the bundle stores the raw command, URL and target env, so a secret passed in the URL or argv (redacted in report.json) is written to `repro.json` and the exported script, and uploaded with the CI artifact. *Fix:* run the scan's Redactor over the bundle.
- [ ] **important** `repro/export_script.py:145`: sandboxed scripts never pass secrets into `docker run` and send literal `{secret:NAME}` placeholders. *Fix:* `-e NAME` for each secret name; drop or flag values that still hold placeholders.
- [ ] **important** `repro/export_script.py:246`: raw HTTP steps don't record their URL, so they are replayed against the MCP URL, and legacy raw steps lack the session and version headers. *Fix:* record the URL in `raw_http_step`; add the headers.
- [ ] **important** `cli/selfval.py:74`: **`probe selfval` passes when nothing was tested** (a bad `--transports`, empty `--seeds`, or an http-only bug in `--fast`), reporting "0 of 0" and exiting 0. *Fix:* exit 2 on empty jobs; require at least one implemented bug.
- [ ] **important** `.github/workflows/release.yml:37`: PyPI publish runs without tests and in parallel with the image builds, so a broken commit, or a failed arm64 image, still burns the version on PyPI. *Fix:* run `make check` in `build`; make `publish-pypi` depend on `images`.
- [ ] **important** `integrations/github-action/action.yml:126`: with an image and the sandbox off (macOS runner, or no docker), the action passes `--image X --no-sandbox` and drops `command`, so Probe has no target and exits 2. *Fix:* fail clearly or use `command`.
- [x] **important** `integrations/github-action/action.yml:197`: the badge updates from any branch push, and publishing it runs `git checkout --orphan` / `git rm -rf .` **in the caller's workspace**. *Fix:* default branch only; use a temp clone or worktree.
- [ ] **important** `cli/run.py:167` (also `cli/repro.py:50`): I/O errors after the scan (writing reports, bundles or the export script) escape as tracebacks with exit 1, which means "findings at threshold" (or "not reproduced"). *Fix:* map them to exit 4 (or 2 for a bad path).
- [x] **important** `report/text.py:5`: `md_text` doesn't stop GFM autolinks or @mentions, so a hostile server name can ping teams and show live links in a PR comment. *Fix:* escape `@` and break autolinks, or use code spans.
- [ ] **important** `.github/workflows/release.yml:67`: the published conformance image is never used by installed Probe (see 2 and 5a).

## 8. Reference server (`reference/refserver`)

The clean server must be correct, or selfval reports false positives against Probe.

- [ ] **important** `wire_bugs.py:190`: **on HTTP, Tasks-extension requests bypass auth, Host/Origin checks and routing** (answered before the Starlette app). *Fix:* answer tasks only after auth and transport security.
- [ ] **important** `config.py:42`: each process signs cursors and requestState with a random key, so two clean instances return different cursors, giving a false positive in `stateless_consistent` and cross-instance "invalid cursor". *Fix:* a deterministic default secret, or set `REFSERVER_SECRET` in the image and profiles.
- [ ] **important** `wire_bugs.py:342`: the stdio proxy reads one byte per syscall (`buffering=0` readline), about 0.9 s per MiB, so the proxied server looks slow to latency and timeout checks; short writes are also ignored. *Fix:* buffered reads; write until complete.
- [ ] **important** `tools/db.py:30`: the clean `query_db` rejects read-only `WITH RECURSIVE` (SQLITE_RECURSIVE is not allowed by the authorizer), and the 5 s limit is unreachable. *Fix:* allow `sqlite3.SQLITE_RECURSIVE`.
- [ ] **important** `tools/fetch.py:63`: the clean `fetch_url` SSRF guard lets through IPv4-compatible `::a.b.c.d` and NAT64 `64:ff9b::/96` addresses (both report `is_global`). *Fix:* unwrap or reject them.
- [ ] **nit** `wire_bugs.py:356`: b08 also turns off the -32600/-32700 replies for *parseable* invalid messages, a second undocumented defect. *Fix:* skip the shim only for unparsable lines.
- [ ] **nit** `wire_bugs.py:320`: the clean shim misses invalid id types (bool, object, array, float) and non-object params, which the SDK then drops silently. *Fix:* reply -32600.
- [ ] **nit** `tasks_layer.py:82`: tasks never expire despite `ttlMs: 60000`, and the table is unbounded and shared across identities. *Fix:* expire and cap.
- [ ] **nit** `__main__.py:35`: temp seeds are cleaned only by `atexit`, so crash bugs (`os._exit`) and signals leave about 8 MB per instance. *Fix:* clean stale dirs at startup.
- [ ] **nit** `auth.py:60`: for identities with hidden tools, a non-string tool name raises TypeError, giving -32603 where -32602 is expected. *Fix:* check the type first.

---

## Suggested order of work

1. **Things that can harm people or leak data**: oauth.py SSRF to metadata (5b), relay DNS fallback (6), url.py permission gate (6), secrets in excerpts, bundles and LLM prompts (5b, 7), the Action wiping the workspace (7), gc deleting live scans (6), refserver Tasks auth bypass (8).
2. **Things that end a scan**: the unhashable id aborting the scan (3), report redaction destroying the report (2), crashes from huge integers, deep JSON and non-ASCII headers (1, 3).
3. **False positives on clean servers**: sections 3, 4 and 5b, plus the refserver's random cursor key (8), which affects the selfval gate directly.
4. **Release and gate integrity**: selfval passing with nothing tested, release publishing before tests and images (7).
5. **T36 conformance**: fix 5a before committing.
6. The nits.

Each fix should come with a regression test that fails before the fix (the project's test-first rule).
