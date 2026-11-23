# Sandbox core

The core provides isolated Docker resources and a stdio runner. Application CLI
commands wrap the callable APIs below. Profile orchestration, fixture seeding,
and HTTP readiness belong to higher layers. Importing these modules creates no
Docker resources.

## Commands

`probe sandbox doctor` checks the Docker CLI, daemon, Linux engine, public subnet
pool, and optional gVisor runtime. It creates no Docker resources and exits
nonzero when a required prerequisite is unavailable.

`probe sandbox gc` collects expired, proven-owned resources and abandoned subnet
leases. The minimum age is one hour. Use `--scan-id ID` to restrict collection to
one scan, `--older-than SECONDS` to increase the age, and `--cache-dir PATH` for a
nondefault lease directory. Partial cleanup or a daemon error produces a nonzero
exit status with diagnostics.

## APIs

- `probe.sandbox.spec.target_spec(scan_id, image, command=None, env=None,
  runtime=None, created=None)` returns Docker SDK container creation arguments.
  A command is a complete executable argv, replacing image ENTRYPOINT and CMD;
  omitting it preserves both image defaults. Only `runsc` is accepted as an
  optional runtime. Fixed locale, Python encoding, and home values cannot be
  overridden. Additional environment values are passed explicitly; host process
  environment is never copied into a target.
- `DockerEnv(scan_id, client=None, cache_dir=..., public_pool=None,
  fixtures_image="probe-fixtures:dev")` supports `with`, or `create()` and
  `close()` in a caller's `finally`. `create_target(...)` creates a stopped,
  hardened container with both data endpoints attached. The async runner owns
  process startup. `close()` returns cleanup errors, retaining the reservation
  when cleanup is incomplete. Context-manager exit raises on cleanup failure or
  adds failure notes to the original exception.
- `start_fixture("fakehttp", api_aliases=...)`, `start_fixture("canary")`, and
  `start_fixture("relay", target_port=...)` attach both endpoints before starting
  the fixture. They use the separate argv flags agreed with the fixtures runtime.
  `control_url(container, port=9090)` returns the inspected loopback-published URL;
  use port 8080 for relay. This method does not assert application readiness.
- `create_inspector(args, writable=False)` returns a stopped container with no
  network and the data volume read-only. Pass `writable=True` for reset. Inspector
  operations are passed after `fixtures inspect --root /data`. The caller starts,
  waits for, and reads the result; the environment owns final removal.
- `initialize_data(trusted_image)` runs a short, networkless helper with only
  CAP_CHOWN to assign the data volume root to UID/GID 10001. It neither walks nor
  changes existing files. The helper requires Python in a trusted image. Never
  pass an untrusted target image. Production runner initialization uses the
  configured fixtures image. FixtureSet should prepare the sandbox volume and
  then pass `initialize_data=False` when it owns population.
- `ContainerRunner(image, sandbox=env, command=None, env=None, runtime=None,
  mode_deadline_s=300, recorder=None, initialize_data=True)` implements the
  committed Runner protocol. Stdio uses a local `docker start -ai CONTAINER_ID`
  subprocess and the existing bounded `StdioTransport`. The runner owns the
  supplied environment: `stop()` removes its containers, fixtures, networks and
  volume. Treat stop as terminal; restart refreshes the main container while
  retaining the fixtures and second instances. Repeated start returns the main
  transport. A second instance shares the same named data volume and fixture
  networks, with an independent container and attachment.
- `probe.sandbox.gc.collect(client=None, cache_dir=..., now=None, age_s=3600,
  scan_id=None)` returns `GCResult(removed, leases, errors)`. `scan_id` optionally
  scopes resource collection. The minimum age is one hour. `doctor(client=None)`
  reports CLI availability, daemon reachability, Linux engine, architecture,
  optional runsc and configured pool validity. The commands above wrap these
  callable APIs.

SDK calls run outside the event loop in ContainerRunner. SDK requests have a
10-second timeout with the default client. Callers injecting a client must supply
an equivalent bounded timeout. Cancellation waits for in-flight creation before
cleanup, avoiding a late-created orphan. The watchdog starts at first start and
kills at the supplied mode budget plus 60 seconds; restart never resets it.
Pass the remaining mode budget if the enclosing scan clock has already started.
The runner caches the main exit code, OOM flag and bounded stderr after teardown.
Stop closes stdin, uses Docker's five-second SIGTERM grace, and escalates to kill;
cleanup still runs when attachment or lifecycle operations fail. Call `stop()` in
an outer `finally`, including after failed startup.

## Isolation and ownership

Scan IDs contain 1–40 lowercase ASCII letters, digits or hyphens, with an
alphanumeric first and last character. The length keeps exclusive control aliases
within a DNS label. Resource names for the three bridges and data volume are
`probe-pub-ID`, `probe-priv-ID`, `probe-ctl-ID`, and `probe-data-ID`. Container names
include the role, scan ID and a random suffix. Every created resource has
`probe.scan` and integer Unix `probe.created` labels. Images are local prerequisites;
this code never builds, pulls or deletes images. Images declaring additional Docker
VOLUME paths are rejected, since those would create unowned anonymous volumes.

Pub uses an explicit global-looking IPv4 /24 on an internal bridge. Priv uses an
explicit RFC1918 /24 on an internal bridge. Targets join only these two bridges,
with `target` as a private alias, and have no published ports or host mounts. Ctl
is a normal bridge used only by fakehttp, canary and relay. Inspectors and volume
initializers have network mode `none`.

Fakehttp receives `fakehttp`, `public.probe.test`, and validated API aliases on
pub. Canary receives its private service and metadata aliases on priv. Names
`probe-fakehttp-admin-ID`, `probe-canary-admin-ID`, and
`probe-relay-control-ID` are attached exclusively on ctl. Fixtures bind their
admin/relay listener to that exclusive name, never their normal container name.
Ports are published only on `127.0.0.1` with a random host port. Binding and
application separation must both hold; loopback publication alone does not
protect a listener bound to all container interfaces.

The target policy fixes UID/GID, a read-only root, private bounded tmpfs mounts,
dropped capabilities, no-new-privileges, process/memory/CPU/file descriptor limits,
and Docker init. The only persistent writable mount is the per-scan named data
volume. Fixture admin traffic never requires joining a target to ctl.

## Subnet leases and cleanup

`SubnetAllocator` uses `flock` around reservation and release in
`~/.cache/probe/subnets` by default. Tests always use temporary directories.
`PROBE_PUBLIC_SUBNET_POOL`, or the explicit `public_pool` argument, must be a
canonical global IPv4 network between /16 and /24. Allocation examines at most
256 public and 4096 private /24 candidates. It excludes inspected Docker subnets
and concurrent reservation records, and fails on exhaustion. Use the same cache
directory for all scans against one daemon. Docker's overlap checks remain the
final authority if another client creates a network concurrently.

Each lease records a random ownership token, local PID, timestamp, and both
subnets. Complete records are flushed to private temporary files before atomic,
no-overwrite publication under the lock. Interrupted writers leave temporary
artifacts, which are recovered only when the exact temporary namespace, private
mode, current UID, and dead writer prove ownership. Nonregular records are opened
without blocking and remain untouched. Release requires the current token.
Stale collection retains young
leases, leases whose local PID is alive, and leases whose scan still has Docker
resources. Malformed records and symlinks are preserved; a reservation encountering
ambiguous records fails closed. Expired leases require both a dead local owner
and proof that Docker has no remaining resources. PID reuse can conservatively
retain a lease until the process exits. The cache is local to one host/daemon;
it is not a distributed lease service.

Cleanup uses retained Docker object IDs and reloaded ownership labels plus exact
name validation before each removal. It removes containers first, then networks
and volumes, and finally the lease. GC accepts only labeled, correctly named
resources older than one hour; surviving labeled resources prevent stale lease
collection. No global prune, unlabeled object removal, recursive host deletion,
or arbitrary host bind mount exists in this module.

## Verification

Run from the repository root:

```sh
uv run pytest tests/sandbox tests/runners/test_container.py -m 'not docker' -q
uv run ruff check src/probe/sandbox src/probe/runners/container.py tests/sandbox tests/runners/test_container.py
uv run ruff format --check .
uv run mypy src
make check
make e2e ARGS='tests/sandbox/test_docker.py -rs'
```

The Docker tests skip only when the daemon or a required local image is missing.
Available reference-image gates cover real stdio, lifecycle, hardening inspection,
volume ownership, blocked external access on each data bridge and both together,
GC, and teardown. A minimal listener using the reference image independently
checks startup DNS, control-IP binding, loopback publication and target isolation.
That listener test does not substitute for the full fixtures-runtime gate.

The full fixture gate requires both `probe-refserver:dev` and
`probe-fixtures:dev`. It checks the global-looking public baseline, private
canary, control-only startup aliases, inaccessible admin ports from targets,
absence of public admin routes, and final ownership cleanup. HTTP target/relay
readiness and FixtureSet seed/reset orchestration remain higher-layer integration
work. A skipped fixture test is a pending acceptance gate, never a complete T14
pass. All Docker tests assert their unique scan has no remaining containers,
networks or volumes in `finally`, including after an assertion fails.


## HTTP targets

`ContainerHttpRunner` (a `ContainerRunner` for streamable HTTP) starts the hardened target on
the internal networks and starts the relay fixture once. The relay is published on a
loopback-only port and forwards raw TCP to `target:<port>`; Probe's HTTP client talks to that
port, so the target never has a route out and nothing outside the machine has a route in. The
relay finds the target by its network alias, so a restarted target is reached through the same
port. Readiness is an HTTP request through the relay (any status counts); a TCP connect proves
nothing because the relay accepts before the target is listening. If the target exits during
startup, its last log lines are in the error. An HTTP server is stateless per request, so
`second_instance()` is `None` and checks that need another instance open a new connection.

`probe run --image REF` (or a profile with `target.image`) uses it when the profile says
`transport: http`, and the stdio `ContainerRunner` otherwise. `profiles/refserver-http.yaml`
is a ready example. The end-to-end tests (`make e2e ARGS="-k http_bugs"`) rebuild
`probe-refserver:dev` first if its source hash label is out of date.
