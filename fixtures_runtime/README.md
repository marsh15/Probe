# Probe fixtures runtime

Private, disposable HTTP/TCP/filesystem fixtures. Python 3.12+, Starlette,
uvicorn and PyYAML; independent `uv.lock`. These endpoints intentionally expose
simulated data, request headers and fault controls. Use isolated test networks
and fake secrets. No authentication, TLS, external HTTP client or publishing.

```sh
uv sync --project fixtures_runtime --frozen
uv run --project fixtures_runtime pytest -q
uv run ruff check fixtures_runtime
uv run ruff format --check fixtures_runtime
make check

docker build -t probe-fixtures:dev fixtures_runtime
docker image inspect probe-fixtures:dev --format '{{.Size}}'
docker run --rm --network none probe-fixtures:dev --help
uv run --project fixtures_runtime python fixtures_runtime/scripts/smoke.py
```

The pytest plugin selects this project's tests when `uv --project` leaves the
working directory at the repository root; explicit pytest paths are honored.
The root suite remains independent. The image assembles the official
`python:3.12-slim` interpreter, its stdlib and discovered ELF libraries into a
small final filesystem. It runs as `10001:10001`, with locked runtime packages
only: no pytest, httpx, uv, pip, compiler, shell or package manager. Nothing pushes
or publishes the local `probe-fixtures:dev` tag.

## CLI and listeners

```sh
fixtures fakehttp --host 0.0.0.0 --port 80 \
  --admin-host HOST --admin-port 9090 [--routes /routes/routes.yaml]
fixtures canary --host 0.0.0.0 --ports 80,8080 \
  --admin-host HOST --admin-port 9090
fixtures relay --listen-host HOST --listen-port 8080 \
  --target-host TARGET --target-port PORT
fixtures inspect --root /data hash
fixtures inspect --root /data diff SNAPSHOT_A_JSON_FILE SNAPSHOT_B_JSON_FILE
fixtures inspect --root /data sqlite-checksum RELATIVE_PATH
fixtures inspect --root /data exists RELATIVE_PATH
fixtures inspect --root /data reset --seed /seed
```

HTTP defaults are those shown, except admin host defaults to `127.0.0.1`.
Relay defaults to listen on `127.0.0.1:8080`; target host/port are required.
The relay target must be a numeric IP, never a DNS name. DockerEnv supplies
`PROBE_RELAY_TARGET_SUBNET` with the lease's private /24 and
`PROBE_RELAY_IDLE_TIMEOUT` with the effective request/startup timeout plus 10 s.
Without a subnet, standalone relay targets must be loopback; the default idle
timeout is 60 s. Relay CLI flags are unchanged.
Inspector defaults to `/data`. JSON output is sorted and compact; invalid
operations exit 2 with a generic JSON error on stderr. SIGTERM/SIGINT shut down
listeners and connections. All HTTP listeners use one process and shared state.

**Admin is a separate ASGI app and socket**, bound only to addresses resolved
from the supplied admin host. There is no wildcard fallback, and the data app
never exposes `/_probe/*`, even through YAML catch-all routes. uvicorn does not
trust forwarded source-IP headers. For T14, supply the scan-specific
`probe-fakehttp-admin-SCAN` / `probe-canary-admin-SCAN` alias exclusively on the
control network. Publish admin port 9090 to host `127.0.0.1` only. Docker port
publishing must target the interface on which admin is bound (normally make
control the primary network); publishing against a data-network address does
not reach the control-only listener. Docker disables published ports when all
attached networks are `--internal`; the smoke uses a normal control bridge and
an internal data bridge, with all published ports restricted to host loopback.
No outbound request is made. Readiness should use data `/hello.txt` or
canary `/`, and admin `/_probe/log` or `/_probe/hits` on its own address.

## fakehttp

`--routes` names a YAML file; its parent is the explicit body-file directory.
No symlink component, absolute body-file path or `..` component is accepted.
Files are captured at startup, so replacing a file cannot redirect later reads.
Example public fixture configuration:

```yaml
collections:
  tasks:
    id_field: id
    seed: [{id: 1, title: seeded}]
routes:
  - method: GET
    path: /files/{name}
    status: 200
    headers: {content-type: text/plain}
    body_file: literal.txt
  - method: POST
    path: /tasks
    collection_op: {name: tasks, op: create}
    latency_ms: 10
  - method: GET
    path: /flaky
    body: recovered
    fault: {status: 429, retry_after: 2, count: 1}
```

Routes are matched in YAML order before built-ins and collections. Each requires
`method`, a Starlette `path` pattern, and exactly one of `body`, `body_file`,
`collection_op`. Optional `status` defaults to 200 for static responses and the
normal CRUD status for collection operations. `headers`, `latency_ms`, and
`fault` are optional. String bodies are literal bytes in UTF-8; other JSON-safe
values become JSON. `collection_op` accepts `{name, op}`, where `op` is `list`,
`get`, `create`, `replace`, `patch`, or `delete`; item operations take the route's
`{id}` parameter. Unknown fields, malformed headers, duplicate routes/seed IDs
and missing collection references fail startup.

| Data endpoint | Result |
| --- | --- |
| `GET /hello.txt` | `200 probe-public-ok` |
| `GET /redirect?to=URL&code=302` | Location redirect; 301/302/303/307/308 |
| `GET /big?bytes=N` | N streamed `x` bytes, 64 KiB chunks, max 64 MiB |
| `GET /slow?ms=N` | Delay 0–30,000 ms, `probe-slow-ok` |
| `GET /json/large?items=N` | `[{"id":0,"value":"probe"},…]`, max 10,000 |
| `GET /c/NAME?page=1&per_page=100` | `{items,page,per_page,total}`, per_page ≤1,000 |
| `GET /c/NAME/ID` | Item object or 404 |
| `POST /c/NAME` | Create object, 201; omitted identity gets next integer |
| `PUT /c/NAME/ID` | Replace object preserving identity, 200 |
| `PATCH /c/NAME/ID` | Merge object preserving identity, 200 |
| `DELETE /c/NAME/ID` | 204, or 404 when absent |

IDs are short nonnegative integers or path-safe strings; duplicates return 409,
identity changes and invalid input 422. Auto IDs do not reuse deleted IDs until
reset, including numeric seed IDs and explicitly supplied numeric IDs. Reset
restores the seed highwater. Collection writes reject invalid JSON, nonfinite
numbers and unpaired Unicode surrogates (including nested values and keys)
before changing rows or ID counters; valid Unicode and emoji are accepted.
Collections preserve insertion order.

| Control endpoint | Result |
| --- | --- |
| `GET /_probe/log?since=0` | Array of retained records with sequence > since |
| `GET /_probe/state` | `{"collections":{"NAME":[…]}}` |
| `POST /_probe/reset` | `{"reset":true}`; restore seeds, clear history and all faults |
| `POST /_probe/fault` | `{route,status:429,retry_after:2,count:N}` → `{"fault":true}` |

Fault route identifies an exact request path or configured Starlette pattern;
N is 1–10,000 and Retry-After 0–3,600 seconds. Matching requests consume one
fault and return 429. Reset also clears YAML startup faults, rather than
rearming them. History contains `sequence`, `method`, `host`, `path`, `headers`
(including traceparent), `body_sha256`, and `source_ip`; bodies are never retained
in history. Sequence numbers stay monotonic across reset. This is an in-memory
fixture, with no durable state or multi-worker support.

## canary and relay

Canary shares bounded history across its data ports, responds `200 probe-canary`
to ordinary HTTP methods and arbitrary paths, and reserves `/_probe/*` from data
access. Its separate admin app provides `GET /_probe/hits?since=0` (same record
shape as fakehttp) and `POST /_probe/reset`.

Relay forwards arbitrary raw TCP bytes in both directions with backpressure,
64 KiB reads, half-close propagation, a 10-second connection timeout,
60-second per-direction inactivity timeout, and at most 128 active connections.
Excess connections close immediately. Closing the relay cancels and awaits all
forwarding tasks and closes both sockets. There is no HTTP parsing or proxy client.

## inspector and limits

`hash` returns a path-sorted object mapping relative paths to `{type,mode,…}`.
Regular files add content `sha256`; symlinks add literal `target` without being
followed; directories include their mode. The root itself is excluded. Changes
to paths, content, mode, or link targets therefore change the snapshot. `diff`
returns sorted `{added,changed,removed}` path arrays. `exists` returns
`{"exists":true|false}`; a final symlink exists without being followed. All
relative paths reject absolute paths, `..`, and traversal through symlinks.

`sqlite-checksum` returns a sorted table map `{NAME:{count,sha256}}`. It reads
an isolated in-memory copy, quotes identifiers, sorts type-tagged canonical rows
and includes column names in each hash. Blob, duplicate-row and WITHOUT ROWID
tables work independently of insertion order. Views, virtual/shadow tables and
generated expressions are excluded; triggers and target-provided SQL are never
executed. The database must be quiescent: checkpoint and close nonempty WALs
first. This is a content checksum, not a byte-level database-file checksum.

Reset requires disjoint explicit data/seed roots and a readonly, quiescent seed.
It preflights seed content and link targets, deletes **only children** of the data
root, and recreates seed files, modes, directories and safe relative symlinks.
Root inode changes, symlinked roots/ancestors, host system roots/trees,
privileged seed modes, unsupported special files and escaping/cyclic seed links
fail closed. Descriptor-relative no-follow operations prevent symlink redirection
of reads/deletes/writes. Stop target writers before snapshot, SQLite inspection
or reset: reset is not transactional against concurrent writers or storage errors.
The root directory/mount is retained and its own mode is not restored.

Bounds: 1 MiB HTTP body (10-second read deadline), 32 KiB/100 headers, 8 KiB path
and query each, 1,000 retained history records, 1,000 fault entries, 100
collections, 10,000 rows/collection, 8 MiB aggregate collection JSON and static
route bodies, 1,000 routes, 1 MiB YAML/configured body file. Inspector allows
10,000 entries, depth 64, regular files/databases ≤64 MiB, reset payload ≤64 MiB,
and SQLite ≤100,000 rows and 64 MiB encoded content per table. Each HTTP listener
(each data port and the separate admin port) admits at most 128 simultaneous TCP
connections, including idle sockets; excess sockets close immediately. Complete
initial headers must arrive within 5 seconds of acceptance. Subsequent headers
must complete within 5 seconds of the preceding response, including idle time;
partial input never extends either deadline. Expiry closes the socket. Body
reads retain their separate 10-second deadline; complete headers cancel the
header timer while a body or response is in progress. Disconnect and shutdown
release admission slots and cancel timers. Rejected oversized requests are not retained.
TLS, sandbox orchestration, profiles and scan tooling belong to later tasks.
