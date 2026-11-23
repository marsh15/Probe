# Scan fixtures

Sandboxed profiles with a `fixtures:` section get a `FixtureSet` before the target
starts. Without that section, existing runner initialization is unchanged. The
scan context exposes the set, and the engine resets it before each active phase.
The runner owns final sandbox cleanup, including failed fixture startup.

`FixtureSet(sandbox, profile.fixtures, token=scan_token(seed, profile.hash))`
provides async `start()`, `snapshot()`, `reset()`, `canary_hits(since=0)` and
`backend_log(since=0)`. `FixtureSet.diff(before, after)` is pure. Filesystem paths
in snapshots and diffs are relative to `/data`; changed paths include mode and
symlink-target changes. SQLite and collection changes have separate lists.
`backend_writes` contains non-GET requests in the snapshot sequence window.
`FixtureState.log_length` is a monotonic sequence cursor, rather than retained
array length: histories are bounded and sequence numbers survive reset. Take
snapshots while the target is quiescent; filesystem, SQLite and HTTP observations
are sequential, not an atomic transaction. Windows exceeding retained HTTP
history cannot recover evicted requests.

`fs.seed_dir` is copied directly into the data root. With `fs.sentinel: true`,
the builder adds `allowed/readme.md`, `allowed/notes/a.txt`, a generated 5 MiB
`allowed/big.log`, `allowed/link_out -> ../secret`, `allowed_evil/evil.txt`,
`secret/SENTINEL` containing `PROBE-SENTINEL-<token>`, and empty `probe-canary/`.
Existing sentinel file collisions are errors. The token is exactly the profile's
per-scan token (currently 12 hexadecimal characters), not independently random.
`allowed_roots` remains profile metadata for checks; the target enforces its own
filesystem access policy.

SQLite and git destinations accept relative paths or absolute paths below
`/data`. SQLite seeds execute in a bounded in-memory database with an authorizer
blocking attached databases, pragmas, extension loading and virtual tables;
only the resulting database is written into the temporary seed tree. Git bundles
are captured regular local files and cloned with user/system configuration,
hooks and templates disabled; no network transport or submodule recursion is
used. With no SQL or bundle, an empty database or repository is created. Unsafe
or invalid inputs fail preparation. SQLite inspection inherits the inspector's
requirement to checkpoint and close nonempty WAL files before snapshotting.

The builder deletes its temporary host tree after producing the bounded archive.
It rejects special files, privileged permission bits and escaping symlinks. A
networkless helper receives the archive through Docker `put_archive`, into the
scan-labeled named volume `probe-seed-ID`. This volume holds separate `data/` and
optional `http/` trees. Only that upload helper mounts the seed writable; target
containers never mount it. Reset uses the existing confined inspector with
`/seed` read-only and `/data` writable, and revalidates the entire seed before
removing data. No container receives host bind mounts. Both normal cleanup and
`probe sandbox gc` recognize the seed volume.

HTTP fixtures capture the routes YAML and referenced body files in `http/`,
mount that seed read-only in fakehttp, attach configured public aliases, and
inject `env_base_urls` as target environment defaults. Explicit target settings
and CLI environment overrides take precedence. Canary starts for every fixture
scan; relay remains owned by the HTTP runner. Admin access uses only inspected
loopback-published control ports, with proxy environment inheritance disabled.
Reset restores filesystem/SQLite/git seeds, resets fakehttp collections and logs,
and clears canary hits. Stop the runner in an outer `finally` when using these
APIs directly.

Run `uv run pytest tests/sandbox -q -m 'not docker'` for fake-based tests and
`make e2e ARGS='-k fixtures'` for the local-image acceptance gates. The canary gate
uses a direct sidecar request on the private network because the clean reference
server's `fetch_url` intentionally refuses private addresses.
