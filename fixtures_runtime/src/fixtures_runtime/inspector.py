"""Deterministic offline inspection and descriptor-confined seed restoration."""

import base64
import hashlib
import json
import os
import sqlite3
import stat
from collections import deque
from itertools import islice
from pathlib import Path

from fixtures_runtime.paths import (
    DIRECTORY,
    MAX_ENTRIES,
    MAX_FILE,
    MissingPath,
    directory,
    parent,
    read_file,
)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def diff(before, after):
    if not isinstance(before, dict) or not isinstance(after, dict):
        raise ValueError("snapshots must be objects")
    return {
        "added": sorted(after.keys() - before.keys()),
        "changed": sorted(k for k in before.keys() & after.keys() if before[k] != after[k]),
        "removed": sorted(before.keys() - after.keys()),
    }


def safe_root(value):
    path = Path(value).absolute()
    forbidden = {
        Path("/"),
        Path.home(),
        *(
            Path("/") / name
            for name in (
                "tmp",
                "var",
                "etc",
                "usr",
                "bin",
                "sbin",
                "lib",
                "lib64",
                "dev",
                "proc",
                "sys",
                "run",
                "boot",
                "opt",
                "home",
                "Users",
                "System",
                "Library",
                "Applications",
                "Volumes",
                "private",
            )
        ),
    }
    system_trees = [
        Path("/") / name
        for name in (
            "etc",
            "usr",
            "bin",
            "sbin",
            "lib",
            "lib64",
            "dev",
            "proc",
            "sys",
            "boot",
            "System",
            "Library",
            "Applications",
        )
    ]
    if (
        path in forbidden
        or ".." in path.parts
        or any(path.is_relative_to(tree) for tree in system_trees)
    ):
        raise ValueError("unsafe data root")
    return path


def inventory(fd, prefix="", result=None, *, strict=False):
    if result is None:
        result = {}
    marker = f"{prefix}/." if prefix else "."
    if len(prefix.split("/")) > 64:
        if strict:
            raise ValueError("directory depth limit exceeded")
        result[marker] = {"type": "limit", "reason": "depth"}
        return result
    with os.scandir(fd) as scan:
        names = sorted(entry.name for entry in islice(scan, MAX_ENTRIES + 1))
    for name in names:
        if len(result) >= MAX_ENTRIES:
            if strict:
                raise ValueError("filesystem entry limit exceeded")
            result["."] = {"type": "limit", "reason": "entries"}
            break
        path = f"{prefix}/{name}" if prefix else name
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        record = {"mode": stat.S_IMODE(info.st_mode)}
        if stat.S_ISLNK(info.st_mode):
            record.update(type="symlink", target=os.readlink(name, dir_fd=fd))
        elif stat.S_ISDIR(info.st_mode):
            record["type"] = "directory"
            result[path] = record
            child = os.open(name, DIRECTORY, dir_fd=fd)
            try:
                inventory(child, path, result, strict=strict)
            finally:
                os.close(child)
            continue
        elif stat.S_ISREG(info.st_mode):
            if info.st_size > MAX_FILE and not strict:
                record.update(
                    type="file",
                    size=info.st_size,
                    mtime_ns=info.st_mtime_ns,
                    inspection="size limit exceeded",
                )
            else:
                content = read_file(fd, name)
                record.update(type="file", sha256=hashlib.sha256(content).hexdigest())
        elif strict:
            raise ValueError("unsupported filesystem entry")
        else:
            continue
        result[path] = record
    return dict(sorted(result.items()))


def remove_children(fd):
    """Delete without hashing, following links, or using the Python recursion stack."""
    stack = []

    def descend(owner, name=None):
        os.fchmod(owner, stat.S_IMODE(os.fstat(owner).st_mode) | 0o700)
        stack.append((owner, name, os.scandir(owner)))

    descend(os.dup(fd))
    try:
        while stack:
            owner, directory_name, scan = stack[-1]
            entry = next(scan, None)
            if entry is None:
                scan.close()
                os.close(owner)
                stack.pop()
                if stack:
                    os.rmdir(directory_name, dir_fd=stack[-1][0])
                continue
            info = os.stat(entry.name, dir_fd=owner, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                os.chmod(
                    entry.name,
                    stat.S_IMODE(info.st_mode) | 0o700,
                    dir_fd=owner,
                    follow_symlinks=False,
                )
                descend(os.open(entry.name, DIRECTORY, dir_fd=owner), entry.name)
            else:
                os.unlink(entry.name, dir_fd=owner)
    finally:
        for owner, _, scan in reversed(stack):
            scan.close()
            os.close(owner)


def validate_seed_link(path, target, entries):
    # Resolve against the already captured seed graph, never against host paths.
    pending = deque([*Path(path).parent.parts, *target.split("/")])
    current, expansions = [], 0
    if Path(target).is_absolute():
        raise ValueError("seed symlink escapes seed root")
    while pending:
        component = pending.popleft()
        if component in {"", "."}:
            continue
        if component == "..":
            if not current:
                raise ValueError("seed symlink escapes seed root")
            current.pop()
            continue
        current.append(component)
        record = entries.get("/".join(current), {})
        if record.get("type") == "symlink":
            expansions += 1
            if expansions > 40 or Path(record["target"]).is_absolute():
                raise ValueError("unsafe seed symlink chain")
            current.pop()
            pending.extendleft(reversed(record["target"].split("/")))


def sqlite_value(value):
    if value is None:
        return ["null"]
    if isinstance(value, bytes):
        return ["blob", base64.b64encode(value).decode()]
    if isinstance(value, float):
        return ["float", value.hex()]
    return ["integer" if isinstance(value, int) else "text", value]


def quote_identifier(value):
    return '"' + value.replace('"', '""') + '"'


class Inspector:
    def __init__(self, root="/data"):
        self.root = safe_root(root)
        with directory(self.root) as fd:
            info = os.fstat(fd)
            self.identity = (info.st_dev, info.st_ino)

    def verify(self, fd):
        info = os.fstat(fd)
        if (info.st_dev, info.st_ino) != self.identity:
            raise ValueError("configured root identity changed")

    def snapshot(self):
        with directory(self.root) as fd:
            self.verify(fd)
            return inventory(fd)

    def exists(self, relative):
        with directory(self.root) as fd:
            self.verify(fd)
            try:
                with parent(fd, relative) as (owner, name):
                    try:
                        os.stat(name, dir_fd=owner, follow_symlinks=False)
                        return True
                    except FileNotFoundError:
                        return False
            except MissingPath:
                return False

    def sqlite_checksum(self, relative):
        with directory(self.root) as fd:
            self.verify(fd)
            # Offline snapshots must not silently omit committed WAL transactions.
            with parent(fd, relative) as (owner, name):
                try:
                    wal = os.stat(name + "-wal", dir_fd=owner, follow_symlinks=False)
                    if wal.st_size:
                        raise ValueError("checkpoint and close the SQLite WAL before inspection")
                except FileNotFoundError:
                    pass
            content = read_file(fd, relative)
        if not content.startswith(b"SQLite format 3\0"):
            raise ValueError("not a SQLite database")
        try:
            with sqlite3.connect(":memory:") as db:
                # WAL has already been rejected if nonempty. Normalize only the
                # in-memory copy so checkpointed WAL-mode files need no disk access.
                memory_image = content[:18] + b"\x01\x01" + content[20:]
                db.deserialize(memory_image)
                db.execute("PRAGMA trusted_schema=OFF")
                db.execute("PRAGMA query_only=ON")
                db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_FILE)
                db.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 1024 * 1024)
                steps = 0

                def progress():
                    nonlocal steps
                    steps += 1
                    return int(steps > 10000)

                db.set_progress_handler(progress, 1000)
                tables = sorted(
                    row[1]
                    for row in db.execute("PRAGMA main.table_list")
                    if row[0] == "main" and row[2] == "table" and not row[1].startswith("sqlite_")
                )
                result = {}
                for name in tables:
                    quoted = quote_identifier(name)
                    # Read ordinary stored columns only. Views, virtual tables
                    # and generated expressions are excluded.
                    columns = [
                        row[1]
                        for row in db.execute(f"PRAGMA main.table_xinfo({quoted})")
                        if row[6] == 0
                    ]
                    if not columns:
                        raise ValueError("table has no ordinary columns")
                    projection = ",".join(quote_identifier(column) for column in columns)
                    rows, total = [], 0
                    for row in db.execute(f"SELECT {projection} FROM main.{quoted}"):  # noqa: S608 - identifiers are quoted, never SQL fragments
                        record = canonical([sqlite_value(value) for value in row])
                        total += len(record)
                        if total > MAX_FILE or len(rows) >= 100000:
                            raise ValueError("SQLite table exceeds inspection limits")
                        rows.append(record)
                    digest = hashlib.sha256()
                    digest.update(canonical(columns) + b"\n")
                    for row in sorted(rows):
                        digest.update(row + b"\n")
                    result[name] = {"count": len(rows), "sha256": digest.hexdigest()}
                return result
        except sqlite3.Error as exc:
            raise ValueError("SQLite inspection failed") from exc

    def reset(self, seed):
        seed = safe_root(seed)
        if seed == self.root or seed in self.root.parents or self.root in seed.parents:
            raise ValueError("seed and data roots must be disjoint")
        with directory(seed) as source, directory(self.root) as destination:
            self.verify(destination)
            entries = inventory(source, strict=True)
            payloads, size = {}, 0
            # Preflight every seed entry before deleting anything. Bounded data is held
            # in memory so a concurrent seed replacement cannot introduce new links.
            for path, record in entries.items():
                if record["mode"] & 0o7000:
                    raise ValueError("seed contains privileged permission bits")
                if record["type"] == "symlink":
                    validate_seed_link(path, record["target"], entries)
                elif record["type"] == "file":
                    payloads[path] = read_file(source, path)
                    size += len(payloads[path])
                    if size > MAX_FILE:
                        raise ValueError("seed exceeds reset size limit")
                    if hashlib.sha256(payloads[path]).hexdigest() != record["sha256"]:
                        raise ValueError("seed changed during validation")
            # The scanner stops target instances before restoration; no hashing is needed.
            remove_children(destination)
            for path, record in entries.items():
                with parent(destination, path) as (owner, name):
                    if record["type"] == "directory":
                        os.mkdir(name, mode=0o700, dir_fd=owner)
                    elif record["type"] == "symlink":
                        os.symlink(record["target"], name, dir_fd=owner)
                    else:
                        output = os.open(
                            name,
                            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                            0o600,
                            dir_fd=owner,
                        )
                        with os.fdopen(output, "wb") as stream:
                            stream.write(payloads[path])
                            os.fchmod(stream.fileno(), record["mode"])
            for path, record in reversed(list(entries.items())):
                if record["type"] == "directory":
                    with parent(destination, path) as (owner, name):
                        child = os.open(name, DIRECTORY, dir_fd=owner)
                        try:
                            os.fchmod(child, record["mode"])
                        finally:
                            os.close(child)
