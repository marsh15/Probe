"""Descriptor-relative filesystem access: never traverse symbolic links."""

import os
import stat
from contextlib import contextmanager
from pathlib import Path, PurePosixPath

MAX_FILE = 64 * 1024 * 1024
MAX_ENTRIES = 10000
DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


class MissingPath(ValueError):
    """A valid relative path has a missing ancestor."""


def parts(relative: str) -> tuple[str, ...]:
    if not isinstance(relative, str) or not relative or "\0" in relative:
        raise ValueError("expected a nonempty relative path")
    parsed = PurePosixPath(relative)
    if parsed.is_absolute() or any(p in {"", ".", ".."} for p in relative.split("/")):
        raise ValueError("path must stay below the configured root")
    return parsed.parts


@contextmanager
def directory(path):
    """Open every ancestor without following links, holding each during descent."""
    raw = Path(os.path.abspath(path))
    original = Path(path).absolute()
    if original != raw:
        raise ValueError("root must not contain parent traversal")
    fd = os.open("/", DIRECTORY)
    try:
        for component in raw.parts[1:]:
            child = os.open(component, DIRECTORY, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    except OSError as exc:
        raise ValueError("directory unavailable or contains symlinks") from exc
    finally:
        os.close(fd)


@contextmanager
def parent(fd: int, relative: str):
    components = parts(relative)
    current = os.dup(fd)
    try:
        for component in components[:-1]:
            child = os.open(component, DIRECTORY, dir_fd=current)
            os.close(current)
            current = child
        yield current, components[-1]
    except FileNotFoundError as exc:
        raise MissingPath("path does not exist") from exc
    except OSError as exc:
        raise ValueError("path unavailable or contains symlinks") from exc
    finally:
        os.close(current)


def read_file(fd: int, relative: str, limit: int = MAX_FILE) -> bytes:
    with parent(fd, relative) as (owner, name):
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=owner)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
                raise ValueError("expected a bounded regular file")
            data = stream.read(limit + 1)
            if len(data) > limit:
                raise ValueError("file exceeds size limit")
            return data
