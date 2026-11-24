"""A file cache for judge answers: the same model and prompt give the same answer on every rerun."""

import json
import os
import tempfile
from hashlib import sha256
from pathlib import Path
from typing import Any

from probe.util.canonical_json import canonical_bytes

DEFAULT_DIR = Path("~/.cache/probe/llm")


def cache_key(model: str, prompt: dict[str, Any]) -> str:
    return sha256(model.encode() + b"|" + canonical_bytes(prompt)).hexdigest()


class JudgeCache:
    def __init__(self, directory: Path | None = None) -> None:
        self.directory = (directory or DEFAULT_DIR).expanduser()

    def _path(self, key: str) -> Path:
        return self.directory / f"{key}.json"

    def get(self, key: str) -> dict[str, Any] | None:
        try:
            data = json.loads(self._path(key).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None  # a missing or damaged entry is just a miss
        return data if isinstance(data, dict) else None

    def put(self, key: str, value: dict[str, Any]) -> None:
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            fd, temp = tempfile.mkstemp(dir=self.directory, suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(value, handle, sort_keys=True)
            os.replace(temp, self._path(key))
        except OSError:
            return  # failing to cache must never fail the scan
