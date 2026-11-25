"""Configuration defaults that must not differ between two instances of the same server."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from refserver.config import Config
from refserver.server import HMACRequestStateCodec
from refserver.tools.notes import CursorCodec


def test_default_secret_is_the_same_in_every_process(tmp_path: Path) -> None:
    first = Config.for_data_root(tmp_path / "a")
    second = Config.for_data_root(tmp_path / "b")
    assert first.secret == second.secret
    assert CursorCodec(first.secret).encode(7) == CursorCodec(second.secret).encode(7)
    payload = b"state"
    assert HMACRequestStateCodec(first.secret).seal(payload) == HMACRequestStateCodec(
        second.secret
    ).seal(payload)


def test_default_secret_is_stable_across_python_processes(tmp_path: Path) -> None:
    code = "from pathlib import Path; from refserver.config import Config; "
    code += "print(Config.for_data_root(Path('x')).secret.hex())"
    outs = {
        subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True, check=True
        ).stdout
        for _ in range(2)
    }
    assert len(outs) == 1


def test_refserver_secret_still_overrides_the_default(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("REFSERVER_SECRET", "custom")
    cfg = Config.from_env(tmp_path)
    assert cfg.secret == b"custom"
    assert cfg.secret != Config.for_data_root(tmp_path).secret
