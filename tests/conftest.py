"""A real refserver (seeded once) that both Probe and the official SDK client talk to.

The server runs from ``reference/refserver/src`` under the test interpreter, so it uses the
same ``mcp`` SDK as the oracle client. Stdio servers are spawned per client; one HTTP server
is shared by the whole session.
"""

import os
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

REFSERVER_SRC = Path(__file__).resolve().parents[1] / "reference" / "refserver" / "src"


def refserver_env(data: Path, bugs: str = "") -> dict[str, str]:
    """Environment for a refserver process; ``bugs`` is a PROBE_REF_BUGS list (clean if empty)."""
    env = {**os.environ, "PYTHONPATH": str(REFSERVER_SRC), "REFSERVER_DATA": str(data)}
    env.pop("PROBE_REF_BUGS", None)
    if bugs:
        env["PROBE_REF_BUGS"] = bugs
    return env


@pytest.fixture(scope="session")
def seeded_data(tmp_path_factory: pytest.TempPathFactory) -> Path:
    data = tmp_path_factory.mktemp("refserver") / "data"
    env = {**os.environ, "PYTHONPATH": str(REFSERVER_SRC)}
    subprocess.run(  # noqa: S603 - fixed argv, test interpreter
        [sys.executable, "-m", "refserver", "seed", "--out", str(data)],
        check=True,
        env=env,
        timeout=120,
    )
    return data


@pytest.fixture(scope="session")
def stdio_command(seeded_data: Path) -> tuple[list[str], dict[str, str]]:
    return [sys.executable, "-m", "refserver", "stdio"], refserver_env(seeded_data)


@contextmanager
def launch_http(data: Path, bugs: str = "") -> Iterator[str]:
    """Run ``refserver http`` on a free port (optionally with injected bugs); yield its /mcp URL."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    server = subprocess.Popen(  # noqa: S603 - fixed argv, test interpreter
        [sys.executable, "-m", "refserver", "http", "--host", "127.0.0.1", "--port", str(port)],
        env=refserver_env(data, bugs),
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 60
        while True:
            if server.poll() is not None:
                stderr = server.stderr.read().decode() if server.stderr else ""
                raise RuntimeError(f"refserver http exited early: {stderr}")
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
                break
            except OSError:
                if time.monotonic() > deadline:
                    raise RuntimeError("refserver http did not start in 60 s") from None
                time.sleep(0.2)
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        server.terminate()
        try:
            server.wait(10)
        except subprocess.TimeoutExpired:
            server.kill()
        if server.stderr:
            server.stderr.close()


@pytest.fixture(scope="session")
def http_url(seeded_data: Path) -> Iterator[str]:
    with launch_http(seeded_data) as url:
        yield url
