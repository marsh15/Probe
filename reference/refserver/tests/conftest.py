from __future__ import annotations

import shutil
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from mcp import Client
from mcp.server.mcpserver import MCPServer
from refserver import bugs
from refserver.config import Config
from refserver.seed.make_seed import make_seed
from refserver.server import build_server


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(autouse=True)
def _no_bugs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(bugs.ENV_VAR, raising=False)
    bugs.load()


@pytest.fixture(scope="session")
def pristine_seed(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return make_seed(tmp_path_factory.mktemp("seed") / "data", seed=1)


@pytest.fixture
def data_root(pristine_seed: Path, tmp_path: Path) -> Path:
    """A private, mutable copy of the seed for one test."""
    root = tmp_path / "data"
    shutil.copytree(pristine_seed, root, symlinks=True)
    return root


@pytest.fixture
def cfg(data_root: Path) -> Config:
    return Config.for_data_root(data_root, secret=b"test-secret")


@pytest.fixture
def server(cfg: Config) -> MCPServer:
    return build_server(cfg)


@pytest.fixture
async def client(server: MCPServer) -> AsyncIterator[Client]:
    async with Client(server) as c:
        yield c
