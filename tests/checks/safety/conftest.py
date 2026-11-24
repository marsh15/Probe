from pathlib import Path

import pytest

from tests.checks.safety.local_fixtures import seed_with_sentinel


@pytest.fixture(scope="session")
def sentinel_data(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return seed_with_sentinel(tmp_path_factory.mktemp("sentinel"))
