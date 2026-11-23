"""Keep the local reference-server image in step with the source it is built from."""

import hashlib
import subprocess
from pathlib import Path
from typing import Any

import docker

REFSERVER = Path(__file__).parents[2] / "reference" / "refserver"
TAG = "probe-refserver:dev"
LABEL = "probe.src-hash"


def source_hash() -> str:
    """A hash of everything the image is built from (the tests directory is not in it)."""
    digest = hashlib.sha256()
    files = [*sorted((REFSERVER / "src").rglob("*.py")), REFSERVER / "pyproject.toml"]
    files += [REFSERVER / "uv.lock", REFSERVER / "Dockerfile"]
    for path in files:
        digest.update(path.relative_to(REFSERVER).as_posix().encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()[:16]


def ensure_current_image(client: Any) -> str:
    """Build ``probe-refserver:dev`` if it is missing or was built from different source."""
    wanted = source_hash()
    try:
        current = (client.images.get(TAG).labels or {}).get(LABEL)
    except docker.errors.ImageNotFound:
        current = None
    if current != wanted:
        # The CLI builds much faster than the SDK's streaming build and shows layer caching.
        subprocess.run(  # noqa: S603 - fixed argv
            ["docker", "build", "--build-arg", f"SRC_HASH={wanted}", "-t", TAG, str(REFSERVER)],  # noqa: S607
            check=True,
            capture_output=True,
            timeout=1200,
        )
    return wanted
