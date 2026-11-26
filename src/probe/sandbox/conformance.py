"""Run the conformance container on the sandbox's private network and read its output.

The hardened container sits only on the private network. Its loopback relay
forwards to ``target:<port>`` and Probe reads suite results from the container log.
"""

import asyncio
import contextlib
import subprocess
import time
from typing import Any

import docker  # type: ignore[import-untyped]
from requests.exceptions import Timeout as DockerRequestTimeout

from probe.sandbox.docker_env import DockerEnv
from probe.sandbox.spec import target_spec

_LOG_LIMIT = 4_000_000  # bytes of container output we are willing to process


class ConformanceImageUnavailable(Exception):
    """The suite image is absent and could not be pulled."""


class ContainerConformanceRunner:
    def __init__(self, sandbox: DockerEnv, image: str) -> None:
        self._sandbox = sandbox
        self._image = image

    def _ensure_image(self, deadline: float) -> None:
        images = self._sandbox.client.images
        try:
            images.get(self._image)
        except docker.errors.ImageNotFound:
            # docker-py's pull has no request deadline. Bound the CLI and verify
            # that the SDK can see what it pulled before creating the container.
            subprocess.run(  # noqa: S603
                ["docker", "pull", "--", self._image],  # noqa: S607
                check=True,
                timeout=max(0, deadline - time.monotonic()),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            images.get(self._image)

    def _run_blocking(self, command: list[str], deadline: float) -> str:
        sandbox = self._sandbox
        spec: dict[str, Any] = target_spec(
            sandbox.scan_id, self._image, command=None, created=sandbox.created
        )
        spec["network"] = sandbox.names["priv"]
        spec["volumes"] = {}
        spec["command"] = command
        spec["stdin_open"] = False
        spec["environment"]["HOME"] = "/tmp"  # noqa: S108
        spec["tmpfs"] = {"/tmp": "rw,size=256m,mode=1777"}  # noqa: S108
        if time.monotonic() >= deadline:
            raise TimeoutError
        container = sandbox._container("conformance", spec)
        try:
            if time.monotonic() >= deadline:
                raise TimeoutError
            container.start()
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                container.wait(timeout=remaining)
            except (TimeoutError, DockerRequestTimeout):
                with contextlib.suppress(Exception):
                    container.kill()
            raw = container.logs(stdout=True, stderr=False)
            return str(raw[:_LOG_LIMIT].decode("utf-8", "replace"))
        finally:
            with contextlib.suppress(Exception):
                sandbox.remove_container(container)

    async def run(self, command: list[str], timeout_s: float) -> str:
        deadline = time.monotonic() + timeout_s
        try:
            async with asyncio.timeout(timeout_s):
                await asyncio.to_thread(self._ensure_image, deadline)
        except (docker.errors.ImageNotFound, OSError, subprocess.SubprocessError) as exc:
            raise ConformanceImageUnavailable from exc
        async with asyncio.timeout(max(0, deadline - time.monotonic())):
            return await asyncio.to_thread(self._run_blocking, command, deadline)
