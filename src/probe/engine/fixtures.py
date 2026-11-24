"""Scan-owned fixture controls used by active operability checks."""

import httpx

from probe.sandbox.fixtures import FixtureSet


class ScanFixtures(FixtureSet):
    """Keep checks on the fixture interface, rather than making network calls themselves."""

    async def backend_fault(self, route: str | None, *, count: int = 1) -> bool:
        """Arm bounded 429 responses, or clear fakehttp faults and restore its seed."""
        if "fakehttp" not in self._services:
            return False
        path = "/_probe/reset" if route is None else "/_probe/fault"
        payload = (
            None
            if route is None
            else {"route": route, "status": 429, "retry_after": 2, "count": count}
        )
        async with httpx.AsyncClient(timeout=2, trust_env=False) as client:
            response = await client.post(self._services["fakehttp"] + path, json=payload)
            response.raise_for_status()
        return True
