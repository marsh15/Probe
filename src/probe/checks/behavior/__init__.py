"""Behavior checks: does the server do the right thing with valid, odd and invalid input?

Importing this package registers every check in it.
"""

from probe.checks.behavior import (  # noqa: F401 - registers the checks
    agent_recovery,
    concurrency,
    idempotency,
    input_handling,
    mrtr,
    pagination,
    results,
    slow,
    stateless,
    survival,
    tasks,
)
