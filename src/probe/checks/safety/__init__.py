"""Safety checks: observed disclosures through tools, inside the sandbox."""

from probe.checks.safety import (  # noqa: F401 - registers the checks
    annotations,
    injection,
    oauth,
    outputs,
    paths,
    secrets,
    state,
    urls,
)
