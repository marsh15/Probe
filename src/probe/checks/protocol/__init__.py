"""Protocol checks: does the server speak MCP the way the spec says?

Importing this package registers every check in it.
"""

from probe.checks.protocol import (  # noqa: F401 - imported to register the checks
    deprecated,
    discover,
    http,
    malformed,
    parity,
    passive,
    unknown_method,
    version,
)
