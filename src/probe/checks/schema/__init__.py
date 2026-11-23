"""Schema checks: are the tool definitions and list results the server publishes well formed?

Importing this package registers every check in it.
"""

from probe.checks.schema import cache, definitions, order, output, scope  # noqa: F401 - registers the checks
