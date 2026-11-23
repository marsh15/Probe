"""Size and time limits for everything that crosses the wire."""

from collections.abc import Mapping
from types import MappingProxyType

from probe.engine.outcomes import Mode

KiB = 1024
MiB = 1024 * KiB

MAX_MESSAGE_BYTES = 16 * MiB
# Deeper values are malformed: code after parsing (redaction, checks) recurses, and how deep
# json.loads itself goes before RecursionError differs between Python versions.
MAX_JSON_DEPTH = 512
# Threshold for behavior.output_bounded, not a transport limit.
MAX_RESULT_BYTES_CHECK = 1 * MiB

DEFAULT_REQUEST_TIMEOUT_S: Mapping[Mode, float] = MappingProxyType(
    {"quick": 15.0, "standard": 30.0, "deep": 60.0}
)
ERA_PROBE_TIMEOUT_S = 10.0
STARTUP_TIMEOUT_S = 30.0
SHUTDOWN_GRACE_S = 2.0
SHUTDOWN_KILL_AFTER_S = 5.0

# One HTTP response stream: a hostile server must not be able to feed us forever.
MAX_STREAM_BYTES = 16 * MiB
MAX_STREAM_EVENTS = 10_000
HTTP_CONNECT_TIMEOUT_S = 10.0
# Notifications and replies have no caller-supplied deadline (requests do).
HTTP_SEND_TIMEOUT_S = 30.0

TRACE_BODY_MAX_BYTES = 64 * KiB
TRACE_SCAN_MAX_BYTES = 200 * MiB
STDERR_RING_BYTES = 1 * MiB

# Keep a hostile server from growing Probe's memory through floods of small messages.
MAX_QUEUED_NOTIFICATIONS = 10_000
MAX_EVENTS = 10_000
EVENT_EXCERPT_BYTES = 1 * KiB
MAX_NOTIFICATION_BYTES = 16 * MiB
MAX_EVENT_BYTES = 4 * MiB
MAX_SERVER_REQUESTS = 32
MAX_SERVER_REQUEST_BYTES = 16 * MiB
# IDs stay reserved for the connection lifetime so duplicate or late replies cannot cross calls.
MAX_REQUEST_IDS = 100_000
MAX_TIMEOUT_HISTORY = 10_000
TRACE_METADATA_BYTES = 1 * MiB


def request_timeout(mode: Mode, scale: float = 1.0) -> float:
    """Per-request timeout for ``mode``, multiplied by ``--timeout-scale``."""
    if scale <= 0:
        raise ValueError("timeout scale must be positive")
    return DEFAULT_REQUEST_TIMEOUT_S[mode] * scale
