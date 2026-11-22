# Wire client

The wire layer sends and receives JSON-RPC over a child process's standard streams.
`StdioTransport.spawn()` starts a process; `StdioTransport(process)` wraps an existing
process with piped stdin and stdout. `request()` returns a response object whose
`unwrap()` method returns the result or raises `JsonRpcError`.

## Request and shutdown rules

- Give every client request a new integer or string ID. Reusing an ID raises `ValueError`,
  including after a timeout or cancellation. This prevents delayed or duplicate replies
  from satisfying a different request.
- A connection accepts up to 100,000 distinct client IDs. Start a new transport if that
  budget is exhausted. Stored IDs are fixed-size hashes; late-response classification
  retains the most recent 10,000 timed-out IDs.
- `RequestTimeout` sends no cancellation message. Late replies are traced and discarded.
- Register a server-request handler with `on_server_request()`. Without one, requests
  receive method-not-found. Invalid handler results receive an internal-error response.
- Await `close()` before closing the recorder. Shutdown closes stdin, escalates through
  terminate and kill when needed, and limits waits for inherited pipes. Concurrent close
  callers share the same result; cancelling one caller does not cancel shutdown.

## Resource limits and evidence

Incoming lines have a 16 MiB limit. Larger lines are discarded through their next newline;
the following messages remain readable. Notification queues and server handlers each have
a 16 MiB decoded-object budget. Handlers also have a 32-task limit. Requests over that
limit are dropped with a `server_request_limit` event. Notifications drop oldest entries
when full; `notifications_dropped` reports the loss. Events have count and byte limits,
and `events_dropped` reports omitted events.

`Recorder` writes redacted JSONL and compresses it on close. Body capture is limited to
64 KiB per record and 200 MiB per scan, including events. Subsequent records contain
metadata within a further 1 MiB total-file allowance. Cap markers explain when capture
stops; `records_dropped` counts records omitted after the file allowance is exhausted.
Pass real secrets explicitly. Fixture values remain visible unless passed as secrets.

With a recorder, `stderr.log` is written beside the trace. An explicit `stderr_path` can
also enable it. The artifact defaults to a 200 MiB limit and uses streaming redaction,
including secrets split across reads. The in-memory stderr tail retains the last 1 MiB.
Trace-write failures are exposed through `recording_error` and a `trace_write_failed`
event while response handling continues. Stderr artifact failures have their own events.

Run the wire acceptance suite with `uv run pytest tests/wire -q`.
