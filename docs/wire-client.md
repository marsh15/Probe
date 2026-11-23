# Wire client

The wire layer sends and receives JSON-RPC over a child process's standard streams
(`StdioTransport`) or over MCP streamable HTTP (`HttpTransport`). `StdioTransport.spawn()`
starts a process; `StdioTransport(process)` wraps an existing process with piped stdin and
stdout. `request()` returns a response object whose `unwrap()` method returns the result or
raises `JsonRpcError`. Both transports share the same request, notification, server-request
and recording behavior; the rules below apply to both unless a section says otherwise.

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

## HTTP transport

`HttpTransport(url, headers=...)` sends every message as a new POST with
`Accept: application/json, text/event-stream`. The reply is read as JSON or as an SSE
stream; both may carry notifications and server requests before the response. A server
request is answered with a separate POST of the reply.

- `request()` needs its response on the same POST. If the POST ends without a response
  carrying that ID, it raises `HttpRequestFailed` at once (with the status and a
  `RawHttpResult`) rather than waiting for the timeout. A JSON-RPC error body on a non-2xx
  status still counts as a response, so a `400` carrying `-32022` returns normally.
- `post(message, headers=..., timeout=...)` sends one message and returns a
  `RawHttpResult` (status, headers, body prefix, parsed responses, timing, and any abort
  or connection error) without raising for HTTP failures. Use it when the status matters.
- `raw_http(headers, body, method=...)` sends exactly what it is given: no default
  headers, no session ID, no validation. It is recorded like any other exchange.
- Redirects are never followed and proxy environment variables are ignored. `Content-Encoding`
  is never decoded, so a compressed body is read as raw bytes and stopped at the size limit.
- A JSON body over the 16 MiB message limit, or an SSE stream over 16 MiB or 10,000 events,
  is aborted and the connection closed. That is also how cancellation reaches the server.
- SSE event types other than `message`, non-JSON event data and a stream that ends
  mid-event are reported as events and do not stop the stream. Empty events (resumption
  primers) are skipped. A timeout closes the stream.
- `Mcp-Session-Id` from a 2xx response is captured in `session_id` and sent on later
  `post()` calls (legacy era). `raw_http()` neither sends nor captures it.

`SseParser` (`probe.wire.sse`) frames events per the WHATWG rules, including CR, LF and
CRLF endings split across chunks. It enforces no limits; the transport counts bytes first.

Run the wire acceptance suite with `uv run pytest tests/wire -q`.
