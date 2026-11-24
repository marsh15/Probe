# The LLM experiment (`--llm`)

Off by default. The score never depends on it, and the rest of Probe never calls a model.

`probe run --llm` adds one informational check, `behavior.agent_recovery`: **do the server's
error messages help an agent fix its call?** For up to three malformed calls per tool that the
server rejected, a model is asked for corrected arguments twice: once shown the server's error
message (arm A) and once without it (arm B, the control). A proposal that fits the tool's input
schema is run against the server; the call has recovered if the server accepts it. The report
shows the recovery rate with the message and the **lift** (A minus B, in points), which is what
the message is worth. Read tools are always tried; tools that may write are tried only inside
the sandbox.

## What you need

- `ANTHROPIC_API_KEY` in the environment (it is never written to any artifact).
- `pip install 'probe-mcp[llm]'`.

```text
probe run --llm --llm-budget-usd 1 --llm-cache ./llm-cache -- my-server
```

## What is sent to the model provider

For each case: the tool's name, description and input schema, the arguments of the failed call
and, in arm A only, the server's error message (fenced, capped at 1500 characters, and labelled
as untrusted data). Nothing else from the scan is sent. Do not use `--llm` on a server whose tool
descriptions or error messages you may not share.

## Determinism, cache and cost

- Model `claude-haiku-4-5-20251001`, temperature 0, one forced tool call (`submit_arguments`).
- Answers are cached by `sha256(model | prompt)` in `~/.cache/probe/llm` (or `--llm-cache`), so
  a rerun gives identical answers and costs nothing; the report counts cache hits.
- Before each call Probe estimates the worst-case cost and refuses it if it would pass
  `--llm-budget-usd` (default 2.0). Cases not run are reported as not run.
- If the API fails for a case, that case is left out, not counted as a failure to recover.
