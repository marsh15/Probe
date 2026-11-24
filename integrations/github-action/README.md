# Probe GitHub Action

Scans an MCP server with [Probe](../../README.md) on every pull request: fails the job on a
finding at or above `fail-on`, uploads SARIF to code scanning, writes the summary (and a diff
against the base branch) to the job summary, and can keep a badge up to date.

```yaml
- uses: OWNER/probe-action@v1
  with:
    image: ghcr.io/OWNER/my-mcp-server:latest
    fail-on: high
```

Give the job `permissions: security-events: write` for SARIF (and `contents: write` for the
badge). Inputs: `command`, `url`, `image`, `profile`, `mode` (default `quick`), `fail-on`
(default `high`), `min-score`, `sandbox` (`auto`), `sarif`, `sarif-anchor`, `badge`,
`badge-branch`, `probe-version`, `compare-base`, `target-env`, `llm`. Outputs: `grade`,
`score`, `exit-code`.

- The sandbox runs only on Linux runners with Docker, and only when an `image` is given.
  Without it, the checks that need canaries and file diffs are skipped (see
  [limitations](../../docs/limitations.md)).
- Inputs reach the shell only through environment variables, never by interpolation into the
  script, so a pull request title or branch name cannot inject commands.
- `llm: true` needs `ANTHROPIC_API_KEY` in the job's `env` and sends tool metadata to the
  model provider ([llm](../../docs/llm.md)).
- Badge: `![probe](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/OWNER/REPO/probe-badges/badge.json)`.

This directory is the source of the action's own repository; publish it there (see
[github-action.md](../../docs/github-action.md)).
