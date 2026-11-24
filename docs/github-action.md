# GitHub Action

The action lives in [integrations/github-action](../integrations/github-action/README.md) and is
published from its own repository so that `uses: OWNER/probe-action@v1` works.

```yaml
permissions:
  security-events: write
jobs:
  probe:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: OWNER/probe-action@v1
        with:
          image: ghcr.io/OWNER/my-mcp-server:latest
          fail-on: high
```

What a run does: install Probe, scan (sandboxed when an image is given and Docker is available),
upload the report as an artifact and the SARIF to code scanning, add the summary to the job
summary, and on pull requests add a diff against the last scan of the base branch (kept in the
Actions cache). The job fails with Probe's exit code, so a finding at or above `fail-on`
(default `high`) fails the pull request. See [cli.md](cli.md) for the exit codes and
[report.md](report.md) for the outputs.

## Publishing it (repository owner)

1. Create the repository `probe-action` and copy `integrations/github-action/` into its root
   (including `.github/workflows/selftest.yml`).
2. Replace `OWNER` in the examples and the self-test with the account that owns the images.
3. Push, wait for the self-test to pass, then tag `v1`.
4. Optional: list it on the GitHub Marketplace.

The self-test needs the images from the release workflow ([releasing.md](releasing.md)).
