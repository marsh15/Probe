# Releasing

Pushing a tag `vX.Y.Z` runs `.github/workflows/release.yml`. It builds the package, publishes
it to PyPI with trusted publishing (no token is stored), pushes multi-architecture
(`linux/amd64`, `linux/arm64`) images for the reference server and the fixtures to GHCR, and
creates the GitHub release from the matching CHANGELOG section.

## One-time setup (repository owner)

1. On PyPI, add a *trusted publisher* for this repository: workflow `release.yml`,
   environment `pypi`.
2. In the repository settings create the environment `pypi` (add a required reviewer if you
   want a manual gate before anything is published).
3. Make the GHCR packages public after the first push (Package settings).

## Each release

1. Set `version` in `pyproject.toml` and `src/probe/__init__.py`.
2. In `CHANGELOG.md` rename `## [Unreleased]` to `## [X.Y.Z] - DATE` and add a new empty
   `## [Unreleased]` above it.
3. Run `make check`, commit, and push to `main`.
4. `git tag vX.Y.Z && git push origin vX.Y.Z`. **This publishes**: it cannot be undone on PyPI.

The workflow stops before publishing if the tag does not equal the package version or the
changelog has no section for it (`python3 scripts/release_notes.py check|notes`).

## Checking a release

```text
uvx --from probe-mcp==X.Y.Z probe version
docker pull ghcr.io/<owner>/refserver:X.Y.Z
docker pull ghcr.io/<owner>/fixtures:X.Y.Z
```
