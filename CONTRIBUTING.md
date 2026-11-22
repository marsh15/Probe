# Contributing to Probe

Thank you for your interest in contributing to Probe!

## Development Setup

1. Clone the repository
2. Install dependencies: `uv sync --all-extras --dev`
3. Run tests: `make check`
4. Run linting: `uv run ruff check .`
5. Format code: `uv run ruff format .`

## Development Workflow

- Create a branch for your work: `git checkout -b <branch-name>`
- Make your changes and ensure tests pass
- Format code with `ruff format`
- Submit a pull request

## Code Style

- Follow PEP 8
- Use type hints
- Write tests for new functionality
- Ensure `make check` passes before submitting a PR

## License

By contributing to Probe, you agree that your contributions will be licensed under the Apache 2.0 License.
