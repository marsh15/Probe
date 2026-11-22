.PHONY: check e2e cov selfval-fast docs-check help

check:
	uv run ruff check .
	uv run ruff format --check .
	uv run mypy src
	uv run pytest -m "not docker" -q

e2e:
	uv run pytest -m docker -q $(ARGS)

cov:
	uv run pytest -m "not docker" --cov=src/probe --cov-report=term-missing --cov-fail-under=85

selfval-fast:
	@echo "selfval-fast: placeholder (selfval infrastructure not yet built)"

docs-check:
	@echo "docs-check: placeholder (documentation checks not yet configured)"

help:
	@echo "Available targets:"
	@echo "  check         - Run linting (ruff), type checking (mypy), and unit tests"
	@echo "  e2e           - Run Docker-based e2e tests"
	@echo "  cov           - Run tests with coverage report (minimum 85%)"
	@echo "  selfval-fast  - Run fast self-validation tests"
	@echo "  docs-check    - Validate documentation"
