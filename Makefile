.PHONY: install dev lint format typecheck security test build clean publish docs docs-serve lint-docs help

# Default target
help:
	@echo "envdrift - Prevent environment variable drift"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  install     Install production dependencies"
	@echo "  dev         Install development dependencies"
	@echo "  lint        Run linting with ruff"
	@echo "  format      Format code with ruff"
	@echo "  typecheck   Run type checking with pyrefly"
	@echo "  security    Run security checks with bandit"
	@echo "  test        Run tests with pytest"
	@echo "  check       Run all checks (lint, typecheck, security, test)"
	@echo "  docs        Build documentation"
	@echo "  docs-serve  Serve documentation locally"
	@echo "  lint-docs   Run markdown linting on docs"
	@echo "  build       Build package for distribution"
	@echo "  publish     Publish to PyPI"
	@echo "  clean       Remove build artifacts"

# Install production dependencies
install:
	uv sync

# Install development dependencies
dev:
	uv sync --all-extras

# Run linting
lint:
	uv run ruff check src tests

# Format code
format:
	uv run ruff check --fix src tests
	uv run ruff format src tests

# Run type checking with pyrefly
typecheck:
	uv run pyrefly check src

# Run security checks with bandit
security:
	uv run bandit -r src -c pyproject.toml

# Run tests
test:
	uv run pytest

# Run all checks
check: lint typecheck security test

# Build package
build: clean
	uv build

# Publish to PyPI
publish: build
	uv publish

# Publish to TestPyPI first (for testing)
publish-test: build
	uv publish --index-url https://test.pypi.org/simple/

# Build documentation
docs:
	uv run mkdocs build --strict

# Serve documentation locally
docs-serve:
	uv run mkdocs serve

# Lint markdown documentation
lint-docs:
	@echo "Linting markdown files..."
	npx markdownlint-cli2 "**/*.md" "#node_modules" "#.venv" "#venv" "#.git" "#dist" "#build" "#site" "#.pytest_cache" \
	 "#.ruff_cache" "#.uv-cache"

# Clean build artifacts
clean:
	rm -rf dist/
	rm -rf build/
	rm -rf site/
	rm -rf *.egg-info/
	rm -rf src/*.egg-info/
	rm -rf .pytest_cache/
	rm -rf .ruff_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
