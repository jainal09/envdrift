.PHONY: install dev lint format typecheck security test test-integration test-integration-up test-integration-down build clean publish docs docs-serve lint-docs help

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
	@echo "  test-integration      Run integration tests (requires Docker)"
	@echo "  test-integration-up   Start integration test containers"
	@echo "  test-integration-down Stop integration test containers"
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
	uv run pyrefly check

# Run security checks with bandit
security:
	uv run bandit -r src -c pyproject.toml

# Run tests
test:
	uv run pytest

# Single source of truth for the integration compose invocation.
#
# --env-file must be passed to EVERY compose command, not just `up`: the compose
# file declares LOCALSTACK_AUTH_TOKEN with a `${...:?}` guard, and compose
# evaluates that interpolation on every parse. If the token lives only in
# tests/.env (the documented fallback), omitting --env-file makes `down` and
# `ps` fail to read the file at all — so the stack could be started but never
# stopped, and the `ps` probe below would silently report zero running services.
COMPOSE_TEST = docker compose $(if $(wildcard tests/.env),--env-file tests/.env,) -f tests/docker-compose.test.yml

# Same invocation for commands that do NOT start containers (down, ps).
#
# The compose file declares LOCALSTACK_AUTH_TOKEN with a `${...:?}` guard,
# evaluated on EVERY parse. So a developer who exported the token, started the
# stack, then ran `make test-integration-down` from a fresh shell (no export,
# no tests/.env) had teardown ABORT, leaving containers, network and volumes
# running. The token is irrelevant when we are not starting anything, so
# supply a placeholder if it is absent — never weaken the guard on `up`.
COMPOSE_TEST_NOSTART = LOCALSTACK_AUTH_TOKEN=$${LOCALSTACK_AUTH_TOKEN:-not-needed-for-teardown} $(COMPOSE_TEST)

# Start integration test containers
#
# LocalStack has been account-gated since 2026.03.0 and exits(55) without a
# token, so fail here with something actionable rather than letting compose
# emit a bare variable-not-set error. A free Hobby token is enough.
test-integration-up:
	@if [ -z "$$LOCALSTACK_AUTH_TOKEN" ] && ! grep -qsE '^[[:space:]]*LOCALSTACK_AUTH_TOKEN[[:space:]]*=[[:space:]]*[^[:space:]]' tests/.env; then \
		echo ""; \
		echo "ERROR: LOCALSTACK_AUTH_TOKEN is not set."; \
		echo ""; \
		echo "LocalStack requires an auth token since 2026.03.0. A FREE Hobby"; \
		echo "token covers everything this suite needs."; \
		echo ""; \
		echo "  1. Sign up at https://app.localstack.cloud"; \
		echo "  2. Copy your Personal Auth Token"; \
		echo "  3. Either export it:"; \
		echo "       export LOCALSTACK_AUTH_TOKEN=ls-..."; \
		echo "     or write tests/.env (gitignored):"; \
		echo "       echo 'LOCALSTACK_AUTH_TOKEN=ls-...' > tests/.env"; \
		echo ""; \
		exit 1; \
	fi
	$(COMPOSE_TEST) up -d --wait
	@echo "Services started. Run 'make test-integration' to run tests."

# Stop integration test containers
test-integration-down:
	@$(COMPOSE_TEST_NOSTART) down -v

# Run integration tests (starts containers if needed)
test-integration:
	@# `grep -c` prints 0 AND exits 1 when nothing matches, so `|| echo 0`
	@# appended a SECOND line: running became "0\n0", the -lt test errored with
	@# "integer expression expected" and took the false branch. The cold-start
	@# case — the only one this guard exists for — therefore never started the
	@# stack, pytest ran against a dead stack, every container test auto-skipped,
	@# and `make test-integration` exited 0 with zero integration tests run.
	@running=$$($(COMPOSE_TEST_NOSTART) ps --status running --format json 2>/dev/null \
		| grep -c '"Service"' || true); \
	running=$${running:-0}; \
	if [ "$$running" -lt 3 ]; then \
		echo "Starting containers ($$running/3 running)..."; \
		$(MAKE) test-integration-up; \
	fi
	uv run --extra test-integration pytest -m "integration" -v

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

# Pinned so the REQUIRED Lint check is reproducible. `npx markdownlint-cli2`
# with no version fetches whatever npm serves that minute, so an upstream
# release could fail a required gate with no PR and no warning.
# renovate: datasource=npm depName=markdownlint-cli2
MARKDOWNLINT_VERSION = 0.23.2

# Lint markdown documentation
lint-docs:
	@echo "Linting markdown files..."
	npx markdownlint-cli2@$(MARKDOWNLINT_VERSION) "**/*.md" "!**/node_modules/**" "!.venv/**" "!venv/**" "!.git/**" "!dist/**" "!build/**" "!site/**" "!.pytest_cache/**" \
	 "!.ruff_cache/**" "!.uv-cache/**" "!**/.vscode-test/**" "!**/CHANGELOG.md"

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
