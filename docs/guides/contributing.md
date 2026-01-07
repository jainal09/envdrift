# Contributing

Thanks for helping improve envdrift! This guide summarizes local setup, style rules, and the checks that keep the project healthy.

## Quick start

- Install deps: `make dev` (uses `uv` to install all extras, including tooling like pre-commit, ruff, bandit, pytest, mkdocs).
- Keep tools current: `uv lock --upgrade` when bumping dependencies.
- Run everything: `make check` (ruff lint, typecheck, bandit, tests) plus docs: `make docs` and `make lint-docs`.

## Pre-commit hooks

- Install hooks once: `uv run pre-commit install`. (You can also run `envdrift hook --install` to write the hook config automatically.)
- Run on demand: `uv run pre-commit run --all-files`.
- Hooks enforce ruff lint/formatting, type/style checks, and markdown linting before commits land.

## Editor setup

- VS Code: install the “Ruff” extension (ms-python.vscode-pylance + charliermarsh.ruff). '
Enable “Format on Save” with Ruff to match CI formatting (`ruff format` + `ruff check --fix`).
- VS Code: install the ["markdownlint" extension](https://marketplace.visualstudio.com/items?itemName=DavidAnson.vscode-markdownlint) for docs linting.
- Optional: add a pre-commit task to run `uv run pre-commit run --files $FilePath`.

## Makefile guide

- `make dev` – install all dev dependencies.
- `make lint` / `make format` – ruff checks (format also runs `ruff format`).
- `make typecheck` – pyrefly static analysis.
- `make security` – bandit security scan.
- `make test` – pytest suite.
- `make check` – lint + typecheck + security + tests.
- `make docs` – mkdocs build (`--strict`).
- `make lint-docs` – markdownlint (keeps docs tidy).
- `make docs-serve` – live docs preview at <http://127.0.0.1:8000/>.

## Required checks and style

- **Lint/Format**: Ruff (`ruff check`, `ruff format`). No `black`/`isort`; Ruff rules win.
- **Types**: Pyrefly (`make typecheck`).
- **Security**: Bandit (`make security`).
- **Tests**: Pytest (`make test`); add coverage for new code paths.
  See the [Testing Guide](../reference/testing.md) for integration tests with Docker.
- **Docs**: `make docs` must pass; lint docs with `make lint-docs` (markdownlint rules: headings increment, fenced code blocks, no trailing spaces).

## PR checklist

- [ ] Code formatted via `make format` (or Ruff on save).
- [ ] `make check` passes locally.
- [ ] Docs updated when behavior or flags change; `make docs` and `make lint-docs` pass.
- [ ] Hooks installed (`uv run pre-commit run --all-files` clean).
- [ ] New functionality covered by tests where practical.
