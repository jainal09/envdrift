# Contributing

Thanks for taking the time to contribute to envdrift.

## Before you start

- Search existing issues and pull requests to avoid duplicates.
- For security issues, see `SECURITY.md`.

## Development setup

```bash
# Install dependencies
uv sync --all-extras

# Run tests
uv run pytest

# Lint and format
uv run ruff check .
uv run ruff format .
```

Optional (recommended) pre-commit hooks:

```bash
pre-commit install
```

## Pull requests

- Keep changes focused and describe the intent in the PR description.
- Add or update tests when behavior changes.
- Update docs when user-facing behavior changes.
- Use Conventional Commits for PR titles and commit messages, for example:
  - `fix: handle missing config`
  - `feat: add new drift report format`
  - `docs: clarify release process`

## Reporting bugs

Use the bug report template and include steps to reproduce, expected behavior,
actual behavior, and relevant logs.

## Requesting features

Use the feature request template and explain the problem you're solving.
