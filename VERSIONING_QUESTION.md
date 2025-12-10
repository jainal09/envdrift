# Python Package Versioning Automation - Question for Web Search

## Current Setup

I have a Python package that uses:
- **Build system**: `hatchling` (defined in pyproject.toml)
- **Publishing tool**: `uv publish`
- **CI/CD**: GitHub Actions
- **Current workflow**: Publishes to PyPI on every push to main branch

## Current Code

### pyproject.toml (relevant parts)
```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "envdrift"
version = "0.1.0"  # <-- HARDCODED VERSION - THIS IS THE PROBLEM
description = "Prevent environment variable drift with Pydantic schema validation, pre-commit hooks, and dotenvx encryption"
readme = "README.md"
license = "MIT"
requires-python = ">=3.11"
```

### Current GitHub Actions Workflow (.github/workflows/publish.yml)
```yaml
name: Publish

on:
  push:
    branches: [main]  # <-- Triggers on EVERY push to main
  workflow_dispatch:

permissions:
  contents: read

jobs:
  publish:
    name: Publish to PyPI
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v6

      - name: Set up Python
        uses: actions/setup-python@v6
        with:
          python-version: "3.11"

      - name: Install uv
        uses: astral-sh/setup-uv@v6

      - name: Install dependencies
        run: uv sync --all-extras

      - name: Run tests
        run: uv run pytest

      - name: Build package
        run: uv build

      - name: Publish to PyPI
        env:
          PYPI_TOKEN: ${{ secrets.PYPI_TOKEN }}
        run: uv publish --token "$PYPI_TOKEN"
```

## The Problem

**The version number is hardcoded at `0.1.0` in pyproject.toml, but the workflow publishes on every merge to main.** This creates issues:

1. PyPI doesn't allow re-publishing the same version number
2. Every merge would fail after the first successful publish (unless I manually update the version each time)
3. Manual version updates are error-prone and easy to forget

## Questions I Need Answered (with 2024-2025 web sources)

Please search the web for current best practices and answer:

1. **What are the most popular automated versioning strategies for Python packages in 2024-2025?**
   - Specifically for projects using `hatchling` as the build backend
   - That work well with `uv publish`
   - With GitHub Actions integration

2. **What are the pros and cons of each approach?**
   - Git tag-based versioning with manual tags
   - Dynamic versioning from git (hatch-vcs, setuptools-scm)
   - Semantic release tools (python-semantic-release)
   - Bump version tools (bump-my-version, bumpversion)

3. **What is the recommended approach for projects using hatchling?**
   - Provide modern examples from 2024-2025
   - Include complete code examples for pyproject.toml
   - Include GitHub Actions workflow examples

4. **How do I implement dynamic versioning with hatch-vcs?**
   - Complete step-by-step setup
   - pyproject.toml configuration
   - GitHub Actions workflow changes needed
   - How to create and tag releases

5. **What workflow triggers should I use for publishing?**
   - Should I trigger on git tags instead of branch pushes?
   - What's the standard practice for production packages?

6. **Are there any recent changes or new tools in 2024-2025 for Python versioning automation?**
   - Especially relevant to `uv` ecosystem
   - Modern alternatives to older tools

## Desired Outcome

I want a solution that:
- ✅ Automatically manages version numbers based on git tags or commits
- ✅ Only publishes new versions when explicitly triggered (not on every merge)
- ✅ Works seamlessly with `uv publish`
- ✅ Uses `hatchling` as the build backend (already configured)
- ✅ Is industry-standard and well-maintained
- ✅ Simple to understand and maintain

## Additional Context

- The package is already published on PyPI
- Using Python 3.11+
- Open source project on GitHub
- Currently at version 0.1.0

---

**Please provide detailed, up-to-date information with sources from 2024-2025 documentation and blog posts.**
