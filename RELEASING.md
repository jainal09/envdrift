# Release Process

This project uses automated versioning with `hatch-vcs` and publishes to PyPI via GitHub Actions.

## Overview

- **Version management**: Automatic, based on git tags
- **Versioning scheme**: Semantic versioning (SemVer)
- **Publishing**: Automated via GitHub Actions when a version tag is pushed

## How It Works

The version number is automatically determined from git tags using `hatch-vcs`. You don't need to manually update the version in `pyproject.toml`.

## Creating a New Release

### 1. Ensure your changes are merged to main

Make sure all changes for the release are merged to the `main` branch and tests are passing.

### 2. Create and push a version tag

Use semantic versioning for tags (e.g., `v0.1.1`, `v0.2.0`, `v1.0.0`):

```bash
# For a patch release (bug fixes)
git tag v0.1.1
git push origin v0.1.1

# For a minor release (new features, backwards compatible)
git tag v0.2.0
git push origin v0.2.0

# For a major release (breaking changes)
git tag v1.0.0
git push origin v1.0.0
```

### 3. Automated publishing

Once the tag is pushed:
1. GitHub Actions automatically triggers the publish workflow
2. Tests are run to ensure quality
3. Package is built with the version from the git tag
4. Package is published to PyPI

### 4. Monitor the workflow

Check the [Actions tab](https://github.com/jainal09/envdrift/actions) to ensure the publish workflow completes successfully.

## Version Numbering Guide

Follow [Semantic Versioning](https://semver.org/):

- **Patch** (0.1.X): Bug fixes, no API changes
- **Minor** (0.X.0): New features, backwards compatible
- **Major** (X.0.0): Breaking changes

## Versioning Between Releases

When not on an exact tag, `hatch-vcs` will generate a version like:
- `0.1.1.dev5+g1234567` - 5 commits after tag v0.1.0, commit hash 1234567

This ensures every commit has a unique, ordered version number.

## Manual Publishing (Emergency)

If you need to publish manually:

```bash
# Ensure you're on the tagged commit
git checkout v0.1.1

# Install dependencies
uv sync --all-extras

# Run tests
uv run pytest

# Build and publish
uv build
uv publish --token $PYPI_TOKEN
```

## Troubleshooting

### "Version already exists" error

If PyPI rejects the version, check:
1. Has this tag been published before?
2. Is there a tag on a commit that's already been published?

### Version not detected correctly

Ensure:
1. You have git history: `git fetch --tags --unshallow` (if needed)
2. You're on or after a tagged commit
3. Tags follow the `v*` pattern (e.g., `v0.1.0`, not `0.1.0`)
