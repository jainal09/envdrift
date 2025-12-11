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

# For a minor release (new features, backward-compatible)
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
- **Minor** (0.X.0): New features, backward-compatible
- **Major** (X.0.0): Breaking changes

## Versioning Between Releases

When not on an exact tag, `hatch-vcs` will generate a version like:

- `0.1.1.dev5+g1234567` - 5 commits after tag v0.1.0, commit hash 1234567

This ensures every commit has a unique, ordered version number.

## Manual Publishing (Emergency)

If you need to publish manually:

```bash
# Ensure you're on the tagged commit (use tags/ prefix to avoid branch/tag ambiguity)
git checkout tags/v0.1.1

# Install dependencies
uv sync --all-extras

# Run tests
uv run pytest

# Build and publish
uv build
uv publish --token $PYPI_TOKEN
```

> **Note**: Always use `git checkout tags/<version>` instead of `git checkout <version>` to avoid
> accidentally creating a branch with the same name as the tag.

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

### Pre-release validation

Before creating and pushing a tag, verify the version doesn't already exist on PyPI:

```bash
# Check if version exists on PyPI
pip index versions envdrift

# Or check directly on PyPI
curl -s https://pypi.org/pypi/envdrift/json | grep -o '"version":"[^"]*"'
```

This prevents "Version already exists" errors and helps avoid creating tags that will fail to publish.

### Cleaning up orphaned tags

If you accidentally created a tag that failed to publish, clean it up:

```bash
# Delete local tag
git tag -d v0.1.X

# Delete remote tag (only if it failed to publish)
git push origin :refs/tags/v0.1.X
```

**Warning**: Only delete tags that have NOT been successfully published to PyPI.
Once a version is on PyPI, the tag should remain in git for version traceability.

### Tag hygiene and force-pushing

**Never force-push tags** - This can cause serious issues:

- Force-pushing a tag to a different commit can trigger republishing attempts
- PyPI will reject the duplicate version, causing workflow failures
- It breaks version traceability and can confuse users

If you need to fix a release:

1. Don't modify existing tags
2. Create a new patch version (e.g., if `v0.1.1` has issues, create `v0.1.2`)
3. Keep the git history clean and traceable
