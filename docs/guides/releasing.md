# Release Process

This project uses release-please, conventional commits, and `hatch-vcs` to
automate versioning, changelogs, GitHub releases, and PyPI publishing.

## Overview

- **Version management**: Automatic, based on git tags via `hatch-vcs`
- **Release automation**: release-please opens release PRs on `main`
- **Changelog**: `CHANGELOG.md` maintained by release-please
- **Publishing**: Automated via GitHub Actions when a version tag is created

## Requirements for merging

- **PR titles must be conventional commits** (enforced by semantic-pr).
- **Commit messages in the PR must be conventional** (enforced by commitlint).
- **Squash merges are enforced**, and the squash commit message uses the PR title.

Example PR titles:

- `feat(cli): add --json output`
- `fix(sync): handle missing vault token`
- `perf(scanner): speed up pattern matching`
- `feat!: remove deprecated flag`

## Creating a New Release

### 1. Merge user-facing changes to main

Merge changes to `main` with a conventional PR title. Use `feat`, `fix`, `perf`,
or a `BREAKING CHANGE` to trigger a release.

### 2. Review the release PR

release-please runs on `main` and opens/updates a "Release please" PR that bumps
the version and updates `CHANGELOG.md`. Review it like any other PR.

### 3. Merge the release PR

Merge the release PR (squash). This creates a tag and GitHub release.

### 4. Automated publishing

When the tag is created:

1. GitHub Actions triggers the publish workflow
2. Tests run for the release tag
3. Package is built with the tag-derived version
4. Package is published to PyPI
5. Release notes are attached to the GitHub release (from `CHANGELOG.md`)

### 5. Monitor the workflows

Check the [Actions tab](https://github.com/jainal09/envdrift/actions) and the
[Releases page](https://github.com/jainal09/envdrift/releases).

## When a Release PR is Created

release-please only creates a release PR when it finds user-facing conventional
commits. If changes are only `chore`, `docs`, or `ci`, it will skip the release.

Use `feat!:` or a `BREAKING CHANGE:` footer to trigger a major release.

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

Manual publishing should be rare. Prefer fixing conventional commits and
letting release-please create the release PR. If you must publish manually:

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

### Release PR not created

If release-please did not open a release PR:

1. Check that merged commits are conventional and user-facing (`feat`, `fix`, `perf`).
2. Verify the release-please workflow ran and succeeded.
3. Confirm `RELEASE_PLEASE_TOKEN` is set in repository secrets.

### Pre-release validation

Before creating and pushing a tag manually, verify the version doesn't already
exist on PyPI:

```bash
# Check if version exists on PyPI
pip index versions envdrift

# Or check directly on PyPI
curl -s https://pypi.org/pypi/envdrift/json | grep -o '"version":"[^"]*"'
```

This prevents "Version already exists" errors and helps avoid creating tags that
will fail to publish.

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
