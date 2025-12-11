# CI/CD Integration

Add envdrift to your CI/CD pipeline to catch drift before deployment.

## GitHub Actions

```yaml
# .github/workflows/validate-env.yml
name: Validate Environment

on:
  push:
    branches: [main]
    paths:
      - '.env.*'
      - 'config/**'
  pull_request:
    paths:
      - '.env.*'
      - 'config/**'

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install envdrift
        run: pip install envdrift

      - name: Validate production env
        run: |
          envdrift validate .env.production \
            --schema config.settings:ProductionSettings \
            --ci

      - name: Check encryption
        run: |
          envdrift encrypt .env.production --check

      - name: Diff dev vs prod
        run: |
          envdrift diff .env.development .env.production --format json
```

## GitLab CI

```yaml
# .gitlab-ci.yml
validate-env:
  stage: test
  image: python:3.11-slim
  script:
    - pip install envdrift
    - envdrift validate .env.production --schema config.settings:ProductionSettings --ci
    - envdrift encrypt .env.production --check
  only:
    changes:
      - .env.*
      - config/**
```

## Pre-commit Hooks

Local validation before commits:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: envdrift-validate
        name: Validate env schema
        entry: envdrift validate --ci --schema config.settings:Settings
        language: system
        files: ^\.env\.(production|staging|development)$
        pass_filenames: true

      - id: envdrift-encryption
        name: Check env encryption
        entry: envdrift encrypt --check
        language: system
        files: ^\.env\.(production|staging)$
        pass_filenames: true
```

Install:

```bash
pip install pre-commit
pre-commit install
```

## Exit Codes

envdrift uses standard exit codes for CI:

| Exit Code | Meaning                                             |
|-----------|-----------------------------------------------------|
| 0         | Validation passed                                   |
| 1         | Validation failed (missing vars, type errors, etc.) |

## Multi-Environment Validation

Validate all environments in one job:

```yaml
jobs:
  validate:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        include:
          - env: development
            settings_class: DevelopmentSettings
          - env: staging
            settings_class: StagingSettings
          - env: production
            settings_class: ProductionSettings
    steps:
      - uses: actions/checkout@v4

      - name: Install envdrift
        run: pip install envdrift

      - name: Validate ${{ matrix.env }}
        run: |
          envdrift validate .env.${{ matrix.env }} \
            --schema config.settings:${{ matrix.settings_class }} \
            --ci
```

## Drift Detection in PRs

Comment on PRs with drift report:

```yaml
- name: Check drift
  id: drift
  run: |
    envdrift diff .env.development .env.production --format json > drift.json

- name: Comment on PR
  uses: actions/github-script@v7
  with:
    script: |
      const fs = require('fs');
      const drift = JSON.parse(fs.readFileSync('drift.json', 'utf8'));

      if (drift.summary.has_drift) {
        github.rest.issues.createComment({
          issue_number: context.issue.number,
          owner: context.repo.owner,
          repo: context.repo.repo,
          body: `## Environment Drift Detected\n\n` +
                `- Added: ${drift.summary.added}\n` +
                `- Removed: ${drift.summary.removed}\n` +
                `- Changed: ${drift.summary.changed}`
        });
      }
```
