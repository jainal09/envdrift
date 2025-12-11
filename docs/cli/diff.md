# envdrift diff

Compare two .env files and show differences.

## Synopsis

```bash
envdrift diff ENV1 ENV2 [OPTIONS]
```

## Description

The `diff` command compares two .env files and shows:

- **Added variables** - Present in ENV2 but not ENV1
- **Removed variables** - Present in ENV1 but not ENV2
- **Changed variables** - Different values between files
- **Unchanged variables** - Same in both (with `--include-unchanged`)

This is useful for:

- Reviewing differences between development and production
- Auditing environment changes before deployment
- Detecting drift between team members' environments

## Arguments

| Argument | Description                           |
| :------- | :------------------------------------ |
| `ENV1`   | Path to first .env file (baseline)    |
| `ENV2`   | Path to second .env file (comparison) |

## Options

### `--schema`, `-s`

Schema for sensitive field detection. When provided, sensitive fields are masked in output.

```bash
envdrift diff .env.dev .env.prod --schema config.settings:Settings
```

### `--service-dir`, `-d`

Directory to add to Python's `sys.path` for schema imports.

```bash
envdrift diff .env.dev .env.prod -s config.settings:Settings -d /app/backend
```

### `--format`, `-f`

Output format: `table` (default) or `json`.

```bash
# Human-readable table (default)
envdrift diff .env.dev .env.prod --format table

# Machine-readable JSON
envdrift diff .env.dev .env.prod --format json
```

### `--show-values`

Show actual values instead of masking them. Use with caution - this may expose secrets!

```bash
envdrift diff .env.dev .env.prod --show-values
```

By default, values are shown but sensitive fields (when schema is provided) are masked.

### `--include-unchanged`

Include variables that are identical in both files.

```bash
envdrift diff .env.dev .env.prod --include-unchanged
```

## Examples

### Basic Comparison

```bash
envdrift diff .env.development .env.production
```

Output:

```text
╭────────────────────── envdrift diff ──────────────────────╮
│ Comparing: .env.development vs .env.production            │
╰───────────────────────────────────────────────────────────╯

┏━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┓
┃ Variable        ┃ .env.development┃ .env.production ┃ Status   ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━┩
│ DEBUG           │ true            │ false           │ changed  │
│ LOG_LEVEL       │ DEBUG           │ WARNING         │ changed  │
│ SENTRY_DSN      │ (missing)       │ https://...     │ added    │
│ DEV_ONLY_VAR    │ testing         │ (missing)       │ removed  │
└─────────────────┴─────────────────┴─────────────────┴──────────┘

Summary: 2 changed, 1 added, 1 removed

Drift detected between environments
```

### JSON Output for CI/CD

```bash
envdrift diff .env.dev .env.prod --format json
```

Output:

```json
{
  "env1_path": ".env.development",
  "env2_path": ".env.production",
  "has_drift": true,
  "differences": [
    {
      "name": "DEBUG",
      "diff_type": "changed",
      "value1": "true",
      "value2": "false",
      "is_sensitive": false
    },
    {
      "name": "SENTRY_DSN",
      "diff_type": "added",
      "value1": null,
      "value2": "https://...",
      "is_sensitive": true
    }
  ],
  "summary": {
    "added": 1,
    "removed": 1,
    "changed": 2,
    "unchanged": 5
  }
}
```

### With Schema for Sensitive Detection

```bash
envdrift diff .env.dev .env.prod --schema config.settings:Settings
```

Sensitive fields (marked with `json_schema_extra={"sensitive": True}`) are labeled in output.

### Show All Variables

```bash
envdrift diff .env.dev .env.prod --include-unchanged
```

### Expose Values (Use with Caution)

```bash
envdrift diff .env.dev .env.prod --show-values
```

### CI/CD Drift Detection

```yaml
# GitHub Actions - Comment on PR with drift report
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

      if (drift.has_drift) {
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

## Diff Types

| Type        | Description                                       |
| :---------- | :------------------------------------------------ |
| `added`     | Variable exists in ENV2 but not ENV1              |
| `removed`   | Variable exists in ENV1 but not ENV2              |
| `changed`   | Variable exists in both but with different values |
| `unchanged` | Variable is identical in both files               |

## Use Cases

### Pre-Deployment Review

Before deploying, compare staging and production:

```bash
envdrift diff .env.staging .env.production
```

### Onboarding New Team Members

Compare your .env with the template:

```bash
envdrift diff .env.example .env
```

### Detecting Configuration Drift

Monitor differences across environments:

```bash
for env in staging production; do
  echo "=== Development vs $env ==="
  envdrift diff .env.development .env.$env
done
```

## See Also

- [validate](validate.md) - Validate against schema
- [encrypt](encrypt.md) - Check encryption status
