# envdrift validate

Validate an .env file against a Pydantic Settings schema.

## Synopsis

```bash
envdrift validate [ENV_FILE] --schema SCHEMA [OPTIONS]
```

## Description

The `validate` command checks that your .env file matches your Pydantic Settings schema. It verifies:

- **Required variables** - All required fields in the schema exist in the .env file
- **Type validation** - Values can be parsed as the expected type (int, bool, etc.)
- **Extra variables** - Warns about variables not defined in the schema (errors if `extra="forbid"`)
- **Encryption status** - Optionally warns if sensitive fields are not encrypted

## Arguments

| Argument   | Description                       | Default |
| :--------- | :-------------------------------- | :------ |
| `ENV_FILE` | Path to the .env file to validate | `.env`  |

## Options

### `--schema`, `-s` (required)

Dotted path to your Pydantic Settings class.

```bash
envdrift validate .env.production --schema config.settings:ProductionSettings
envdrift validate .env -s myapp.config:Settings
```

The format is `module.path:ClassName` where:

- `module.path` is the Python import path
- `ClassName` is the Settings class name

### `--service-dir`, `-d`

Directory to add to Python's `sys.path` for imports. Useful for monorepos or when running from a different directory.

```bash
# Schema is in /app/backend/config/settings.py
envdrift validate .env -s config.settings:Settings -d /app/backend

# Monorepo structure
envdrift validate services/api/.env -s config:Settings -d services/api
```

### `--ci`

CI mode: exit with code 1 if validation fails. Use this in CI/CD pipelines.

```bash
envdrift validate .env.production -s config.settings:ProductionSettings --ci
```

Without `--ci`, the command always exits with code 0 (unless there's a fatal error like missing file).

### `--check-encryption` / `--no-check-encryption`

Control whether to check if sensitive variables are encrypted.

```bash
# Check encryption (default)
envdrift validate .env.production -s config.settings:ProductionSettings --check-encryption

# Skip encryption check
envdrift validate .env.production -s config.settings:ProductionSettings --no-check-encryption
```

When enabled, unencrypted sensitive fields are reported as **warnings** (not errors). Use `envdrift encrypt --check` for strict encryption enforcement.

### `--fix`

Output a template for missing variables. Useful for quickly adding required fields.

```bash
envdrift validate .env.production -s config.settings:ProductionSettings --fix
```

Example output:

```text
# Missing required variables:
# API key for external service
NEW_API_KEY="encrypted:YOUR_VALUE_HERE"

# Database connection string
DATABASE_URL=
```

### `--verbose`, `-v`

Show additional details including missing optional variables with their defaults.

```bash
envdrift validate .env.production -s config.settings:ProductionSettings -v
```

## Examples

### Basic Validation

```bash
envdrift validate .env.production --schema config.settings:ProductionSettings
```

Output when passing:

```text
╭─────────────────────── envdrift validate ───────────────────────╮
│ Validating: .env.production                                     │
│ Schema: config.settings:ProductionSettings                      │
╰─────────────────────────────────────────────────────────────────╯

Validation PASSED
```

### Validation with Errors

```bash
envdrift validate .env.production --schema config.settings:ProductionSettings
```

Output when failing:

```text
╭─────────────────────── envdrift validate ───────────────────────╮
│ Validating: .env.production                                     │
│ Schema: config.settings:ProductionSettings                      │
╰─────────────────────────────────────────────────────────────────╯

Validation FAILED

MISSING REQUIRED VARIABLES:
  * DATABASE_URL - PostgreSQL connection string
  * API_KEY - Backend service API key

TYPE ERRORS:
  * PORT: Expected integer, got 'not_a_number'

Summary: 3 error(s), 0 warning(s)

Run with --fix to generate template for missing variables.
```

### CI/CD Pipeline

```yaml
# GitHub Actions
- name: Validate environment
  run: |
    pip install envdrift
    envdrift validate .env.production \
      --schema config.settings:ProductionSettings \
      --ci
```

### Generate Fix Template

```bash
envdrift validate .env.production -s config.settings:ProductionSettings --fix
```

### Validate Multiple Environments

```bash
# Development
envdrift validate .env.development -s config.settings:DevelopmentSettings --ci

# Staging
envdrift validate .env.staging -s config.settings:StagingSettings --ci

# Production
envdrift validate .env.production -s config.settings:ProductionSettings --ci
```

### Skip Encryption Warnings

```bash
envdrift validate .env.development -s config.settings:Settings --no-check-encryption
```

### Verbose Output

```bash
envdrift validate .env.production -s config.settings:ProductionSettings -v
```

Shows missing optional variables:

```text
MISSING OPTIONAL VARIABLES (have defaults):
  * DEBUG (default: False)
  * LOG_LEVEL (default: INFO)
  * WORKERS (default: 4)
```

## Schema Requirements

Your Pydantic Settings class should be importable. If you have module-level code that instantiates settings, check for `ENVDRIFT_SCHEMA_EXTRACTION`:

```python
import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    DATABASE_URL: str
    DEBUG: bool = False

# Skip instantiation during schema extraction
if os.getenv("ENVDRIFT_SCHEMA_EXTRACTION"):
    settings = None
else:
    settings = Settings()
```

## What Gets Validated

| Check                              | Error/Warning | Description                                          |
| :--------------------------------- | :------------ | :--------------------------------------------------- |
| Missing required vars              | Error         | Fields without defaults must exist                   |
| Type mismatches                    | Error         | Values must parse as the expected type               |
| Extra vars (with `extra="forbid"`) | Error         | Unknown variables not allowed                        |
| Extra vars (with `extra="ignore"`) | Warning       | Unknown variables allowed but noted                  |
| Unencrypted sensitive vars         | Warning       | Fields marked `sensitive=True` should be encrypted   |

## See Also

- [diff](diff.md) - Compare .env files
- [encrypt](encrypt.md) - Check/perform encryption
- [init](init.md) - Generate schema from .env
