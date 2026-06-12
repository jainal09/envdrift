# Quick Start

Get up and running with envdrift in 5 minutes.

## Option A: Generate Schema from Existing .env

If you already have a `.env` file, generate a schema automatically:

```bash
envdrift init .env --output config.py
```

This creates a Pydantic Settings class based on your existing variables:

```python
# config.py (generated)
"""Auto-generated Pydantic Settings class."""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Settings generated from .env."""

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="forbid",
    )

    API_KEY: str = Field(json_schema_extra={"sensitive": True})
    DATABASE_URL: str = Field(json_schema_extra={"sensitive": True})
    DEBUG: bool = False
    LOG_LEVEL: str
```

Fields are emitted in alphabetical order, and variables detected as sensitive (by
name or value) are annotated with `json_schema_extra={"sensitive": True}`. Plain
string variables without a boolean or integer value are left required (no default).

## Option B: Write Schema Manually

Create a Pydantic Settings class that defines your expected environment variables:

```python
# config.py
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        extra="forbid",  # Reject unknown variables
    )

    # Required variables (no default = must exist)
    DATABASE_URL: str = Field(json_schema_extra={"sensitive": True})
    API_KEY: str = Field(json_schema_extra={"sensitive": True})

    # Optional with defaults
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"
    PORT: int = 8000
```

## Validate Your .env

```bash
envdrift validate .env --schema config:Settings
```

If everything matches:

```text
╭─────────────────────── envdrift validate ───────────────────────╮
│ Validating: .env                                                │
│ Schema: config:Settings                                          │
╰─────────────────────────────────────────────────────────────────╯

Validation PASSED
```

The `Summary:` line is printed only when there are errors or warnings; a fully
clean pass ends at `Validation PASSED`.

If there's a mismatch:

```text
Validation FAILED

MISSING REQUIRED VARIABLES:
  * API_KEY

TYPE ERRORS:
  * PORT: Expected integer, got 'not_a_number'

Summary: 2 error(s), 0 warning(s)
```

## Compare Environments

Spot differences between dev and production:

```bash
envdrift diff .env.dev .env.prod
```

Output:

```text
╭───────────────────── envdrift diff ──────────────────────╮
│ Comparing: .env.dev vs .env.prod                         │
╰──────────────────────────────────────────────────────────╯

┏━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┓
┃ Variable     ┃ .env.dev  ┃ .env.prod               ┃ Status  ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━┩
│ DEBUG        │ true      │ false                   │ changed │
│ DEV_ONLY_VAR │ x         │ (missing)               │ removed │
│ LOG_LEVEL    │ DEBUG     │ WARNING                 │ changed │
│ SENTRY_DSN   │ (missing) │ https://abc@sentry.io/1 │  added  │
└──────────────┴───────────┴─────────────────────────┴─────────┘

Summary: 2 changed, 1 added, 1 removed

Drift detected between environments
```

## Encrypt Secrets

Encrypt your production secrets before committing:

```bash
# Encrypt the file
envdrift encrypt .env.prod

# Check encryption status
envdrift encrypt .env.prod --check
```

After encryption:

```bash
# .env.prod (encrypted)
DOTENV_PUBLIC_KEY="034a5c..."
DATABASE_URL="encrypted:BD7HQzb..."
API_KEY="encrypted:BD9XKwm..."
DEBUG=false
```

The `DOTENV_PUBLIC_KEY*` line is a dotenvx artifact (a public key, not a
secret). `envdrift validate` knows about it, so the encrypted file still
validates cleanly against your generated schema — even with `extra="forbid"`.

## Add to CI/CD

Validate environments in your pipeline:

```yaml
# .github/workflows/validate.yml
- name: Validate production env
  run: |
    pip install envdrift
    envdrift validate .env.prod --schema config:Settings --ci
```

The `--ci` flag ensures the build fails on validation errors.

## Team Workflow (Optional)

Share encryption keys with your team via a cloud vault:

```bash
# Push your key to Azure Key Vault
envdrift vault-push . my-app-key --env production --provider azure --vault-url https://myvault.vault.azure.net/

# Team members pull the key (no config needed) - writes .env.keys and decrypts .env.production
envdrift vault-pull . my-app-key --env production --provider azure --vault-url https://myvault.vault.azure.net/
```

> `vault-pull` is the config-free, single-secret counterpart of `vault-push`. For
> multi-service flows driven by a `[vault.sync]` config, use `envdrift pull`.

## Pre-commit Hook (Optional)

Validate on every commit:

```bash
envdrift hook --config
```

Add the output to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: envdrift-validate
        name: Validate .env files
        entry: envdrift validate .env.prod --schema config:Settings --ci
        language: system
        files: ^\.env\.prod$
        pass_filenames: false
```

## Next Steps

- [How It Works](../concepts/how-it-works.md) — Understand the mental model
- [CLI Reference](../cli/index.md) — All available commands
- [Schema Best Practices](../guides/schema.md) — Design better schemas
- [Encryption Guide](../guides/encryption.md) — dotenvx vs SOPS
- [Env File Sync](../guides/env-file-sync.md) — Team key sharing
- [CI/CD Integration](../guides/cicd.md) — Pipeline setup
