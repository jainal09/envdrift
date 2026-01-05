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
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="forbid")

    DATABASE_URL: str = Field(json_schema_extra={"sensitive": True})
    API_KEY: str = Field(json_schema_extra={"sensitive": True})
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"
```

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
Summary: 0 error(s), 0 warning(s)
```

If there's a mismatch:

```text
Validation FAILED

MISSING REQUIRED VARIABLES:
  * API_KEY - No default value, must be set

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
Comparing: .env.dev vs .env.prod

ADDED (in .env.prod only):
  + SENTRY_DSN

REMOVED (in .env.dev only):
  - DEV_ONLY_VAR

CHANGED:
  ~ DEBUG: true -> false
  ~ LOG_LEVEL: DEBUG -> WARNING
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
envdrift vault-push . my-app-key --provider azure --vault-url https://myvault.vault.azure.net/

# Team members pull the key
envdrift pull --provider azure --vault-url https://myvault.vault.azure.net/
```

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
- [Vault Sync](../guides/vault-sync.md) — Team key sharing
- [CI/CD Integration](../guides/cicd.md) — Pipeline setup
