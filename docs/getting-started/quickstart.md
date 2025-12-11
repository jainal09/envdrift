# Quick Start

Get up and running with envdrift in 5 minutes.

## 1. Define Your Schema

Create a Pydantic Settings class that defines your expected environment variables:

```python
# config/settings.py
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

## 2. Create Your .env File

```bash
# .env
DATABASE_URL=postgres://localhost/mydb
API_KEY=sk-dev-key-12345
DEBUG=true
LOG_LEVEL=DEBUG
PORT=8000
```

## 3. Validate

```bash
envdrift validate .env --schema config.settings:Settings
```

If everything matches, you'll see:

```text
Validation PASSED for .env
Summary: 0 error(s), 0 warning(s)
```

If there's a mismatch:

```text
Validation FAILED for .env

MISSING REQUIRED VARIABLES:
  - API_KEY

Summary: 1 error(s), 0 warning(s)
```

## 4. Compare Environments

```bash
envdrift diff .env.development .env.production
```

Output:

```text
Comparing: .env.development vs .env.production

ADDED (in .env.production only):
  + SENTRY_DSN

REMOVED (in .env.development only):
  - DEV_ONLY_VAR

CHANGED:
  ~ DEBUG: true -> false
  ~ LOG_LEVEL: DEBUG -> WARNING
```

## 5. Set Up Pre-commit Hook

```bash
envdrift hook --config
```

Add the output to your `.pre-commit-config.yaml`.

## Next Steps

- [CLI Reference](../reference/cli.md) - All available commands
- [Schema Best Practices](../guides/schema.md) - How to structure your settings
- [CI/CD Integration](../guides/cicd.md) - Add to your pipeline
