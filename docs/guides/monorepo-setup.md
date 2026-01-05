# Monorepo Setup

This guide explains how to use envdrift in a monorepo with multiple services.

## Directory Structure

A typical monorepo might look like:

```text
my-monorepo/
├── envdrift.toml           # Shared config
├── services/
│   ├── api/
│   │   ├── .env.production
│   │   ├── .env.keys
│   │   └── config.py       # API-specific schema
│   ├── web/
│   │   ├── .env.production
│   │   ├── .env.keys
│   │   └── config.py       # Web-specific schema
│   └── worker/
│       ├── .env.production
│       ├── .env.keys
│       └── config.py       # Worker-specific schema
└── shared/
    └── settings.py         # Shared base schema
```

## Shared Base Schema

Create a base schema that all services extend:

```python
# shared/settings.py
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

class BaseAppSettings(BaseSettings):
    """Base settings shared across all services."""

    model_config = SettingsConfigDict(extra="forbid")

    # Common required variables
    ENVIRONMENT: str
    LOG_LEVEL: str = "INFO"

    # Common secrets
    DATABASE_URL: str = Field(json_schema_extra={"sensitive": True})
```

## Service-Specific Schemas

Each service extends the base with its own requirements:

```python
# services/api/config.py
from shared.settings import BaseAppSettings
from pydantic import Field

class Settings(BaseAppSettings):
    """API service settings."""

    API_KEY: str = Field(json_schema_extra={"sensitive": True})
    API_RATE_LIMIT: int = 100
    CORS_ORIGINS: str = "*"
```

```python
# services/web/config.py
from shared.settings import BaseAppSettings

class Settings(BaseAppSettings):
    """Web frontend settings."""

    NEXT_PUBLIC_API_URL: str
    SESSION_SECRET: str
```

```python
# services/worker/config.py
from shared.settings import BaseAppSettings
from pydantic import Field

class Settings(BaseAppSettings):
    """Background worker settings."""

    REDIS_URL: str = Field(json_schema_extra={"sensitive": True})
    WORKER_CONCURRENCY: int = 4
```

## Validation

Use `--service-dir` to set the correct Python path:

```bash
# Validate each service
envdrift validate services/api/.env.production \
    --schema config:Settings \
    --service-dir services/api

envdrift validate services/web/.env.production \
    --schema config:Settings \
    --service-dir services/web

envdrift validate services/worker/.env.production \
    --schema config:Settings \
    --service-dir services/worker
```

### Validation Script

Create a script to validate all services:

```bash
#!/bin/bash
# scripts/validate-all.sh

set -e

SERVICES=("api" "web" "worker")

for service in "${SERVICES[@]}"; do
    echo "Validating $service..."
    envdrift validate "services/$service/.env.production" \
        --schema config:Settings \
        --service-dir "services/$service" \
        --ci
done

echo "All services validated!"
```

## Configuration

Configure vault sync for all services:

```toml
# envdrift.toml
[vault]
provider = "azure"

[vault.azure]
vault_url = "https://my-keyvault.vault.azure.net/"

[vault.sync]
default_vault_name = "my-keyvault"

# API service
[[vault.sync.mappings]]
secret_name = "api-dotenvx-key"
folder_path = "services/api"
environment = "production"

# Web service
[[vault.sync.mappings]]
secret_name = "web-dotenvx-key"
folder_path = "services/web"
environment = "production"

# Worker service
[[vault.sync.mappings]]
secret_name = "worker-dotenvx-key"
folder_path = "services/worker"
environment = "production"
```

## Sync and Pull

Sync keys for all services at once:

```bash
# Sync keys from vault
envdrift sync

# Or pull (sync + decrypt)
envdrift pull
```

Output:

```text
Processing: services/api
  + services/api/.env.keys - created

Processing: services/web
  + services/web/.env.keys - created

Processing: services/worker
  + services/worker/.env.keys - created

╭──────────── Sync Summary ────────────╮
│ Services processed: 3                │
│ Created: 3                           │
│ Updated: 0                           │
│ Skipped: 0                           │
│ Errors: 0                            │
╰──────────────────────────────────────╯
```

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/validate.yml
name: Validate Environment

on:
  pull_request:
    paths:
      - 'services/**/.env.*'
      - 'services/**/config.py'

jobs:
  validate:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        service: [api, web, worker]

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          pip install envdrift
          pip install -e shared/  # If shared is a package

      - name: Validate ${{ matrix.service }}
        run: |
          envdrift validate services/${{ matrix.service }}/.env.production \
            --schema config:Settings \
            --service-dir services/${{ matrix.service }} \
            --ci
```

### Pre-commit Hook

Validate changed services only:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: envdrift-validate-api
        name: Validate API env
        entry: envdrift validate services/api/.env.production --schema config:Settings --service-dir services/api --ci
        language: system
        files: ^services/api/\.env\.production$
        pass_filenames: false

      - id: envdrift-validate-web
        name: Validate Web env
        entry: envdrift validate services/web/.env.production --schema config:Settings --service-dir services/web --ci
        language: system
        files: ^services/web/\.env\.production$
        pass_filenames: false

      - id: envdrift-validate-worker
        name: Validate Worker env
        entry: envdrift validate services/worker/.env.production --schema config:Settings --service-dir services/worker --ci
        language: system
        files: ^services/worker/\.env\.production$
        pass_filenames: false
```

## Comparing Across Services

Compare the same environment across services:

```bash
# Compare API and Worker database configs
envdrift diff services/api/.env.production services/worker/.env.production
```

Compare a service across environments:

```bash
# Compare API staging vs production
envdrift diff services/api/.env.staging services/api/.env.production
```

## Tips

### Use Profiles for Local Development

```toml
# Local dev mappings
[[vault.sync.mappings]]
secret_name = "api-local-key"
folder_path = "services/api"
profile = "local"
activate_to = "services/api/.env"

[[vault.sync.mappings]]
secret_name = "web-local-key"
folder_path = "services/web"
profile = "local"
activate_to = "services/web/.env"
```

```bash
# Pull local development keys
envdrift pull --profile local
```

### Shared .env.keys Location

If services share the same encryption key, use a single keys file:

```toml
[[vault.sync.mappings]]
secret_name = "shared-key"
folder_path = "."  # Root of monorepo
```

Then reference it from each service:

```bash
# Set DOTENV_KEYS_PATH or create symlinks
ln -s ../../.env.keys services/api/.env.keys
```

### Makefile for Convenience

```makefile
# Makefile
.PHONY: validate-all sync-all pull-all lock-all

SERVICES := api web worker

validate-all:
	@for service in $(SERVICES); do \
		echo "Validating $$service..."; \
		envdrift validate services/$$service/.env.production \
			--schema config:Settings \
			--service-dir services/$$service \
			--ci; \
	done

sync-all:
	envdrift sync

pull-all:
	envdrift pull

lock-all:
	envdrift lock --verify-vault
```

## See Also

- [CI/CD Integration](cicd.md) — Pipeline setup
- [Schema Best Practices](schema.md) — Schema design patterns
- [Vault Sync](vault-sync.md) — Team key sharing
