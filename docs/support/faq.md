# Frequently Asked Questions

## General

### What's the difference between `validate` and `diff`?

- **`validate`** checks a single `.env` file against a Pydantic schema (type checking, required fields, extras)
- **`diff`** compares two `.env` files to show differences (added, removed, changed variables)

Use `validate` to catch schema violations. Use `diff` to compare environments.

### Can I use envdrift without encryption?

Yes. The core `validate` and `diff` commands work without encryption:

```bash
envdrift validate .env --schema config:Settings
envdrift diff .env.dev .env.prod
```

Encryption is optional but recommended for production secrets.

### Can I use envdrift without a schema?

Partially. You can use `diff` without a schema:

```bash
envdrift diff .env.dev .env.prod
```

But `validate` requires a schema—that's the whole point!

If you don't have a schema yet, generate one:

```bash
envdrift init .env --output config.py
```

### Does envdrift modify my .env files?

Only when you explicitly ask it to:

- `encrypt` — Encrypts values in-place
- `decrypt` — Decrypts values in-place
- `pull` — Decrypts after syncing keys

Commands like `validate`, `diff`, and `encrypt --check` are read-only.

## Encryption

### Should I use dotenvx or SOPS?

| Choose dotenvx if... | Choose SOPS if... |
|:---------------------|:------------------|
| You want simplicity | You have existing KMS infrastructure |
| You're a small team | You need native cloud KMS integration |
| You want partial encryption | You need key rotation and audit logs |
| You're new to secrets management | You're in an enterprise environment |

See [Encryption Backends](../concepts/encryption-backends.md) for a detailed comparison.

### How do I share encryption keys with my team?

Use vault sync:

1. Push your keys to a cloud vault: `envdrift vault-push`
2. Team members pull keys: `envdrift sync` or `envdrift pull`

This way, keys are stored securely in the cloud and synced on demand.

### Can I encrypt only some variables?

With dotenvx, you can use **partial encryption**:

```toml
# envdrift.toml
[partial_encryption]
enabled = true

[[partial_encryption.environments]]
name = "production"
clear_file = ".env.production.clear"
secret_file = ".env.production.secret"
combined_file = ".env.production"
```

See [Partial Encryption](../guides/partial-encryption.md).

### What happens if I lose my encryption keys?

**You cannot decrypt your files.** This is by design—encryption is only secure if keys are required.

Best practices:

1. Store keys in a cloud vault (Azure, AWS, HashiCorp, GCP)
2. Keep a secure backup of keys
3. Use vault sync to ensure all team members have access

### Can I rotate encryption keys?

**dotenvx:** Decrypt with old key, re-encrypt with new key, push new key to vault.

**SOPS:** Use your KMS provider's key rotation feature, or add new keys as recipients.

## Schema

### How do I mark a field as sensitive?

Use `json_schema_extra`:

```python
from pydantic import Field
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    API_KEY: str = Field(json_schema_extra={"sensitive": True})
```

Sensitive fields trigger encryption warnings if not encrypted.

### How do I make a field optional?

Provide a default value:

```python
class Settings(BaseSettings):
    # Required (no default)
    DATABASE_URL: str

    # Optional (has default)
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"
```

### How do I handle nested settings?

Use Pydantic's nested model support:

```python
class DatabaseSettings(BaseSettings):
    URL: str
    POOL_SIZE: int = 5

class Settings(BaseSettings):
    DATABASE: DatabaseSettings
```

With env prefix:

```bash
DATABASE__URL=postgres://...
DATABASE__POOL_SIZE=10
```

### Can I use different schemas for different environments?

Yes, create environment-specific classes:

```python
from pydantic_settings import BaseSettings

class AppSettings(BaseSettings):
    DATABASE_URL: str
    API_KEY: str

class DevelopmentSettings(AppSettings):
    DEBUG: bool = True

class ProductionSettings(AppSettings):
    DEBUG: bool = False
    SENTRY_DSN: str  # Required only in production
```

```bash
envdrift validate .env.dev --schema config:DevelopmentSettings
envdrift validate .env.prod --schema config:ProductionSettings
```

## Vault

### Which vault provider should I use?

Use whatever your team already uses:

- **Azure shop?** → Azure Key Vault
- **AWS shop?** → AWS Secrets Manager
- **GCP shop?** → GCP Secret Manager
- **Multi-cloud or self-hosted?** → HashiCorp Vault

See [Vault Providers](../concepts/vault-providers.md) for details.

### Can I use multiple vault providers?

You can specify different providers per mapping, but you'll need to provide credentials for each when syncing.

### How do I set up vault access in CI/CD?

Use your cloud provider's OIDC integration:

```yaml
# GitHub Actions - AWS
- uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: arn:aws:iam::123456789:role/my-role
    aws-region: us-east-1
- run: envdrift sync --provider aws
```

See [CI/CD Integration](../guides/cicd.md).

## Monorepo

### How do I use envdrift in a monorepo?

Use `--service-dir` for validation and configure multiple mappings:

```bash
# Validate service-specific schema
envdrift validate services/api/.env --schema config:Settings --service-dir services/api
```

```toml
# envdrift.toml
[[vault.sync.mappings]]
secret_name = "api-key"
folder_path = "services/api"

[[vault.sync.mappings]]
secret_name = "web-key"
folder_path = "services/web"
```

See [Monorepo Setup](../guides/monorepo-setup.md).

### Can I share a schema across services?

Yes, put the shared schema in a common package and import it:

```python
# services/api/config.py
from shared.settings import BaseAppSettings

class Settings(BaseAppSettings):
    API_SPECIFIC_VAR: str
```

## CI/CD

### How do I fail the build on validation errors?

Use the `--ci` flag:

```bash
envdrift validate .env.production --schema config:Settings --ci
```

Without `--ci`, validation errors are reported but don't cause a non-zero exit.

### Can I validate multiple environments in CI?

Yes, run multiple validation commands:

```yaml
- run: |
    envdrift validate .env.staging --schema config:Settings --ci
    envdrift validate .env.production --schema config:Settings --ci
```

### How do I decrypt in CI without storing keys in the repo?

Option 1: Store private key as CI secret

```yaml
- env:
    DOTENV_PRIVATE_KEY: ${{ secrets.DOTENV_PRIVATE_KEY }}
  run: |
    echo "DOTENV_PRIVATE_KEY=$DOTENV_PRIVATE_KEY" > .env.keys
    envdrift decrypt .env.production
```

Option 2: Use vault sync with CI credentials

```yaml
- run: envdrift pull --provider azure --vault-url ${{ secrets.VAULT_URL }}
```

## Migration

### Coming from python-dotenv?

envdrift reads the same `.env` format. Add a schema:

```bash
# Generate schema from existing .env
envdrift init .env --output config.py

# Start validating
envdrift validate .env --schema config:Settings
```

### Coming from django-environ?

Map your `environ.Env()` calls to Pydantic:

```python
# Before (django-environ)
import environ
env = environ.Env()
DATABASE_URL = env.db()
DEBUG = env.bool("DEBUG", default=False)

# After (pydantic-settings)
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    DATABASE_URL: str
    DEBUG: bool = False
```

See [Migrating](../guides/migrating.md).
