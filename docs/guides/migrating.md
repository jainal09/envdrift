# Migrating to envdrift

This guide helps you migrate from other environment variable tools to envdrift.

## From Plain .env (No Validation)

If you're using `.env` files without validation, adding envdrift is straightforward.

### Step 1: Generate a Schema

```bash
# Generate schema from your existing .env
envdrift init .env --output config.py
```

This creates a Pydantic Settings class:

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

### Step 2: Review and Refine

Edit the generated schema:

- Add descriptions to fields
- Adjust default values
- Mark additional fields as sensitive
- Add type constraints

```python
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="forbid")

    DATABASE_URL: str = Field(
        json_schema_extra={"sensitive": True},
        description="PostgreSQL connection URL"
    )
    API_KEY: str = Field(
        json_schema_extra={"sensitive": True},
        description="External API key"
    )
    DEBUG: bool = Field(default=False, description="Enable debug mode")
    LOG_LEVEL: str = Field(default="INFO", pattern="^(DEBUG|INFO|WARNING|ERROR)$")
```

### Step 3: Validate

```bash
envdrift validate .env --schema config:Settings
```

### Step 4: Add to CI

```yaml
# .github/workflows/validate.yml
- run: pip install envdrift
- run: envdrift validate .env.production --schema config:Settings --ci
```

## From python-dotenv

If you're using `python-dotenv` with manual validation, envdrift automates that.

### Before

```python
# config.py
import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("DATABASE_URL required")

DEBUG = os.getenv("DEBUG", "false").lower() == "true"
PORT = int(os.getenv("PORT", "8000"))
```

### After

```python
# config.py
from pydantic import Field
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    DATABASE_URL: str = Field(json_schema_extra={"sensitive": True})
    DEBUG: bool = False
    PORT: int = 8000

# Optional: create instance for import
settings = Settings()
```

Usage in your app remains similar:

```python
# Before
from config import DATABASE_URL, DEBUG

# After
from config import settings
DATABASE_URL = settings.DATABASE_URL
DEBUG = settings.DEBUG
```

### Key Differences

| python-dotenv | envdrift + Pydantic |
|:--------------|:--------------------|
| Manual type conversion | Automatic type coercion |
| Manual required checks | Schema-defined requirements |
| No cross-env comparison | `envdrift diff` |
| Manual encryption | Built-in encryption support |

## From python-decouple

python-decouple has similar concepts to Pydantic Settings.

### Before

```python
# settings.py
from decouple import config, Csv

DATABASE_URL = config("DATABASE_URL")
DEBUG = config("DEBUG", default=False, cast=bool)
ALLOWED_HOSTS = config("ALLOWED_HOSTS", cast=Csv())
SECRET_KEY = config("SECRET_KEY")
```

### After

```python
# config.py
from pydantic import Field
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    DATABASE_URL: str = Field(json_schema_extra={"sensitive": True})
    DEBUG: bool = False
    ALLOWED_HOSTS: list[str] = ["localhost"]  # Pydantic handles list parsing
    SECRET_KEY: str = Field(json_schema_extra={"sensitive": True})

settings = Settings()
```

### Mapping Cast Types

| python-decouple | Pydantic |
|:----------------|:---------|
| `cast=bool` | `field: bool` |
| `cast=int` | `field: int` |
| `cast=float` | `field: float` |
| `cast=Csv()` | `field: list[str]` |
| `cast=Choices(...)` | `field: Literal["a", "b"]` |

### List Parsing

Pydantic parses comma-separated values automatically:

```bash
# .env
ALLOWED_HOSTS=localhost,example.com
```

```python
class Settings(BaseSettings):
    ALLOWED_HOSTS: list[str]  # Parses to ["localhost", "example.com"]
```

## From django-environ

django-environ is popular in Django projects.

### Before

```python
# settings.py
import environ

env = environ.Env(
    DEBUG=(bool, False),
    ALLOWED_HOSTS=(list, []),
)

environ.Env.read_env(".env")

DEBUG = env("DEBUG")
SECRET_KEY = env("SECRET_KEY")
DATABASES = {"default": env.db()}
ALLOWED_HOSTS = env("ALLOWED_HOSTS")
```

### After

```python
# config.py
from pydantic import Field, PostgresDsn
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    DEBUG: bool = False
    SECRET_KEY: str = Field(json_schema_extra={"sensitive": True})
    DATABASE_URL: PostgresDsn = Field(json_schema_extra={"sensitive": True})
    ALLOWED_HOSTS: list[str] = []

settings = Settings()
```

```python
# settings.py (Django)
from config import settings

DEBUG = settings.DEBUG
SECRET_KEY = settings.SECRET_KEY
ALLOWED_HOSTS = settings.ALLOWED_HOSTS

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": settings.DATABASE_URL.path[1:],  # Remove leading /
        "USER": settings.DATABASE_URL.username,
        "PASSWORD": settings.DATABASE_URL.password,
        "HOST": settings.DATABASE_URL.host,
        "PORT": settings.DATABASE_URL.port or 5432,
    }
}
```

### Using dj-database-url

If you prefer the simpler approach:

```python
import dj_database_url
from config import settings

DATABASES = {
    "default": dj_database_url.parse(str(settings.DATABASE_URL))
}
```

## From direnv

direnv is complementary to envdrift—use both!

direnv loads `.env` files into your shell. envdrift validates and manages them.

### Workflow

1. Use direnv for local development (auto-loads .env)
2. Use envdrift for validation and encryption

```bash
# .envrc (direnv)
dotenv .env
```

```bash
# Validate before committing
envdrift validate .env --schema config:Settings
envdrift encrypt .env
```

### CI/CD

In CI, you don't need direnv. Use envdrift directly:

```yaml
- run: |
    envdrift decrypt .env.production
    source .env.production  # Or use your app's .env loader
```

## From dotenv-vault

dotenv-vault is similar to envdrift's encryption features.

### Key Differences

| dotenv-vault | envdrift |
|:-------------|:---------|
| Hosted vault | BYO vault (Azure, AWS, etc.) |
| No schema validation | Pydantic schema validation |
| Single encryption backend | dotenvx + SOPS |
| Dedicated CLI | Part of broader toolset |

### Migration

1. Decrypt your dotenv-vault files
2. Re-encrypt with envdrift: `envdrift encrypt .env.production`
3. Push keys to your vault: `envdrift vault-push`

## General Migration Checklist

- [ ] Generate or create a Pydantic schema
- [ ] Run `envdrift validate` on all .env files
- [ ] Set up encryption with `envdrift encrypt`
- [ ] Configure vault sync for team access
- [ ] Add validation to CI/CD pipeline
- [ ] Add pre-commit hooks
- [ ] Update documentation for team

## Tips

### Gradual Migration

Start with validation only, add encryption later:

```bash
# Phase 1: Validation
envdrift validate .env --schema config:Settings

# Phase 2: Encryption (later)
envdrift encrypt .env.production
envdrift vault-push . my-key
```

### Keep Existing Loaders

You can use envdrift for validation while keeping your existing env loader:

```python
# Still works
from dotenv import load_dotenv
load_dotenv()

# But now validated at build time
# envdrift validate .env --schema config:Settings --ci
```

### Test in Development First

Before enforcing in CI:

1. Run validation locally: `envdrift validate .env --schema config:Settings`
2. Fix any issues
3. Add `--ci` flag in pipeline

## See Also

- [Quick Start](../getting-started/quickstart.md) — Getting started guide
- [Schema Best Practices](schema.md) — Schema design patterns
- [CI/CD Integration](cicd.md) — Pipeline setup
