# Schema Best Practices

How to structure your Pydantic Settings for maximum drift protection.

## Mark Sensitive Fields

Use `json_schema_extra={"sensitive": True}` to mark fields that should be encrypted:

```python
from pydantic import Field
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # Sensitive - envdrift will check encryption
    DATABASE_URL: str = Field(json_schema_extra={"sensitive": True})
    API_KEY: str = Field(json_schema_extra={"sensitive": True})
    JWT_SECRET: str = Field(json_schema_extra={"sensitive": True})

    # Not sensitive - plaintext is OK
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"
```

## Use extra="forbid" in Production

Strict mode catches typos and forgotten variables:

```python
from pydantic_settings import BaseSettings, SettingsConfigDict

class ProductionSettings(BaseSettings):
    model_config = SettingsConfigDict(
        extra="forbid",  # Reject unknown variables
    )
```

This catches errors like:

```bash
$ envdrift validate .env.prod --schema config:ProductionSettings
ERROR: Extra variables not in schema: DATABSE_URL  # Typo caught!
```

## Split Settings by Environment

Create a base class and environment-specific overrides:

```python
# config/base.py
from pydantic import Field
from pydantic_settings import BaseSettings

class BaseAppSettings(BaseSettings):
    """Shared settings across all environments."""
    DATABASE_URL: str = Field(json_schema_extra={"sensitive": True})
    REDIS_URL: str = Field(json_schema_extra={"sensitive": True})
    API_KEY: str = Field(json_schema_extra={"sensitive": True})

    LOG_LEVEL: str = "INFO"
    DEBUG: bool = False
```

```python
# config/production.py
from pydantic_settings import SettingsConfigDict
from .base import BaseAppSettings

class ProductionSettings(BaseAppSettings):
    """Production settings - strict mode."""
    model_config = SettingsConfigDict(
        env_file=".env.production",
        extra="forbid",  # No unknown vars allowed
    )

    DEBUG: bool = False  # Always false in prod
    LOG_LEVEL: str = "WARNING"
```

```python
# config/development.py
from pydantic_settings import SettingsConfigDict
from .base import BaseAppSettings

class DevelopmentSettings(BaseAppSettings):
    """Development settings - permissive mode."""
    model_config = SettingsConfigDict(
        env_file=".env.development",
        extra="ignore",  # Allow extra vars for experimentation
    )

    DEBUG: bool = True
    LOG_LEVEL: str = "DEBUG"
```

## Required vs Optional Fields

Fields without defaults are required:

```python
class Settings(BaseSettings):
    # Required - must be in .env
    DATABASE_URL: str
    API_KEY: str

    # Optional - have defaults
    DEBUG: bool = False
    PORT: int = 8000
    LOG_LEVEL: str = "INFO"
```

## Type Hints for Validation

envdrift validates types based on your hints:

```python
class Settings(BaseSettings):
    PORT: int = 8000        # Must be an integer
    DEBUG: bool = False     # Must be true/false
    WORKERS: int = 4        # Must be an integer
    TIMEOUT: float = 30.0   # Must be a number
```

If `.env` contains `PORT=not_a_number`, validation fails:

```text
TYPE ERRORS:
  - PORT: expected int, got 'not_a_number'
```

## Nested Settings

For complex configurations:

```python
from pydantic import BaseModel

class DatabaseConfig(BaseModel):
    host: str = "localhost"
    port: int = 5432
    name: str = "mydb"

class Settings(BaseSettings):
    database: DatabaseConfig = DatabaseConfig()

    @property
    def database_url(self) -> str:
        return f"postgres://{self.database.host}:{self.database.port}/{self.database.name}"
```

## Validation in Application

Load settings at startup to fail fast:

```python
# app.py
from config.settings import Settings

settings = Settings()  # Validates on instantiation

# If validation fails, app won't start
```

Combined with envdrift in CI:

```bash
# In CI pipeline
envdrift validate .env.production --schema config.settings:ProductionSettings --ci
```
