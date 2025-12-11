# envdrift init

Generate a Pydantic Settings class from an existing .env file.

## Synopsis

```bash
envdrift init [ENV_FILE] [OPTIONS]
```

## Description

The `init` command bootstraps your schema by generating a Pydantic Settings class from an existing .env file. It:

- **Infers types** - Detects booleans, integers, and strings
- **Detects sensitive fields** - Marks likely secrets with `sensitive=True`
- **Creates required fields** - String values become required (no default)
- **Adds defaults** - Boolean and integer values get defaults

This is useful when:

- Starting with an existing project that has .env files
- Migrating from dotenv to pydantic-settings
- Creating a baseline schema to customize

## Arguments

| Argument   | Description                   | Default |
| :--------- | :---------------------------- | :------ |
| `ENV_FILE` | Path to the .env file to read | `.env`  |

## Options

### `--output`, `-o`

Output file path for the generated Settings class.

```bash
envdrift init .env --output config/settings.py
envdrift init .env -o settings.py
```

### `--class-name`, `-c`

Name for the generated Settings class.

```bash
envdrift init .env --class-name AppConfig
envdrift init .env -c ProductionSettings
```

### `--detect-sensitive` / `--no-detect-sensitive`

Control automatic detection of sensitive variables.

```bash
# Enable detection (default)
envdrift init .env --detect-sensitive

# Disable detection
envdrift init .env --no-detect-sensitive
```

## Examples

### Basic Generation

```bash
envdrift init .env
```

Input `.env`:

```bash
DATABASE_URL=postgres://localhost/mydb
API_KEY=sk-123456
DEBUG=true
PORT=8000
LOG_LEVEL=INFO
```

Generated `settings.py`:

```python
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
    DEBUG: bool = True
    LOG_LEVEL: str
    PORT: int = 8000
```

### Custom Output Path

```bash
envdrift init .env.production --output config/production.py
```

### Custom Class Name

```bash
envdrift init .env --output settings.py --class-name AppSettings
```

### Without Sensitive Detection

```bash
envdrift init .env --no-detect-sensitive
```

All fields will be generated without `sensitive=True`, even if they look like secrets.

## Type Inference

| .env Value                  | Inferred Type | Has Default   |
| :-------------------------- | :------------ | :------------ |
| `true`, `false`             | `bool`        | Yes           |
| `123`, `8000`               | `int`         | Yes           |
| `hello`, `postgres://...`   | `str`         | No (required) |

## Sensitive Detection

Variables are marked sensitive if their **name** matches:

- `*_KEY`, `*_SECRET`, `*_TOKEN`
- `*_PASSWORD`, `*_PASS`
- `*_CREDENTIAL*`, `*_API_KEY`
- `JWT_*`, `AUTH_*`, `*_DSN`

Or if their **value** matches patterns:

- API keys: `sk-*`, `pk-*`
- AWS keys: `AKIA*`
- Database URLs with credentials
- JWT tokens

## Generated Schema Features

The generated schema includes:

```python
model_config = SettingsConfigDict(
    env_file=".env",      # Reads from .env by default
    extra="forbid",       # Rejects unknown variables
)
```

This provides strict validation out of the box.

## Customization

After generating, you should customize:

1. **Add descriptions**:

   ```python
   DATABASE_URL: str = Field(
       description="PostgreSQL connection string",
       json_schema_extra={"sensitive": True}
   )
   ```

2. **Add validators**:

   ```python
   @field_validator("PORT")
   @classmethod
   def validate_port(cls, v: int) -> int:
       if not 1 <= v <= 65535:
           raise ValueError("Invalid port number")
       return v
   ```

3. **Split by environment**:

   ```python
   class BaseSettings(BaseSettings):
       DATABASE_URL: str = Field(json_schema_extra={"sensitive": True})

   class DevelopmentSettings(BaseSettings):
       DEBUG: bool = True

   class ProductionSettings(BaseSettings):
       DEBUG: bool = False
   ```

## Workflow

1. **Generate initial schema**:

   ```bash
   envdrift init .env --output config/settings.py
   ```

2. **Review and customize**:
   - Add descriptions
   - Adjust types if needed
   - Add validators
   - Mark additional sensitive fields

3. **Validate**:

   ```bash
   envdrift validate .env --schema config.settings:Settings
   ```

4. **Set up pre-commit**:

   ```bash
   envdrift hook --config
   ```

## See Also

- [validate](validate.md) - Validate against schema
- [hook](hook.md) - Set up pre-commit hooks
