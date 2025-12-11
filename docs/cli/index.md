# CLI Reference

envdrift provides a command-line interface for validating environment files against Pydantic schemas, comparing environments, and managing encryption.

## Installation

```bash
pip install envdrift
# or with uv
uv add envdrift
```

## Commands

| Command                  | Description                                            |
| ------------------------ | ------------------------------------------------------ |
| [validate](validate.md)  | Validate .env files against Pydantic schemas           |
| [diff](diff.md)          | Compare two .env files and show differences            |
| [encrypt](encrypt.md)    | Check or perform encryption using dotenvx              |
| [decrypt](decrypt.md)    | Decrypt encrypted .env files                           |
| [init](init.md)          | Generate Pydantic Settings from .env files             |
| [hook](hook.md)          | Manage pre-commit hook integration                     |
| [version](version.md)    | Show envdrift version                                  |

## Global Options

All commands support these options:

```bash
--help                  Show help message and exit
--install-completion    Install shell completion
--show-completion       Show completion script
```

## Quick Examples

```bash
# Validate production env against schema
envdrift validate .env.production --schema config.settings:ProductionSettings

# Compare dev vs prod environments
envdrift diff .env.development .env.production

# Check if secrets are encrypted
envdrift encrypt .env.production --check

# Generate schema from existing .env
envdrift init .env --output settings.py
```

## Exit Codes

| Code | Meaning                                                       |
| ---- | ------------------------------------------------------------- |
| 0    | Success                                                       |
| 1    | Validation failed, file not found, or other error             |

## Environment Variables

| Variable                     | Description                                                                                                        |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `ENVDRIFT_SCHEMA_EXTRACTION` | Set by envdrift during schema loading. Check this in your settings module to skip instantiation during validation. |

## Schema Path Format

The `--schema` option uses Python's dotted import path format:

```text
module.submodule:ClassName
```

Examples:

- `config.settings:Settings`
- `myapp.config:ProductionSettings`
- `src.config.settings:AppConfig`
