# CLI Reference

## Commands Overview

```text
Usage: envdrift [OPTIONS] COMMAND [ARGS]...

Commands:
  validate   Validate an .env file against a Pydantic schema
  diff       Compare two .env files and show differences
  encrypt    Check or perform encryption on .env file using dotenvx
  decrypt    Decrypt an encrypted .env file using dotenvx
  init       Generate a Pydantic Settings class from an existing .env file
  hook       Manage pre-commit hook integration
  version    Show envdrift version
```

---

## validate

Validate an .env file against a Pydantic schema.

```bash
envdrift validate [ENV_FILE] --schema SCHEMA [OPTIONS]
```

### Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `ENV_FILE` | Path to .env file to validate | `.env` |

### Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--schema` | `-s` | Dotted path to Settings class (required) | - |
| `--service-dir` | `-d` | Directory to add to sys.path for imports | - |
| `--ci` | - | CI mode: exit with code 1 on failure | `false` |
| `--check-encryption` | - | Check if sensitive vars are encrypted | `true` |
| `--no-check-encryption` | - | Skip encryption check | - |
| `--fix` | - | Output template for missing variables | `false` |
| `--verbose` | `-v` | Show additional details | `false` |

### Examples

```bash
# Basic validation
envdrift validate .env --schema myapp.config:Settings

# Validate production env with verbose output
envdrift validate .env.production --schema myapp.config:ProductionSettings -v

# CI mode (fails pipeline on validation error)
envdrift validate .env --schema myapp.config:Settings --ci

# Generate fix template for missing vars
envdrift validate .env --schema myapp.config:Settings --fix
```

---

## diff

Compare two .env files and show differences.

```bash
envdrift diff ENV1 ENV2 [OPTIONS]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `ENV1` | Path to first .env file |
| `ENV2` | Path to second .env file |

### Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--schema` | `-s` | Schema for sensitive field detection | - |
| `--format` | - | Output format: `table` or `json` | `table` |
| `--show-values` | - | Show actual values (careful with secrets!) | `false` |
| `--include-unchanged` | - | Include unchanged variables in output | `false` |

### Examples

```bash
# Compare dev and prod
envdrift diff .env.development .env.production

# Output as JSON
envdrift diff .env.dev .env.prod --format json

# Show values (use with caution)
envdrift diff .env.dev .env.prod --show-values

# Include unchanged vars
envdrift diff .env.dev .env.prod --include-unchanged
```

---

## encrypt

Check or perform encryption on .env file using dotenvx.

```bash
envdrift encrypt [ENV_FILE] [OPTIONS]
```

### Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `ENV_FILE` | Path to .env file | `.env` |

### Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--check` | - | Only check encryption status, don't encrypt | `false` |
| `--schema` | `-s` | Schema for sensitive field detection | - |

### Examples

```bash
# Check encryption status
envdrift encrypt .env.production --check

# Check with schema for better detection
envdrift encrypt .env.production --check --schema myapp.config:Settings

# Encrypt the file (downloads dotenvx if needed)
envdrift encrypt .env.production
```

---

## decrypt

Decrypt an encrypted .env file using dotenvx.

```bash
envdrift decrypt [ENV_FILE]
```

### Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `ENV_FILE` | Path to encrypted .env file | `.env` |

### Examples

```bash
envdrift decrypt .env.production
```

---

## init

Generate a Pydantic Settings class from an existing .env file.

```bash
envdrift init [ENV_FILE] [OPTIONS]
```

### Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `ENV_FILE` | Path to .env file to read | `.env` |

### Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--output` | `-o` | Output file for Settings class | `settings.py` |
| `--class-name` | `-c` | Name for the Settings class | `Settings` |
| `--detect-sensitive` | - | Auto-detect sensitive variables | `true` |

### Examples

```bash
# Generate from .env
envdrift init .env --output config/settings.py

# Custom class name
envdrift init .env --output settings.py --class-name AppConfig

# Without sensitive detection
envdrift init .env --no-detect-sensitive
```

---

## hook

Manage pre-commit hook integration.

```bash
envdrift hook [OPTIONS]
```

### Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--install` | `-i` | Install pre-commit hooks | `false` |
| `--config` | - | Show pre-commit config snippet | `false` |

### Examples

```bash
# Show pre-commit configuration
envdrift hook

# Show just the config snippet
envdrift hook --config

# Install hooks (requires pyyaml)
envdrift hook --install
```

---

## version

Show envdrift version.

```bash
envdrift version
```
