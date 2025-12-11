# CLI Reference

For detailed CLI documentation, see the [CLI Reference](../cli/index.md).

## Quick Reference

| Command                        | Description                                  |
| :----------------------------- | :------------------------------------------- |
| [validate](../cli/validate.md) | Validate .env files against Pydantic schemas |
| [diff](../cli/diff.md)         | Compare two .env files and show differences  |
| [encrypt](../cli/encrypt.md)   | Check or perform encryption using dotenvx    |
| [decrypt](../cli/decrypt.md)   | Decrypt encrypted .env files                 |
| [init](../cli/init.md)         | Generate Pydantic Settings from .env files   |
| [hook](../cli/hook.md)         | Manage pre-commit hook integration           |
| [version](../cli/version.md)   | Show envdrift version                        |

## Common Examples

```bash
# Validate production env against schema
envdrift validate .env.production --schema config.settings:ProductionSettings --ci

# Compare environments
envdrift diff .env.development .env.production

# Check encryption status
envdrift encrypt .env.production --check --schema config.settings:ProductionSettings

# Generate schema from existing .env
envdrift init .env --output config/settings.py

# Show pre-commit hook config
envdrift hook --config
```
