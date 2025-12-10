# Encryption with dotenvx

envdrift integrates with [dotenvx](https://dotenvx.com/) for encrypted `.env` files.

## Why Encrypt?

- **Commit secrets safely** - Encrypted `.env` files can be committed to git
- **No more secret sharing** - Team members decrypt locally with their keys
- **Audit trail** - Git history shows who changed what

## Quick Start

### Check Encryption Status

```bash
envdrift encrypt .env.production --check
```

Output:

```text
Encryption Report for .env.production

ENCRYPTED VARIABLES:
  - DATABASE_URL
  - API_KEY
  - JWT_SECRET

PLAINTEXT VARIABLES:
  - DEBUG
  - LOG_LEVEL
  - PORT

PLAINTEXT SECRETS DETECTED:
  - AWS_ACCESS_KEY_ID (looks like a secret but not encrypted)

Encryption ratio: 50% (3/6 variables encrypted)
```

### Encrypt a File

```bash
envdrift encrypt .env.production
```

This downloads dotenvx (if needed) and encrypts the file.

### Decrypt for Development

```bash
envdrift decrypt .env.production
```

## How It Works

1. **dotenvx binary** - envdrift downloads the dotenvx binary to `.venv/bin/` on first use
2. **Encryption** - Uses AES-256-GCM encryption
3. **Key management** - Keys stored in `.env.keys` (never commit this!)

## File Structure

After encryption:

```text
.env.production          # Encrypted (safe to commit)
.env.keys                 # Private keys (NEVER commit!)
```

Your `.gitignore` should include:

```gitignore
.env.keys
```

## Encrypted File Format

```bash
#/---BEGIN DOTENV ENCRYPTED---/
DOTENV_PUBLIC_KEY_PRODUCTION="03abc123..."
DATABASE_URL="encrypted:BDQE1234567890abcdef..."
API_KEY="encrypted:BDQEsecretkey123456..."
DEBUG=false
#/---END DOTENV ENCRYPTED---/
```

Note: Non-sensitive values like `DEBUG` remain plaintext.

## Schema Integration

Mark sensitive fields in your schema for better detection:

```python
from pydantic import Field
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    DATABASE_URL: str = Field(json_schema_extra={"sensitive": True})
    API_KEY: str = Field(json_schema_extra={"sensitive": True})
    DEBUG: bool = False  # Not sensitive
```

Then check:

```bash
envdrift encrypt .env.production --check --schema config.settings:Settings
```

## Pre-commit Hook

Block unencrypted secrets from being committed:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: envdrift-encryption
        name: Check env encryption
        entry: envdrift encrypt --check
        language: system
        files: ^\.env\.(production|staging)$
        pass_filenames: true
```

## Key Management

### Development

Store keys locally in `.env.keys`:

```bash
# .env.keys
DOTENV_PRIVATE_KEY_PRODUCTION="abc123..."
```

### CI/CD

Pass the key as an environment variable:

```yaml
# GitHub Actions
env:
  DOTENV_PRIVATE_KEY_PRODUCTION: ${{ secrets.DOTENV_PRIVATE_KEY_PRODUCTION }}
```

### Production

Use a secrets manager (Azure Key Vault, AWS Secrets Manager, etc.) to store the private key:

```python
from envdrift.vault import AzureKeyVault

vault = AzureKeyVault(vault_url="https://myvault.vault.azure.net")
key = vault.get_secret("dotenv-private-key-production")

# Set as environment variable before running app
os.environ["DOTENV_PRIVATE_KEY_PRODUCTION"] = key.value
```

## Troubleshooting

### "dotenvx not found"

The binary is downloaded automatically, but if it fails:

```bash
# Check if binary exists
ls .venv/bin/dotenvx

# Manual download
envdrift encrypt .env --check  # Triggers download
```

### "Decryption failed"

1. Check `.env.keys` exists
2. Verify the key matches the encrypted file
3. Check `DOTENV_PRIVATE_KEY_*` environment variable is set
