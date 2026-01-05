# Encryption with dotenvx and SOPS

envdrift supports encrypted `.env` files with [dotenvx](https://dotenvx.com/) (default)
and [SOPS](https://github.com/getsops/sops).

Supported backends:

- **dotenvx**: Simple CLI-managed encryption with `.env.keys`
- **SOPS**: KMS/age/PGP-backed encryption with `.sops.yaml` policies

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

If `encryption.dotenvx.auto_install` is enabled, envdrift installs dotenvx and encrypts the file.

For SOPS:

```bash
envdrift encrypt .env.production --backend sops --age age1example
```

### Decrypt for Development

```bash
envdrift decrypt .env.production
```

For SOPS, ensure your key source is available (for example, set
`SOPS_AGE_KEY_FILE=keys.txt`) and run:

```bash
envdrift decrypt .env.production --backend sops
```

## How dotenvx Works

1. **dotenvx binary** - envdrift can auto-install the dotenvx binary to `.venv/bin/` when enabled
2. **Encryption** - Uses AES-256-GCM encryption
3. **Key management** - Keys stored in `.env.keys` (never commit this!)

## Dotenvx File Structure

After encryption:

```text
.env.production          # Encrypted (safe to commit)
.env.keys                 # Private keys (NEVER commit!)
```

Your `.gitignore` should include:

```gitignore
.env.keys
```

## Dotenvx Encrypted File Format

```bash
#/---BEGIN DOTENV ENCRYPTED---/
DOTENV_PUBLIC_KEY_PRODUCTION="03abc123..."
DATABASE_URL="encrypted:BDQE1234567890abcdef..."
API_KEY="encrypted:BDQEsecretkey123456..."
DEBUG=false
#/---END DOTENV ENCRYPTED---/
```

Note: Non-sensitive values like `DEBUG` remain plaintext.

## SOPS Encrypted File Format

SOPS encrypts values in place while keeping keys readable:

```bash
DATABASE_URL="ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]"
API_KEY="ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]"
```

SOPS relies on your chosen key management system (age, KMS, PGP, etc.) and a
`.sops.yaml` configuration in the repo.

## SOPS Configuration

Use envdrift config to set SOPS defaults. Auto-install is opt-in; set
`auto_install = true` if you want envdrift to download the binary for you:

```toml
[encryption]
backend = "sops"

[encryption.sops]
auto_install = false
config_file = ".sops.yaml"
age_key_file = "keys.txt"
age_recipients = "age1example"
# kms_arn = "arn:aws:kms:..."
# gcp_kms = "projects/.../locations/.../keyRings/.../cryptoKeys/..."
# azure_kv = "https://myvault.vault.azure.net/keys/my-key"
```

When decrypting locally, set your age private key:

```bash
export SOPS_AGE_KEY_FILE=keys.txt
envdrift decrypt .env.production --backend sops
```

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

## Dotenvx Key Management

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

SOPS does not use `.env.keys`; key management lives in your SOPS setup
(age key files, KMS, or PGP) and the `.sops.yaml` policy.

## Troubleshooting

### Windows: ".env.local" Encryption Fails

There is a known bug in dotenvx on Windows where files named exactly `.env.local`
cause the error:

```text
Input string must contain hex characters in even length
```

**Workaround**: Rename your file to a different suffix:

```powershell
# Instead of .env.local, use:
.env.localenv
.env.dev
.env.development
```

Then update your `envdrift.toml` mapping:

```toml
[[vault.sync.mappings]]
secret_name = "my-service-dev"
folder_path = "my-service"
environment = "localenv"  # matches .env.localenv
```

!!! note
    envdrift will detect this issue and show a helpful error message with
    workaround suggestions when you try to encrypt `.env.local` on Windows.

### Cross-Platform Line Endings

envdrift automatically normalizes line endings (CRLF → LF) before encryption
to ensure files encrypted on Windows can be decrypted on Linux/macOS and vice versa.

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

### "sops not found"

Install SOPS and retry:

```bash
brew install sops
```

### "SOPS decryption failed"

1. Confirm `SOPS_AGE_KEY_FILE` (or `SOPS_AGE_KEY`) is set for age
2. Verify access to your KMS/PGP keys
3. Ensure `.sops.yaml` rules match the file you're decrypting
