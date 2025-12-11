# envdrift encrypt

Check or perform encryption on .env files using dotenvx.

## Synopsis

```bash
envdrift encrypt [ENV_FILE] [OPTIONS]
```

## Description

The `encrypt` command works with [dotenvx](https://dotenvx.com/) to manage encryption of .env files. It can:

- **Check encryption status** - Report which variables are encrypted/plaintext
- **Detect plaintext secrets** - Identify sensitive values that should be encrypted
- **Perform encryption** - Encrypt the file using dotenvx (downloads automatically)

## Arguments

| Argument   | Description           | Default |
| :--------- | :-------------------- | :------ |
| `ENV_FILE` | Path to the .env file | `.env`  |

## Options

### `--check`

Only check encryption status without modifying the file. Exits with code 1 if plaintext secrets are detected.

```bash
envdrift encrypt .env.production --check
```

### `--schema`, `-s`

Schema for better sensitive field detection. Fields marked with `json_schema_extra={"sensitive": True}` are checked.

```bash
envdrift encrypt .env.production --check --schema config.settings:ProductionSettings
```

### `--service-dir`, `-d`

Directory to add to Python's `sys.path` for schema imports.

```bash
envdrift encrypt .env.production --check -s config.settings:Settings -d /app/backend
```

## Examples

### Check Encryption Status

```bash
envdrift encrypt .env.production --check
```

Output:

```text
╭─────────────────── envdrift encrypt --check ───────────────────╮
│ Encryption Status: .env.production                             │
╰────────────────────────────────────────────────────────────────╯

File is partially encrypted

Variables:
  Encrypted:  3
  Plaintext:  5
  Empty:      0
  Encryption ratio: 37%

PLAINTEXT SECRETS DETECTED:
  * API_KEY_BACKEND
  * JWT_SECRET

WARNINGS:
  * DATABASE_URL contains credentials but is not encrypted

Recommendation:
  Run: dotenvx encrypt -f <env_file>
```

### Check with Schema

```bash
envdrift encrypt .env.production --check --schema config.settings:ProductionSettings
```

With a schema, envdrift knows exactly which fields are sensitive:

```python
class ProductionSettings(BaseSettings):
    DATABASE_URL: str = Field(json_schema_extra={"sensitive": True})
    API_KEY: str = Field(json_schema_extra={"sensitive": True})
    DEBUG: bool = False  # Not sensitive
```

### Encrypt a File

```bash
envdrift encrypt .env.production
```

This will:

1. Download dotenvx if not installed
2. Encrypt the file using AES-256-GCM
3. Create `.env.keys` with the private key (never commit this!)

### CI/CD Encryption Check

```yaml
# GitHub Actions
- name: Check secrets are encrypted
  run: |
    envdrift encrypt .env.production --check \
      --schema config.settings:ProductionSettings
```

The command exits with code 1 if plaintext secrets are detected, failing the pipeline.

## Encryption Report

The `--check` option provides a detailed report:

| Section           | Description                                            |
| :---------------- | :----------------------------------------------------- |
| Overall Status    | Fully encrypted, partially encrypted, or not encrypted |
| Variables         | Count of encrypted, plaintext, and empty variables     |
| Encryption Ratio  | Percentage of variables that are encrypted             |
| Plaintext Secrets | Variables detected as secrets but not encrypted        |
| Warnings          | Additional concerns (e.g., credentials in URLs)        |

## How Encryption Works

envdrift integrates with [dotenvx](https://dotenvx.com/) for encryption:

1. **Encrypted format**: Values prefixed with `encrypted:` are AES-256-GCM encrypted
2. **Key storage**: Private keys stored in `.env.keys` (add to `.gitignore`)
3. **Safe to commit**: Encrypted `.env` files can be committed to git

Example encrypted file:

```bash
#/---BEGIN DOTENV ENCRYPTED---/
DOTENV_PUBLIC_KEY_PRODUCTION="03abc123..."
DATABASE_URL="encrypted:BDQE1234567890abcdef..."
API_KEY="encrypted:BDQEsecretkey123456..."
DEBUG=false
#/---END DOTENV ENCRYPTED---/
```

## Sensitive Detection

envdrift detects sensitive values using:

### Schema-based Detection

Fields with `json_schema_extra={"sensitive": True}`:

```python
API_KEY: str = Field(json_schema_extra={"sensitive": True})
```

### Name-based Detection

Variable names matching patterns:

- `*_KEY`, `*_SECRET`, `*_TOKEN`
- `*_PASSWORD`, `*_PASS`
- `*_CREDENTIAL*`, `*_API_KEY`
- `JWT_*`, `AUTH_*`, `*_DSN`

### Value-based Detection

Values matching patterns:

- API keys: `sk-*`, `pk-*`, `ghp_*`, `gho_*`, `xox*-*`
- AWS keys: `AKIA*`
- Database URLs with credentials: `postgres://user:pass@...`
- JWT tokens: `eyJ*`

## Exit Codes

| Code | Meaning                                                          |
| :--- | :--------------------------------------------------------------- |
| 0    | No plaintext secrets detected (or encryption successful)         |
| 1    | Plaintext secrets detected (with `--check`) or encryption failed |

## See Also

- [decrypt](decrypt.md) - Decrypt encrypted files
- [validate](validate.md) - Validate with encryption warnings
