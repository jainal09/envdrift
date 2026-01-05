# How It Works

This page explains the mental model behind envdrift and how its components work together.

## The Three Pillars

### 1. Schema Validation

At the core of envdrift is schema-based validation using Pydantic:

```python
from pydantic import Field
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # Required (no default = must exist in .env)
    DATABASE_URL: str = Field(json_schema_extra={"sensitive": True})

    # Optional (has default)
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"
```

When you run `envdrift validate`, it:

1. Loads your Pydantic Settings class
2. Parses the `.env` file
3. Checks for missing required fields
4. Validates types (string to int/bool conversion)
5. Optionally checks for extra undefined variables
6. Reports encryption status for sensitive fields

### 2. Encryption

envdrift supports encrypting `.env` files so secrets aren't stored in plaintext:

```text
Before encryption:
DATABASE_URL=postgres://user:password@host/db

After encryption (dotenvx):
DATABASE_URL="encrypted:BDJ7N2Z..."
```

Two backends are supported:

- **dotenvx** — Simple, file-based encryption with `.env.keys`
- **SOPS** — Enterprise-grade encryption with KMS integration

See [Encryption Backends](encryption-backends.md) for a detailed comparison.

### 3. Vault Sync

For team workflows, encryption keys need to be shared. envdrift integrates with cloud vaults (see [Vault Providers](vault-providers.md)):

```text
Developer A                    Cloud Vault                    Developer B
    │                              │                              │
    │  envdrift vault-push ──────► │                              │
    │                              │ ◄────── envdrift sync        │
    │                              │                              │
    │  (has .env.keys)             │  (stores keys)     (gets .env.keys)
```

## Workflow: Development Cycle

### Solo Developer

```bash
# 1. Define schema
vim config.py

# 2. Create .env
vim .env

# 3. Validate
envdrift validate .env --schema config:Settings

# 4. Encrypt before commit
envdrift encrypt .env

# 5. Commit encrypted file
git add .env && git commit
```

### Team Workflow

```bash
# === New team member onboarding ===
git clone repo
envdrift pull  # Syncs keys from vault + decrypts

# === Daily development ===
envdrift pull          # Start of day: get keys, decrypt
vim .env               # Make changes
envdrift lock          # End of day: encrypt before commit

# === CI/CD ===
envdrift validate .env.production --schema config:Settings --ci
```

## The pull/lock Cycle

The `pull` and `lock` commands form a complete workflow:

```text
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│    ┌──────────┐                           ┌──────────┐          │
│    │          │                           │          │          │
│    │  Vault   │ ◄───── envdrift sync ──── │  Local   │          │
│    │  (keys)  │                           │ .env.keys│          │
│    │          │ ────── envdrift push ───► │          │          │
│    └──────────┘                           └──────────┘          │
│                                                 │               │
│                                                 │               │
│    ┌──────────┐                           ┌──────────┐          │
│    │          │                           │          │          │
│    │  .env    │ ◄──── envdrift pull ───── │ Encrypted│          │
│    │(decrypted│                           │   .env   │          │
│    │  local)  │ ───── envdrift lock ────► │  (repo)  │          │
│    └──────────┘                           └──────────┘          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

| Command | Direction | Purpose |
|:--------|:----------|:--------|
| `pull` | Vault → Local | Sync keys, decrypt files for development |
| `lock` | Local → Repo | Verify keys, encrypt files for commit |
| `sync` | Vault → Local | Sync keys only (no decrypt) |
| `vault-push` | Local → Vault | Push new keys to vault |

## Encryption Detection

envdrift automatically detects which encryption backend was used:

| Backend | Detection Method |
|:--------|:-----------------|
| dotenvx | `DOTENV_PUBLIC_KEY` variable or values prefixed with `encrypted:` |
| SOPS | `ENC[AES256_GCM,...]` value format |

## Sensitive Field Detection

Fields are marked as sensitive if:

1. **Explicit annotation** — `Field(json_schema_extra={"sensitive": True})`
2. **Name pattern** — Contains `password`, `secret`, `key`, `token`, `credential`
3. **Value pattern** — Looks like an API key (`sk_`, `ghp_`, etc.)

## Configuration Discovery

envdrift looks for configuration in this order:

1. Explicit `--config` flag
2. `envdrift.toml` in current directory
3. `envdrift.toml` in parent directories
4. `pyproject.toml` with `[tool.envdrift]` section

## Exit Codes

All commands follow consistent exit code conventions:

| Code | Meaning |
|:-----|:--------|
| 0 | Success |
| 1 | Validation failure, encryption error, or configuration issue |
| 2 | Missing required arguments or invalid options |

For CI/CD pipelines, use the `--ci` flag to ensure proper exit codes on validation failures.
