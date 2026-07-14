# envdrift pull

Pull keys from vault and decrypt all env files (one-command developer setup).

The **key-sync** part of this workflow is dotenvx-only. The decrypt step uses your
configured backend, so `pull --skip-sync` *can* decrypt SOPS files when a
`[vault.sync]` section is present — but the recommended SOPS path is plain
`envdrift decrypt`. See the [SOPS Backend Guide](../guides/sops.md#using-pull-and-lock-with-sops).

## Synopsis

```bash
envdrift pull [OPTIONS]
```

## Description

The `pull` command is the recommended way to onboard new developers. It combines two operations:

1. **Sync keys from vault** - Fetches `DOTENV_PRIVATE_KEY_*` secrets from cloud vaults and writes them to local `.env.keys` files
2. **Decrypt env files** - Decrypts all `.env.<environment>` files for each configured service

Just run `envdrift pull` and all encrypted environment files are ready to use.

Configuration is auto-discovered from:

- `pyproject.toml` with `[tool.envdrift.vault.sync]` section
- `envdrift.toml` with `[vault.sync]` section
- Explicit `--config` file

## Options

### `--config`, `-c`

Path to sync configuration file (TOML preferred; legacy `pair.txt` still supported).

```bash
# Auto-discover (recommended)
envdrift pull

# Explicit config
envdrift pull -c envdrift.toml
```

### `--provider`, `-p`

Vault provider to use. Options: `azure`, `aws`, `hashicorp`, `gcp`.

Usually read from TOML config; use this to override.

### `--vault-url`

Vault URL. Required for Azure and HashiCorp providers.

Usually read from TOML config; use this to override.

### `--region`

AWS region for Secrets Manager. Default: `us-east-1`.

### `--project-id`

GCP project ID for Secret Manager. Required for the `gcp` provider unless configured in TOML.

### `--force`, `-f`

Force update all key mismatches without prompting.

```bash
envdrift pull --force
```

### `--profile`

Filter mappings by profile and activate the specified environment.

Use this when you have multiple environment configurations (e.g., `local`, `prod`, `soak`) and want to set up a specific one.

```bash
# Pull only the 'local' profile
envdrift pull --profile local
```

When a profile is specified:

- Regular mappings (without a profile) are always processed
- Only the matching profile mapping is processed
- If `activate_to` is configured, the decrypted file is copied to that path

### `--skip-sync`

Skip syncing keys from vault, only decrypt files. Useful when keys are already local.

```bash
envdrift pull --skip-sync
```

### `--merge`, `-m`

For partial encryption setups: create a combined decrypted `.env` file from `.clear` + `.secret` files.

> **Note:** This flag only has effect when partial encryption is enabled in your config.
> Without partial encryption configuration, `--merge` behaves like a normal pull.

When this flag is used with partial encryption enabled, the command will:

1. Decrypt `.env.{env}.secret` files
2. Merge `.env.{env}.clear` + decrypted `.env.{env}.secret` → `.env.{env}`
3. Add the combined file to `.gitignore` (it contains decrypted secrets)

This creates a single usable `.env` file for local development.

> **Note:** The merged `.env.{env}` file contains decrypted secrets, so it is
> added to `.gitignore` (just like `envdrift push`) to keep a routine
> `git add .` from staging plaintext secrets. Commit only the `.clear` and
> `.secret` files, never the combined file. The merged file is written
> atomically with owner-only permissions (`0600` on POSIX, like `.env.keys`),
> never world-readable at the process umask.

```bash
# Decrypt and merge partial encryption files
envdrift pull --merge

# Combined with skip-sync when keys are already local
envdrift pull --skip-sync --merge
```

## Examples

### Basic Pull

```bash
# Auto-discover config and pull everything
envdrift pull
```

### With Explicit Config

```bash
envdrift pull -c envdrift.toml
```

### Override Provider Settings

```bash
envdrift pull -p azure --vault-url https://myvault.vault.azure.net/
```

### Force Update Without Prompts

```bash
envdrift pull --force
```

### Pull With Profile

```bash
# Set up local development environment
envdrift pull --profile local
```

## Output

The command shows progress in two steps:

### Step 1: Sync Keys

```text
Pull - Syncing keys and decrypting env files
Provider: azure | Services: 3

Step 1: Syncing keys from vault...

Processing: services/myapp (myapp-key, env: production)
Processing: services/auth (auth-key, env: production)
  + services/myapp (myapp-key, env: production) - created
  = services/auth (auth-key, env: production) - skipped

╭──────────── Sync Summary ────────────╮
│ Services processed: 2                │
│ Created: 1                           │
│ Updated: 0                           │
│ Skipped: 1                           │
│ Errors: 0                            │
╰──────────────────────────────────────╯
```

### Step 2: Decrypt Files

```text
Step 2: Decrypting environment files...

  + services/myapp/.env.production - decrypted
  = services/auth/.env.production - skipped (not encrypted)

╭──────────── Decrypt Summary ─────────╮
│ Decrypted: 1                         │
│ Skipped: 1                           │
│ Errors: 0                            │
╰──────────────────────────────────────╯

Setup complete! Your environment files are ready to use.
```

## Configuration File Format

Same as `envdrift sync`. See [sync documentation](sync.md#configuration-file-format) for details.

Example `envdrift.toml`:

```toml
[vault]
provider = "azure"

[vault.azure]
vault_url = "https://my-keyvault.vault.azure.net/"

[vault.sync]
default_vault_name = "my-keyvault"

# Regular mapping (always processed)
[[vault.sync.mappings]]
secret_name = "myapp-key"
folder_path = "services/myapp"
environment = "production"

[[vault.sync.mappings]]
secret_name = "postgres-key"
folder_path = "secrets/postgresql"
environment = "production"  # Key stays DOTENV_PRIVATE_KEY_PRODUCTION
env_file = "postgresql.env" # Decrypt secrets/postgresql/postgresql.env

# Profile mappings (processed only with --profile)
[[vault.sync.mappings]]
secret_name = "local-key"
folder_path = "."
profile = "local"              # Only process with --profile local
activate_to = ".env"           # Copy .env.local to .env after decryption

[[vault.sync.mappings]]
secret_name = "prod-key"
folder_path = "."
profile = "prod"
activate_to = ".env"
```

### Profile vs Environment

- **`environment`**: Specifies which `.env.<environment>` file to look for (e.g., `production` → `.env.production`)
- **`env_file`**: Overrides the file path when a service uses another dotenv-style filename (e.g., `postgresql.env`)
- **`profile`**: Tags a mapping for filtering with `--profile`

The effective environment is resolved in this priority order:

1. The explicit `environment` field (if set)
2. The `profile` field (if set)
3. `"production"` (default)

## Exit Codes

| Code | Meaning                                                                       |
| :--- | :----------------------------------------------------------------------------- |
| 0    | Success (all synced and decrypted)                                              |
| 1    | Error (sync failure or decryption failure)                                      |
| 1    | A mapping's `folder_path` does not exist (broken sync config, reported per row) |
| 1    | A mapped env file cannot be read (e.g. not valid UTF-8) — clean per-file error  |

## Prerequisites

- Cloud vault credentials configured (Azure CLI, AWS credentials, etc.)
- The decryption tool matching your configured backend installed: `dotenvx` (default)
  or SOPS — whichever your `[encryption]` backend is

## See Also

- [sync](sync.md) - Sync keys only (without decryption)
- [decrypt](decrypt.md) - Decrypt a single .env file
- [vault-pull](vault-pull.md) - Config-free single-secret pull + decrypt (no sync config required)
- [vault-push](vault-push.md) - Push keys to vault (opposite of pull)
- [Env File Sync Guide](../guides/env-file-sync.md) - Detailed setup guide
