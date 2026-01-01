# envdrift pull

Pull keys from vault and decrypt all env files (one-command developer setup).

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

Vault provider to use. Options: `azure`, `aws`, `hashicorp`.

Usually read from TOML config; use this to override.

### `--vault-url`

Vault URL. Required for Azure and HashiCorp providers.

Usually read from TOML config; use this to override.

### `--region`

AWS region for Secrets Manager. Default: `us-east-1`.

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

Processing: services/myapp
Processing: services/auth
  + services/myapp - created
  = services/auth - skipped

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
- **`profile`**: Tags a mapping for filtering with `--profile`

When `environment` is not set, it defaults from:

1. The explicit `environment` field (if set)
2. The `profile` field (if set)
3. `"production"` (default)

## Exit Codes

| Code | Meaning                                    |
| :--- | :----------------------------------------- |
| 0    | Success (all synced and decrypted)         |
| 1    | Error (sync failure or decryption failure) |

## Prerequisites

- Cloud vault credentials configured (Azure CLI, AWS credentials, etc.)
- `dotenvx` installed for decryption

## See Also

- [sync](sync.md) - Sync keys only (without decryption)
- [decrypt](decrypt.md) - Decrypt a single .env file
- [vault-push](vault-push.md) - Push keys to vault (opposite of pull)
- [Vault Sync Guide](../guides/vault-sync.md) - Detailed setup guide
