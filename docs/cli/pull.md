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

[[vault.sync.mappings]]
secret_name = "myapp-key"
folder_path = "services/myapp"
environment = "production"

[[vault.sync.mappings]]
secret_name = "auth-key"
folder_path = "services/auth"
environment = "staging"
```

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
