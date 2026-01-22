# envdrift lock

Verify keys and encrypt all env files (opposite of pull - prepares for commit).

## Synopsis

```bash
envdrift lock [OPTIONS]
```

## Description

The `lock` command is the opposite of `pull`. While `pull` syncs keys and decrypts files for
development, `lock` verifies keys and encrypts files before committing.
This workflow is specific to dotenvx and does not apply to SOPS.

This command ensures your environment files are properly encrypted before committing. It can:

1. **Verify key consistency** - Check that local `.env.keys` match vault secrets (prevents key drift)
2. **Sync keys from vault** - Optionally fetch keys from vault to ensure consistency
3. **Encrypt env files** - Encrypt all decrypted `.env.<environment>` files using dotenvx

This is the recommended command before committing changes to ensure:

- Local encryption keys are in sync with the team's vault keys
- All .env files are properly encrypted
- No plaintext secrets are accidentally committed

Configuration is auto-discovered from:

- `pyproject.toml` with `[tool.envdrift.vault.sync]` section
- `envdrift.toml` with `[vault.sync]` section
- Explicit `--config` file

## Options

### `--config`, `-c`

Path to sync configuration file (TOML preferred; legacy `pair.txt` still supported).

```bash
# Auto-discover (recommended)
envdrift lock

# Explicit config
envdrift lock -c envdrift.toml
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

Force encryption without prompting.

```bash
envdrift lock --force
```

### `--profile`

Filter mappings by profile and process only the specified environment.

```bash
# Lock only the 'local' profile
envdrift lock --profile local
```

### `--verify-vault`

Verify that local `.env.keys` match vault secrets before encrypting.

This helps detect key drift where a developer may have re-encrypted with a new key that doesn't match the team's shared vault key.

```bash
envdrift lock --verify-vault
```

### `--sync-keys`

Sync keys from vault before encrypting. This implies `--verify-vault`.

Use this to ensure your local keys are up-to-date with vault before encrypting.

```bash
envdrift lock --sync-keys
```

### `--check`

Check encryption status only (dry run). Reports what would be encrypted without making changes.

```bash
envdrift lock --check
```

### `--all`

Include partial encryption files in the locking process. When set:

1. **No longer skips combined files** - Partial encryption combined files (e.g., `.env.production`) get encrypted like regular files
2. **Encrypts `.secret` files** - Ensures partial encryption secret files are also locked
3. **Deletes combined files** - Removes the merged combined files after locking

This is useful when you want to lock everything and clean up generated files before committing.

```bash
# Lock everything including partial encryption files
envdrift lock --all

# Force mode with partial encryption
envdrift lock -f --all

# Check what would happen
envdrift lock --check --all
```

## Smart Encryption

When `smart_encryption` is enabled in your configuration, the `lock` command will skip
re-encryption if the file content hasn't changed. This reduces unnecessary git noise
caused by non-deterministic encryption algorithms used by dotenvx and SOPS.

### The Problem

Both dotenvx (ECIES) and SOPS use encryption that produces different ciphertext each time,
even for identical plaintext. This means:

- Decrypting and re-encrypting an unchanged file creates a "modified" file in git
- Git history becomes cluttered with meaningless changes
- Code reviews show confusing diffs

### The Solution

With smart encryption enabled:

1. Before re-encrypting, the command compares current content with the decrypted git version
2. If content is unchanged, it restores the original encrypted file from git
3. No new ciphertext is generated, so git shows no changes

### Configuration

Enable in your `envdrift.toml`:

```toml
[encryption]
backend = "dotenvx"
smart_encryption = true
```

### Example Output

```text
Step 1: Encrypting environment files...

  = .env.production - skipped (content unchanged, restored encrypted version from git)
  + .env.staging - encrypted
```

## Examples

### Basic Lock

```bash
# Encrypt all env files
envdrift lock
```

### Verify Keys Then Lock

```bash
# Check keys match vault, then encrypt
envdrift lock --verify-vault
```

### Sync Keys Then Lock

```bash
# Fetch keys from vault, then encrypt
envdrift lock --sync-keys
```

### Check-Only Mode (Dry Run)

```bash
# See what would be encrypted
envdrift lock --check
```

### Lock With Profile

```bash
# Lock a specific profile
envdrift lock --profile local
```

### Lock Including Partial Encryption Files

```bash
# Lock everything, including partial encryption files
envdrift lock -f --all
```

### Force Lock Without Prompts

```bash
# CI-friendly: encrypt all without prompting
envdrift lock --force
```

### Override Provider Settings

```bash
envdrift lock -p azure --vault-url https://myvault.vault.azure.net/
```

## Output

### Without Vault Verification

```text
Lock - Verifying keys and encrypting env files
Provider: azure | Mode: Interactive | Services: 3

Step 1: Encrypting environment files...

  + services/myapp/.env.production - encrypted
  = services/auth/.env.production - skipped (already encrypted)

╭──────────── Lock Summary ────────────╮
│ Encrypted: 1                         │
│ Already encrypted: 1                 │
│ Skipped: 0                           │
│ Errors: 0                            │
╰──────────────────────────────────────╯

Lock complete! Your environment files are encrypted and ready to commit.
```

### With Vault Verification

```text
Lock - Verifying keys and encrypting env files
Provider: azure | Mode: Interactive | Services: 2

Step 1: Verifying keys with vault...

  ✓ services/myapp - keys match vault
  ✗ services/auth - KEY MISMATCH: local key differs from vault!

ERROR: Found 1 key mismatch(es). Run with --sync-keys to update local keys, or --force to encrypt anyway.
```

### With Key Sync

```text
Lock - Verifying keys and encrypting env files (profile: local)
Provider: azure | Mode: FORCE | Services: 1

Step 1: Verifying keys with vault...

Processing: .
  + . - created

╭──────────── Sync Summary ────────────╮
│ Services processed: 1                │
│ Created: 1                           │
│ Updated: 0                           │
│ Skipped: 0                           │
│ Errors: 0                            │
╰──────────────────────────────────────╯

Step 2: Encrypting environment files...

  + ./.env.local - encrypted

╭──────────── Lock Summary ────────────╮
│ Encrypted: 1                         │
│ Already encrypted: 0                 │
│ Skipped: 0                           │
│ Errors: 0                            │
╰──────────────────────────────────────╯

Lock complete! Your environment files are encrypted and ready to commit.
```

### With --all (Partial Encryption)

```text
Lock - Verifying keys and encrypting env files
Provider: azure | Mode: FORCE | Services: 3 | Including partial encryption

Step 1: Encrypting environment files...

  + services/api/.env.production - encrypted
  = services/auth/.env.production - skipped (already encrypted)
  + synapse/.env.production - encrypted

Step 2: Processing partial encryption files...

  = synapse/.env.production.secret - skipped (already encrypted)
  - synapse/.env.production - deleted (combined file)

╭──────────── Lock Summary ────────────╮
│ Encrypted: 2                         │
│ Already encrypted: 1                 │
│ Skipped: 0                           │
│ Errors: 0                            │
│ Partial secrets encrypted: 0         │
│ Combined files deleted: 1            │
╰──────────────────────────────────────╯

Lock complete! Your environment files are encrypted and ready to commit.
```

## Warnings and Errors

The `lock` command catches many edge cases and provides helpful warnings and errors:

### Warnings

| Warning                                    | Meaning                                                              |
|:-------------------------------------------|:---------------------------------------------------------------------|
| `.env.keys not found`                      | No encryption keys file exists; a new key will be generated           |
| `{KEY} missing from .env.keys`             | The expected private key for this environment isn't in the keys file  |
| `vault secret is empty`                    | The vault secret exists but has no value                             |
| `vault secret not found`                   | The secret doesn't exist in the vault                                |
| `multiple .env files found`                | Multiple `.env.*` files exist; specify the environment explicitly      |
| `file not found`                           | The expected `.env.<environment>` file doesn't exist                   |
| `partially encrypted (N%)`                 | The file is only partially encrypted; will re-encrypt                 |
| `partial encryption combined file`         | File is a generated combined file; use `--all` to include             |

### Errors

| Error               | Meaning                                                |
|:--------------------|:-------------------------------------------------------|
| `KEY MISMATCH`      | Local key differs from vault key - potential key drift |
| `vault error`       | Failed to access or authenticate with the vault        |
| `encryption failed` | dotenvx failed to encrypt the file                      |
| `Key sync failed`   | Could not sync keys from vault                         |

## Exit Codes

| Code | Meaning                                                  |
|:-----|:---------------------------------------------------------|
| 0    | Success (all files encrypted or verified)                  |
| 1    | Error (key mismatch, encryption failure, or vault error) |

## Configuration File Format

Same as `envdrift pull` and `envdrift sync`. See [sync documentation](sync.md#configuration-file-format) for details.

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
profile = "local"
activate_to = ".env"
```

## Workflow: pull and lock

The `pull` and `lock` commands form a complete development workflow:

```bash
# Starting development (decrypt files)
envdrift pull

# ... make changes to .env files ...

# Before committing (encrypt files)
envdrift lock --verify-vault

# If keys are out of sync
envdrift lock --sync-keys
```

### CI/CD Pre-commit Hook

```yaml
# pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: envdrift-lock
        name: Ensure env files are encrypted
        entry: envdrift lock --check --force
        language: system
        files: ^\.env\.(production|staging|development)$
        pass_filenames: false
```

## Prerequisites

- Cloud vault credentials configured (Azure CLI, AWS credentials, etc.)
- `dotenvx` installed for encryption

## See Also

- [pull](pull.md) - Pull keys and decrypt files (opposite of lock)
- [sync](sync.md) - Sync keys only (without encryption/decryption)
- [encrypt](encrypt.md) - Encrypt a single .env file
- [decrypt](decrypt.md) - Decrypt a single .env file
- [vault-push](vault-push.md) - Push keys to vault
