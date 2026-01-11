# envdrift pull-partial

Decrypt secret files for editing in partial encryption workflows.

## Synopsis

```bash
envdrift pull-partial [OPTIONS]
```

## Description

The `pull-partial` command is part of the [partial encryption](../guides/partial-encryption.md)
workflow. It decrypts `.secret` files in-place so you can edit sensitive variables.

After editing, use `envdrift push` to re-encrypt and regenerate the combined file.

This command requires partial encryption to be configured in `envdrift.toml`.

## Options

### `--env`, `-e`

Decrypt only a specific environment instead of all configured environments.

```bash
envdrift pull-partial --env production
```

### `--backend`, `-b`

Select the encryption backend (`dotenvx` or `sops`). Defaults to config or dotenvx.

```bash
envdrift pull-partial --backend sops
```

## Configuration

Partial encryption must be enabled in `envdrift.toml`:

```toml
[partial_encryption]
enabled = true

[[partial_encryption.environments]]
name = "production"
clear_file = ".env.production.clear"
secret_file = ".env.production.secret"
combined_file = ".env.production"
```

## Examples

### Decrypt All Environments

```bash
envdrift pull-partial
```

Decrypts secret files for all configured environments.

### Decrypt Specific Environment

```bash
envdrift pull-partial --env production
```

Only decrypts the production secret file.

### Typical Workflow

```bash
# 1. Pull latest changes
git pull

# 2. Decrypt secret files for editing
envdrift pull-partial

# 3. Edit source files
vim .env.production.clear    # Non-sensitive changes
vim .env.production.secret   # Sensitive changes (now decrypted)

# 4. Re-encrypt and combine
envdrift push

# 5. Commit
git add .env.production.clear .env.production.secret .env.production
git commit -m "Update configuration"
```

## Exit Codes

| Code | Meaning                                  |
| :--- | :--------------------------------------- |
| 0    | Decryption completed successfully        |
| 1    | Error (missing config, file not found, decryption failed) |

## See Also

- [push](push.md) - Encrypt and combine files
- [Partial Encryption Guide](../guides/partial-encryption.md) - Full workflow documentation
- [decrypt](decrypt.md) - Standard decryption command
