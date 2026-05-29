# envdrift pull-partial

Decrypt secret files for editing in partial encryption workflows.

## Synopsis

```bash
envdrift pull-partial [OPTIONS]
```

## Description

The `pull-partial` command is part of the [partial encryption](../guides/partial-encryption.md)
workflow. Its exact behaviour depends on the mode configured for each environment:

**Combine mode** (default): decrypts `.secret` files in place so you can edit sensitive
variables. After editing, run `envdrift push` to re-encrypt and regenerate the combined file.

**Secrets-only mode** (`secrets_only = true`): decrypts every file matching `pattern`
inside `secrets_dir` in place. No combined file is involved. The `pattern` glob is
non-recursive by default; use `**/.env*` if your secrets are in nested
subdirectories. `secrets_dir` is required — pulling with `secrets_only = true`
but no `secrets_dir` is rejected at config-load time.

The summary panel reports `Decrypted: N` (files actually decrypted on this run)
and `Skipped: M` (files that were already decrypted, including those skipped in
environments where some other files were decrypted).

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

# Combine mode
[[partial_encryption.environments]]
name = "staging"
clear_file = ".env.staging.clear"
secret_file = ".env.staging.secret"
combined_file = ".env.staging"

# Secrets-only mode
[[partial_encryption.environments]]
name = "production"
secrets_only = true
secrets_dir = "secrets/production/"
pattern = ".env*"
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

# 5. Commit source files only — the combined file is gitignored
git add .env.production.clear .env.production.secret
git commit -m "Update configuration"
```

## Plaintext protection

While a secret file is decrypted, `pull-partial` marks it `skip-worktree` in your
local clone so a plain `git add .` will not stage it. `envdrift push` lifts the
protection once the file is re-encrypted. This is a local guardrail only — it is not
shared with teammates and can be bypassed with `git add -f`, so never force-add a
decrypted secret file. The same protection applies to every file decrypted in
secrets-only mode.

## Exit Codes

| Code | Meaning                                  |
| :--- | :--------------------------------------- |
| 0    | Decryption completed successfully        |
| 1    | Error (missing config, file not found, decryption failed) |

## See Also

- [push](push.md) - Encrypt and combine files
- [Partial Encryption Guide](../guides/partial-encryption.md) - Full workflow documentation
- [decrypt](decrypt.md) - Standard decryption command
