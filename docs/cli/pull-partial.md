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
environments where some other files were decrypted). In secrets-only mode a pull
stops at the first file it cannot decrypt; the files decrypted before it are
still counted in `Decrypted: N`.

This command requires partial encryption to be configured in `envdrift.toml`.

## Options

### `--env`, `-e`

Decrypt only a specific environment instead of all configured environments.

```bash
envdrift pull-partial --env production
```

Partial encryption always uses dotenvx for decryption; there is no backend option
to select. A SOPS-encrypted secret file is reported as an error, not decrypted (see
[When a decrypt fails](#when-a-decrypt-fails)).

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

The plaintext notice is printed whenever this run decrypted at least one file,
even when another environment failed and the command exits 1.

## When a decrypt fails

dotenvx decrypts value by value. When one value was encrypted under another key
(for example after a merge, or through key drift), dotenvx writes the values it
could decrypt and then fails. `pull-partial` takes a byte-for-byte copy of each
secret file before dotenvx runs and writes it back on failure, so the file is left
as it was (still encrypted, CRLF line endings included) instead of half decrypted
and unprotected. The error names the value dotenvx could not decrypt:

```text
✗ Failed to decrypt .env.production.secret: dotenvx decryption failed: ☠ [DECRYPTION_FAILED] could not decrypt STRIPE_API_KEY. ...
.env.production.secret was left as it was: envdrift restored the bytes it had before the decrypt.
```

If envdrift cannot write the file back, the message says the file may now hold
decrypted plaintext, marks it `skip-worktree`, and says whether that protection
worked.

`pull-partial` also reads each secret file back after dotenvx exits 0, because the
exit code alone can lie. A SOPS-encrypted secret file is one example: dotenvx finds
nothing it can decrypt, prints "no change" and exits 0. A file that still holds
ciphertext is reported as a failure that names the file and the format. It is not
counted as decrypted and not marked `skip-worktree`, and it is left as it was:

```text
✗ Failed to decrypt .env.production.secret: it still holds SOPS ciphertext. pull-partial decrypts with dotenvx,
which does not read SOPS files; run `envdrift decrypt .env.production.secret --backend sops` instead.
```

Leftover dotenvx ciphertext is reported the same way (`it still holds dotenvx
ciphertext`), which usually means the decryption key is missing or invalid.

## Exit Codes

| Code | Meaning                                  |
| :--- | :--------------------------------------- |
| 0    | Decryption completed successfully        |
| 1    | Error (missing config, file not found, decryption failed) |

## See Also

- [push](push.md) - Encrypt and combine files
- [Partial Encryption Guide](../guides/partial-encryption.md) - Full workflow documentation
- [decrypt](decrypt.md) - Standard decryption command
