# envdrift decrypt

Decrypt an encrypted .env file using dotenvx, or verify that a vault key can decrypt a file (drift detection).

## Synopsis

```bash
envdrift decrypt [ENV_FILE]
envdrift decrypt [ENV_FILE] --verify-vault [--provider ...]
```

## Description

The `decrypt` command decrypts .env files that were encrypted with dotenvx.
It can also **verify** that a key stored in your vault can decrypt the file without actually decrypting it (useful for catching key drift in CI/pre-commit).

- Local development after cloning a repo
- Viewing encrypted values
- Migrating to a different encryption system

## Arguments

| Argument   | Description                     | Default |
| :--------- | :------------------------------ | :------ |
| `ENV_FILE` | Path to the encrypted .env file | `.env`  |

## Examples

### Basic Decryption

```bash
envdrift decrypt .env.production
```

### Verify vault key (drift detection, no decryption performed)

```bash
envdrift decrypt .env.production --verify-vault --ci \
  -p azure --vault-url https://myvault.vault.azure.net \
  --secret myapp-dotenvx-key
```

Exit code 0 if the vault key can decrypt the file, 1 if it cannot.

### Decrypt Specific Environment

```bash
envdrift decrypt .env.staging
```

## Requirements

### Private Key

Decryption requires the private key, which can be provided via:

1. **`.env.keys` file** (recommended for local development):

   ```bash
   # .env.keys
   DOTENV_PRIVATE_KEY_PRODUCTION="abc123..."
   ```

2. **Environment variable** (recommended for CI/CD):

   ```bash
   export DOTENV_PRIVATE_KEY_PRODUCTION="abc123..."
   envdrift decrypt .env.production
   ```

### dotenvx

The dotenvx binary is required. envdrift will:

1. Check if dotenvx is installed
2. If not, provide installation instructions

## Workflow

### Local Development

After cloning a repo with encrypted .env files:

```bash
# 1. Get the private key from your team (securely!)
# 2. Add it to .env.keys
echo 'DOTENV_PRIVATE_KEY_PRODUCTION="your-key-here"' > .env.keys

# 3. Decrypt
envdrift decrypt .env.production
```

### CI/CD Pipeline (decrypt)

```yaml
# GitHub Actions
env:
  DOTENV_PRIVATE_KEY_PRODUCTION: ${{ secrets.DOTENV_PRIVATE_KEY_PRODUCTION }}

steps:
  - name: Decrypt environment
    run: envdrift decrypt .env.production
```

### CI/pre-commit drift check (verify-vault)

```bash
envdrift decrypt .env.production --verify-vault --ci \
  -p azure --vault-url https://myvault.vault.azure.net \
  --secret myapp-dotenvx-key
```

Failure shows WRONG_PRIVATE_KEY and prints repair steps:

- `git restore <file>`
- `envdrift sync --force ...` to restore .env.keys from vault
- `envdrift encrypt <file>` to re-encrypt with the vault key

## Error Handling

### Missing Private Key

```text
[ERROR] Decryption failed
Check that .env.keys exists or DOTENV_PRIVATE_KEY_* is set
```

### Wrong Private Key

```text
[ERROR] Decryption failed
The private key does not match the encrypted file
```

When using `--verify-vault`, a wrong key returns exit 1 with a message like:

```text
[ERROR] ✗ Vault key CANNOT decrypt this file!
...
To fix:
  1. Restore the encrypted file: git restore .env.production
  2. Restore vault key locally: envdrift sync --force -c pair.txt -p azure --vault-url https://...
  3. Re-encrypt with the vault key: envdrift encrypt .env.production
```

### dotenvx Not Installed

```text
[ERROR] dotenvx is not installed
Install: curl -sfS https://dotenvx.sh | sh
```

## Security Notes

- Never commit `.env.keys` to version control
- Add `.env.keys` to your `.gitignore`
- Use secrets management (GitHub Secrets, Vault, etc.) for CI/CD
- Rotate keys if they are ever exposed
- For drift tests, clear cached keys (`.env.keys`, `DOTENV_PRIVATE_KEY_*` dirs, /tmp)
  or run in a clean temp dir so dotenvx does not silently reuse an old key.

## See Also

- [encrypt](encrypt.md) - Encrypt .env files
- [validate](validate.md) - Validate .env files
