# envdrift decrypt

Decrypt an encrypted .env file using dotenvx or SOPS, or verify that a vault key can
decrypt a file (dotenvx drift detection).

## Synopsis

```bash
envdrift decrypt [ENV_FILE]
envdrift decrypt [ENV_FILE] --verify-vault [--provider ...]
```

## Description

The `decrypt` command decrypts .env files that were encrypted with dotenvx or SOPS.
It can also **verify** that a key stored in your vault can decrypt the file without actually decrypting it (useful for catching key drift in CI/pre-commit).

- Local development after cloning a repo
- Viewing encrypted values
- Migrating to a different encryption system

## Arguments

| Argument   | Description                     | Default |
| :--------- | :------------------------------ | :------ |
| `ENV_FILE` | Path to the encrypted .env file | `.env`  |

## Options

### `--backend`, `-b`

Select the encryption backend (`dotenvx` or `sops`). Defaults to auto-detect,
then config, then dotenvx.

```bash
envdrift decrypt .env.production --backend sops
```

### SOPS Options

- `--sops-config` Path to `.sops.yaml`
- `--age-key-file` Age private key file for decryption (sets `SOPS_AGE_KEY_FILE`)

## Examples

### Basic Decryption

```bash
envdrift decrypt .env.production
```

### Decrypt with SOPS

```bash
export SOPS_AGE_KEY_FILE=keys.txt
envdrift decrypt .env.production --backend sops
```

### Verify vault key (drift detection, no decryption performed)

Vault verification is only supported with the dotenvx backend.

```bash
# Auto-discovered provider/vault/secret via envdrift.toml or pyproject
envdrift decrypt .env.production --verify-vault --ci

# Override vault settings explicitly (bypass auto-discovery)
envdrift decrypt .env.production --verify-vault --ci \
  -p azure --vault-url https://myvault.vault.azure.net \
  --secret myapp-dotenvx-key

# GCP Secret Manager
envdrift decrypt .env.production --verify-vault --ci \
  -p gcp --project-id my-gcp-project \
  --secret myapp-dotenvx-key
```

Exit code 0 if the vault key can decrypt the file, 1 if it cannot.

### Decrypt Specific Environment

```bash
envdrift decrypt .env.staging
```

## Requirements

### Dotenvx Private Key

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

Enable `encryption.dotenvx.auto_install` in config to allow auto-installation.

### SOPS Keys

SOPS uses your configured key management system (age, KMS, PGP, etc.). For age:

```bash
export SOPS_AGE_KEY_FILE=keys.txt
```

Ensure the `sops` binary is installed (for example, `brew install sops`) or enable
`encryption.sops.auto_install`.

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

For SOPS, ensure your SOPS keys are available (age/KMS/PGP) and run:

```bash
envdrift decrypt .env.production --backend sops
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
  2. Restore vault key locally: envdrift sync --force (add -c envdrift.toml if auto-discovery doesn't find the config)
  3. Re-encrypt with the vault key: envdrift encrypt .env.production
```

### dotenvx Not Installed

```text
[ERROR] dotenvx is not installed
Install: curl -sfS https://dotenvx.sh | sh
```

### SOPS Decryption Failed

```text
[ERROR] Decryption failed: SOPS decryption failed
```

Check `SOPS_AGE_KEY_FILE`, your KMS/PGP credentials, and `.sops.yaml` rules.

## Security Notes

- Never commit `.env.keys` to version control
- Add `.env.keys` to your `.gitignore`
- SOPS key material is managed outside envdrift (age/KMS/PGP)
- Use secrets management (GitHub Secrets, Vault, etc.) for CI/CD
- Rotate keys if they are ever exposed
- For drift tests, clear cached keys (`.env.keys`, `DOTENV_PRIVATE_KEY_*` dirs, /tmp)
  or run in a clean temp dir so dotenvx does not silently reuse an old key.

## See Also

- [encrypt](encrypt.md) - Encrypt .env files
- [validate](validate.md) - Validate .env files
