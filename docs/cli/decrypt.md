# envdrift decrypt

Decrypt an encrypted .env file using dotenvx or SOPS, or verify that a vault key can
decrypt a file (dotenvx drift detection).

## Synopsis

```bash
envdrift decrypt [ENV_FILE]
envdrift decrypt [ENV_FILE] --verify-vault --provider <p> --secret <name> \
  [--vault-url ... | --project-id ... | --region ...]
```

## Description

The `decrypt` command decrypts .env files that were encrypted with dotenvx or SOPS.
It can also **verify** that a key stored in your vault can decrypt the file without actually decrypting it (useful for catching key drift in CI/pre-commit).

- Local development after cloning a repo
- Viewing encrypted values
- Migrating to a different encryption system

### Honest no-op on non-encrypted files (dotenvx backend)

With the **dotenvx** backend, if the target file has no encrypted values
`decrypt` reports an honest no-op (`Nothing to decrypt: <file> has no encrypted
values.`) instead of claiming a decryption happened. The file is left
byte-for-byte untouched — dotenvx is not invoked at all — so a plaintext file
(including one with CRLF line endings) or a non-`.env` binary file is never
silently rewritten or corrupted.

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

Vault verification is only supported with the dotenvx backend. `--provider` and
`--secret` are always required with `--verify-vault` (they are not read from
`envdrift.toml`); `--vault-url` is also required for azure/hashicorp and
`--project-id` for gcp.

```bash
# Azure Key Vault (or HashiCorp): --vault-url is required
envdrift decrypt .env.production --verify-vault --ci \
  -p azure --vault-url https://myvault.vault.azure.net \
  --secret myapp-dotenvx-key

# GCP Secret Manager: --project-id is required
envdrift decrypt .env.production --verify-vault --ci \
  -p gcp --project-id my-gcp-project \
  --secret myapp-dotenvx-key
```

Exit code 0 if the vault key can decrypt the file, 1 if it cannot.

The vault value is normalized the same way `envdrift lock --verify-vault` and
`envdrift sync` parse it: surrounding whitespace, one layer of quotes, and a
`DOTENV_PRIVATE_KEY_<ENV>=` prefix are stripped. A vault secret stored as the
literal `.env.keys` line `DOTENV_PRIVATE_KEY_PRODUCTION="<hex>"` (quoted, as
`vault-push` writes it) therefore verifies identically to the bare `<hex>`
value — all three verify commands agree on the same vault secret.

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

On failure it prints `✗ Vault key CANNOT decrypt this file!` followed by repair
steps:

- `git restore <file>`
- `envdrift sync --force -p <provider>` to restore the vault key locally. When
  the current command discovered a TOML config, the hint includes
  `-c <resolved-config>`; `--vault-url`/`--region`/`--project-id` are appended
  when those flags were passed.
- `envdrift encrypt <file>` to re-encrypt with the vault key

!!! note "`--verify-vault` only verifies — it does not fetch the key"
    This is a **read-only CI check**: it fetches the vault key, tests decryption
    against a byte-for-byte copy of the file in a throwaway temp dir, and discards
    everything (the original file is *not* decrypted and no `.env.keys` is
    written). The copy preserves the file exactly — encoding and line endings
    included — on every platform. To actually fetch a key onto a machine and
    decrypt for use, see [`vault-pull`](vault-pull.md).

## Error Handling

### Missing or Wrong Private Key

When the private key is missing or does not match the encrypted file, decryption
fails with a single line carrying the underlying dotenvx error:

```text
[ERROR] Decryption failed: dotenvx decryption failed: <dotenvx error>
```

Check that `.env.keys` exists or `DOTENV_PRIVATE_KEY_*` is set, and that the key
matches the one used to encrypt the file.

When using `--verify-vault`, a wrong key returns exit 1 with a message like:

```text
[ERROR] ✗ Vault key CANNOT decrypt this file!
...
To fix:
  1. Restore the encrypted file: git restore .env.production
  2. Restore vault key locally: envdrift sync --force -p azure
  3. Re-encrypt with the vault key: envdrift encrypt .env.production
```

### dotenvx Not Installed

```text
[ERROR] dotenvx is not installed

dotenvx is not installed.

Option 1 - Install to ~/.local/bin (recommended):
  curl -sfS "https://dotenvx.sh?directory=$HOME/.local/bin" | sh -s -- --version=<pinned version>
  (Make sure ~/.local/bin is in your PATH)

Option 2 - Install to current directory:
  curl -sfS "https://dotenvx.sh?directory=." | sh -s -- --version=<pinned version>

Option 3 - System-wide install (requires sudo):
  curl -sfS https://dotenvx.sh | sudo sh -s -- --version=<pinned version>

After installing, run your envdrift command again.
```

envdrift substitutes `<pinned version>` with the exact dotenvx version it pins
(maintained in `src/envdrift/constants.json` and bumped by Renovate), so the
printed commands always install the version envdrift expects.

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
