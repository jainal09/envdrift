# envdrift decrypt

Decrypt an encrypted .env file using dotenvx or SOPS, or verify that a vault key can
decrypt a file (dotenvx drift detection).

## Synopsis

```bash
envdrift decrypt [OPTIONS] [env_file]
envdrift decrypt [env_file] --verify-vault --provider <p> --secret <name> \
  [--vault-url ... | --project-id ... | --region ...]
```

## Description

The `decrypt` command decrypts .env files that were encrypted with dotenvx or SOPS.
It can also **verify** that a key stored in your vault can decrypt the file without actually decrypting it (useful for catching key drift in CI/pre-commit).

- Local development after cloning a repo
- Viewing encrypted values
- Migrating to a different encryption system

The target must be a regular file. Directories are refused with `[ERROR] Not a file: <path>`
and exit code 1 before hook setup, backend selection, or vault access.

### Honest no-op on non-encrypted files (dotenvx backend)

With the **dotenvx** backend, if the target file has no encrypted values
`decrypt` reports an honest no-op (`Nothing to decrypt: <file> has no encrypted
values.`) instead of claiming a decryption happened. The file is left
byte-for-byte untouched — dotenvx is not invoked at all — so a plaintext file
(including one with CRLF line endings) or a non-`.env` binary file is never
silently rewritten or corrupted. Ciphertext counts in any quote style dotenvx
writes it in, backticks included (`` API_KEY=`encrypted:...` ``).

### Values come back exactly as written

dotenvx's own `decrypt` writes each value the way `dotenvx run` would load it: it
expands `$VAR` and `${VAR}` from your shell's environment, runs `$(...)`, drops the
backslash of `\$`, takes the value of a variable your shell already has under the
same name, and rewrites the plaintext values of a partly encrypted file the same
way. `DB_PASSWORD=Xk9$mQ2zz!` came back as `DB_PASSWORD=Xk9!`.

envdrift has dotenvx decrypt only the ciphertext, in a copy that holds nothing else,
and prints the result instead of writing it. It then writes each value back as the
exact text it was encrypted from, inside the quotes it had. Every other line of the
file is left as it was, except that line endings are normalized to LF. A file that is
not valid UTF-8 is refused with nothing changed. A file that changes while dotenvx
runs, as when an editor saves it, keeps the change, and the decrypt fails: run it
again. `pull`, `vault-pull` and `pull-partial` decrypt the same way, so a `push` after
them re-encrypts the same secrets.

### Refuses the key store and companion files

`envdrift decrypt .env.keys` (or any `.keys`/`.example`/`.sample`/`.template`
target) is refused by name — case-insensitively, so `.env.KEYS` counts —
with a non-zero exit: the dotenvx private-key store
and plaintext companion files are never encrypted by envdrift in the first
place (`envdrift encrypt` refuses them too), so "decrypting" one is always a
mistake rather than a no-op worth reporting as success. Leading-dash filenames
(e.g. `-dash.env`) are passed to dotenvx as `./-dash.env` so they decrypt
normally via `envdrift decrypt -- -dash.env`.

## Arguments

| Argument   | Description                     | Default |
| :--------- | :------------------------------ | :------ |
| `[env_file]` | Path to the encrypted .env file | `.env`  |

## Options

### `--backend`, `-b`

Select the encryption backend (`dotenvx` or `sops`). Defaults to auto-detect,
then config, then dotenvx.

```bash
envdrift decrypt .env.production --backend sops
```

### SOPS Options

- `--sops-config` Path to `.sops.yaml`
- `--age-key-file` Age private key file for decryption (sets `SOPS_AGE_KEY_FILE`;
  the explicit flag overrides an ambient `SOPS_AGE_KEY_FILE` export)

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
`envdrift.toml`). Provider settings use the explicit CLI flag first, then the
matching `[vault.<provider>]` configuration. HashiCorp additionally falls back
to `VAULT_ADDR` when neither `--vault-url` nor `[vault.hashicorp] url` is set;
surrounding whitespace is stripped and a whitespace-only value is treated as
unset.

```bash
# Azure Key Vault: pass the URL explicitly or configure [vault.azure]
envdrift decrypt .env.production --verify-vault --ci \
  -p azure --vault-url https://myvault.vault.azure.net \
  --secret myapp-dotenvx-key

# HashiCorp Vault: VAULT_ADDR can supply the URL
VAULT_ADDR=https://vault.example.com envdrift decrypt .env.production \
  --verify-vault --ci -p hashicorp --secret myapp-dotenvx-key

# GCP Secret Manager: pass the project explicitly or configure [vault.gcp]
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
  `-c <resolved-config>`; the effective `--vault-url`/`--region`/`--project-id`
  values are appended after CLI/config/environment resolution.
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
fails with the underlying dotenvx error (the `dotenvx decryption failed:` prefix
appears once) and says what happened to the file:

```text
[ERROR] Decryption failed: dotenvx decryption failed: <dotenvx error>
.env.production was left as it was.
```

Check that `.env.keys` exists or `DOTENV_PRIVATE_KEY_*` is set, and that the key
matches the one used to encrypt the file.

### A Value Encrypted Under Another Key

When one value was encrypted under a different key (for example after a merge, or
through key drift), the decrypt fails. dotenvx decrypts the values in a copy (see
[Values come back exactly as written](#values-come-back-exactly-as-written)), and the
file is written only once every value decrypted, so a failed decrypt leaves the file
as it was, CRLF line endings included, and never leaves decrypted secrets in a
tracked file. The error names the value dotenvx could not decrypt:

```text
[ERROR] Decryption failed: dotenvx decryption failed: ☠ [DECRYPTION_FAILED] could not decrypt STRIPE_API_KEY. ...
.env.production was left as it was.
```

envdrift also takes a byte-for-byte copy of the file before it decrypts, and writes it
back when the file changed and the decrypt failed after all, or exited 0 but left
ciphertext behind (`Decryption did not take effect`). The copy goes back whole or not at all: it is written to a
temporary file next to the file and renamed over it, so if envdrift cannot write
it back (a full disk, for example), the file is left as dotenvx wrote it, never
cut short. The message then says the file may now hold decrypted plaintext, marks
it `skip-worktree` so a plain `git add .` won't stage it, and says whether that
protection worked. When it did not, the advice depends on why:
`git checkout -- <file>` for a tracked file, or `envdrift encrypt <file>` for a
file git has no copy of (untracked, or outside a git repository). The git commands
act on the file the plaintext is in: for a symlink, the file it points to, with
`git -C <directory>` when that file is not in the current directory.
`envdrift pull` and `vault-pull` decrypt through the same code, so they leave a
file as it was in the same way.

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
