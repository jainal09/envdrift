# envdrift encrypt

Check or perform encryption on .env files using dotenvx or SOPS.

## Synopsis

```bash
envdrift encrypt [ENV_FILE]... [OPTIONS]
```

## Description

The `encrypt` command works with [dotenvx](https://dotenvx.com/) or
[SOPS](https://github.com/getsops/sops) to manage encryption of .env files. It can:

- **Check encryption status** - Report which variables are encrypted/plaintext
- **Detect plaintext secrets** - Identify sensitive values that should be encrypted
- **Perform encryption** - Encrypt the file using the selected backend

> Vault verification has moved to `envdrift decrypt --verify-vault`. Use decrypt for drift checks; encrypt no longer supports `--verify-vault`.

If `--backend` is omitted, envdrift uses the configured backend (envdrift.toml/pyproject.toml) or defaults to dotenvx.

### Safety guarantees

The `encrypt` command verifies its own outcome rather than trusting the backend's
exit code (dotenvx can exit `0` without encrypting):

- **Refuses content-free files.** An empty, blank-line-only, or comment-only file
  has no variables to encrypt, so the command declines with a non-zero exit
  instead of letting dotenvx scaffold a placeholder-secrets template into it.
- **Refuses the key store and companion files.** `envdrift encrypt .env.keys`
  would encrypt the dotenvx private-key store itself — the keys become
  ciphertext under a brand-new keypair whose private half is never saved,
  permanently locking out every encrypted file in the project — so the command
  refuses any `.keys`/`.example`/`.sample`/`.template` target by name, for
  every backend. The name match is case-insensitive (`.env.KEYS` names the
  same file on macOS/Windows default filesystems), and a renamed or symlinked
  key store (`mv .env.keys prodkeys.env`) is still refused by content: a file
  carrying `DOTENV_PRIVATE_KEY*` entries is never encrypted.
- **Handles leading-dash filenames.** A file like `-dash.env` is passed to
  dotenvx as `./-dash.env` so its CLI cannot misparse the name as flags
  (which previously fabricated a different file full of placeholder secrets).
  Use `envdrift encrypt -- -dash.env` so envdrift's own CLI accepts the name.
- **Reports silent encryption failures.** When the key is missing or malformed
  (a `.env.keys` that is a directory, garbage, or a mismatched key), the file is
  re-read after the call; if any plaintext value survives, the command fails
  loudly instead of printing `[OK]`.

Multiple env files can be passed in one invocation. With `--check`, each file gets
its own report and the exit code is 1 if any file should block a commit — this keeps
the command usable as a pre-commit `pass_filenames: true` hook, where every matched
staged file is appended to a single command line. Without `--check`, each file is
encrypted in turn.

## Arguments

| Argument      | Description                    | Default |
| :------------ | :----------------------------- | :------ |
| `ENV_FILE`... | Path(s) to the .env file(s)    | `.env`  |

## Options

### `--check`

Only check encryption status without modifying the file. Exits with code 1 if plaintext secrets are detected.

```bash
envdrift encrypt .env.production --check
```

### `--schema`, `-s`

Schema for better sensitive field detection. Fields marked with `json_schema_extra={"sensitive": True}` are checked.

```bash
envdrift encrypt .env.production --check --schema config.settings:ProductionSettings
```

### `--service-dir`, `-d`

Directory to add to Python's `sys.path` for schema imports.

```bash
envdrift encrypt .env.production --check -s config.settings:Settings -d /app/backend
```

### `--backend`, `-b`

Select the encryption backend (`dotenvx` or `sops`). Defaults to config or dotenvx.

```bash
envdrift encrypt .env.production --backend sops
```

### SOPS Options

- `--sops-config` Path to `.sops.yaml`
- `--age` Age public key(s) for encryption
- `--age-key-file` Age private key file for decryption (sets `SOPS_AGE_KEY_FILE`)
- `--kms` AWS KMS key ARN
- `--gcp-kms` GCP KMS resource ID
- `--azure-kv` Azure Key Vault key URL

## Examples

### Check Encryption Status

```bash
envdrift encrypt .env.production --check
```

Output:

```text
╭─────────────────── envdrift encrypt --check ───────────────────╮
│ Encryption Status: .env.production                             │
╰────────────────────────────────────────────────────────────────╯

File is partially encrypted

Variables:
  Encrypted:  3
  Plaintext:  5
  Empty:      0
  Encryption ratio: 38%

PLAINTEXT SECRETS DETECTED:
  * API_KEY_BACKEND
  * JWT_SECRET

WARNINGS:
  * 'API_KEY_BACKEND' has a value that looks like a secret
  * 'JWT_SECRET' has a name suggesting sensitive data

Recommendation:
  Run: envdrift encrypt .env.production
```

### Check with Schema

```bash
envdrift encrypt .env.production --check --schema config.settings:ProductionSettings
```

With a schema, envdrift knows exactly which fields are sensitive:

```python
class ProductionSettings(BaseSettings):
    DATABASE_URL: str = Field(json_schema_extra={"sensitive": True})
    API_KEY: str = Field(json_schema_extra={"sensitive": True})
    DEBUG: bool = False  # Not sensitive
```

### Encrypt with dotenvx

```bash
envdrift encrypt .env.production
```

This will:

1. Install dotenvx if `encryption.dotenvx.auto_install` is enabled
2. Generate an ECIES (secp256k1) keypair, encrypt each sensitive value with the
   public key (ECIES envelope around an AES-256-GCM payload), and rewrite the
   file in place
3. Create `.env.keys` with the matching private key (never commit this!)

### Encrypt with SOPS

```bash
envdrift encrypt .env.production --backend sops --age age1example
```

SOPS uses `.sops.yaml` (or the key options above) and does not create `.env.keys`.
Ensure the `sops` binary is installed or enable `encryption.sops.auto_install`.

### CI/CD Encryption Check

```yaml
# GitHub Actions
- name: Check secrets are encrypted
  run: |
    envdrift encrypt .env.production --check \
      --schema config.settings:ProductionSettings
```

The command exits with code 1 if plaintext secrets are detected, failing the pipeline.

## Encryption Report

The `--check` option provides a detailed report:

| Section           | Description                                            |
| :---------------- | :----------------------------------------------------- |
| Overall Status    | Fully encrypted, partially encrypted, or not encrypted |
| Variables         | Count of encrypted, plaintext, and empty variables     |
| Encryption Ratio  | Percentage of variables that are encrypted             |
| Plaintext Secrets | Variables detected as secrets but not encrypted        |
| Warnings          | Additional concerns (e.g., credentials in URLs)        |

## How dotenvx Encryption Works

envdrift integrates with [dotenvx](https://dotenvx.com/) for encryption:

1. **Encrypted format**: dotenvx uses ECIES (secp256k1 public-key encryption)
   wrapping an AES-256-GCM payload. Each sensitive value is encrypted to the
   project's public key and prefixed with `encrypted:`
2. **Key storage**: The matching private key lives in `.env.keys` (add to
   `.gitignore`); the public key is written into the encrypted file as
   `DOTENV_PUBLIC_KEY_<ENV>` so anyone can encrypt new values without the
   private key
3. **Safe to commit**: Encrypted `.env` files can be committed to git

Example encrypted file:

```bash
#/-------------------[DOTENV_PUBLIC_KEY]--------------------/
DOTENV_PUBLIC_KEY_PRODUCTION="03abc123..."
DATABASE_URL="encrypted:BDQE1234567890abcdef..."
API_KEY="encrypted:BDQEsecretkey123456..."
DEBUG=false
#/----------------------------------------------------------/
```

## How SOPS Encryption Works

envdrift shells out to [SOPS](https://github.com/getsops/sops) for encryption:

1. **Encrypted format**: Values use the `ENC[AES256_GCM,...]` format
2. **Key storage**: Keys live in your SOPS setup (age, KMS, PGP, etc.)
3. **Config**: `.sops.yaml` controls which files and keys are used
4. **Idempotent**: Re-encrypting a file that is already SOPS-encrypted is a
   clean no-op (exit 0, "already encrypted (no change)"). A pre-commit hook
   firing twice, a CI re-run, or a documented re-run will not fail.
5. **Explicit config is validated**: If you pass `--sops-config` (or set
   `sops_config_file` in `envdrift.toml`) pointing at a path that does not
   exist, encryption fails with `SOPS config file not found: <path>` rather
   than silently falling back to an ambient `.sops.yaml` (which could encrypt
   with the wrong keys).

## Sensitive Detection

envdrift detects sensitive values using:

### Schema-based Detection

Fields with `json_schema_extra={"sensitive": True}`:

```python
API_KEY: str = Field(json_schema_extra={"sensitive": True})
```

### Name-based Detection

Variable names matching patterns:

- `*_KEY`, `*_SECRET`, `*_TOKEN`
- `*_PASSWORD`, `*_PASS`
- `*_CREDENTIAL*`, `*_API_KEY`
- `JWT_*`, `AUTH_*`, `PRIVATE_*`, `*_DSN`

### Value-based Detection

Values matching patterns:

- API keys: `sk-*`, `pk-*`, `ghp_*`, `gho_*`, `xox*-*`
- AWS keys: `AKIA*`
- Database URLs with credentials: `postgres://user:pass@...`
- JWT tokens: `eyJ*`

## Exit Codes

| Code | Meaning                                                          |
| :--- | :--------------------------------------------------------------- |
| 0    | No plaintext secrets detected (or encryption successful)         |
| 1    | Plaintext secrets detected (with `--check`) or encryption failed |

## See Also

- [decrypt](decrypt.md) - Decrypt encrypted files
- [validate](validate.md) - Validate with encryption warnings
