# envdrift sync

Sync encryption keys from cloud vaults to local .env.keys files.
This command is specific to dotenvx keys; SOPS users should rely on SOPS/KMS key workflows.

## Synopsis

```bash
envdrift sync [OPTIONS]
```

## Description

The `sync` command fetches `DOTENV_PRIVATE_KEY_*` secrets from cloud vaults and synchronizes them to local `.env.keys` files for dotenvx decryption.

This enables secure key distribution without committing keys to source control. Keys are stored in cloud vaults (Azure Key Vault, AWS Secrets Manager,
HashiCorp Vault, or GCP Secret Manager) and synced to local development environments or CI/CD pipelines.

If `--config` is omitted, envdrift auto-discovers `envdrift.toml` or a `pyproject.toml` with `[tool.envdrift]` in the current directory tree.

Supported vault providers:

- **Azure Key Vault** - Microsoft Azure's secret management service
- **AWS Secrets Manager** - Amazon Web Services secret storage
- **HashiCorp Vault** - Open-source secrets management
- **GCP Secret Manager** - Google Cloud secret storage

Auto-discovery usually supplies provider, vault URL, and region from your config file.
Pass CLI flags when you need to override those defaults or when using legacy `pair.txt`, and use `-c` to pin a specific config file (common in CI).

## Options

### `--config`, `-c`

Path to sync configuration file (TOML preferred; legacy `pair.txt` still supported). Optional when auto-discovery finds `envdrift.toml` or `pyproject.toml`
(with `[tool.envdrift]`).

```bash
# Preferred: TOML with provider + mappings (auto-discovered, so -c is optional)
envdrift sync

# Explicit path if needed
envdrift sync --config envdrift.toml

# Legacy: pair.txt (requires provider flags)
envdrift sync --config pair.txt -p azure --vault-url https://myvault.vault.azure.net/
```

### `--provider`, `-p`

Vault provider to use. Required when the config doesn’t include a provider (e.g., legacy `pair.txt`); optional otherwise. Use this to override TOML defaults.

Options: `azure`, `aws`, `hashicorp`, `gcp`

TOML configs usually include the provider; pass `--provider` to override.

### `--vault-url`

Vault URL. **Required for Azure and HashiCorp.**

Only required when using legacy configs or overriding the TOML defaults.

### `--region`

AWS region for Secrets Manager. Default: `us-east-1`.

Only required when using legacy configs or overriding the TOML defaults.

### `--project-id`

GCP project ID for Secret Manager. Required for the `gcp` provider unless configured in TOML.

Only required when using legacy configs or overriding the TOML defaults.

### `--verify`

Check only mode. Reports differences without modifying files.

Reports mismatches as errors but exits non-zero only when combined with `--ci`. In CI/CD, use `--verify --ci` so the build fails on drift.

### `--force`, `-f`

Force update all mismatches without prompting.

### `--check-decryption`

After syncing, verify that the keys can decrypt `.env` files.

This tests actual decryption using dotenvx to ensure keys are valid. The check
is **non-destructive**: the encrypted file and the synced keys file are copied
into a throwaway temp directory and dotenvx decrypts the copy there, so the
working-tree file is never decrypted or rewritten (its bytes are identical
before and after, whether the check passes or fails). Stray
`DOTENV_PRIVATE_KEY*` variables in your shell are ignored so the verdict
reflects the synced `.env.keys`, and mappings with relative `folder_path`
values (the usual monorepo layout) verify correctly from the project root.

If any decryption test fails, `sync` exits 1 — with or without `--ci`. The
check also refuses to run when dotenvx is not installed: skipping every test
would verify nothing, so `sync` reports the missing binary and exits 1
instead of silently succeeding.

### `--validate-schema`

Run schema validation after sync.

### `--schema`, `-s`

Schema path for validation (used with `--validate-schema`).

### `--service-dir`, `-d`

Service directory for schema imports.

### `--ci`

CI mode. Exit with code 1 on any errors.

## Configuration File Format

### TOML Format (recommended)

In `envdrift.toml`:

```toml
[vault]
provider = "azure"  # azure | aws | hashicorp | gcp

[vault.azure]
vault_url = "https://my-keyvault.vault.azure.net/"

[vault.gcp]
project_id = "my-gcp-project"

[vault.sync]
default_vault_name = "my-keyvault"
env_keys_filename = ".env.keys"

[[vault.sync.mappings]]
secret_name = "myapp-key"
folder_path = "services/myapp"

[[vault.sync.mappings]]
secret_name = "auth-service-key"
folder_path = "services/auth"
vault_name = "other-vault"  # Parsed but informational only — does NOT route (see note below)
environment = "staging"     # Use DOTENV_PRIVATE_KEY_STAGING

[[vault.sync.mappings]]
secret_name = "postgres-key"
folder_path = "secrets/postgresql"
environment = "production"  # Use DOTENV_PRIVATE_KEY_PRODUCTION
env_file = "postgresql.env" # Custom dotenv filename inside folder_path
```

Place the file in the project root so auto-discovery finds it; pass `-c envdrift.toml` in CI to pin the exact file.

!!! warning "`folder_path` must be an existing directory"
    Each mapping's `folder_path` is validated: a folder that does not exist
    (for example a typo like `servces/api`), or that points at a regular
    file instead of a directory, is reported as a per-mapping
    **error** — the row says `Mapping folder does not exist or is not a
    directory`, the summary counts it under `Errors`, and `sync --ci`,
    `pull`, and `vault-push --all` exit non-zero. Only a *missing env file
    inside an existing folder* is a benign skip ("file not created yet").

!!! note "`vault_name` / `default_vault_name` do not switch the vault"
    `vault_name` (per-mapping) and `default_vault_name` are parsed and accepted
    but are **informational only** — the sync/push engine fetches and pushes
    every secret from the single vault you configured via `--vault-url` /
    `[vault.<provider>]` (or `--region` / `--project-id`). A per-mapping
    `vault_name` does **not** route that secret to a different vault, so
    `vault-push --all` pushes every mapping to the one configured vault. To use a
    separate vault, run a separate config. See the `vault_name` row in
    [configuration.md](../reference/configuration.md) and the note in
    [env-file-sync.md](../guides/env-file-sync.md#mappings).

### Legacy Format (pair.txt)

```text
# Secret name = folder path
myapp-dotenvx-key=services/myapp
auth-service-key=services/auth

# With a vault-name prefix (parsed but informational only — does NOT route)
myvault/api-service-key=services/api
```

**Format:** `secret-name=folder-path` or `vault-name/secret-name=folder-path`

The optional `vault-name/` prefix is parsed for backward compatibility but, like
the TOML `vault_name` field, is **informational only** — the secret is still
fetched from / pushed to the single configured vault (see the note above).

- Lines starting with `#` are comments
- Empty lines are ignored
- Whitespace is trimmed

`pair.txt` is still supported, but TOML is recommended for new setups because it captures provider defaults and mappings together.

## Examples

### Azure Key Vault

```bash
# Basic sync (provider + url in envdrift.toml)
envdrift sync -c envdrift.toml

# Override provider/url on the CLI if needed
envdrift sync -c envdrift.toml -p azure --vault-url https://myvault.vault.azure.net/

# Force update
envdrift sync -c envdrift.toml --force

# Verify mode (CI)
envdrift sync -c envdrift.toml --verify --ci
```

### AWS Secrets Manager

```bash
# Default region (from TOML)
envdrift sync -c envdrift.toml

# Override region
envdrift sync -c envdrift.toml --region us-west-2

# CI mode with decryption check
envdrift sync -c envdrift.toml --check-decryption --ci
```

### HashiCorp Vault

```bash
# Basic sync
envdrift sync -c envdrift.toml

# Production
envdrift sync -c envdrift.toml --verify
```

### CI/CD Integration

These snippets pin `-c envdrift.toml` so CI runs use the intended config even if the working directory differs.
If your pipeline runs at the repo root and auto-discovery is reliable, you can omit `-c`.

#### GitHub Actions

```yaml
jobs:
  sync-keys:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Azure Login
        uses: azure/login@v1
        with:
          creds: ${{ secrets.AZURE_CREDENTIALS }}

      - name: Sync encryption keys
        run: |
          pip install envdrift[azure]
          envdrift sync -c envdrift.toml --check-decryption --ci
```

#### AWS with OIDC

```yaml
jobs:
  sync-keys:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789:role/github-actions
          aws-region: us-east-1

      - name: Sync encryption keys
        run: |
          pip install envdrift[aws]
          envdrift sync -c envdrift.toml --check-decryption --ci
```

## Modes

### Interactive Mode (default)

Prompts for confirmation when values mismatch.

```text
Value mismatch for myapp-key:
  Local:  abc123def456...
  Vault:  xyz789abc012...
Update local file with vault value? (y/N):
```

### Verify Mode (`--verify`)

Reports differences without modifying files. Mismatches are reported as errors, but the command exits non-zero only when combined with `--ci`
(use `--verify --ci` to fail the build on mismatch).

```text
  x services/myapp - error
    Error: Local value differs from vault
    Local:  abc123def456...
    Vault:  xyz789abc012...
```

Every error row carries its reason. A missing local key is reported with a
message that distinguishes a missing `.env.keys` file from a file that exists
but lacks the expected key:

```text
  x services/myapp - error
    Error: DOTENV_PRIVATE_KEY_PRODUCTION missing from services/myapp/.env.keys
```

### Force Mode (`--force`)

Updates all mismatches without prompting. Creates backups before updating.

```text
  ~ services/myapp - updated
    Backup: services/myapp/.env.keys.backup.20240115_143022
```

## Output

### Per-Service Status

```text
  + services/myapp - created
  ~ services/auth - updated
  = services/api - skipped
  * services/ci - ephemeral (key not stored locally)
  x services/broken - error
```

Icons:

- `+` - Created new .env.keys file
- `~` - Updated existing file
- `=` - Skipped (values match, or env file not created yet)
- `*` - Ephemeral (key fetched from vault, deliberately not stored locally)
- `x` - Error occurred (vault error, or the mapping's `folder_path` does not exist)

### Decryption Test Results

```text
  + services/myapp - created
    Decryption: PASSED
```

### Summary Panel

```text
╭──────────── Sync Summary ────────────╮
│ Services processed: 3                │
│ Created: 1                           │
│ Updated: 1                           │
│ Skipped: 1                           │
│ Errors: 0                            │
│                                      │
│ Decryption Tests:                    │
│   Passed: 2                          │
│   Failed: 0                          │
╰──────────────────────────────────────╯
All services synced successfully
```

When ephemeral mode is in use, the summary adds an `Ephemeral:` line counting
the services whose keys were fetched but deliberately not stored locally:

```text
│ Skipped: 0                           │
│ Ephemeral: 1 (not stored locally)    │
│ Errors: 0                            │
```

## Exit Codes

| Code | Meaning                                                                  |
| :--- | :------------------------------------------------------------------------ |
| 0    | Success (all synced, no errors)                                            |
| 1    | Error (vault error, sync failure, decryption failure)                      |
| 1    | `--ci`: any per-mapping error, including a `folder_path` that does not exist |
| 1    | `--check-decryption`: any decryption test failed (even without `--ci`)     |
| 1    | `--check-decryption`: dotenvx is not installed (nothing can be verified)    |

## Authentication

### Azure Key Vault

Uses Azure Identity's `DefaultAzureCredential`, which tries in order:

1. Environment variables (`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_CLIENT_SECRET`)
2. Managed Identity (in Azure)
3. Azure CLI (`az login`)
4. VS Code Azure extension
5. Interactive browser

### AWS Secrets Manager

Uses boto3's credential chain:

1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
2. Shared credential file (`~/.aws/credentials`)
3. IAM role (EC2, ECS, Lambda)

### HashiCorp Vault

For `sync`, the only supported authentication method is the `VAULT_TOKEN` environment variable.
(The vault client also accepts a `token` parameter, but that is internal/programmatic only and is not exposed as a CLI flag.)

## Security Notes

- `.env.keys` files are created with `600` permissions (owner read/write only)
- Backups are created before updates
- Never commit `.env.keys` to version control
- Add `.env.keys` to your `.gitignore`

## See Also

- [encrypt](encrypt.md) - Check/perform encryption
- [decrypt](decrypt.md) - Decrypt .env files
- [Env File Sync Guide](../guides/env-file-sync.md) - Detailed setup guide
