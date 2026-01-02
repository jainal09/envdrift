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

Use this in CI/CD to verify keys are in sync without making changes.

### `--force`, `-f`

Force update all mismatches without prompting.

### `--check-decryption`

After syncing, verify that the keys can decrypt `.env` files.

This tests actual decryption using dotenvx to ensure keys are valid.

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
vault_name = "other-vault"  # Override default
environment = "staging"     # Use DOTENV_PRIVATE_KEY_STAGING
```

Place the file in the project root so auto-discovery finds it; pass `-c envdrift.toml` in CI to pin the exact file.

### Legacy Format (pair.txt)

```text
# Secret name = folder path
myapp-dotenvx-key=services/myapp
auth-service-key=services/auth

# With explicit vault name
myvault/api-service-key=services/api
```

**Format:** `secret-name=folder-path` or `vault-name/secret-name=folder-path`

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

Reports differences without modifying files. Returns exit code 1 if mismatches detected.

```text
  x services/myapp - error
    Error: Value mismatch detected
    Local:  abc123def456...
    Vault:  xyz789abc012...
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
  x services/broken - error
```

Icons:

- `+` - Created new .env.keys file
- `~` - Updated existing file
- `=` - Skipped (values match)
- `x` - Error occurred

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

## Exit Codes

| Code | Meaning                                               |
| :--- | :---------------------------------------------------- |
| 0    | Success (all synced, no errors)                       |
| 1    | Error (vault error, sync failure, decryption failure) |

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

1. `--token` option
2. `VAULT_TOKEN` environment variable

## Security Notes

- `.env.keys` files are created with `600` permissions (owner read/write only)
- Backups are created before updates
- Never commit `.env.keys` to version control
- Add `.env.keys` to your `.gitignore`

## See Also

- [encrypt](encrypt.md) - Check/perform encryption
- [decrypt](decrypt.md) - Decrypt .env files
- [Vault Sync Guide](../guides/vault-sync.md) - Detailed setup guide
