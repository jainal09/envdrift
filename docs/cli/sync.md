# envdrift sync

Sync encryption keys from cloud vaults to local .env.keys files.

## Synopsis

```bash
envdrift sync [OPTIONS]
```

## Description

The `sync` command fetches `DOTENV_PRIVATE_KEY_*` secrets from cloud vaults and synchronizes them to local `.env.keys` files for dotenvx decryption.

This enables secure key distribution without committing keys to source control. Keys are stored in cloud vaults (Azure Key Vault, AWS Secrets Manager,
or HashiCorp Vault) and synced to local development environments or CI/CD pipelines.

Supported vault providers:

- **Azure Key Vault** - Microsoft Azure's secret management service
- **AWS Secrets Manager** - Amazon Web Services secret storage
- **HashiCorp Vault** - Open-source secrets management

## Options

### `--config`, `-c`

Path to sync configuration file (pair.txt format). **Required.**

```bash
envdrift sync --config pair.txt -p azure --vault-url https://myvault.vault.azure.net/
```

### `--provider`, `-p`

Vault provider to use. **Required.**

Options: `azure`, `aws`, `hashicorp`

```bash
envdrift sync -c pair.txt --provider azure --vault-url https://myvault.vault.azure.net/
envdrift sync -c pair.txt --provider aws --region us-west-2
envdrift sync -c pair.txt --provider hashicorp --vault-url http://localhost:8200
```

### `--vault-url`

Vault URL. **Required for Azure and HashiCorp.**

```bash
# Azure Key Vault
envdrift sync -c pair.txt -p azure --vault-url https://myvault.vault.azure.net/

# HashiCorp Vault
envdrift sync -c pair.txt -p hashicorp --vault-url http://localhost:8200
```

### `--region`

AWS region for Secrets Manager. Default: `us-east-1`.

```bash
envdrift sync -c pair.txt -p aws --region us-west-2
```

### `--verify`

Check only mode. Reports differences without modifying files.

```bash
envdrift sync -c pair.txt -p azure --vault-url $URL --verify
```

Use this in CI/CD to verify keys are in sync without making changes.

### `--force`, `-f`

Force update all mismatches without prompting.

```bash
envdrift sync -c pair.txt -p azure --vault-url $URL --force
```

### `--check-decryption`

After syncing, verify that the keys can decrypt `.env` files.

```bash
envdrift sync -c pair.txt -p azure --vault-url $URL --check-decryption
```

This tests actual decryption using dotenvx to ensure keys are valid.

### `--validate-schema`

Run schema validation after sync.

```bash
envdrift sync -c pair.txt -p azure --vault-url $URL --validate-schema --schema config.settings:Settings
```

### `--schema`, `-s`

Schema path for validation (used with `--validate-schema`).

```bash
envdrift sync -c pair.txt -p azure --vault-url $URL --validate-schema -s config.settings:Settings
```

### `--service-dir`, `-d`

Service directory for schema imports.

```bash
envdrift sync -c pair.txt -p azure --vault-url $URL --validate-schema -s config.settings:Settings -d ./backend
```

### `--ci`

CI mode. Exit with code 1 on any errors.

```bash
envdrift sync -c pair.txt -p azure --vault-url $URL --verify --ci
```

## Configuration File Format

### Simple Format (pair.txt)

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

### TOML Format

In `envdrift.toml`:

```toml
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

## Examples

### Azure Key Vault

```bash
# Basic sync
envdrift sync -c pair.txt -p azure --vault-url https://myvault.vault.azure.net/

# Force update
envdrift sync -c pair.txt -p azure --vault-url https://myvault.vault.azure.net/ --force

# Verify mode (CI)
envdrift sync -c pair.txt -p azure --vault-url $VAULT_URL --verify --ci
```

### AWS Secrets Manager

```bash
# Default region (us-east-1)
envdrift sync -c pair.txt -p aws

# Specific region
envdrift sync -c pair.txt -p aws --region us-west-2

# CI mode with decryption check
envdrift sync -c pair.txt -p aws --region us-west-2 --check-decryption --ci
```

### HashiCorp Vault

```bash
# Basic sync
envdrift sync -c pair.txt -p hashicorp --vault-url http://localhost:8200

# Production
envdrift sync -c pair.txt -p hashicorp --vault-url https://vault.example.com --verify
```

### CI/CD Integration

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
          envdrift sync -c pair.txt -p azure \
            --vault-url ${{ secrets.VAULT_URL }} \
            --check-decryption --ci
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
          envdrift sync -c pair.txt -p aws --check-decryption --ci
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
