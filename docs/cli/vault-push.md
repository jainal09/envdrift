# envdrift vault-push

Push encryption keys from local `.env.keys` files to cloud vaults.
This command is specific to dotenvx keys; SOPS users should use their SOPS key management workflows.

## Synopsis

```bash
envdrift vault-push [OPTIONS] [FOLDER] [SECRET_NAME]
```

## Description

The `vault-push` command uploads `DOTENV_PRIVATE_KEY_*` secrets from local `.env.keys` files to cloud vaults.
This is the reverse of `envdrift sync` - it pushes local keys to the vault instead of pulling from it.

This enables secure key distribution by:

- Uploading newly generated encryption keys to centralized vault storage
- Sharing keys across team members and CI/CD pipelines
- Backing up encryption keys to secure cloud storage

Supported vault providers:

- **Azure Key Vault** - Microsoft Azure's secret management service
- **AWS Secrets Manager** - Amazon Web Services secret storage
- **HashiCorp Vault** - Open-source secrets management

## Modes

### Normal Mode (from .env.keys)

Reads a specific key from a `.env.keys` file and pushes it to the vault.

```bash
envdrift vault-push ./services/myapp my-secret-name --env production
```

This reads `DOTENV_PRIVATE_KEY_PRODUCTION` from `./services/myapp/.env.keys` and pushes it to the vault as `my-secret-name`.

### Direct Mode

Push a key-value pair directly without reading from a file.

```bash
envdrift vault-push --direct my-secret-name "DOTENV_PRIVATE_KEY_PROD=abc123..."
```

### All Services Mode

Push all secrets defined in the sync configuration. This mode automatically checks for
unencrypted files (encrypting them if needed) and pushes keys for any secrets
that are missing from the vault.

```bash
envdrift vault-push --all
```

To overwrite existing secrets instead of skipping them, add `--force`:

```bash
envdrift vault-push --all --force
```

## Options

### `FOLDER`

Path to the folder containing the `.env.keys` file (normal mode) or the secret name (direct mode).

### `SECRET_NAME`

Name for the secret in the vault (normal mode) or the value to push (direct mode).

### `--env`, `-e`

Environment suffix for the key name. Required in normal mode.

For example, `--env soak` looks for `DOTENV_PRIVATE_KEY_SOAK` in the `.env.keys` file.

### `--direct`

Enable direct mode. Push a key-value pair directly without reading from a file.

```bash
envdrift vault-push --direct secret-name "KEY=value" -p aws
```

### `--all`

Push all secrets defined in sync config (skipping existing unless `--force` is set).

### `--force`, `-f`

Push all secrets in `--all` mode even if they already exist.

### `--config`, `-c`

Path to sync config file (TOML).

### `--provider`, `-p`

Vault provider to use. Required unless configured in `envdrift.toml`.

Options: `azure`, `aws`, `hashicorp`, `gcp`

### `--vault-url`

Vault URL. **Required for Azure and HashiCorp** unless configured in `envdrift.toml`.

### `--region`

AWS region for Secrets Manager. Default: `us-east-1`.

### `--project-id`

GCP project ID for Secret Manager. Required for the `gcp` provider unless configured in `envdrift.toml`.

## Configuration

Settings can be configured in `envdrift.toml`:

```toml
[vault]
provider = "azure"

[vault.azure]
vault_url = "https://my-keyvault.vault.azure.net/"

[vault.aws]
region = "us-east-1"

[vault.hashicorp]
url = "https://vault.example.com:8200"

[vault.gcp]
project_id = "my-gcp-project"
```

When configured, you can omit the `--provider`, `--vault-url`, and `--project-id` flags.

## Examples

### Azure Key Vault

```bash
# Push from .env.keys file
envdrift vault-push ./services/myapp myapp-key --env production \
  -p azure --vault-url https://myvault.vault.azure.net/

# Using config from envdrift.toml
envdrift vault-push ./services/myapp myapp-key --env production
```

### AWS Secrets Manager

```bash
# Push from .env.keys file
envdrift vault-push ./services/myapp myapp-key --env staging -p aws

# With custom region
envdrift vault-push ./services/myapp myapp-key --env staging \
  -p aws --region us-west-2

# Direct mode
envdrift vault-push --direct myapp-staging-key \
  "DOTENV_PRIVATE_KEY_STAGING=abc123..." -p aws
```

### HashiCorp Vault

```bash
# Push from .env.keys file
envdrift vault-push ./services/myapp myapp-key --env dev \
  -p hashicorp --vault-url https://vault.example.com:8200
```

### CI/CD Integration

#### GitHub Actions

```yaml
jobs:
  push-keys:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Azure Login
        uses: azure/login@v1
        with:
          creds: ${{ secrets.AZURE_CREDENTIALS }}

      - name: Push encryption key to vault
        run: |
          pip install envdrift[azure]
          envdrift vault-push ./services/myapp myapp-key --env production
```

## Output

On success:

```text
Pushed secret 'myapp-key' to azure vault
  Version: abc123def456
```

On error:

```text
Error: Key 'DOTENV_PRIVATE_KEY_STAGING' not found in ./services/myapp/.env.keys
```

## Exit Codes

| Code | Meaning                                           |
| :--- | :------------------------------------------------ |
| 0    | Success (secret pushed)                           |
| 1    | Error (auth failure, file not found, vault error) |

## Authentication

### Azure Key Vault

Uses Azure Identity's `DefaultAzureCredential`:

1. Environment variables (`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_CLIENT_SECRET`)
2. Managed Identity (in Azure)
3. Azure CLI (`az login`)

### AWS Secrets Manager

Uses boto3's credential chain:

1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
2. Shared credential file (`~/.aws/credentials`)
3. IAM role (EC2, ECS, Lambda)

### HashiCorp Vault

1. `VAULT_TOKEN` environment variable

## Security Notes

- Ensure you have write permissions to the vault
- The secret value includes the full `KEY=value` format for compatibility with dotenvx
- Use CI/CD secrets or managed identities for authentication in production

## See Also

- [sync](sync.md) - Pull encryption keys from vaults to local files
- [encrypt](encrypt.md) - Check/perform encryption
- [Vault Sync Guide](../guides/vault-sync.md) - Detailed vault setup guide
