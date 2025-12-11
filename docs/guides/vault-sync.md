# Vault Sync Guide

This guide covers setting up vault synchronization to distribute encryption keys securely across your team and CI/CD pipelines.

## Overview

When using dotenvx for encryption, each environment has a private key stored in `.env.keys`. These keys:

- Should **never** be committed to version control
- Need to be **shared securely** with team members
- Must be **available in CI/CD** for decryption

The `envdrift sync` command solves this by storing keys in cloud vaults and syncing them to local environments.

## Architecture

```text
┌─────────────────┐
│   Cloud Vault   │
│  (Azure/AWS/HC) │
│                 │
│  ┌───────────┐  │
│  │ app-key   │  │
│  │ auth-key  │  │
│  │ api-key   │  │
│  └───────────┘  │
└────────┬────────┘
         │
         │ envdrift sync
         │
         ▼
┌─────────────────────────────────────┐
│         Local Environment           │
│                                     │
│  services/                          │
│    app/.env.keys    ◄── app-key     │
│    auth/.env.keys   ◄── auth-key    │
│    api/.env.keys    ◄── api-key     │
│                                     │
└─────────────────────────────────────┘
```

## Quick Start

### 1. Install with vault support

```bash
# Azure Key Vault
pip install envdrift[azure]

# AWS Secrets Manager
pip install envdrift[aws]

# HashiCorp Vault
pip install envdrift[hashicorp]

# All providers
pip install envdrift[vault]
```

### 2. Create a configuration file

Create `pair.txt` in your project root:

```text
# Format: secret-name=folder-path
myapp-dotenvx-key=services/myapp
auth-service-dotenvx-key=services/auth
```

### 3. Store your keys in the vault

**Azure Key Vault:**

```bash
az keyvault secret set \
  --vault-name my-keyvault \
  --name myapp-dotenvx-key \
  --value "$(cat services/myapp/.env.keys | grep DOTENV_PRIVATE_KEY_PRODUCTION | cut -d'=' -f2)"
```

**AWS Secrets Manager:**

```bash
aws secretsmanager create-secret \
  --name myapp-dotenvx-key \
  --secret-string "$(cat services/myapp/.env.keys | grep DOTENV_PRIVATE_KEY_PRODUCTION | cut -d'=' -f2)"
```

**HashiCorp Vault:**

```bash
vault kv put secret/myapp-dotenvx-key \
  value="$(cat services/myapp/.env.keys | grep DOTENV_PRIVATE_KEY_PRODUCTION | cut -d'=' -f2)"
```

### 4. Sync keys locally

```bash
# Azure
envdrift sync -c pair.txt -p azure --vault-url https://my-keyvault.vault.azure.net/

# AWS
envdrift sync -c pair.txt -p aws --region us-east-1

# HashiCorp
envdrift sync -c pair.txt -p hashicorp --vault-url http://localhost:8200
```

## Provider Setup

### Azure Key Vault

#### Prerequisites

1. Azure CLI installed and logged in
2. Key Vault created
3. Access policy configured

#### Authentication Methods

**Environment Variables:**

```bash
export AZURE_CLIENT_ID="..."
export AZURE_TENANT_ID="..."
export AZURE_CLIENT_SECRET="..."
```

**Azure CLI:**

```bash
az login
```

**Managed Identity (in Azure):**
No configuration needed - automatically uses the VM/App Service identity.

#### Access Policy

Grant your identity these permissions:

- **Get** - Read secrets
- **List** - List secret names

```bash
az keyvault set-policy \
  --name my-keyvault \
  --upn user@example.com \
  --secret-permissions get list
```

#### Example

```bash
# Login
az login

# Sync
envdrift sync -c pair.txt -p azure --vault-url https://my-keyvault.vault.azure.net/
```

### AWS Secrets Manager

#### Prerequisites

1. AWS CLI configured
2. IAM permissions for Secrets Manager

#### Authentication Methods

**Environment Variables:**

```bash
export AWS_ACCESS_KEY_ID="..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_REGION="us-east-1"
```

**Credentials File:**

```ini
# ~/.aws/credentials
[default]
aws_access_key_id = ...
aws_secret_access_key = ...
```

**IAM Role (EC2/ECS/Lambda):**
No configuration needed - automatically uses instance profile.

#### IAM Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:ListSecrets"
      ],
      "Resource": "arn:aws:secretsmanager:us-east-1:123456789:secret:*-dotenvx-key*"
    }
  ]
}
```

#### Example

```bash
# Configure credentials
aws configure

# Sync
envdrift sync -c pair.txt -p aws --region us-east-1
```

### HashiCorp Vault

#### Prerequisites

1. Vault server running
2. Token with read access
3. KV v2 secrets engine enabled

#### Authentication

**Environment Variable:**

```bash
export VAULT_TOKEN="hvs.xxx..."
```

**Token File:**

```bash
vault login -method=userpass username=myuser
# Token saved to ~/.vault-token
```

#### Policy

```hcl
path "secret/data/*" {
  capabilities = ["read", "list"]
}
```

#### Example

```bash
# Login
vault login

# Sync
envdrift sync -c pair.txt -p hashicorp --vault-url http://localhost:8200
```

## Configuration

### Simple Format (pair.txt)

```text
# Comments start with #
secret-name=folder-path

# Multiple services
myapp-dotenvx-key=services/myapp
auth-service-key=services/auth-service
api-gateway-key=services/api

# With explicit vault name (Azure)
production-vault/prod-key=services/prod
```

### TOML Format (envdrift.toml)

```toml
[vault.sync]
default_vault_name = "my-keyvault"
env_keys_filename = ".env.keys"

[[vault.sync.mappings]]
secret_name = "myapp-key"
folder_path = "services/myapp"

[[vault.sync.mappings]]
secret_name = "auth-key"
folder_path = "services/auth"
environment = "staging"  # Use DOTENV_PRIVATE_KEY_STAGING

[[vault.sync.mappings]]
secret_name = "prod-key"
folder_path = "services/prod"
vault_name = "production-vault"  # Override default
```

## CI/CD Integration

### GitHub Actions - Azure

```yaml
name: Deploy

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Azure Login
        uses: azure/login@v1
        with:
          creds: ${{ secrets.AZURE_CREDENTIALS }}

      - name: Install envdrift
        run: pip install envdrift[azure]

      - name: Sync encryption keys
        run: |
          envdrift sync -c pair.txt -p azure \
            --vault-url ${{ secrets.VAULT_URL }} \
            --force --ci

      - name: Decrypt environment files
        run: envdrift decrypt .env.production

      - name: Deploy
        run: ./deploy.sh
```

### GitHub Actions - AWS with OIDC

```yaml
name: Deploy

on:
  push:
    branches: [main]

permissions:
  id-token: write
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789:role/github-actions
          aws-region: us-east-1

      - name: Install envdrift
        run: pip install envdrift[aws]

      - name: Sync and verify keys
        run: |
          envdrift sync -c pair.txt -p aws \
            --check-decryption --ci
```

### GitLab CI

```yaml
deploy:
  image: python:3.11
  script:
    - pip install envdrift[azure]
    - envdrift sync -c pair.txt -p azure --vault-url $VAULT_URL --force --ci
    - envdrift decrypt .env.production
    - ./deploy.sh
  variables:
    AZURE_CLIENT_ID: $AZURE_CLIENT_ID
    AZURE_TENANT_ID: $AZURE_TENANT_ID
    AZURE_CLIENT_SECRET: $AZURE_CLIENT_SECRET
```

## Workflows

### Initial Setup

1. **Generate encryption keys locally:**

   ```bash
   dotenvx encrypt .env.production
   # Creates .env.keys with DOTENV_PRIVATE_KEY_PRODUCTION
   ```

2. **Store key in vault:**

   ```bash
   az keyvault secret set \
     --vault-name my-keyvault \
     --name myapp-dotenvx-key \
     --value "$(grep DOTENV_PRIVATE_KEY_PRODUCTION .env.keys | cut -d'=' -f2)"
   ```

3. **Create pair.txt:**

   ```text
   myapp-dotenvx-key=.
   ```

4. **Add .env.keys to .gitignore:**

   ```text
   .env.keys
   ```

5. **Commit encrypted .env files:**

   ```bash
   git add .env.production pair.txt
   git commit -m "Add encrypted environment"
   ```

### New Team Member Onboarding

1. Clone the repository
2. Get vault access from team lead
3. Run sync:

   ```bash
   envdrift sync -c pair.txt -p azure --vault-url https://my-keyvault.vault.azure.net/
   ```

4. Decrypt for local development:

   ```bash
   envdrift decrypt .env.development
   ```

### Key Rotation

1. Generate new key:

   ```bash
   dotenvx encrypt .env.production --rotate
   ```

2. Update vault:

   ```bash
   az keyvault secret set \
     --vault-name my-keyvault \
     --name myapp-dotenvx-key \
     --value "$(grep DOTENV_PRIVATE_KEY_PRODUCTION .env.keys | cut -d'=' -f2)"
   ```

3. Team syncs:

   ```bash
   envdrift sync -c pair.txt -p azure --vault-url $URL --force
   ```

## Troubleshooting

### Authentication Errors

**Azure:**

```bash
# Check login status
az account show

# Re-login
az login
```

**AWS:**

```bash
# Check credentials
aws sts get-caller-identity

# Check region
echo $AWS_REGION
```

**HashiCorp:**

```bash
# Check token
vault token lookup

# Re-login
vault login
```

### Secret Not Found

Check secret name matches exactly:

```bash
# Azure
az keyvault secret list --vault-name my-keyvault

# AWS
aws secretsmanager list-secrets

# HashiCorp
vault kv list secret/
```

### Permission Denied

Verify your identity has required permissions:

- Azure: Get, List on Key Vault secrets
- AWS: secretsmanager:GetSecretValue, secretsmanager:ListSecrets
- HashiCorp: read, list on secret path

### Verify Mode Fails

Use `--verify` to check without modifying:

```bash
envdrift sync -c pair.txt -p azure --vault-url $URL --verify
```

This shows what would change without making modifications.

## Best Practices

1. **Use separate vaults per environment** - Production keys in production vault
2. **Rotate keys regularly** - Especially after team changes
3. **Limit vault access** - Only CI/CD and necessary team members
4. **Use OIDC in CI/CD** - Avoid storing long-lived credentials
5. **Verify in CI before deploy** - Use `--check-decryption --ci`
6. **Backup keys** - Store copies in secure location

## See Also

- [sync command](../cli/sync.md) - CLI reference
- [encrypt](../cli/encrypt.md) - Encryption command
- [decrypt](../cli/decrypt.md) - Decryption command
