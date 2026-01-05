# Vault Providers

envdrift integrates with four cloud vault providers for team-wide encryption key sharing. This page compares them and helps you choose.

## Quick Comparison

| Feature | Azure Key Vault | AWS Secrets Manager | HashiCorp Vault | GCP Secret Manager |
|:--------|:----------------|:--------------------|:----------------|:-------------------|
| **Best for** | Azure shops | AWS shops | Multi-cloud | GCP shops |
| **Pricing** | Per operation | Per secret/month | Self-hosted or Cloud | Per operation |
| **Auth** | Azure AD/CLI | IAM roles/keys | Tokens, OIDC, etc. | Service accounts |
| **Setup** | Moderate | Easy | Complex | Easy |
| **Self-hosted** | No | No | Yes | No |

## Azure Key Vault

Best for teams already using Azure.

### Installation

```bash
pip install "envdrift[azure]"
```

### Authentication

Uses Azure Identity SDK's `DefaultAzureCredential`, which tries providers in this order:

1. **Environment variables** (`AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`)
2. **Workload Identity** (Kubernetes with Azure AD Workload Identity)
3. **Managed Identity** (VMs, App Service, Functions, etc.)
4. **Azure CLI** (`az login`)
5. **Azure PowerShell** (`Connect-AzAccount`)
6. **Azure Developer CLI** (`azd auth login`)
7. **Interactive Browser** (prompts for login)
8. **Visual Studio Code** (VS Code Azure extension)
9. **Shared Token Cache** (tokens cached by other Azure tools)

### Configuration

```toml
# envdrift.toml
[vault]
provider = "azure"

[vault.azure]
vault_url = "https://my-keyvault.vault.azure.net/"

[[vault.sync.mappings]]
secret_name = "myapp-dotenvx-key"
folder_path = "."
```

### CLI Usage

```bash
# Sync keys from Azure Key Vault
envdrift sync --provider azure --vault-url https://my-keyvault.vault.azure.net/

# Push keys to Azure Key Vault
envdrift vault-push . my-secret-name --provider azure --vault-url https://my-keyvault.vault.azure.net/
```

### Pros

- Native Azure AD integration
- Fine-grained access policies
- Audit logging built-in
- Managed HSM option for high security

### Cons

- Azure-only
- Requires Azure subscription
- Can be complex to set up permissions

## AWS Secrets Manager

Best for teams already using AWS.

### Installation

```bash
pip install "envdrift[aws]"
```

### Authentication

Uses boto3's credential chain, which tries providers in this order:

1. **Explicit credentials** passed to `boto3.client()` or `boto3.Session()`
2. **Environment variables** (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`)
3. **Assume Role providers** (profiles with `role_arn` and `source_profile`)
4. **Assume Role with Web Identity** (IRSA for Kubernetes, web identity tokens)
5. **AWS IAM Identity Center (SSO)** credential provider
6. **Shared credentials file** (`~/.aws/credentials`)
7. **AWS config file** (`~/.aws/config`)
8. **Container credential provider** (ECS/EKS task roles)
9. **Instance Metadata Service (IMDS)** (EC2 instance profile)

### Configuration

```toml
# envdrift.toml
[vault]
provider = "aws"

[vault.aws]
region = "us-east-1"

[[vault.sync.mappings]]
secret_name = "myapp/dotenvx-key"
folder_path = "."
```

### CLI Usage

```bash
# Sync keys from AWS Secrets Manager
envdrift sync --provider aws --region us-east-1

# Push keys
envdrift vault-push . my-secret-name --provider aws --region us-east-1
```

### Pros

- Simple IAM-based permissions
- Automatic rotation support
- Cross-region replication
- Well-documented

### Cons

- AWS-only
- Per-secret pricing can add up
- No local/self-hosted option

## HashiCorp Vault

Best for multi-cloud or self-hosted requirements.

### Installation

```bash
pip install "envdrift[hashicorp]"
```

### Authentication

Uses the `hvac` library with multiple auth methods:

1. Token (`VAULT_TOKEN` environment variable)
2. AppRole
3. OIDC
4. Kubernetes
5. Many others

### Configuration

```toml
# envdrift.toml
[vault]
provider = "hashicorp"

[vault.hashicorp]
url = "https://vault.example.com"
# token = "hvs.xxx"  # Or use VAULT_TOKEN env var

[[vault.sync.mappings]]
secret_name = "secret/data/myapp/dotenvx-key"
folder_path = "."
```

### CLI Usage

```bash
# Set token
export VAULT_TOKEN="hvs.xxx"

# Sync keys
envdrift sync --provider hashicorp --vault-url https://vault.example.com

# Push keys
envdrift vault-push . myapp/dotenvx-key --provider hashicorp --vault-url https://vault.example.com
```

### Pros

- Self-hosted option
- Multi-cloud support
- Extremely flexible auth
- Dynamic secrets, leases, rotation
- Open source

### Cons

- Complex to set up and maintain
- Requires infrastructure knowledge
- Self-hosted = self-managed

## GCP Secret Manager

Best for teams already using Google Cloud.

### Installation

```bash
pip install "envdrift[gcp]"
```

### Authentication

Uses Google Cloud's Application Default Credentials (ADC), which tries providers in this order:

1. **`GOOGLE_APPLICATION_CREDENTIALS` env var** → path to service account JSON key
2. **User credentials** from `gcloud auth application-default login`
3. **Attached service account** via metadata server (GCE, GKE, Cloud Run, Cloud Functions)
4. **Workload Identity Federation** (for non-GCP identity providers and CI/CD)

### Configuration

```toml
# envdrift.toml
[vault]
provider = "gcp"

[vault.gcp]
project_id = "my-gcp-project"

[[vault.sync.mappings]]
secret_name = "myapp-dotenvx-key"
folder_path = "."
```

### CLI Usage

```bash
# Sync keys from GCP Secret Manager
envdrift sync --provider gcp --project-id my-gcp-project

# Push keys
envdrift vault-push . my-secret-name --provider gcp --project-id my-gcp-project
```

### Pros

- Simple GCP IAM integration
- Automatic replication
- Version history
- Pay-per-use pricing

### Cons

- GCP-only
- Requires GCP project
- Less feature-rich than HashiCorp Vault

## Choosing a Provider

| If you... | Use... |
|:----------|:-------|
| Already use Azure | Azure Key Vault |
| Already use AWS | AWS Secrets Manager |
| Already use GCP | GCP Secret Manager |
| Need multi-cloud | HashiCorp Vault |
| Need self-hosted | HashiCorp Vault |
| Want simplest setup | AWS Secrets Manager or GCP |
| Need enterprise features | HashiCorp Vault or Azure |

## Common Configuration

All providers share the same sync mapping structure:

```toml
[[vault.sync.mappings]]
# Required: secret name in vault
secret_name = "myapp-dotenvx-key"

# Required: local folder with .env.keys
folder_path = "services/myapp"

# Optional: environment suffix (for DOTENV_PRIVATE_KEY_PRODUCTION, etc.)
environment = "production"

# Optional: profile for filtering
profile = "local"

# Optional: copy decrypted file to this path
activate_to = ".env.production"
```

## Multiple Providers

You can use different providers for different environments:

```toml
# Production uses Azure
[[vault.sync.mappings]]
secret_name = "prod-key"
folder_path = "."
environment = "production"
# Uses default provider (azure)

# Local dev uses HashiCorp
[[vault.sync.mappings]]
secret_name = "local-key"
folder_path = "."
profile = "local"
# Override with --provider hashicorp when syncing
```

## CI/CD Integration

See the [CI/CD Guide](../guides/cicd.md) for provider-specific authentication in pipelines.

Quick examples:

```yaml
# GitHub Actions - Azure
- uses: azure/login@v1
  with:
    creds: ${{ secrets.AZURE_CREDENTIALS }}
- run: envdrift sync --provider azure

# GitHub Actions - AWS
- uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: arn:aws:iam::123456789:role/my-role
- run: envdrift sync --provider aws

# GitHub Actions - GCP
- uses: google-github-actions/auth@v2
  with:
    credentials_json: ${{ secrets.GCP_SA_KEY }}
- run: envdrift sync --provider gcp --project-id my-project
```
