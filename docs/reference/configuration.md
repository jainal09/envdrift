# Configuration Reference

envdrift can be configured using a TOML configuration file. This page documents all available options.

## Configuration Files

envdrift looks for configuration in this order:

1. Explicit `--config` flag on CLI commands
2. `envdrift.toml` in current directory
3. `envdrift.toml` in parent directories (up to root)
4. `pyproject.toml` with `[tool.envdrift]` section

## File Formats

### envdrift.toml

```toml
[envdrift]
schema = "config:Settings"

[vault]
provider = "azure"
# ... vault settings ...

[encryption]
backend = "dotenvx"
# ... encryption settings ...

[guard]
scanners = ["native", "gitleaks"]
# ... guard settings ...
```

### pyproject.toml

```toml
[tool.envdrift]
schema = "config:Settings"

[tool.envdrift.vault]
provider = "azure"
# ... vault settings ...

[tool.envdrift.encryption]
backend = "dotenvx"
# ... encryption settings ...

[tool.envdrift.guard]
scanners = ["native", "gitleaks"]
# ... guard settings ...
```

## Sections

### [envdrift] — Core Settings

Core configuration options for envdrift.

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `schema` | `string` | `null` | Default schema path for validation (e.g., `config:Settings`) |
| `environments` | `list[string]` | `["development", "staging", "production"]` | List of environment names |
| `env_file_pattern` | `string` | `".env.{environment}"` | Pattern for .env file names (`{environment}` is replaced) |

```toml
[envdrift]
schema = "config.settings:ProductionSettings"
environments = ["development", "staging", "production"]
env_file_pattern = ".env.{environment}"
```

### [validation] — Validation Settings

Controls how `envdrift validate` behaves.

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `check_encryption` | `bool` | `true` | Warn if sensitive fields are not encrypted |
| `strict_extra` | `bool` | `true` | Treat extra variables as errors (matches `extra="forbid"`) |
| `secret_patterns` | `list[string]` | `[]` | Additional regex patterns for detecting sensitive variables |

```toml
[validation]
check_encryption = true
strict_extra = true
secret_patterns = [
    "^STRIPE_",
    "^TWILIO_",
    "^SENDGRID_",
]
```

### [guard] — Secret Scanning Settings

Configuration for the `envdrift guard` command.

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `scanners` | `list[string]` | `["native", "gitleaks"]` | Scanners to enable (`native`, `gitleaks`, `trufflehog`, `detect-secrets`) |
| `auto_install` | `bool` | `true` | Auto-install missing external scanners |
| `include_history` | `bool` | `false` | Scan git history for secrets |
| `check_entropy` | `bool` | `false` | Enable entropy detection in the native scanner |
| `entropy_threshold` | `float` | `4.5` | Minimum entropy to flag a value as suspicious |
| `fail_on_severity` | `string` | `"high"` | Severity threshold used by `envdrift guard --ci` |
| `ignore_paths` | `list[string]` | `[]` | Glob patterns ignored by the native scanner |
| `verify_secrets` | `bool` | `false` | Reserved for future verified secret checks |

```toml
[guard]
scanners = ["native", "gitleaks", "trufflehog", "detect-secrets"]
auto_install = true
include_history = false
check_entropy = true
entropy_threshold = 4.5
fail_on_severity = "high"
ignore_paths = ["tests/**", "*.test.py"]
verify_secrets = false
```

Notes:

- `ignore_paths` applies to the native scanner's file walk.
- `scanners` can be set under `[tool.envdrift.guard]` in `pyproject.toml`.

### [encryption] — Encryption Settings

Configuration for encryption backends.

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `backend` | `string` | `"dotenvx"` | Encryption backend: `dotenvx` or `sops` |

```toml
[encryption]
backend = "dotenvx"
```

#### [encryption.dotenvx] — dotenvx Settings

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `auto_install` | `bool` | `false` | Automatically install dotenvx if not found |

```toml
[encryption.dotenvx]
auto_install = true
```

#### [encryption.sops] — SOPS Settings

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `auto_install` | `bool` | `false` | Automatically install SOPS if not found |
| `config_file` | `string` | `null` | Path to `.sops.yaml` configuration file |
| `age_key_file` | `string` | `null` | Path to age private key file |
| `age_recipients` | `string` | `null` | Age public key(s) for encryption |
| `kms_arn` | `string` | `null` | AWS KMS key ARN |
| `gcp_kms` | `string` | `null` | GCP KMS resource ID |
| `azure_kv` | `string` | `null` | Azure Key Vault key URL |

```toml
[encryption.sops]
auto_install = false
config_file = ".sops.yaml"
age_key_file = "~/.config/sops/age/keys.txt"
age_recipients = "age1abc..."
# Or use cloud KMS:
# kms_arn = "arn:aws:kms:us-east-1:123456789:key/abc-123"
# gcp_kms = "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key"
# azure_kv = "https://my-vault.vault.azure.net/keys/my-key/abc123"
```

### [vault] — Vault Provider Settings

Configuration for cloud vault integration.

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `provider` | `string` | `"azure"` | Vault provider: `azure`, `aws`, `hashicorp`, `gcp` |

```toml
[vault]
provider = "azure"
```

#### [vault.azure] — Azure Key Vault Settings

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `vault_url` | `string` | `null` | Azure Key Vault URL (e.g., `https://my-vault.vault.azure.net/`) |

```toml
[vault.azure]
vault_url = "https://my-keyvault.vault.azure.net/"
```

#### [vault.aws] — AWS Secrets Manager Settings

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `region` | `string` | `"us-east-1"` | AWS region |

```toml
[vault.aws]
region = "us-east-1"
```

#### [vault.hashicorp] — HashiCorp Vault Settings

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `url` | `string` | `null` | HashiCorp Vault URL |

```toml
[vault.hashicorp]
url = "https://vault.example.com:8200"
# Token is read from VAULT_TOKEN environment variable
```

#### [vault.gcp] — GCP Secret Manager Settings

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `project_id` | `string` | `null` | GCP project ID |

```toml
[vault.gcp]
project_id = "my-gcp-project"
```

### [vault.sync] — Vault Sync Settings

Configuration for the `envdrift sync`, `envdrift pull`, and `envdrift lock` commands.

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `default_vault_name` | `string` | `null` | Default vault name for mappings |
| `env_keys_filename` | `string` | `".env.keys"` | Name of the keys file |
| `max_workers` | `int \| None` | `null` | Parallel workers for pull/lock file operations |
| `ephemeral_keys` | `bool` | `false` | Never store `.env.keys` locally; fetch from vault on-demand |

```toml
[vault.sync]
default_vault_name = "my-keyvault"
env_keys_filename = ".env.keys"
max_workers = 4
ephemeral_keys = false  # Set true to never store keys locally
```

#### [[vault.sync.mappings]] — Sync Mappings

Each mapping defines how a vault secret maps to a local service directory.

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `secret_name` | `string` | **required** | Name of the secret in the vault |
| `folder_path` | `string` | **required** | Local folder containing .env.keys |
| `vault_name` | `string` | `null` | Override default vault name |
| `environment` | `string` | `null` | Environment suffix (e.g., `production` for `DOTENV_PRIVATE_KEY_PRODUCTION`) |
| `profile` | `string` | `null` | Profile name for filtering with `--profile` |
| `activate_to` | `string` | `null` | Path to copy decrypted file when profile is activated |
| `ephemeral_keys` | `bool` | `null` | Per-mapping override for ephemeral mode |

```toml
# Basic mapping
[[vault.sync.mappings]]
secret_name = "myapp-dotenvx-key"
folder_path = "."
environment = "production"

# Mapping with vault override
[[vault.sync.mappings]]
secret_name = "service2-key"
folder_path = "services/service2"
vault_name = "other-vault"
environment = "staging"

# Profile mapping (used with --profile)
[[vault.sync.mappings]]
secret_name = "local-dev-key"
folder_path = "."
profile = "local"
activate_to = ".env"  # Copy .env.local to .env after decrypt

# Ephemeral mapping (never stores keys locally for this service)
[[vault.sync.mappings]]
secret_name = "ci-service-key"
folder_path = "services/ci"
ephemeral_keys = true  # Always fetch from vault
```

### [precommit] — Pre-commit Hook Settings

Configuration for pre-commit hook integration.

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `files` | `list[string]` | `[]` | Files to validate on commit |
| `schemas` | `dict[string, string]` | `{}` | Per-file schema overrides |

```toml
[precommit]
files = [
    ".env.production",
    ".env.staging",
]

[precommit.schemas]
".env.production" = "config.settings:ProductionSettings"
".env.staging" = "config.settings:StagingSettings"
```

### [partial_encryption] — Partial Encryption Settings

Configuration for the partial encryption feature (separate clear and secret files).

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `enabled` | `bool` | `false` | Enable partial encryption |

```toml
[partial_encryption]
enabled = true
```

#### [[partial_encryption.environments]] — Environment Configuration

Each environment defines the file structure for partial encryption.

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `name` | `string` | **required** | Environment name |
| `clear_file` | `string` | **required** | Path to cleartext (non-sensitive) variables |
| `secret_file` | `string` | **required** | Path to secret (encrypted) variables |
| `combined_file` | `string` | **required** | Path to combined output file |

```toml
[[partial_encryption.environments]]
name = "production"
clear_file = ".env.production.clear"
secret_file = ".env.production.secret"
combined_file = ".env.production"

[[partial_encryption.environments]]
name = "staging"
clear_file = ".env.staging.clear"
secret_file = ".env.staging.secret"
combined_file = ".env.staging"
```

## Complete Example

```toml
# envdrift.toml

[envdrift]
schema = "config.settings:Settings"
environments = ["development", "staging", "production"]
env_file_pattern = ".env.{environment}"

[validation]
check_encryption = true
strict_extra = true
secret_patterns = ["^STRIPE_", "^TWILIO_"]

[guard]
scanners = ["native", "gitleaks"]
fail_on_severity = "high"
ignore_paths = ["tests/**"]

[encryption]
backend = "dotenvx"

[encryption.dotenvx]
auto_install = true

[vault]
provider = "azure"

[vault.azure]
vault_url = "https://my-keyvault.vault.azure.net/"

[vault.sync]
default_vault_name = "my-keyvault"
env_keys_filename = ".env.keys"

[[vault.sync.mappings]]
secret_name = "app-prod-key"
folder_path = "."
environment = "production"

[[vault.sync.mappings]]
secret_name = "app-staging-key"
folder_path = "."
environment = "staging"

[[vault.sync.mappings]]
secret_name = "app-local-key"
folder_path = "."
profile = "local"
activate_to = ".env"

[precommit]
files = [".env.production", ".env.staging"]

[precommit.schemas]
".env.production" = "config.settings:ProductionSettings"
".env.staging" = "config.settings:StagingSettings"
```

## Environment Variables

Some settings can be overridden with environment variables:

| Variable | Description |
|:---------|:------------|
| `DOTENV_PRIVATE_KEY` | dotenvx private key for decryption |
| `DOTENV_PRIVATE_KEY_{ENV}` | Environment-specific private key |
| `SOPS_AGE_KEY_FILE` | Path to age private key file |
| `VAULT_TOKEN` | HashiCorp Vault token |
| `AZURE_CLIENT_ID` | Azure service principal client ID |
| `AZURE_CLIENT_SECRET` | Azure service principal secret |
| `AZURE_TENANT_ID` | Azure tenant ID |
| `AWS_ACCESS_KEY_ID` | AWS access key |
| `AWS_SECRET_ACCESS_KEY` | AWS secret key |
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to GCP service account key |
| `ENVDRIFT_SCHEMA_EXTRACTION` | Set to skip Settings instantiation during schema extraction |

## See Also

- [Encryption Backends](../concepts/encryption-backends.md) — Compare dotenvx vs SOPS
- [Vault Providers](../concepts/vault-providers.md) — Compare cloud vault providers
- [Vault Sync Guide](../guides/vault-sync.md) — Detailed vault sync setup
