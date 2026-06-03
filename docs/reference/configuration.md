# Configuration Reference

envdrift can be configured using a TOML configuration file. This page documents all available options.

## Configuration Files

envdrift resolves configuration as follows:

1. An explicit `--config` flag on CLI commands always wins.
2. Otherwise, envdrift walks upward from the current directory to the
   filesystem root. In each directory it checks `envdrift.toml` first, then a
   `pyproject.toml` containing a `[tool.envdrift]` section, before moving to the
   parent directory.

The nearest directory wins overall, and within a single directory `envdrift.toml`
takes precedence over `pyproject.toml`. As a result, a nearer directory's
`pyproject.toml` outranks a farther parent's `envdrift.toml`.

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

```toml
[envdrift]
schema = "config.settings:ProductionSettings"
environments = ["development", "staging", "production"]
```

### [validation] — Validation Settings

Settings parsed under the `[validation]` section.

> **Note:** `envdrift validate` does not currently read these keys. The command
> always loads its options from CLI flags (for example
> `--check-encryption/--no-check-encryption`, default on) and always treats
> extra variables as errors. `strict_extra` and `secret_patterns` are parsed
> into the config object but are not yet consumed by any command, so setting
> them has no effect on validation behavior today.

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `check_encryption` | `bool` | `true` | Parsed but not consumed; the same-named `--check-encryption/--no-check-encryption` CLI flag (default on) controls this instead |
| `strict_extra` | `bool` | `true` | Parsed but not consumed; extra variables are always treated as errors |
| `secret_patterns` | `list[string]` | `[]` | Parsed but not consumed; no command reads these patterns |

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
| `scanners` | `list[string]` | `["native", "gitleaks"]` | Scanners to enable (`native`, `gitleaks`, `trufflehog`, `detect-secrets`, `kingfisher`, `git-secrets`, `talisman`, `trivy`, `infisical`) |
| `auto_install` | `bool` | `true` | Auto-install missing external scanners |
| `include_history` | `bool` | `false` | Scan git history for secrets |
| `check_entropy` | `bool` | `false` | Enable entropy detection in the native scanner |
| `entropy_threshold` | `float` | `4.5` | Minimum entropy to flag a value as suspicious |
| `fail_on_severity` | `string` | `"high"` | Severity threshold used by `envdrift guard --ci` |
| `skip_clear_files` | `bool` | `false` | Skip `.clear` files from scanning entirely |
| `skip_encrypted_files` | `bool` | `true` | Skip findings from files with dotenvx/SOPS encryption markers |
| `skip_duplicate` | `bool` | `false` | Show only unique findings by secret value |
| `skip_gitignored` | `bool` | `false` | Skip findings from files that are in `.gitignore` |
| `ignore_paths` | `list[string]` | `[]` | Glob patterns ignored by the native scanner |
| `ignore_rules` | `dict[string, list[string]]` | `{}` | Per-rule path patterns to ignore (rule ID → glob patterns) |
| `verify_secrets` | `bool` | `false` | Reserved for future verified secret checks |

```toml
[guard]
scanners = ["native", "gitleaks", "trufflehog", "detect-secrets"]
auto_install = true
include_history = false
check_entropy = true
entropy_threshold = 4.5
fail_on_severity = "high"
skip_clear_files = false
skip_encrypted_files = true
skip_duplicate = false
skip_gitignored = false
ignore_paths = ["tests/**", "*.test.py"]
verify_secrets = false

[guard.ignore_rules]
"high-entropy-string" = ["**/*.clear"]
```

Notes:

- `ignore_paths` applies to the native scanner's file walk.
- `skip_encrypted_files` defaults to `true`, so findings from files carrying
  dotenvx/SOPS encryption markers are filtered out unless you set it to `false`.
- `scanners` can be set under `[tool.envdrift.guard]` in `pyproject.toml`.

### [encryption] — Encryption Settings

Configuration for encryption backends.

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `backend` | `string` | `"dotenvx"` | Encryption backend: `dotenvx` or `sops` |
| `smart_encryption` | `bool` | `false` | Skip re-encryption when file content is unchanged (reduces git noise) |

```toml
[encryption]
backend = "dotenvx"
smart_encryption = false
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
| `folder_path` | `string` | **required** | Local folder containing `.env.keys` |
| `vault_name` | `string` | `null` | Parsed but informational only — every mapping is fetched from the single vault you configured via `--vault-url` / `[vault.<provider>]`. See the note in [env-file-sync.md](../guides/env-file-sync.md#mappings). |
| `environment` | `string` | `null` (resolves to profile name, else `"production"`) | **Identity** — which `.env.<environment>` file this mapping targets and which `DOTENV_PRIVATE_KEY_<ENVIRONMENT>` key it reads/writes. Always runs (unless filtered out by `profile`). |
| `profile` | `string` | `null` | **Selector** — tags this mapping as profile-only. Untagged mappings always run. Profile-tagged mappings only run when you pass a matching `--profile <name>` on the CLI. |
| `activate_to` | `string` | `null` | After decrypt, copy the decrypted file to this path. Typical use: `activate_to = ".env"` on a profile mapping so apps that read a plain `.env` get the right one for the active profile. |
| `ephemeral_keys` | `bool` | `null` | Per-mapping override for ephemeral mode (no `.env.keys` written to disk). |

##### `environment` vs `profile` — when to use which

These two fields solve different problems and are often used together:

- `environment` answers **"which file?"** — it pins the mapping to
  `.env.<environment>` and `DOTENV_PRIVATE_KEY_<ENVIRONMENT>`. Use it whenever
  the mapping should always be processed (typical for monorepos where every
  service has its own env).
- `profile` answers **"should this run now?"** — it's a CLI-driven filter.
  Untagged mappings always run; a mapping with `profile = "X"` only runs when
  you pass `--profile X`. Use it when one project has multiple mutually
  exclusive env configs (e.g. local vs prod-debug on the same laptop) and you
  want to switch between them with a flag.

Resolution rule for the effective environment (the `.env.<X>` file name and
`DOTENV_PRIVATE_KEY_<X>` key): **explicit `environment` > `profile` >
`"production"`**. So a mapping with only `profile = "local"` and no
`environment` resolves to `.env.local` / `DOTENV_PRIVATE_KEY_LOCAL`; set
`environment` explicitly to decouple the CLI selector name from the file name.

See [Profiles in the Env File Sync guide](../guides/env-file-sync.md#profiles)
for full worked examples.

```toml
# Basic mapping — always runs, targets .env.production
[[vault.sync.mappings]]
secret_name = "myapp-dotenvx-key"
folder_path = "."
environment = "production"

# Always-runs mapping for a different service + environment
[[vault.sync.mappings]]
secret_name = "service2-key"
folder_path = "services/service2"
environment = "staging"

# Profile mapping — only runs with `envdrift pull --profile local`.
# `environment` defaults to the profile name, so this targets .env.local
# and uses DOTENV_PRIVATE_KEY_LOCAL.
[[vault.sync.mappings]]
secret_name = "local-dev-key"
folder_path = "."
profile = "local"
activate_to = ".env"  # Copy .env.local to .env after decrypt

# Profile + explicit environment — only runs with `--profile qa-laptop`,
# but the file is .env.staging (decoupled from the CLI selector name).
[[vault.sync.mappings]]
secret_name = "qa-key"
folder_path = "."
profile = "qa-laptop"
environment = "staging"
activate_to = ".env"

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

Configuration for the partial encryption feature. Two modes are supported — see the
[Partial Encryption Guide](../guides/partial-encryption.md) for full details.

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `enabled` | `bool` | `false` | Enable partial encryption |

```toml
[partial_encryption]
enabled = true
```

#### [[partial_encryption.environments]] — Environment Configuration

Each entry in the array configures one environment. Set `secrets_only = true` to use
secrets-only mode; omit it (or set `false`) for the default combine mode.

**Combine mode fields** (used when `secrets_only = false`, the default):

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `name` | `string` | **required** | Environment name |
| `clear_file` | `string` | **required** | Path to plaintext (non-sensitive) variables file |
| `secret_file` | `string` | **required** | Path to secret variables file (encrypted in place) |
| `combined_file` | `string` | **required** | Path to the merged output file written by `push` |

**Secrets-only mode fields** (used when `secrets_only = true`):

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `name` | `string` | **required** | Environment name |
| `secrets_only` | `bool` | `false` | Enable secrets-only mode |
| `secrets_dir` | `string` | **required** | Directory containing secret env files to encrypt/decrypt. Must be set and resolve to a directory; configs with `secrets_only = true` but no `secrets_dir` are rejected at load time. |
| `pattern` | `string` | `".env*"` | Glob pattern applied inside `secrets_dir`. Non-recursive by default — use `**/.env*` for nested subdirectories. |

Envdrift validates each environment entry at config-load time and raises a
`ValueError` if required fields for the selected mode are missing (e.g.
combine-mode entries without `clear_file`/`secret_file`/`combined_file`, or
secrets-only entries without `secrets_dir`).

```toml
# Combine mode — merges .clear + encrypted .secret into a single output file
[[partial_encryption.environments]]
name = "staging"
clear_file = ".env.staging.clear"
secret_file = ".env.staging.secret"
combined_file = ".env.staging"

# Secrets-only mode — encrypts/decrypts secrets_dir in place, configs are never touched
[[partial_encryption.environments]]
name = "production"
secrets_only = true
secrets_dir = "secrets/production/"
pattern = ".env*"
```

### [guardian] — Background Agent Settings

Per-project configuration for the background agent (envdrift-agent), which
watches `.env` files and auto-encrypts them after a period of inactivity.

> **Note:** `enabled = true` does **not** auto-register the project with the
> agent. Registration is explicit — run `envdrift agent register` (or
> `envdrift init --watch`) from the project root to add it to
> `~/.envdrift/projects.json`. The daemon then loads the project and honors
> the `[guardian]` settings below. `enabled = false` (the default) tells the
> daemon to skip an already-registered project.

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `enabled` | `bool` | `false` | Permit the agent to watch this project (requires explicit `envdrift agent register`) |
| `idle_timeout` | `string` | `"5m"` | Encrypt after the file is idle for this long; format `<number><s\|m\|h\|d>` (e.g. `30s`, `5m`, `1h`) |
| `patterns` | `list[string]` | `[".env*"]` | File patterns to watch |
| `exclude` | `list[string]` | `[".env.example", ".env.sample", ".env.keys"]` | Files to skip |
| `notify` | `bool` | `true` | Show a desktop notification when encrypting |

```toml
[guardian]
enabled = false
idle_timeout = "5m"
patterns = [".env*"]
exclude = [".env.example", ".env.sample", ".env.keys"]
notify = true
```

## Complete Example

```toml
# envdrift.toml

[envdrift]
schema = "config.settings:Settings"
environments = ["development", "staging", "production"]

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
- [Env File Sync Guide](../guides/env-file-sync.md) — Detailed vault sync setup
