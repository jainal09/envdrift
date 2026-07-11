# Encryption Backends

envdrift supports two encryption backends: **dotenvx** and **SOPS**. This page helps you choose the right one for your needs.

## Quick Comparison

| Feature | dotenvx | SOPS |
|:--------|:--------|:-----|
| **Complexity** | Simple | More complex |
| **Key storage** | `.env.keys` file | External KMS or age keys |
| **Cloud KMS** | No (vault sync for key sharing) | Yes (native AWS/GCP/Azure KMS) |
| **Team sharing** | Via envdrift vault sync | Via KMS permissions or key files |
| **Partial encryption** | Yes | No |
| **Best for** | Small teams, simple setups | Enterprise, existing KMS infra |

## dotenvx

[dotenvx](https://dotenvx.com/) is a simple encryption tool designed specifically for `.env` files.

### How It Works

1. Generates a keypair stored in `.env.keys`
2. Encrypts values in-place in the `.env` file
3. Decrypts using the private key from `.env.keys`

### File Structure

```text
.env.production           # Encrypted (committed)
.env.keys                 # Private keys (NOT committed, synced via vault)
```

### Encrypted Format

```bash
# .env.production (encrypted)
DOTENV_PUBLIC_KEY_PRODUCTION="034a5c..."
DATABASE_URL=encrypted:BD7HQzb...
API_KEY=encrypted:BD9XKwm...
DEBUG=encrypted:BD2QpRf...
```

### Advantages

- Simple setup, no external dependencies
- Variable names remain readable while every value is encrypted
- Consistent whole-file encryption with no accidental plaintext values
- Works with envdrift's vault sync for team key sharing

### Disadvantages

- Requires key file management
- No native cloud KMS integration
- Single key for all values in a file

### When to Use

- Small to medium teams
- Projects without existing KMS infrastructure
- When simplicity is preferred over enterprise features

## SOPS

[SOPS](https://github.com/getsops/sops) (Secrets OPerationS) is Mozilla's enterprise-grade encryption tool.

### How It Works

1. Uses external key management (age, AWS KMS, GCP KMS, Azure Key Vault, or PGP)
2. Encrypts values while preserving file structure
3. Supports multiple key recipients for team access

### Configuration

SOPS uses a `.sops.yaml` file for configuration:

```yaml
# .sops.yaml
creation_rules:
  - path_regex: \.env\.production$
    age: "age1abc..."

  - path_regex: \.env\.staging$
    kms: "arn:aws:kms:us-east-1:123456789:key/abc-123"
```

### Encrypted Format

```bash
# .env.production (SOPS encrypted)
DATABASE_URL=ENC[AES256_GCM,data:5Tz8n...,type:str]
API_KEY=ENC[AES256_GCM,data:9Kx2m...,type:str]
DEBUG=false
sops_mac=ENC[AES256_GCM,data:abc...,type:str]
```

### Key Options

| Key Type | Use Case |
|:---------|:---------|
| **age** | Simple, file-based keys (like dotenvx) |
| **AWS KMS** | AWS-native key management |
| **GCP KMS** | GCP-native key management |
| **Azure Key Vault** | Azure-native key management |
| **PGP** | GPG-based encryption |

### Advantages

- Native cloud KMS integration
- Multiple key recipients (team access without sharing keys)
- Enterprise-grade security
- Widely adopted in DevOps/SRE communities

### Disadvantages

- More complex setup
- Requires external tooling (sops CLI)
- KMS costs for cloud-managed keys
- More verbose encrypted format

### When to Use

- Enterprise environments
- Existing KMS infrastructure (AWS/GCP/Azure)
- Large teams with complex access control needs
- When audit trails and key rotation are required

## envdrift Commands

Both backends use the same envdrift commands:

```bash
# Encrypt with dotenvx (default)
envdrift encrypt .env.production

# Encrypt with SOPS (age recipients)
envdrift encrypt .env.production --backend sops --age "age1..."

# Encrypt with SOPS using a cloud KMS key
# (use --kms for AWS, --gcp-kms for GCP, --azure-kv for Azure)
envdrift encrypt .env.production --backend sops --kms "arn:aws:kms:us-east-1:123456789:key/abc-123"

# Check encryption status
envdrift encrypt .env.production --check

# Decrypt
envdrift decrypt .env.production
```

`encrypt`/`decrypt` operate on a single env file. To encrypt or decrypt every env
file in a project at once, use the higher-level `envdrift lock` (verify keys and
encrypt all env files) and `envdrift pull` (pull keys from the vault and decrypt all
env files) commands. See the [Env File Sync guide](../guides/env-file-sync.md).

### Backend Auto-Detection

envdrift automatically detects which backend was used:

```bash
# Auto-detects backend and decrypts
envdrift decrypt .env.production
```

## Configuration

Set a default backend in `envdrift.toml`. Backend-specific options live in the
`[encryption.dotenvx]` and `[encryption.sops]` subsections (flat `sops_*` keys
under `[encryption]` are ignored by the parser):

```toml
[encryption]
# Default backend (dotenvx or sops)
backend = "dotenvx"

# dotenvx settings
[encryption.dotenvx]
auto_install = true

# SOPS settings
[encryption.sops]
auto_install = true
config_file = ".sops.yaml"
age_key_file = "~/.config/sops/age/keys.txt"
age_recipients = "age1abc..."
# Cloud KMS alternatives to age (set the one you use)
# kms_arn = "arn:aws:kms:us-east-1:123456789:key/abc-123"
# gcp_kms = "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key"
# azure_kv = "https://my-vault.vault.azure.net/keys/my-key/<version>"
```

For a full SOPS setup (including the Azure Key Vault walkthrough and how `lock`/`pull`
behave with SOPS), see the [SOPS Backend Guide](../guides/sops.md).

## Migration Between Backends

### From dotenvx to SOPS

```bash
# 1. Decrypt with dotenvx
envdrift decrypt .env.production

# 2. Re-encrypt with SOPS
envdrift encrypt .env.production --backend sops --age "age1..."
```

### From SOPS to dotenvx

```bash
# 1. Decrypt with SOPS
envdrift decrypt .env.production

# 2. Re-encrypt with dotenvx
envdrift encrypt .env.production --backend dotenvx
```

## Recommendation

| Scenario | Recommendation |
|:---------|:---------------|
| Starting fresh, small team | dotenvx |
| AWS/GCP/Azure environment | SOPS with native KMS |
| Existing SOPS usage | SOPS |
| Need partial encryption | dotenvx |
| Need key rotation/audit | SOPS with KMS |
| Simplicity over features | dotenvx |
