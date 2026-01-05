<p align="center">
  <img src="assets/images/env-drift-logo.png" alt="envdrift logo" width="250">
</p>

<p align="center">
  <strong>Sync environment variables across your team. No more "it works on my machine."</strong>
</p>

<p align="center">
  <a href="https://pypi.org/project/envdrift/"><img src="https://badge.fury.io/py/envdrift.svg" alt="PyPI version"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python 3.11+"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
  <a href="https://codecov.io/gh/jainal09/envdrift"><img src="https://codecov.io/gh/jainal09/envdrift/graph/badge.svg" alt="codecov"></a>
</p>

---

## The Problem

Every team faces this:

- New developer joins → spends half a day hunting for the right `.env` values
- Someone updates a secret → nobody else knows until production breaks
- "Can you send me the latest API keys?" in Slack → security nightmare
- Environment drift between dev, staging, and production → 3am outages

**Paid SaaS solutions exist, but do you really want to trust your production secrets to someone else's infrastructure?**

## The Solution

envdrift is an **open-source** CLI that syncs encrypted environment files across your team
using **your existing cloud vault**—no hosted service, no additional servers, no third-party trust.

| | Hosted SaaS | envdrift |
|:--|:------------|:---------|
| **Your secrets** | On their servers | On YOUR infrastructure |
| **Infrastructure** | New service to manage | Uses existing vault (Azure/AWS/GCP/HashiCorp) |
| **Cost** | Per-seat pricing | Free and open source |
| **Trust model** | Trust the vendor | Zero third-party trust |

```bash
# New team member onboarding - one command
envdrift pull

# That's it. Keys synced from vault, .env files decrypted, ready to code.
```

### How It Works

1. **You encrypt** your `.env` file and push the encryption key to your cloud vault
2. **Team members pull** the key from vault and decrypt locally
3. **Everyone stays in sync** — same encrypted secrets, same decryption keys

## Quick Start

### 1. Set up encryption (once per project)

```bash
# Encrypt your .env file
envdrift encrypt .env.production

# Push the encryption key to your team's vault
envdrift vault-push . my-app-key --provider azure --vault-url https://myvault.vault.azure.net/
```

### 2. Team members onboard instantly

```bash
# New developer runs one command
envdrift pull --provider azure --vault-url https://myvault.vault.azure.net/

# Done! .env.production is decrypted and ready
```

### 3. Keep environments in sync

```bash
# Before committing changes
envdrift lock    # Encrypts files, verifies keys match vault

# After pulling latest code
envdrift pull    # Syncs keys, decrypts files
```

## Beyond Sync: Full Environment Management

Once your team is syncing environments, envdrift also provides:

| Feature | Description |
|:--------|:------------|
| **Schema Validation** | Validate .env files against Pydantic schemas—catch missing variables before deployment |
| **Environment Diffing** | Compare dev vs staging vs production—spot drift instantly |
| **CI/CD Integration** | Fail builds when environments are misconfigured |
| **Pre-commit Hooks** | Ensure files are encrypted before every commit |
| **Partial Encryption** | Keep non-sensitive vars readable, encrypt only secrets |

```bash
# Validate against your schema
envdrift validate .env.production --schema config:Settings

# Compare environments
envdrift diff .env.staging .env.production
```

## Installation

```bash
pip install envdrift

# With your vault provider
pip install "envdrift[azure]"     # Azure Key Vault
pip install "envdrift[aws]"       # AWS Secrets Manager
pip install "envdrift[hashicorp]" # HashiCorp Vault
pip install "envdrift[gcp]"       # GCP Secret Manager
pip install "envdrift[vault]"     # All providers
```

## What's Next?

<div class="grid cards" markdown>

- :material-cloud-sync: **Vault Sync Guide**

    ---

    Set up team-wide environment sync with your cloud vault.

    [:octicons-arrow-right-24: Get Started](guides/vault-sync.md)

- :material-rocket-launch: **Quick Start**

    ---

    Full walkthrough from installation to team sync.

    [:octicons-arrow-right-24: Quick Start](getting-started/quickstart.md)

- :material-lock: **Encryption Guide**

    ---

    Choose between dotenvx and SOPS encryption backends.

    [:octicons-arrow-right-24: Encryption](guides/encryption.md)

- :material-console: **CLI Reference**

    ---

    Complete documentation for all commands.

    [:octicons-arrow-right-24: Commands](cli/index.md)

</div>
