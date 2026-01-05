<p align="center">
  <img src="https://raw.githubusercontent.com/jainal09/envdrift/main/docs/assets/images/env-drift-logo.png" alt="envdrift logo" width="300">
</p>

# envdrift

[![PyPI version](https://badge.fury.io/py/envdrift.svg)](https://badge.fury.io/py/envdrift)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docs](https://img.shields.io/badge/docs-mkdocs-blue)](https://jainal09.github.io/envdrift)
[![codecov](https://codecov.io/gh/jainal09/envdrift/graph/badge.svg)](https://codecov.io/gh/jainal09/envdrift)

Sync environment variables across your team. No more "it works on my machine."

## The Problem

- New developer joins → spends half a day hunting for the right `.env` values
- Someone updates a secret → nobody else knows until production breaks
- "Can you send me the latest API keys?" in Slack → security nightmare

**Paid SaaS solutions exist, but do you really want your production secrets on someone else's infrastructure?**

## The Solution

envdrift is an **open-source** CLI that syncs encrypted `.env` files using **your existing cloud vault**.
No hosted service, no additional servers, no third-party trust.

- **Your infrastructure** — Works with Azure Key Vault, AWS Secrets Manager, HashiCorp Vault, GCP Secret Manager
- **Zero trust required** — Secrets never leave your cloud
- **No new servers** — Just a CLI tool, no client-server architecture
- **Free forever** — MIT licensed, no per-seat pricing

```bash
# New team member onboarding - one command
envdrift pull

# That's it. Keys synced from vault, .env files decrypted, ready to code.
```

## Installation

```bash
pip install "envdrift[vault]"  # All vault providers
```

## Quick Start

**1. Encrypt and push to vault (once per project):**

```bash
envdrift encrypt .env.production
envdrift vault-push . my-app-key --provider azure --vault-url https://myvault.vault.azure.net/
```

**2. Team members pull instantly:**

```bash
envdrift pull --provider azure --vault-url https://myvault.vault.azure.net/
```

**3. Daily workflow:**

```bash
envdrift pull   # After git pull - sync keys, decrypt
envdrift lock   # Before commit - encrypt, verify keys
```

## Beyond Sync

| Feature | Description |
|:--------|:------------|
| **Schema Validation** | Validate .env against Pydantic schemas |
| **Environment Diffing** | Compare dev vs staging vs production |
| **Vault Integration** | Azure, AWS, HashiCorp, GCP |
| **Encryption** | dotenvx and SOPS backends |
| **CI/CD Mode** | Fail builds on misconfiguration |

```bash
envdrift validate .env --schema config:Settings
envdrift diff .env.dev .env.prod
```

## Documentation

Full documentation: **[jainal09.github.io/envdrift](https://jainal09.github.io/envdrift)**

## License

MIT
