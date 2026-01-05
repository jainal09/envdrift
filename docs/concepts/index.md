# Concepts

Before diving into the CLI commands, it helps to understand the core concepts behind envdrift.

## Core Ideas

envdrift is built around three main ideas:

1. **Schema-first validation** — Define your expected environment variables in Pydantic, and envdrift validates your `.env` files against that schema.

2. **Encryption at rest** — Secrets should be encrypted in your repository. envdrift supports two
   encryption backends (dotenvx and SOPS) and integrates with cloud vaults for key management.

3. **Drift detection** — Compare environments to catch configuration drift before it causes production issues.

## In This Section

- [How It Works](how-it-works.md) — Understand the mental model and workflows
- [Encryption Backends](encryption-backends.md) — Compare dotenvx vs SOPS
- [Vault Providers](vault-providers.md) — Compare Azure, AWS, HashiCorp, and GCP

## Quick Overview

```text
┌─────────────────────────────────────────────────────────────────┐
│                        Your Repository                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  config.py (Schema)          .env.production (Encrypted)        │
│  ┌────────────────────┐      ┌────────────────────────────┐     │
│  │ class Settings:    │      │ DATABASE_URL="encrypted:..." │    │
│  │   DATABASE_URL: str│ ──── │ API_KEY="encrypted:..."      │    │
│  │   API_KEY: str     │      │ DEBUG=false                  │    │
│  │   DEBUG: bool      │      └────────────────────────────┘     │
│  └────────────────────┘                                          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │      envdrift validate       │
                    │      envdrift diff           │
                    │      envdrift encrypt        │
                    └──────────────────────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │        Cloud Vault           │
                    │  (Azure/AWS/HashiCorp/GCP)   │
                    │                              │
                    │  Stores encryption keys      │
                    │  for team-wide access        │
                    └──────────────────────────────┘
```
