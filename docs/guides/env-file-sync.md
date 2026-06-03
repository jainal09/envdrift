# Env File Sync Guide

This guide covers the most secure way to sync and distribute `.env` files across
your team using **your existing cloud infrastructure** and your **git repo** — no
hosted service, no extra servers, no third-party trust. This is the core purpose
of envdrift, and this guide covers it end to end.

The feature that makes this work is what we call **Vault Sync**: your encrypted
`.env` files live in git, and the *key that decrypts them* lives in your cloud
vault. A teammate clones the repo, runs one command, and gets the right values
instantly — because they can reach the vault, not because anyone Slacked them a
secret.

!!! info "Vault Sync applies when you encrypt with **dotenvx** (the default)"
    Vault Sync distributes the dotenvx private key — the `DOTENV_PRIVATE_KEY_<ENV>`
    value stored in `.env.keys` — through your cloud vault. Every command in the
    family (`vault-push`, `vault-pull`, `sync`, `pull`, and `decrypt --verify-vault`)
    is built around that `.env.keys` artifact, which is dotenvx-specific.

    **SOPS users don't use Vault Sync** — and don't need to. SOPS has no portable
    `.env.keys` private key; it delegates decryption to your KMS/age/PGP, which is
    *already* a key-distribution system that controls who can decrypt. You still get
    the rest of envdrift with SOPS — `envdrift encrypt`/`decrypt --backend sops` are
    the recommended path, and `lock`/`pull` can drive SOPS too (they need a
    `[vault.sync]` section, and `pull` needs `--skip-sync`). You just grant decryption
    access through SOPS's own key management instead of pushing a key to a vault. See
    the [SOPS Backend Guide](sops.md) for the full setup.

## Overview

Syncing is driven by a single, central config file — `envdrift.toml` in your
project root (or a `[tool.envdrift]` section in `pyproject.toml` if you're in a
Python project). This file tells envdrift which vault you use and which secrets map
to which `.env` folders. Create it once, commit it, and every teammate's `pull`
just works.

The key model behind it all:

- Each environment has a private key — `DOTENV_PRIVATE_KEY_<ENV>` — stored locally
  in `.env.keys`.
- That `.env.keys` file must **never** be committed. It is the one secret that
  unlocks everything.
- Instead of sharing it over Slack, you store it **in your cloud vault** and let
  teammates and CI fetch it on demand.

## Two ways to sync

envdrift gives you a quick, zero-config path for a single secret and a full,
config-driven path for a whole team. Start with the first, graduate to the second.

| | Config-free (single secret) | Team sync (`envdrift.toml`) |
|:--|:--|:--|
| **Commands** | `vault-push` / `vault-pull` | `sync` / `pull` |
| **Config file** | None | `envdrift.toml` (one-time) |
| **Scope** | One secret → one folder | Many secrets → many folders |
| **Best for** | Trying it out, a single service, ad-hoc onboarding | Real team workflow, monorepos, CI/CD |

### Tier 1 — config-free (try it in 2 minutes)

Push a key to your vault, then pull it back somewhere else — no config file at all.

```bash
# You: encrypt and push the key to the vault (once)
envdrift encrypt .env.production
envdrift vault-push . myapp-dotenvx-key --env production \
  -p azure --vault-url https://my-keyvault.vault.azure.net/

# Teammate: pull the key and auto-decrypt .env.production (one command)
envdrift vault-pull . myapp-dotenvx-key --env production \
  -p azure --vault-url https://my-keyvault.vault.azure.net/
```

`vault-pull` writes `DOTENV_PRIVATE_KEY_PRODUCTION` into `./.env.keys` and decrypts
`.env.production` in one step. Add `--no-decrypt` to fetch the key only. See
[`vault-push`](../cli/vault-push.md) and [`vault-pull`](../cli/vault-pull.md).

### Tier 2 — team sync via `envdrift.toml` (the real workflow)

Once you have more than one secret — or you want onboarding to be a single
`envdrift pull` with no flags — move the vault and mappings into `envdrift.toml`.
This is the heart of envdrift: every key for every service, synced from one config.

```bash
envdrift pull   # syncs every mapped key AND decrypts every mapped .env file
envdrift sync   # syncs keys only (no decryption) when you want more control
```

The rest of this guide focuses on Tier 2.

## Architecture

```text
        git repo (committed)              cloud vault (key storage)
   ┌──────────────────────────┐      ┌──────────────────────────┐
   │ services/app/.env.prod 🔒│      │  app-key                 │
   │ services/auth/.env.prod🔒│      │  auth-key                │
   │ envdrift.toml            │      │  api-key                 │
   └──────────────────────────┘      └─────────────┬────────────┘
                                                    │
                          envdrift pull / sync      │
                                                    ▼
                      ┌────────────────────────────────────────┐
                      │            Local environment            │
                      │  services/app/.env.keys   ◄── app-key   │
                      │  services/auth/.env.keys  ◄── auth-key  │
                      │  (then .env files decrypted in place)   │
                      └────────────────────────────────────────┘
```

The encrypted `.env` files travel through git; the keys travel through the vault.
Neither half is useful without the other, and the secret values never leave your
infrastructure.

## Team sync setup

### 1. Install with vault support

```bash
pip install "envdrift[azure]"       # Azure Key Vault
pip install "envdrift[aws]"         # AWS Secrets Manager
pip install "envdrift[hashicorp]"   # HashiCorp Vault
pip install "envdrift[gcp]"         # GCP Secret Manager
pip install "envdrift[vault]"       # all providers
```

### 2. Create `envdrift.toml`

One config file, one provider. Pick the provider you actually use — you don't stack
multiple providers in the same config.

```toml
[vault]
provider = "azure"   # one of: azure | aws | hashicorp | gcp

[vault.azure]
vault_url = "https://my-keyvault.vault.azure.net/"

[vault.sync]
default_vault_name = "my-keyvault"
max_workers = 4   # optional: parallelize pull/lock file operations

[[vault.sync.mappings]]
secret_name = "myapp-dotenvx-key"
folder_path = "services/myapp"

[[vault.sync.mappings]]
secret_name = "auth-service-dotenvx-key"
folder_path = "services/auth"
environment = "staging"   # reads/writes DOTENV_PRIVATE_KEY_STAGING
```

Using a different provider? Replace the `provider` value and the provider block:

=== "Azure"

    ```toml
    [vault]
    provider = "azure"

    [vault.azure]
    vault_url = "https://my-keyvault.vault.azure.net/"
    ```

=== "AWS"

    ```toml
    [vault]
    provider = "aws"

    [vault.aws]
    region = "us-east-1"
    ```

=== "HashiCorp"

    ```toml
    [vault]
    provider = "hashicorp"

    [vault.hashicorp]
    url = "https://vault.example.com:8200"
    ```

=== "GCP"

    ```toml
    [vault]
    provider = "gcp"

    [vault.gcp]
    project_id = "my-gcp-project"
    ```

> **Python projects:** you can put the same sections under `[tool.envdrift]` in
> `pyproject.toml` instead (e.g. `[tool.envdrift.vault]`). Auto-discovery finds
> either file.

### 3. Store your key in the vault

Read the dotenvx private key out of `.env.keys` and store it as a vault secret. Use
`envdrift vault-push` (works for any provider without leaving envdrift), or your
provider's own CLI for the one-time upload:

=== "envdrift (any provider)"

    ```bash
    envdrift vault-push services/myapp myapp-dotenvx-key --env production \
      -p azure --vault-url https://my-keyvault.vault.azure.net/
    ```

=== "Azure CLI"

    ```bash
    az keyvault secret set --vault-name my-keyvault --name myapp-dotenvx-key \
      --value "$(grep DOTENV_PRIVATE_KEY_PRODUCTION services/myapp/.env.keys | cut -d'=' -f2)"
    ```

=== "AWS CLI"

    ```bash
    aws secretsmanager create-secret --name myapp-dotenvx-key \
      --secret-string "$(grep DOTENV_PRIVATE_KEY_PRODUCTION services/myapp/.env.keys | cut -d'=' -f2)"
    ```

=== "HashiCorp"

    ```bash
    vault kv put secret/myapp-dotenvx-key \
      value="$(grep DOTENV_PRIVATE_KEY_PRODUCTION services/myapp/.env.keys | cut -d'=' -f2)"
    ```

=== "GCP"

    ```bash
    gcloud secrets create myapp-dotenvx-key --replication-policy="automatic"
    printf "%s" "$(grep DOTENV_PRIVATE_KEY_PRODUCTION services/myapp/.env.keys | cut -d'=' -f2)" \
      | gcloud secrets versions add myapp-dotenvx-key --data-file=-
    ```

### 4. Sync keys locally

Auto-discovery finds `envdrift.toml` (or `[tool.envdrift]` in `pyproject.toml`)
anywhere up the tree. Pass `-c envdrift.toml` only when running outside the repo
root or pinning an exact file in CI.

```bash
envdrift pull          # syncs keys AND decrypts every mapped .env file (onboarding)
envdrift sync          # syncs keys only
envdrift sync -c envdrift.toml   # explicit config path
```

## Provider setup

envdrift doesn't reinvent cloud authentication — it uses each provider's **standard
credential chain**. If your CLI is already logged in, envdrift is already
authenticated. The table below is the entire envdrift-specific contract: which
credentials it resolves, and the *minimum read* permissions `sync`/`pull` need. For
installing CLIs, creating vaults, and logging in, follow the provider's own docs
(linked).

> **Read vs write:** the permissions below are the **read** access that `sync`/`pull`/
> `decrypt --verify-vault` require. `vault-push` additionally needs **write** (Azure
> `Set`, AWS `secretsmanager:PutSecretValue`/`CreateSecret`, Vault `create`/`update`,
> GCP `secretmanager.versions.add`).

| Provider | envdrift authenticates via | Minimum permissions | Provider auth docs |
|:--|:--|:--|:--|
| **Azure Key Vault** | `DefaultAzureCredential` — env vars (`AZURE_CLIENT_ID`/`TENANT_ID`/`CLIENT_SECRET`) → `az login` → managed identity | Secrets: **Get**, **List** | [Azure auth](https://learn.microsoft.com/azure/key-vault/general/authentication) |
| **AWS Secrets Manager** | boto3 default chain — env vars → `~/.aws/credentials` → IAM role (EC2/ECS/Lambda) | `secretsmanager:GetSecretValue` (auth via STS — no `ListSecrets` needed) | [AWS credentials](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html) |
| **HashiCorp Vault** | URL from `--vault-url` or `[vault.hashicorp].url`; token from the `VAULT_TOKEN` env var | `read`, `list` on the secret path | [Vault auth](https://developer.hashicorp.com/vault/docs/auth) |
| **GCP Secret Manager** | Application Default Credentials — `gcloud auth application-default login` or `GOOGLE_APPLICATION_CREDENTIALS` | `roles/secretmanager.secretAccessor` (+ list) | [GCP ADC](https://cloud.google.com/docs/authentication/application-default-credentials) |

Least-privilege policy snippets for the providers that need an explicit policy
document:

=== "Azure access policy"

    ```bash
    az keyvault set-policy --name my-keyvault \
      --upn user@example.com --secret-permissions get list
    ```

=== "AWS IAM policy"

    ```json
    {
      "Version": "2012-10-17",
      "Statement": [{
        "Effect": "Allow",
        "Action": ["secretsmanager:GetSecretValue"],
        "Resource": "arn:aws:secretsmanager:us-east-1:123456789:secret:*-dotenvx-key*"
      }]
    }
    ```

=== "HashiCorp policy"

    ```hcl
    path "secret/data/*" {
      capabilities = ["read", "list"]
    }
    ```

## Configuration reference

### Mappings

Each `[[vault.sync.mappings]]` block maps one vault secret to one folder:

```toml
[vault.sync]
default_vault_name = "my-keyvault"
env_keys_filename = ".env.keys"   # optional, defaults to .env.keys

[[vault.sync.mappings]]
secret_name = "myapp-key"
folder_path = "services/myapp"

[[vault.sync.mappings]]
secret_name = "auth-key"
folder_path = "services/auth"
environment = "staging"          # uses DOTENV_PRIVATE_KEY_STAGING

[[vault.sync.mappings]]
secret_name = "prod-key"
folder_path = "services/prod"
vault_name = "production-vault"  # override default_vault_name per mapping
```

### Ephemeral keys mode

Fetch keys from the vault and pass them straight to dotenvx via environment
variables — **never writing `.env.keys` to disk**. Ideal for CI/CD and
security-sensitive or short-lived environments.

```toml
[vault.sync]
ephemeral_keys = true   # central: applies to all mappings

[[vault.sync.mappings]]
secret_name = "ci-key"
folder_path = "services/ci"
ephemeral_keys = true   # or enable per-mapping
```

With ephemeral keys, `pull` fetches the key, passes it via `DOTENV_PRIVATE_KEY_*`,
decrypts in place, and writes no key file.

!!! warning
    In ephemeral mode there is no local fallback — if the vault is unavailable,
    the command fails.

### Profiles

Profiles let one project hold multiple environment configurations (local, staging,
prod). A mapping tagged with `profile` is only processed when you pass that
`--profile`; untagged mappings always run.

```toml
[[vault.sync.mappings]]
secret_name = "shared-key"
folder_path = "."

[[vault.sync.mappings]]
secret_name = "local-key"
folder_path = "."
profile = "local"          # only with --profile local
activate_to = ".env"       # copy decrypted .env.local → .env

[[vault.sync.mappings]]
secret_name = "prod-key"
folder_path = "."
profile = "prod"
activate_to = ".env"
```

```bash
envdrift pull --profile local
envdrift pull --profile prod
```

- **`profile`** — tags a mapping for filtering. Without `--profile`, only untagged
  mappings run.
- **`activate_to`** — path to copy the decrypted file to (e.g. `.env`) for apps that
  expect a plain `.env`.
- **`environment`** — if omitted, defaults to the `profile` value (profile `local` →
  `.env.local`).

### Legacy `pair.txt`

Still supported for backwards compatibility, but TOML is preferred (it keeps
provider defaults and mappings together).

```text
# secret-name=folder-path
myapp-dotenvx-key=services/myapp
auth-service-key=services/auth
production-vault/prod-key=services/prod   # explicit vault name (Azure)
```

## Drift detection

To confirm an encrypted file still matches the key in your vault — without
decrypting anything — use `decrypt --verify-vault`. This is a read-only CI/pre-commit
check (dotenvx only):

```bash
envdrift decrypt .env.production --verify-vault --ci \
  -p azure --vault-url https://my-keyvault.vault.azure.net/ \
  --secret myapp-dotenvx-key
```

Exit `0` if the vault key can decrypt the file, `1` if it can't — with repair steps:

1. `git restore .env.production`
2. `envdrift sync --force` (auto-discovers `envdrift.toml`; add `-c` / provider flags
   only to override)
3. `envdrift encrypt .env.production`

See [`decrypt`](../cli/decrypt.md) for the full verify-vault behavior.

## CI/CD integration

=== "GitHub Actions — Azure"

    ```yaml
    jobs:
      deploy:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4
          - uses: azure/login@v1
            with:
              creds: ${{ secrets.AZURE_CREDENTIALS }}
          - run: pip install "envdrift[azure]"
          - run: envdrift sync --force --ci
          - run: envdrift decrypt .env.production
          - run: ./deploy.sh
    ```

=== "GitHub Actions — AWS (OIDC)"

    ```yaml
    permissions:
      id-token: write
      contents: read
    jobs:
      deploy:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4
          - uses: aws-actions/configure-aws-credentials@v4
            with:
              role-to-assume: arn:aws:iam::123456789:role/github-actions
              aws-region: us-east-1
          - run: pip install "envdrift[aws]"
          - run: envdrift sync --check-decryption --ci
    ```

=== "GitLab CI"

    ```yaml
    deploy:
      image: python:3.11
      script:
        - pip install "envdrift[azure]"
        - envdrift sync --force --ci
        - envdrift decrypt .env.production
        - ./deploy.sh
      variables:
        AZURE_CLIENT_ID: $AZURE_CLIENT_ID
        AZURE_TENANT_ID: $AZURE_TENANT_ID
        AZURE_CLIENT_SECRET: $AZURE_CLIENT_SECRET
    ```

## Workflows

### Initial setup

```bash
# 1. Encrypt locally (creates .env.keys with DOTENV_PRIVATE_KEY_PRODUCTION)
envdrift encrypt .env.production

# 2. Store the key in the vault
envdrift vault-push . myapp-dotenvx-key --env production \
  -p azure --vault-url https://my-keyvault.vault.azure.net/

# 3. Add .env.keys to .gitignore, then commit the encrypted file + config
echo ".env.keys" >> .gitignore
git add .env.production envdrift.toml .gitignore
git commit -m "Add encrypted environment + vault sync config"
```

### New team member onboarding

```bash
git clone <repo> && cd <repo>
# (get vault access from your team lead)
envdrift pull        # syncs every key AND decrypts every .env file — done
```

That's the whole promise: one command, no Slacked secrets.

### Key rotation

Rotation is a **dotenvx-native** operation — envdrift has no `--rotate`, so this one
step calls the [`dotenvx`](https://dotenvx.com) binary directly (envdrift wraps
dotenvx for everything else). After rotating, re-push the new key and teammates resync:

```bash
dotenvx encrypt .env.production --rotate     # dotenvx CLI: new key in .env.keys
envdrift vault-push . myapp-dotenvx-key --env production \
  -p azure --vault-url https://my-keyvault.vault.azure.net/
# teammates pick it up with:
envdrift sync --force
```

## Troubleshooting

These are the envdrift-specific failure modes. For provider login/credential issues,
see the provider auth docs linked in [Provider setup](#provider-setup).

**Secret not found** — the `secret_name` in your mapping must match the vault secret
exactly. List what's actually there:

```bash
az keyvault secret list --vault-name my-keyvault     # Azure
aws secretsmanager list-secrets                       # AWS
vault kv list secret/                                 # HashiCorp
gcloud secrets list                                   # GCP
```

**Permission denied** — your identity needs the minimum permissions from the
[Provider setup](#provider-setup) table (Get/List, or the equivalent). Control-plane
access to *see* the vault is separate from data-plane access to *read* secret values.

**`--env` mismatch on pull** — a secret pushed for `production` holds
`DOTENV_PRIVATE_KEY_PRODUCTION`; pulling it with a different `--env` fails fast. Use
the same environment you pushed with.

**Preview without changing anything** — `envdrift sync --verify` shows what would
change without writing.

## Best practices

1. **One provider per config** — a config sets a single `provider`; don't mix.
2. **Separate vaults per environment** — keep production keys in a production vault.
3. **Least privilege** — grant only Get/List (or equivalent); see the table above.
4. **Use OIDC in CI/CD** — avoid long-lived credentials.
5. **Ephemeral keys in CI** — set `ephemeral_keys = true` so nothing persists to disk.
6. **Verify before deploy** — `envdrift decrypt --verify-vault --ci` catches drift.
7. **Rotate after team changes** — and re-push the new key to the vault.

## See also

- [`vault-pull`](../cli/vault-pull.md) — config-free single-secret pull (onboarding)
- [`vault-push`](../cli/vault-push.md) — config-free single-secret push
- [`pull`](../cli/pull.md) — sync every key + decrypt (the team workflow)
- [`sync`](../cli/sync.md) — sync keys only
- [`decrypt`](../cli/decrypt.md) — decryption + `--verify-vault` drift check
- [`encrypt`](../cli/encrypt.md) — encryption
