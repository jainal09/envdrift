# SOPS Backend Guide

envdrift supports two encryption backends: **dotenvx** (default) and **SOPS**.
This guide is the end-to-end reference for the **SOPS** path — how it differs from
dotenvx, why SOPS users don't use envdrift's Vault Sync, and exactly how to set it
up against a cloud KMS (with a full Azure Key Vault walkthrough).

If you're choosing between backends first, read
[Encryption Backends](../concepts/encryption-backends.md). If you want the shared
encrypt/decrypt mechanics, see [Encryption](encryption.md).

## The core difference: who distributes the decrypt key

This is the single most important thing to understand, because it changes which
commands you use.

| | dotenvx | SOPS |
|:--|:--|:--|
| **Decrypt key lives in** | a portable `.env.keys` file (`DOTENV_PRIVATE_KEY_<ENV>`) | your KMS / age / PGP — there is **no** `.env.keys` |
| **How teammates get decrypt access** | envdrift **Vault Sync** pushes the key to a cloud vault and pulls it back | you grant access in **KMS/age/PGP itself** (e.g. an Azure RBAC role on the key) |
| **Team commands** | `sync`, `pull`, `vault-push`, `vault-pull`, `decrypt --verify-vault` | not needed — use `encrypt` / `decrypt` |

dotenvx has one secret artifact (`.env.keys`) that must reach every teammate, so
envdrift gives you Vault Sync to distribute it. SOPS has **no** such portable
secret: it wraps each file's data key with your KMS/age/PGP key, and *that* system
already decides who can decrypt. So with SOPS you never push a key anywhere — you
add a teammate to the KMS key (or hand them an age key) and they can decrypt
immediately.

!!! info "SOPS does not use Vault Sync — and doesn't need to"
    The entire Vault Sync family (`vault-push`, `vault-pull`, `sync`, and
    `decrypt --verify-vault`) is built around the dotenvx `.env.keys` artifact and
    is dotenvx-only. `decrypt --verify-vault` explicitly rejects non-dotenvx
    backends. SOPS access control lives in your KMS/age/PGP, not in an envdrift
    vault mapping.

## Two ways to use vault clouds — don't confuse them

The word "vault" means two different things here:

1. **envdrift Vault Sync** — pushes/pulls the dotenvx `.env.keys` private key using
   your cloud vault's **secrets** API (e.g. Azure Key Vault *secrets*). dotenvx only.
2. **A cloud KMS as the SOPS key** — SOPS wraps the file's data key with a cloud
   **key** (e.g. Azure Key Vault *keys*, AWS KMS, GCP KMS). This is SOPS-native.

So SOPS absolutely uses cloud vaults — just through the **keys** API via SOPS's own
config, not through envdrift's key-pushing commands. The permission sets are
different: dotenvx Vault Sync needs **Secrets** Get/List; SOPS + Azure Key Vault
needs **Keys** crypto permissions (see below).

## Install

```bash
pip install envdrift          # SOPS support needs no extra envdrift extras
```

You also need the `sops` binary on PATH. Either install it yourself
(`brew install sops`, or see the [SOPS releases](https://github.com/getsops/sops/releases))
or let envdrift fetch it by setting `auto_install = true` (below).

## Configuration

Set SOPS as the backend in `envdrift.toml` (or `[tool.envdrift]` in
`pyproject.toml`). All SOPS options live under the **`[encryption.sops]`**
subsection:

```toml
[encryption]
backend = "sops"

[encryption.sops]
auto_install = false              # set true to let envdrift download the sops binary
config_file = ".sops.yaml"        # optional: path to a SOPS policy file
age_recipients = "age1example..." # age public key(s) for encryption
age_key_file = "keys.txt"         # age private key for local decryption (sets SOPS_AGE_KEY_FILE)
# kms_arn  = "arn:aws:kms:us-east-1:123456789:key/abc-123"
# gcp_kms  = "projects/p/locations/global/keyRings/r/cryptoKeys/k"
# azure_kv = "https://my-vault.vault.azure.net/keys/my-key/<version>"
```

!!! warning "Use the `[encryption.sops]` subsection — not flat keys"
    Options are read from the `[encryption.sops]` table (`config_file`,
    `age_recipients`, `azure_kv`, …). Flat keys like `sops_config_file` under
    `[encryption]` are **ignored** by the parser.

## The simple path: `encrypt` / `decrypt`

For SOPS this is all you need — no vault mappings, no extra config sections.

```bash
# Encrypt in place (backend + key resolved from envdrift.toml)
envdrift encrypt .env.production

# Or pick the backend/key explicitly, ignoring config
envdrift encrypt .env.production --backend sops --age age1example...

# Decrypt in place (backend auto-detected from the file's SOPS metadata)
envdrift decrypt .env.production
```

SOPS encrypts values while keeping keys readable and appends its own metadata:

```bash
DATABASE_URL=ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]
API_KEY=ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]
sops_version=3.11.0
```

`encrypt`/`decrypt` accept these SOPS flags (overriding config):
`--backend`, `--sops-config`, `--age`, `--age-key-file`, `--kms`, `--gcp-kms`,
`--azure-kv`. See [`encrypt`](../cli/encrypt.md) and [`decrypt`](../cli/decrypt.md).

## Azure Key Vault walkthrough (verified end-to-end)

This sets up SOPS to wrap your data keys with an Azure Key Vault **key**. envdrift
authenticates to Azure via SOPS, which uses the standard Azure credential chain
(`az login`, env vars, or managed identity).

### 1. Permissions — Key Vault **keys**, not secrets

SOPS uses the vault's **keys** API. This is a different RBAC role than dotenvx Vault
Sync (which uses **secrets**). On the vault, grant:

| Task | Built-in role |
|:--|:--|
| Create the key (one-time) | **Key Vault Crypto Officer** |
| Encrypt / decrypt files (everyone) | **Key Vault Crypto User** |

```bash
# Replace <user-or-principal> and the scope with your vault's resource ID
SCOPE=$(az keyvault show --name my-vault --query id -o tsv)

az role assignment create --assignee "<user-or-principal>" \
  --role "Key Vault Crypto Officer" --scope "$SCOPE"   # to create keys
az role assignment create --assignee "<user-or-principal>" \
  --role "Key Vault Crypto User"   --scope "$SCOPE"   # to encrypt/decrypt
```

RBAC changes take ~30–60s to propagate. If you only hold *Key Vault Secrets
Officer* (the dotenvx Vault Sync role), `az keyvault key create` will fail with
`Forbidden (ForbiddenByRbac)` — that's the secrets-vs-keys distinction in action.

### 2. Create the key

```bash
az keyvault key create --vault-name my-vault --name sops-key \
  --kty RSA --size 2048 --query "key.kid" -o tsv
# -> https://my-vault.vault.azure.net/keys/sops-key/<version>
```

### 3. Point envdrift at it

```toml
[encryption]
backend = "sops"

[encryption.sops]
azure_kv = "https://my-vault.vault.azure.net/keys/sops-key/<version>"
```

### 4. Encrypt and decrypt

```bash
envdrift encrypt .env.production       # wraps the data key with your Azure key
envdrift decrypt .env.production       # calls Azure to unwrap, restores plaintext
```

The encrypted file records which key was used, so decryption needs no extra config —
only `az login` (or any Azure credential with *Key Vault Crypto User* on the key):

```bash
sops_azure_kv__list_0__map_vault_url=https://my-vault.vault.azure.net
sops_azure_kv__list_0__map_name=sops-key
sops_azure_kv__list_0__map_version=<version>
```

### Granting a teammate decrypt access

No key push. Give them **Key Vault Crypto User** on the key (or vault) and they can
`envdrift decrypt` immediately:

```bash
az role assignment create --assignee teammate@example.com \
  --role "Key Vault Crypto User" --scope "$SCOPE"
```

## Using `pull` and `lock` with SOPS

Partly — and this trips people up, so here is the precise behavior.

`pull` and `lock` are part of the **Vault Sync family**. They do two things:

1. A **key-sync step** (fetch/verify the dotenvx `.env.keys` private key from a
   vault) — this is **dotenvx-only**.
2. An **encrypt/decrypt step** that uses whichever backend your config resolves to —
   this **does** support SOPS.

Consequences for SOPS:

- `lock` and `pull` **refuse to start without a `[vault.sync]` section** (and a
  `[vault]` provider block with a `vault_url`) — they derive their file work-list
  and build a vault client up front, regardless of backend. A pure-SOPS project
  has none of that.
- Plain `envdrift pull` runs the key-sync step, which looks for a dotenvx secret and
  **fails** for SOPS. You must use `envdrift pull --skip-sync` to skip straight to
  decryption.

**Recommendation:** for SOPS, use `envdrift encrypt` / `envdrift decrypt`. They need
no vault scaffolding and are the intended SOPS workflow. Only reach for `lock`/`pull`
if you specifically want their batch file-discovery, in which case add a minimal
`[vault.sync]`/`[vault]` block and run `pull --skip-sync`.

```toml
# Minimal scaffolding ONLY if you want lock/pull to drive SOPS encrypt/decrypt.
# No key is ever pushed/pulled here — access is your KMS/age/PGP.
[vault]
provider = "azure"

[vault.azure]
vault_url = "https://my-vault.vault.azure.net/"

[vault.sync]
default_vault_name = "my-vault"

[[vault.sync.mappings]]
secret_name = "unused-for-sops"   # never read for SOPS; only gives a work-list
folder_path = "."
environment = "production"
```

```bash
envdrift lock --force          # encrypts mapped files with SOPS
envdrift pull --skip-sync      # decrypts mapped files with SOPS (no secrets call)
```

## What SOPS does not support

- **envdrift Vault Sync** (`vault-push`, `vault-pull`, `sync`,
  `decrypt --verify-vault`) — dotenvx-only by design.
- **Partial encryption** (`push` / `pull-partial`) — dotenvx-only.

## See also

- [Encryption Backends](../concepts/encryption-backends.md) — choosing dotenvx vs SOPS
- [Encryption](encryption.md) — shared encrypt/decrypt mechanics
- [`encrypt`](../cli/encrypt.md) / [`decrypt`](../cli/decrypt.md) — command reference
- [Env File Sync](env-file-sync.md) — the dotenvx team (Vault Sync) workflow
