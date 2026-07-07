# envdrift vault-pull

Pull a single encryption key from a cloud vault into a local `.env.keys` file.
This command is specific to dotenvx keys; SOPS users should use their SOPS key management workflows.

## Synopsis

```bash
envdrift vault-pull [OPTIONS] FOLDER SECRET_NAME
```

## Description

The `vault-pull` command is the **config-free, single-secret inverse** of
[`vault-push`](vault-push.md). It fetches one secret from a cloud vault, writes
the `DOTENV_PRIVATE_KEY_<ENV>` key into `<folder>/.env.keys`, and — by default —
decrypts the matching `.env.<env>` file so a single command onboards a developer
with **no TOML configuration required**.

This complements [`envdrift pull`](pull.md), which requires a `[vault.sync]`
configuration and operates on multiple services. Use `vault-pull` when you just
need one secret and don't want to maintain a sync config.

Supported vault providers:

- **Azure Key Vault** - Microsoft Azure's secret management service
- **AWS Secrets Manager** - Amazon Web Services secret storage
- **HashiCorp Vault** - Open-source secrets management
- **GCP Secret Manager** - Google Cloud secret storage

## Modes

### Pull key and decrypt (default)

Fetches the secret, writes the key to `.env.keys`, and decrypts `.env.<env>`.

```bash
envdrift vault-pull ./services/myapp my-secret-name --env production \
  -p azure --vault-url https://myvault.vault.azure.net/
```

This fetches `my-secret-name`, writes `DOTENV_PRIVATE_KEY_PRODUCTION` to
`./services/myapp/.env.keys`, and decrypts `./services/myapp/.env.production`.

For a custom dotenv filename, pass `--env-file` while keeping `--env` as the key
suffix:

```bash
envdrift vault-pull ./secrets/postgresql postgres-key --env production \
  --env-file postgresql.env -p azure --vault-url https://myvault.vault.azure.net/
```

### Pull key only (skip decryption)

Use `--no-decrypt` to only write the key without touching the `.env.<env>` file.

```bash
envdrift vault-pull ./services/myapp my-secret-name --env production --no-decrypt \
  -p azure --vault-url https://myvault.vault.azure.net/
```

## Options

### `FOLDER`

Path to the folder where the fetched `.env.keys` file is written (and which contains
the `.env.<env>` file to decrypt).

### `SECRET_NAME`

Name of the secret to fetch from the vault.

### `--env`, `-e`

**Required.** Environment suffix that names the key written to `.env.keys`
(e.g., `--env soak` writes `DOTENV_PRIVATE_KEY_SOAK`). It also selects which
`.env.<env>` file is decrypted unless `--no-decrypt` is used.

The secret value may be stored as either `DOTENV_PRIVATE_KEY_<ENV>=<value>`
(the format written by `vault-push`) or a bare value — both are handled. When
the stored value carries a `DOTENV_PRIVATE_KEY_<SUFFIX>=` prefix, the `<SUFFIX>`
must match `--env`; a mismatch (e.g. a `DOTENV_PRIVATE_KEY_STAGING=` value pulled
with `--env production`) is rejected rather than silently relabeled, so a key
for one environment is never installed as another.

The fetched value is normalized through the same parser used by `envdrift sync`
and `lock --verify-vault` before anything is written, so these storage shapes
all yield the bare key:

- surrounding whitespace and one layer of quotes are stripped (including a
  whole-line-quoted `"DOTENV_PRIVATE_KEY_<ENV>=<key>"` value)
- a JSON key/value document (the AWS console's native storage shape, or a
  HashiCorp KV entry) holding a `DOTENV_PRIVATE_KEY_<ENV>` field has that field
  extracted
- a multi-line `.env.keys` file blob (e.g. pushed with
  `az keyvault secret set --file .env.keys`) has the matching key line extracted

Anything that cannot be reduced to a single key token fails with an error naming
the secret's layout instead of writing a corrupted `.env.keys`: JSON documents
without a usable key field, multi-line documents without a key line, binary
payloads (AWS `SecretBinary` / non-UTF-8 GCP payloads), and values that still
contain whitespace or look like structured documents after normalization.

### `--no-decrypt`

Only write the key to `.env.keys`; do not decrypt the `.env.<env>` file.

### `--env-file`

Custom dotenv filename to decrypt, relative to `FOLDER`. This is useful for files
like `postgresql.env` or `dotnet-service-template.env.sqa`. The key name still
comes from `--env`.

### `--config`, `-c`

Path to an `envdrift.toml` config file used to read default provider settings.

### `--provider`, `-p`

Vault provider to use. Required unless configured in `envdrift.toml`.

Options: `azure`, `aws`, `hashicorp`, `gcp`

### `--vault-url`

Vault URL. **Required for Azure and HashiCorp** unless configured in `envdrift.toml`.

### `--region`

AWS region for Secrets Manager. Default: `us-east-1`.

### `--project-id`

GCP project ID for Secret Manager. Required for the `gcp` provider unless configured in `envdrift.toml`.

## Configuration

Provider settings can be read from `envdrift.toml`:

```toml
[vault]
provider = "azure"

[vault.azure]
vault_url = "https://my-keyvault.vault.azure.net/"

[vault.aws]
region = "us-east-1"

[vault.hashicorp]
url = "https://vault.example.com:8200"

[vault.gcp]
project_id = "my-gcp-project"
```

When configured, you can omit the `--provider`, `--vault-url`, and `--project-id` flags.

## Examples

### Azure Key Vault

```bash
# Pull and decrypt
envdrift vault-pull ./services/myapp myapp-key --env production \
  -p azure --vault-url https://myvault.vault.azure.net/

# Using config from envdrift.toml
envdrift vault-pull ./services/myapp myapp-key --env production
```

### AWS Secrets Manager

```bash
envdrift vault-pull ./services/myapp myapp-key --env staging \
  -p aws --region us-west-2
```

### HashiCorp Vault

```bash
envdrift vault-pull ./services/myapp myapp-key --env dev \
  -p hashicorp --vault-url https://vault.example.com:8200
```

### GCP Secret Manager

```bash
envdrift vault-pull ./services/myapp myapp-key --env production \
  -p gcp --project-id my-gcp-project
```

## Output

On success:

```text
Pulled 'myapp-key' -> DOTENV_PRIVATE_KEY_PRODUCTION written to services/myapp/.env.keys
Decrypted services/myapp/.env.production
```

On error, the command prints a single clean `[ERROR]` line and exits 1 — never
a raw traceback. AWS not-found errors name the region that was searched (the
client defaults to `us-east-1` when `--region` is omitted):

```text
[ERROR] Secret 'myapp-key' not found in azure vault
[ERROR] Secret 'myapp-key' not found in aws vault (region us-east-1)
[ERROR] Folder not found: ./services/typo
[ERROR] Cannot write services/myapp/.env.keys: [Errno 13] Permission denied: ...
```

`FOLDER` must be an existing directory; it is validated before the secret is
fetched.

## Exit Codes

| Code | Meaning                                              |
| :--- | :--------------------------------------------------- |
| 0    | Success (key written, file decrypted if applicable)  |
| 1    | Error (auth failure, secret not found, decrypt error) |

## Authentication

`vault-pull` uses the same credential chains as `vault-push`:

- **Azure Key Vault**: `DefaultAzureCredential` (env vars, Managed Identity, `az login`)
- **AWS Secrets Manager**: boto3 credential chain (env vars, `~/.aws/credentials`, IAM role)
- **HashiCorp Vault**: `VAULT_TOKEN` environment variable
- **GCP Secret Manager**: Application Default Credentials

## `vault-pull` vs `decrypt --verify-vault`

Both commands fetch a key from your vault, but they do very different things — don't confuse them:

| | `vault-pull` | `decrypt --verify-vault` |
| :--- | :--- | :--- |
| **Purpose** | Onboarding — get the key and use it | CI health-check — does the shared key still work? |
| **Writes `.env.keys`?** | **Yes** | No |
| **Decrypts the real file?** | **Yes** (unless `--no-decrypt`) | No — tests in a throwaway temp dir, then discards |
| **Persists anything?** | Yes | No (prints *"Original file was not decrypted"*) |

Use `vault-pull` to actually fetch a key onto a machine and decrypt. Use
[`decrypt --verify-vault`](decrypt.md) only to verify, in CI, that the vault's
shared key can still decrypt an encrypted file — it never writes the key or
touches the file.

## See Also

- [vault-push](vault-push.md) - Push a single key to a vault (opposite of vault-pull)
- [pull](pull.md) - Config-based, multi-service pull + decrypt
- [decrypt](decrypt.md) - Decrypt an env file using a local key (and `--verify-vault` CI check)
- [Env File Sync Guide](../guides/env-file-sync.md) - Detailed vault setup guide
