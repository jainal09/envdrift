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
(the format written by `vault-push`) or a bare value — both are handled.

### `--no-decrypt`

Only write the key to `.env.keys`; do not decrypt the `.env.<env>` file.

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

On error:

```text
Error: Secret 'myapp-key' not found in azure vault
```

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

## See Also

- [vault-push](vault-push.md) - Push a single key to a vault (opposite of vault-pull)
- [pull](pull.md) - Config-based, multi-service pull + decrypt
- [decrypt](decrypt.md) - Decrypt an env file using a local key
- [Vault Sync Guide](../guides/vault-sync.md) - Detailed vault setup guide
