# envdrift decrypt

Decrypt an encrypted .env file using dotenvx.

## Synopsis

```bash
envdrift decrypt [ENV_FILE]
```

## Description

The `decrypt` command decrypts .env files that were encrypted with dotenvx. This is useful for:

- Local development after cloning a repo
- Viewing encrypted values
- Migrating to a different encryption system

## Arguments

| Argument   | Description                     | Default |
| :--------- | :------------------------------ | :------ |
| `ENV_FILE` | Path to the encrypted .env file | `.env`  |

## Examples

### Basic Decryption

```bash
envdrift decrypt .env.production
```

Output:

```text
[OK] Decrypted .env.production
```

### Decrypt Specific Environment

```bash
envdrift decrypt .env.staging
```

## Requirements

### Private Key

Decryption requires the private key, which can be provided via:

1. **`.env.keys` file** (recommended for local development):

   ```bash
   # .env.keys
   DOTENV_PRIVATE_KEY_PRODUCTION="abc123..."
   ```

2. **Environment variable** (recommended for CI/CD):

   ```bash
   export DOTENV_PRIVATE_KEY_PRODUCTION="abc123..."
   envdrift decrypt .env.production
   ```

### dotenvx

The dotenvx binary is required. envdrift will:

1. Check if dotenvx is installed
2. If not, provide installation instructions

## Workflow

### Local Development

After cloning a repo with encrypted .env files:

```bash
# 1. Get the private key from your team (securely!)
# 2. Add it to .env.keys
echo 'DOTENV_PRIVATE_KEY_PRODUCTION="your-key-here"' > .env.keys

# 3. Decrypt
envdrift decrypt .env.production
```

### CI/CD Pipeline

```yaml
# GitHub Actions
env:
  DOTENV_PRIVATE_KEY_PRODUCTION: ${{ secrets.DOTENV_PRIVATE_KEY_PRODUCTION }}

steps:
  - name: Decrypt environment
    run: envdrift decrypt .env.production
```

## Error Handling

### Missing Private Key

```text
[ERROR] Decryption failed
Check that .env.keys exists or DOTENV_PRIVATE_KEY_* is set
```

### Wrong Private Key

```text
[ERROR] Decryption failed
The private key does not match the encrypted file
```

### dotenvx Not Installed

```text
[ERROR] dotenvx is not installed
Install: curl -sfS https://dotenvx.sh | sh
```

## Security Notes

- Never commit `.env.keys` to version control
- Add `.env.keys` to your `.gitignore`
- Use secrets management (GitHub Secrets, Vault, etc.) for CI/CD
- Rotate keys if they are ever exposed

## See Also

- [encrypt](encrypt.md) - Encrypt .env files
- [validate](validate.md) - Validate .env files
