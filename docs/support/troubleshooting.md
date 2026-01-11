# Troubleshooting

Common issues and how to resolve them.

## Known Issues

- Partial encryption: `envdrift lock` could encrypt combined files (like `.env.production`)
  and make non-sensitive values unreadable. Fix: lock now skips `.clear` and combined
  files; use `envdrift push` for partial encryption workflows on older versions.

## Schema Validation Issues

### "Module not found" when validating

**Problem:**

```text
Error: Cannot import module 'config.settings'
```

**Solution:**

1. Check the module path is correct (use `:` to separate module from class)
2. Use `--service-dir` to add the correct directory to Python path

```bash
# Wrong
envdrift validate .env --schema config.settings.Settings

# Correct
envdrift validate .env --schema config.settings:Settings

# With service directory
envdrift validate .env --schema config:Settings --service-dir ./backend
```

### Settings class instantiates on import

**Problem:**

```text
ValidationError: DATABASE_URL field required
```

This happens when your settings module creates a `Settings()` instance at import time.

**Solution:**

Guard the instantiation:

```python
import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    DATABASE_URL: str

# Guard against import during schema extraction
if not os.getenv("ENVDRIFT_SCHEMA_EXTRACTION"):
    settings = Settings()
```

### "Extra fields not permitted"

**Problem:**

```text
EXTRA VARIABLES (not in schema):
  - EXTRA_VAR
```

**Solution:**

Either add the variable to your schema or change the `extra` setting:

```python
class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        extra="ignore"  # or "allow" to silence the warning
    )
```

## Encryption Issues

### "dotenvx not found"

**Problem:**

```text
Error: dotenvx is not installed
```

**Solution:**

Install dotenvx:

```bash
# macOS
brew install dotenvx/brew/dotenvx

# npm
npm install -g @dotenvx/dotenvx

# Or enable auto-install in config
```

```toml
# envdrift.toml
[encryption.dotenvx]
auto_install = true
```

### "sops not found"

**Problem:**

```text
Error: sops is not installed
```

**Solution:**

Install SOPS:

```bash
# macOS
brew install sops

# Linux
wget https://github.com/getsops/sops/releases/download/v3.8.1/sops-v3.8.1.linux.amd64 -O /usr/local/bin/sops
chmod +x /usr/local/bin/sops
```

### "Failed to decrypt: no key found"

**Problem:**

```text
Error: could not decrypt: no key found to decrypt
```

**Causes and solutions:**

1. **Missing .env.keys file** — Run `envdrift sync` to fetch keys from vault
2. **Wrong key** — The file was encrypted with a different key
3. **SOPS: Missing age key** — Set `SOPS_AGE_KEY_FILE` or add key to `~/.config/sops/age/keys.txt`

```bash
# For dotenvx
envdrift sync  # Fetches keys from vault

# For SOPS with age
export SOPS_AGE_KEY_FILE=~/.config/sops/age/keys.txt
```

### "File is not encrypted"

**Problem:**

```text
Warning: File does not appear to be encrypted
```

**Solution:**

The file wasn't encrypted. Run encrypt:

```bash
envdrift encrypt .env.production
```

## Vault Issues

### Azure: "DefaultAzureCredential failed"

**Problem:**

```text
azure.core.exceptions.ClientAuthenticationError: DefaultAzureCredential failed
```

**Solutions:**

1. Login with Azure CLI: `az login`
2. Set environment variables:

   ```bash
   export AZURE_CLIENT_ID="..."
   export AZURE_CLIENT_SECRET="..."
   export AZURE_TENANT_ID="..."
   ```

3. Check you have access to the Key Vault in Azure portal

### AWS: "Unable to locate credentials"

**Problem:**

```text
botocore.exceptions.NoCredentialsError: Unable to locate credentials
```

**Solutions:**

1. Configure AWS CLI: `aws configure`
2. Set environment variables:

   ```bash
   export AWS_ACCESS_KEY_ID="..."
   export AWS_SECRET_ACCESS_KEY="..."
   ```

3. In CI, use OIDC or IAM roles

### HashiCorp: "permission denied"

**Problem:**

```text
hvac.exceptions.Forbidden: permission denied
```

**Solutions:**

1. Check your token has the correct policies
2. Ensure the token hasn't expired
3. Verify the secret path is correct (including `secret/data/` prefix for KV v2)

```bash
export VAULT_TOKEN="hvs.xxx"
vault kv get secret/myapp/key  # Test access manually
```

### GCP: "Could not automatically determine credentials"

**Problem:**

```text
google.auth.exceptions.DefaultCredentialsError: Could not automatically determine credentials
```

**Solutions:**

1. Login with gcloud: `gcloud auth application-default login`
2. Set service account key:

   ```bash
   export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account.json"
   ```

### "Secret not found"

**Problem:**

```text
Error: Secret 'myapp-key' not found in vault
```

**Solutions:**

1. Check the secret name matches exactly (case-sensitive)
2. Verify the secret exists: check vault UI or CLI
3. Push the secret first: `envdrift vault-push . myapp-key`

## Pre-commit Hook Issues

### Hook doesn't run

**Problem:**

Pre-commit skips envdrift hooks.

**Solution:**

Ensure the hook is properly configured:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: envdrift-validate
        name: Validate .env files
        entry: envdrift validate
        args: [".env.production", "--schema", "config:Settings", "--ci"]
        language: system
        files: ^\.env\.production$
        pass_filenames: false
```

### "envdrift: command not found" in pre-commit

**Problem:**

Pre-commit can't find envdrift.

**Solution:**

Use the full path or ensure it's in PATH:

```yaml
entry: /path/to/venv/bin/envdrift validate
# or
entry: python -m envdrift validate
```

## CI/CD Issues

### Validation passes locally but fails in CI

**Causes:**

1. **Different Python version** — Schema behaves differently
2. **Missing dependencies** — Install with `pip install envdrift[vault]`
3. **Different working directory** — Use absolute paths or `--service-dir`

### Exit code is always 0

**Problem:**

Pipeline doesn't fail on validation errors.

**Solution:**

Add `--ci` flag:

```bash
envdrift validate .env.production --schema config:Settings --ci
```

### Can't decrypt in CI

**Problem:**

```text
Error: No key found to decrypt
```

**Solutions:**

1. Store the private key as a CI secret
2. Use vault sync with CI credentials
3. For SOPS, configure KMS access for the CI runner

```yaml
# GitHub Actions example
- name: Decrypt env
  env:
    DOTENV_PRIVATE_KEY: ${{ secrets.DOTENV_PRIVATE_KEY }}
  run: |
    echo "DOTENV_PRIVATE_KEY=$DOTENV_PRIVATE_KEY" > .env.keys
    envdrift decrypt .env.production
```

## Performance Issues

### Slow schema loading

**Problem:**

`envdrift validate` takes a long time to start.

**Causes:**

1. Heavy imports in your settings module
2. Database connections at import time

**Solution:**

Guard expensive operations:

```python
import os

if not os.getenv("ENVDRIFT_SCHEMA_EXTRACTION"):
    # Expensive imports or operations here
    from myapp.database import engine
```

## Getting Help

If you're still stuck:

1. Run with `--verbose` for more details
2. Check the [FAQ](faq.md)
3. Search [GitHub Issues](https://github.com/jainal09/envdrift/issues)
4. Open a new issue with reproduction steps
