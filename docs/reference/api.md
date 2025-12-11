# Python API Reference

Use envdrift programmatically in your Python code.

## Core Functions

### validate

Validate an .env file against a Pydantic schema.

```python
from envdrift import validate

result = validate(
    env_file=".env",
    schema="config.settings:Settings",
    service_dir=None,
    check_encryption=True,
)

if result.valid:
    print("Validation passed!")
else:
    print(f"Missing required: {result.missing_required}")
    print(f"Extra variables: {result.extra_vars}")
    print(f"Type errors: {result.type_errors}")
    print(f"Unencrypted secrets: {result.unencrypted_secrets}")
```

**Parameters:**

| Parameter          | Type                  | Description                           | Default  |
|--------------------|-----------------------|---------------------------------------|----------|
| `env_file`         | `Path \| str`         | Path to .env file                     | `".env"` |
| `schema`           | `str`                 | Dotted path to Settings class         | Required |
| `service_dir`      | `Path \| str \| None` | Directory to add to sys.path          | `None`   |
| `check_encryption` | `bool`                | Check if sensitive vars are encrypted | `True`   |

**Returns:** `ValidationResult`

### diff

Compare two .env files.

```python
from envdrift import diff

result = diff(
    env1=".env.development",
    env2=".env.production",
    schema=None,
    mask_values=True,
)

if result.has_drift:
    print(f"Added: {result.added_count}")
    print(f"Removed: {result.removed_count}")
    print(f"Changed: {result.changed_count}")

    for d in result.get_added():
        print(f"+ {d.name}")
    for d in result.get_removed():
        print(f"- {d.name}")
    for d in result.get_changed():
        print(f"~ {d.name}: {d.value1} -> {d.value2}")
```

**Parameters:**

| Parameter     | Type          | Description                        | Default  |
|---------------|---------------|------------------------------------|----------|
| `env1`        | `Path \| str` | Path to first .env file            | Required |
| `env2`        | `Path \| str` | Path to second .env file           | Required |
| `schema`      | `str \| None` | Schema for sensitive field masking | `None`   |
| `mask_values` | `bool`        | Mask sensitive values              | `True`   |

**Returns:** `DiffResult`

### init

Generate a Settings class from an existing .env file.

```python
from envdrift import init

output_path = init(
    env_file=".env",
    output="settings.py",
    class_name="Settings",
    detect_sensitive=True,
)

print(f"Generated: {output_path}")
```

**Parameters:**

| Parameter          | Type          | Description                | Default         |
|--------------------|---------------|----------------------------|-----------------|
| `env_file`         | `Path \| str` | Path to .env file          | `".env"`        |
| `output`           | `Path \| str` | Output file path           | `"settings.py"` |
| `class_name`       | `str`         | Name for Settings class    | `"Settings"`    |
| `detect_sensitive` | `bool`        | Auto-detect sensitive vars | `True`          |

**Returns:** `Path` to generated file

---

## Core Classes

### EnvParser

Parse .env files.

```python
from envdrift.core import EnvParser

parser = EnvParser()
env = parser.parse(".env")

for name, var in env.variables.items():
    print(f"{name}={var.value} (encrypted: {var.is_encrypted})")
```

### Validator

Validate env files against schemas.

```python
from envdrift.core import EnvParser, SchemaLoader, Validator

parser = EnvParser()
env = parser.parse(".env")

loader = SchemaLoader()
schema = loader.extract_metadata(MySettings)

validator = Validator()
result = validator.validate(env, schema)
```

### DiffEngine

Compare env files.

```python
from envdrift.core import EnvParser, DiffEngine

parser = EnvParser()
env1 = parser.parse(".env.dev")
env2 = parser.parse(".env.prod")

engine = DiffEngine()
result = engine.diff(env1, env2)
```

### EncryptionDetector

Analyze encryption status.

```python
from envdrift.core import EnvParser, EncryptionDetector

parser = EnvParser()
env = parser.parse(".env")

detector = EncryptionDetector()
report = detector.analyze(env)

print(f"Encrypted: {report.encrypted_vars}")
print(f"Plaintext secrets: {report.plaintext_secrets}")
```

---

## Vault Clients

### Azure Key Vault

```python
from envdrift.vault import AzureKeyVault

vault = AzureKeyVault(vault_url="https://myvault.vault.azure.net")
secret = vault.get_secret("database-url")
print(secret.value)
```

### AWS Secrets Manager

```python
from envdrift.vault import AWSSecretsManager

vault = AWSSecretsManager(region_name="us-east-1")
secret = vault.get_secret("prod/database-url")
print(secret.value)
```

### HashiCorp Vault

```python
from envdrift.vault import HashiCorpVault

vault = HashiCorpVault(
    url="https://vault.example.com",
    token="hvs.xxx",
)
secret = vault.get_secret("secret/data/myapp", key="database_url")
print(secret.value)
```
