# Glossary

Quick reference for terms used throughout envdrift documentation.

## A

### Azure Key Vault

Microsoft Azure's cloud service for securely storing and accessing secrets, keys, and certificates. envdrift supports syncing encryption keys from
Azure Key Vault using the `sync` command with `-p azure`.

### AWS Secrets Manager

Amazon Web Services' secrets management service. envdrift supports syncing encryption keys from AWS Secrets Manager using the `sync` command with
`-p aws`.

## B

### BaseSettings

Pydantic's base class for settings management. envdrift validates `.env` files against classes that inherit from `pydantic_settings.BaseSettings`.

## D

### Dotenvx

An open-source tool for encrypting `.env` files using AES-256-GCM encryption. envdrift integrates with dotenvx for encryption/decryption operations.
See [dotenvx.com](https://dotenvx.com).

### DOTENV_PRIVATE_KEY

The private key used by dotenvx to decrypt encrypted `.env` files. Stored in `.env.keys` files with format `DOTENV_PRIVATE_KEY_{ENVIRONMENT}=<key>`.

### Drift

When environment variables become inconsistent between different environments (dev, staging, production) or between the schema definition and actual
`.env` files. envdrift helps detect and prevent drift.

## E

### Encryption Ratio

The percentage of variables in a `.env` file that are encrypted. Shown in the `envdrift encrypt --check` output.

### .env File

A file containing environment variables in `KEY=value` format. Common naming conventions include `.env.development`, `.env.staging`, and `.env.production`.

### .env.keys

A file containing dotenvx private keys for decryption. Should never be committed to version control. Format:

```text
DOTENV_PRIVATE_KEY_PRODUCTION=<key>
DOTENV_PRIVATE_KEY_STAGING=<key>
```

### Extra Variables

Environment variables present in a `.env` file but not defined in the schema. Can indicate configuration drift or deprecated variables.

## F

### Field Metadata

Information about a schema field including name, type, whether it's required, default value, description, and sensitivity status.

### Force Mode

A sync mode (`--force`) that updates all mismatched values without prompting for confirmation.

## H

### HashiCorp Vault

An open-source secrets management tool. envdrift supports syncing encryption keys from HashiCorp Vault using the `sync` command with `-p hashicorp`.

## I

### Interactive Mode

The default sync mode where envdrift prompts for confirmation before updating mismatched values.

## M

### Missing Optional

Variables defined in the schema with defaults that are not present in the `.env` file. These don't cause validation failure since defaults will be used.

### Missing Required

Variables defined as required in the schema but not present in the `.env` file. These cause validation failure.

## P

### pair.txt

A configuration file format for the `sync` command that maps vault secret names to local folder paths:

```text
secret-name=folder-path
vault-name/secret-name=folder-path
```

### Plaintext Secret

A sensitive variable that is not encrypted. envdrift warns about these during validation and the `encrypt --check` command can enforce encryption.

### Pre-commit Hook

A git hook that runs before commits. envdrift can install hooks to validate `.env` files and check encryption status automatically.

### Pydantic

A Python library for data validation using type annotations. envdrift uses Pydantic for schema definition and validation.

### Pydantic Settings

An extension of Pydantic for managing application settings, including loading from `.env` files. envdrift validates against
`pydantic_settings.BaseSettings` subclasses.

## S

### Schema

A Pydantic Settings class that defines the expected structure, types, and constraints of environment variables. Example:

```python
class Settings(BaseSettings):
    DATABASE_URL: str = Field(json_schema_extra={"sensitive": True})
    DEBUG: bool = False
```

### Schema Path

A dotted import path to a Settings class, in format `module.path:ClassName`. Example: `config.settings:ProductionSettings`.

### Sensitive Field

A field marked with `json_schema_extra={"sensitive": True}` that should be encrypted in production environments.

### Service Directory

The directory added to Python's import path when loading a schema. Specified with `--service-dir` or `-d`.

### Sync

The process of fetching encryption keys from a cloud vault and updating local `.env.keys` files. See [sync command](cli/sync.md).

## T

### Type Error

When a variable's value cannot be converted to the type specified in the schema (e.g., `"abc"` for an `int` field).

## U

### Unencrypted Secret

A variable marked as sensitive in the schema but stored in plaintext (not encrypted with dotenvx). Shown as a warning during validation.

## V

### Validation

The process of checking a `.env` file against a schema to ensure all required variables are present, types are correct, and sensitive fields are
properly handled.

### ValidationResult

The output of validation containing:

- `valid`: Whether validation passed
- `missing_required`: Required variables not in .env
- `missing_optional`: Optional variables not in .env
- `extra_vars`: Variables in .env but not in schema
- `unencrypted_secrets`: Sensitive variables not encrypted
- `type_errors`: Variables with wrong types
- `warnings`: Non-fatal issues

### Vault

A secure storage system for secrets. envdrift supports Azure Key Vault, AWS Secrets Manager, and HashiCorp Vault.

### Vault Provider

The cloud service or tool used for secrets storage. Options: `azure`, `aws`, `hashicorp`.

### Verify Mode

A sync mode (`--verify`) that checks for differences without modifying any files. Useful for CI/CD pipelines.

## See Also

- [CLI Reference](cli/index.md) - All commands and options
- [Quick Start](getting-started/quickstart.md) - Getting started guide
- [Schema Best Practices](guides/schema.md) - Writing effective schemas
