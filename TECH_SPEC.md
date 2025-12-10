# envdrift Technical Specification

**Version:** 0.1.0 (Target Release)
**Author:** Jainal Gosaliya
**Last Updated:** 2025-12-09

---

## Table of Contents

1. [Overview](#1-overview)
2. [Goals & Non-Goals](#2-goals--non-goals)
3. [Architecture](#3-architecture)
4. [Core Modules](#4-core-modules)
5. [CLI Commands](#5-cli-commands)
6. [Multi-Vault Support](#6-multi-vault-support)
7. [dotenvx Integration Strategy](#7-dotenvx-integration-strategy)
8. [Configuration](#8-configuration)
9. [Testing Strategy](#9-testing-strategy)
10. [Migration from Shell Scripts](#10-migration-from-shell-scripts)
11. [Dependencies](#11-dependencies)
12. [Milestones](#12-milestones)

---

## 1. Overview

### What is envdrift?

`envdrift` is a Python CLI tool and library that prevents environment variable drift between development, staging, and production environments. It provides:

- **Schema validation** against Pydantic Settings classes
- **Cross-environment diff** to detect configuration drift
- **Encryption detection** for dotenvx-encrypted .env files
- **Pre-commit hook** integration
- **Multi-vault key sync** from AWS Secrets Manager, Azure Key Vault, and HashiCorp Vault

### Problem Statement

Environment variable drift causes:
- Production outages from missing/wrong config
- Silent failures when defaults mask missing vars
- Security incidents from unencrypted secrets in repos
- "Works on my machine" syndrome

### Solution

A unified tool that:
1. Validates .env files against typed Pydantic schemas at commit time
2. Detects differences between environment configs
3. Ensures secrets are encrypted before commit
4. Syncs encryption keys from cloud vaults

---

## 2. Goals & Non-Goals

### Goals

| Goal | Priority | Description |
|------|----------|-------------|
| Schema validation | P0 | Validate .env against Pydantic Settings class |
| Cross-env diff | P0 | Compare two .env files, show differences |
| Encryption detection | P0 | Detect unencrypted secrets, warn/block |
| Pre-commit hook | P0 | Block commits with invalid/unencrypted config |
| CI mode | P0 | Exit codes for CI/CD pipelines |
| Multi-vault sync | P1 | Support AWS, Azure, HashiCorp Vault |
| Schema generation | P1 | Generate Settings class from existing .env |
| Rich CLI output | P1 | Beautiful terminal output with Rich |
| dotenvx integration | P2 | Encrypt/decrypt via dotenvx CLI |
| Python API | P2 | Importable library, not just CLI |

### Non-Goals

- **Not a secrets manager**: We sync keys, not store them
- **Not a dotenvx replacement**: We wrap it, not reimplement it
- **Not a Pydantic replacement**: We use Pydantic, not compete with it
- **Not a configuration loader**: We validate, apps load their own config

---

## 3. Architecture

### High-Level Design

```
┌─────────────────────────────────────────────────────────────────┐
│                         envdrift CLI                             │
├─────────────────────────────────────────────────────────────────┤
│  validate  │  diff  │  init  │  sync  │  encrypt  │  hook       │
└─────┬──────┴───┬────┴───┬────┴───┬────┴─────┬─────┴──────┬──────┘
      │          │        │        │          │            │
      ▼          ▼        ▼        ▼          ▼            ▼
┌──────────┐ ┌───────┐ ┌──────┐ ┌───────┐ ┌─────────┐ ┌─────────┐
│ Schema   │ │ Diff  │ │Schema│ │ Vault │ │ dotenvx │ │Pre-commit│
│ Validator│ │ Engine│ │ Gen  │ │ Sync  │ │ Wrapper │ │ Manager │
└────┬─────┘ └───┬───┘ └──┬───┘ └───┬───┘ └────┬────┘ └────┬────┘
     │           │        │         │          │           │
     ▼           ▼        ▼         ▼          ▼           ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Core Components                           │
├──────────────┬──────────────┬──────────────┬────────────────────┤
│ EnvParser    │ SchemaLoader │ VaultClient  │ EncryptionDetector │
└──────────────┴──────────────┴──────────────┴────────────────────┘
```

### Directory Structure

```
envdrift/
├── src/envdrift/
│   ├── __init__.py           # Public API exports
│   ├── cli.py                # Typer CLI application
│   ├── core/
│   │   ├── __init__.py
│   │   ├── parser.py         # .env file parsing
│   │   ├── schema.py         # Pydantic schema loading
│   │   ├── validator.py      # Validation logic
│   │   ├── diff.py           # Cross-environment diff
│   │   └── encryption.py     # Encryption detection
│   ├── vault/
│   │   ├── __init__.py
│   │   ├── base.py           # Abstract vault interface
│   │   ├── azure.py          # Azure Key Vault
│   │   ├── aws.py            # AWS Secrets Manager
│   │   └── hashicorp.py      # HashiCorp Vault
│   ├── integrations/
│   │   ├── __init__.py
│   │   ├── dotenvx.py        # dotenvx CLI wrapper
│   │   └── precommit.py      # Pre-commit hook management
│   ├── output/
│   │   ├── __init__.py
│   │   └── rich.py           # Rich console formatting
│   └── config.py             # envdrift configuration (envdrift.toml)
├── tests/
│   ├── conftest.py           # Pytest fixtures
│   ├── test_parser.py
│   ├── test_validator.py
│   ├── test_diff.py
│   ├── test_encryption.py
│   ├── test_vault/
│   │   ├── test_azure.py
│   │   ├── test_aws.py
│   │   └── test_hashicorp.py
│   └── test_cli.py
├── pyproject.toml
├── envdrift.toml.example     # Example config file
└── TECH_SPEC.md              # This document
```

---

## 4. Core Modules

### 4.1 EnvParser (`core/parser.py`)

Parses .env files into structured data.

```python
from dataclasses import dataclass
from pathlib import Path
from enum import Enum

class EncryptionStatus(Enum):
    ENCRYPTED = "encrypted"      # dotenvx encrypted value
    PLAINTEXT = "plaintext"      # Unencrypted value
    EMPTY = "empty"              # No value

@dataclass
class EnvVar:
    """Parsed environment variable."""
    name: str
    value: str
    line_number: int
    encryption_status: EncryptionStatus
    raw_line: str

@dataclass
class EnvFile:
    """Parsed .env file."""
    path: Path
    variables: dict[str, EnvVar]
    comments: list[str]
    is_encrypted: bool  # True if ANY var is encrypted

class EnvParser:
    """Parse .env files with dotenvx encryption awareness."""

    ENCRYPTED_PATTERN = re.compile(r"^encrypted:")

    def parse(self, path: Path) -> EnvFile:
        """Parse .env file and return structured data."""
        ...

    def parse_string(self, content: str) -> EnvFile:
        """Parse .env content from string (for testing)."""
        ...
```

**Features to port from `validate_env_schema.py`:**
- Handle `KEY=value`, `KEY="value"`, `KEY='value'`
- Detect dotenvx `encrypted:` prefix
- Track line numbers for error reporting
- Skip comments and blank lines

### 4.2 SchemaLoader (`core/schema.py`)

Dynamically loads Pydantic Settings classes.

```python
from typing import Any
from pydantic_settings import BaseSettings

@dataclass
class FieldMetadata:
    """Metadata about a settings field."""
    name: str
    required: bool
    sensitive: bool
    default: Any
    description: str | None
    field_type: type

@dataclass
class SchemaMetadata:
    """Complete schema metadata."""
    class_name: str
    module_path: str
    fields: dict[str, FieldMetadata]
    extra_policy: str  # "forbid", "ignore", "allow"

class SchemaLoader:
    """Load and introspect Pydantic Settings classes."""

    def load(self, dotted_path: str) -> type[BaseSettings]:
        """
        Load settings class from dotted path.

        Args:
            dotted_path: e.g., "config.settings:ProductionSettings"

        Returns:
            The Pydantic Settings class
        """
        ...

    def extract_metadata(self, settings_cls: type[BaseSettings]) -> SchemaMetadata:
        """Extract field metadata from Settings class."""
        ...

    def get_schema_metadata_func(self, module_path: str) -> dict | None:
        """
        Check if module has get_schema_metadata() function.
        This allows projects to customize schema export.
        """
        ...
```

**Features to port:**
- Dynamic import via `importlib`
- Extract from `model_fields`
- Support `get_schema_metadata()` function in module
- Handle `json_schema_extra={"sensitive": True}`

### 4.3 Validator (`core/validator.py`)

Core validation logic.

```python
from dataclasses import dataclass

@dataclass
class ValidationResult:
    """Result of schema validation."""
    valid: bool
    missing_required: set[str]
    missing_optional: set[str]
    extra_vars: set[str]
    unencrypted_secrets: set[str]
    type_errors: dict[str, str]  # {var: error_message}
    warnings: list[str]

class Validator:
    """Validate .env files against Pydantic schemas."""

    # Patterns that suggest a value is a secret
    SECRET_PATTERNS = [
        re.compile(r"^sk[-_]"),           # API keys
        re.compile(r"^pk[-_]"),           # Public/private keys
        re.compile(r"password", re.I),    # Passwords
        re.compile(r"secret", re.I),      # Secrets
        re.compile(r"^ghp_"),             # GitHub tokens
        re.compile(r"^xox[baprs]-"),      # Slack tokens
        re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access keys
        re.compile(r"^postgres://.*:.*@"), # DB URLs with creds
        re.compile(r"^mysql://.*:.*@"),
        re.compile(r"^redis://.*:.*@"),
    ]

    def validate(
        self,
        env_file: EnvFile,
        schema: SchemaMetadata,
        check_encryption: bool = True,
        check_extra: bool = True,
    ) -> ValidationResult:
        """
        Validate env file against schema.

        Checks:
        1. All required vars exist
        2. No unexpected vars (if schema has extra="forbid")
        3. Sensitive vars are encrypted
        4. Values match expected types (basic check)
        """
        ...

    def is_value_suspicious(self, value: str) -> bool:
        """Check if plaintext value looks like a secret."""
        ...
```

### 4.4 Diff Engine (`core/diff.py`)

Compare environments.

```python
from dataclasses import dataclass
from enum import Enum

class DiffType(Enum):
    ADDED = "added"           # In env2 but not env1
    REMOVED = "removed"       # In env1 but not env2
    CHANGED = "changed"       # Different values
    UNCHANGED = "unchanged"   # Same values

@dataclass
class VarDiff:
    """Difference for a single variable."""
    name: str
    diff_type: DiffType
    value1: str | None        # Value in env1 (masked if sensitive)
    value2: str | None        # Value in env2 (masked if sensitive)
    is_sensitive: bool

@dataclass
class DiffResult:
    """Result of comparing two env files."""
    env1_path: Path
    env2_path: Path
    differences: list[VarDiff]
    added_count: int
    removed_count: int
    changed_count: int

    @property
    def has_drift(self) -> bool:
        return self.added_count + self.removed_count + self.changed_count > 0

class DiffEngine:
    """Compare two .env files."""

    def diff(
        self,
        env1: EnvFile,
        env2: EnvFile,
        schema: SchemaMetadata | None = None,
        mask_values: bool = True,
    ) -> DiffResult:
        """
        Compare two env files.

        Args:
            env1: First env file (typically dev/staging)
            env2: Second env file (typically prod)
            schema: Optional schema for sensitive field detection
            mask_values: Whether to mask sensitive values in output
        """
        ...
```

### 4.5 Encryption Detector (`core/encryption.py`)

Detect encryption status.

```python
@dataclass
class EncryptionReport:
    """Report on encryption status of an env file."""
    path: Path
    is_fully_encrypted: bool
    encrypted_vars: set[str]
    plaintext_vars: set[str]
    plaintext_secrets: set[str]  # Plaintext vars that look like secrets
    warnings: list[str]

class EncryptionDetector:
    """Detect encryption status of .env files."""

    def analyze(
        self,
        env_file: EnvFile,
        schema: SchemaMetadata | None = None,
    ) -> EncryptionReport:
        """Analyze encryption status of env file."""
        ...

    def should_block_commit(self, report: EncryptionReport) -> bool:
        """Determine if this file should block a commit."""
        return len(report.plaintext_secrets) > 0
```

---

## 5. CLI Commands

### 5.1 `envdrift validate`

```bash
# Basic usage
envdrift validate .env.production --schema myapp.config:ProductionSettings

# CI mode (exit 1 on failure)
envdrift validate .env.production --schema myapp.config:Settings --ci

# Skip encryption check
envdrift validate .env --schema app:Settings --no-check-encryption

# Generate fix template for missing vars
envdrift validate .env.production --schema app:Settings --fix

# Verbose output
envdrift validate .env.production --schema app:Settings --verbose
```

**Options:**
| Option | Short | Description |
|--------|-------|-------------|
| `--schema` | `-s` | Dotted path to Settings class (required) |
| `--ci` | | CI mode: exit 1 on any failure |
| `--check-encryption/--no-check-encryption` | | Check sensitive vars are encrypted (default: true) |
| `--fix` | | Output template for missing variables |
| `--verbose` | `-v` | Show additional details |
| `--service-dir` | `-d` | Service directory for imports |

### 5.2 `envdrift diff`

```bash
# Compare two env files
envdrift diff .env.development .env.production

# With schema for sensitive field detection
envdrift diff .env.dev .env.prod --schema app:Settings

# Show actual values (not masked)
envdrift diff .env.dev .env.prod --show-values

# Output as JSON
envdrift diff .env.dev .env.prod --format json
```

**Options:**
| Option | Short | Description |
|--------|-------|-------------|
| `--schema` | `-s` | Schema for sensitive field detection |
| `--show-values` | | Don't mask sensitive values |
| `--format` | `-f` | Output format: table (default), json, yaml |

### 5.3 `envdrift init`

```bash
# Generate Settings class from .env
envdrift init .env --output settings.py

# Specify class name
envdrift init .env --output settings.py --class-name AppSettings

# Detect sensitive vars automatically
envdrift init .env --output settings.py --detect-sensitive
```

### 5.4 `envdrift sync`

```bash
# Sync keys from vault (uses envdrift.toml config)
envdrift sync

# Sync specific service
envdrift sync --service myapp

# Verify only (don't modify files)
envdrift sync --verify

# Force update without prompting
envdrift sync --force

# Test decryption after sync
envdrift sync --check-decryption

# Validate schema after sync
envdrift sync --validate-schema
```

**Options:**
| Option | Short | Description |
|--------|-------|-------------|
| `--service` | `-s` | Sync specific service only |
| `--verify` | | Only check, don't modify files |
| `--force` | | Update all mismatches without prompting |
| `--check-decryption` | | Test that keys can decrypt .env files |
| `--validate-schema` | | Run schema validation after sync |
| `--config` | `-c` | Path to config file (default: envdrift.toml) |

### 5.5 `envdrift encrypt`

```bash
# Encrypt .env file (wrapper around dotenvx)
envdrift encrypt .env.production

# Decrypt (for editing)
envdrift decrypt .env.production

# Check encryption status
envdrift encrypt --check .env.production
```

### 5.6 `envdrift hook`

```bash
# Install pre-commit hook
envdrift hook install

# Generate hook config for .pre-commit-config.yaml
envdrift hook config

# Run hook manually
envdrift hook run
```

---

## 6. Multi-Vault Support

### 6.1 Abstract Interface

```python
# vault/base.py
from abc import ABC, abstractmethod
from dataclasses import dataclass

@dataclass
class SecretValue:
    """Value retrieved from vault."""
    name: str
    value: str
    version: str | None
    metadata: dict

class VaultClient(ABC):
    """Abstract interface for vault backends."""

    @abstractmethod
    def get_secret(self, name: str) -> SecretValue:
        """Retrieve a secret by name."""
        ...

    @abstractmethod
    def list_secrets(self, prefix: str = "") -> list[str]:
        """List available secret names."""
        ...

    @abstractmethod
    def is_authenticated(self) -> bool:
        """Check if client is authenticated."""
        ...

    @abstractmethod
    def authenticate(self) -> None:
        """Authenticate to the vault."""
        ...
```

### 6.2 Azure Key Vault

```python
# vault/azure.py
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

class AzureKeyVaultClient(VaultClient):
    """Azure Key Vault implementation."""

    def __init__(self, vault_url: str):
        self.vault_url = vault_url
        self._client: SecretClient | None = None

    def authenticate(self) -> None:
        credential = DefaultAzureCredential()
        self._client = SecretClient(
            vault_url=self.vault_url,
            credential=credential,
        )

    def get_secret(self, name: str) -> SecretValue:
        secret = self._client.get_secret(name)
        return SecretValue(
            name=name,
            value=secret.value,
            version=secret.properties.version,
            metadata={"enabled": secret.properties.enabled},
        )
```

### 6.3 AWS Secrets Manager

```python
# vault/aws.py
import boto3

class AWSSecretsManagerClient(VaultClient):
    """AWS Secrets Manager implementation."""

    def __init__(self, region: str = "us-east-1"):
        self.region = region
        self._client = None

    def authenticate(self) -> None:
        self._client = boto3.client(
            "secretsmanager",
            region_name=self.region,
        )

    def get_secret(self, name: str) -> SecretValue:
        response = self._client.get_secret_value(SecretId=name)
        return SecretValue(
            name=name,
            value=response["SecretString"],
            version=response.get("VersionId"),
            metadata={"arn": response["ARN"]},
        )
```

### 6.4 HashiCorp Vault

```python
# vault/hashicorp.py
import hvac

class HashiCorpVaultClient(VaultClient):
    """HashiCorp Vault implementation."""

    def __init__(self, url: str, token: str | None = None):
        self.url = url
        self.token = token
        self._client: hvac.Client | None = None

    def authenticate(self) -> None:
        self._client = hvac.Client(url=self.url, token=self.token)
        if not self._client.is_authenticated():
            raise AuthenticationError("Failed to authenticate to Vault")

    def get_secret(self, name: str, mount_point: str = "secret") -> SecretValue:
        response = self._client.secrets.kv.v2.read_secret_version(
            path=name,
            mount_point=mount_point,
        )
        return SecretValue(
            name=name,
            value=response["data"]["data"].get("value", ""),
            version=str(response["data"]["metadata"]["version"]),
            metadata=response["data"]["metadata"],
        )
```

### 6.5 Vault Factory

```python
# vault/__init__.py
from enum import Enum

class VaultProvider(Enum):
    AZURE = "azure"
    AWS = "aws"
    HASHICORP = "hashicorp"

def get_vault_client(provider: VaultProvider, **config) -> VaultClient:
    """Factory to create vault client."""
    match provider:
        case VaultProvider.AZURE:
            return AzureKeyVaultClient(vault_url=config["vault_url"])
        case VaultProvider.AWS:
            return AWSSecretsManagerClient(region=config.get("region", "us-east-1"))
        case VaultProvider.HASHICORP:
            return HashiCorpVaultClient(
                url=config["url"],
                token=config.get("token"),
            )
```

---

## 7. dotenvx Integration Strategy

### Decision: Wrap, Don't Reimplement

**Rationale:**
1. dotenvx is mature, tested, and maintained
2. Encryption is security-critical - don't roll our own
3. dotenvx has npm install, but also standalone binaries
4. We add value via validation, not encryption

### 7.1 dotenvx Wrapper

```python
# integrations/dotenvx.py
import subprocess
import shutil
from pathlib import Path

class DotenvxNotFoundError(Exception):
    """dotenvx CLI not found."""
    pass

class DotenvxError(Exception):
    """dotenvx command failed."""
    pass

class DotenvxWrapper:
    """Wrapper around dotenvx CLI."""

    def __init__(self):
        self._binary = self._find_binary()

    def _find_binary(self) -> str:
        """Find dotenvx binary."""
        # Check common locations
        for name in ["dotenvx", "npx dotenvx"]:
            if shutil.which(name.split()[0]):
                return name
        raise DotenvxNotFoundError(
            "dotenvx not found. Install with: npm install -g @dotenvx/dotenvx"
        )

    def encrypt(self, env_file: Path) -> None:
        """Encrypt an env file in place."""
        result = subprocess.run(
            [*self._binary.split(), "encrypt", "-f", str(env_file)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise DotenvxError(f"Encryption failed: {result.stderr}")

    def decrypt(self, env_file: Path) -> None:
        """Decrypt an env file in place."""
        result = subprocess.run(
            [*self._binary.split(), "decrypt", "-f", str(env_file)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise DotenvxError(f"Decryption failed: {result.stderr}")

    def is_installed(self) -> bool:
        """Check if dotenvx is installed."""
        try:
            self._find_binary()
            return True
        except DotenvxNotFoundError:
            return False

    @staticmethod
    def install_instructions() -> str:
        """Return installation instructions."""
        return """
Install dotenvx:
  npm install -g @dotenvx/dotenvx

Or with Homebrew:
  brew install dotenvx/brew/dotenvx

Or download binary:
  curl -sfS https://dotenvx.sh | sh
"""
```

### 7.2 Installation Check in CLI

```python
# In CLI commands that need dotenvx
@app.command()
def encrypt(env_file: Path):
    """Encrypt .env file using dotenvx."""
    dotenvx = DotenvxWrapper()

    if not dotenvx.is_installed():
        console.print("[red]dotenvx is not installed[/red]")
        console.print(dotenvx.install_instructions())
        raise typer.Exit(1)

    dotenvx.encrypt(env_file)
    console.print(f"[green]✓ Encrypted {env_file}[/green]")
```

---

## 8. Configuration

### 8.1 envdrift.toml

```toml
# envdrift.toml - Project configuration

[envdrift]
# Default schema for validation
schema = "config.settings:ProductionSettings"

# Environments to manage
environments = ["development", "staging", "production"]

# Path pattern for env files
env_file_pattern = ".env.{environment}"

[validation]
# Check encryption by default
check_encryption = true

# Treat extra vars as errors (matches Pydantic extra="forbid")
strict_extra = true

# Secret detection patterns (extend defaults)
secret_patterns = [
    "^STRIPE_",
    "^TWILIO_",
]

[vault]
# Vault provider: azure, aws, hashicorp
provider = "azure"

[vault.azure]
vault_url = "https://my-vault.vault.azure.net/"

[vault.aws]
region = "us-east-1"

[vault.hashicorp]
url = "https://vault.example.com:8200"
# token from VAULT_TOKEN env var

# Key mappings: vault_secret_name -> local_path
[vault.mappings]
"myapp-dotenvx-key" = "."
"service2-dotenvx-key" = "services/service2"

[precommit]
# Files to validate on commit
files = [
    ".env.production",
    ".env.staging",
]

# Schema per environment (optional override)
[precommit.schemas]
production = "config.settings:ProductionSettings"
staging = "config.settings:StagingSettings"
```

### 8.2 Config Loader

```python
# config.py
from pathlib import Path
from dataclasses import dataclass
import tomllib

@dataclass
class EnvdriftConfig:
    """Loaded configuration."""
    schema: str
    environments: list[str]
    vault_provider: str
    vault_config: dict
    vault_mappings: dict[str, str]
    # ... other fields

def load_config(path: Path | None = None) -> EnvdriftConfig:
    """Load configuration from envdrift.toml."""
    if path is None:
        path = Path("envdrift.toml")

    if not path.exists():
        return EnvdriftConfig()  # Defaults

    with open(path, "rb") as f:
        data = tomllib.load(f)

    return EnvdriftConfig(
        schema=data.get("envdrift", {}).get("schema"),
        # ... parse other fields
    )
```

---

## 9. Testing Strategy

### 9.1 Test Structure

```
tests/
├── conftest.py              # Shared fixtures
├── fixtures/                # Test data
│   ├── valid.env
│   ├── invalid.env
│   ├── encrypted.env
│   └── settings.py          # Test Pydantic Settings
├── unit/
│   ├── test_parser.py
│   ├── test_validator.py
│   ├── test_diff.py
│   └── test_encryption.py
├── integration/
│   ├── test_cli.py
│   ├── test_precommit.py
│   └── test_vault_sync.py   # Requires mocking
└── e2e/
    └── test_full_workflow.py
```

### 9.2 Key Test Cases

#### Parser Tests
```python
def test_parse_simple_env():
    """Parse KEY=value format."""

def test_parse_quoted_values():
    """Parse KEY="value" and KEY='value'."""

def test_parse_encrypted_values():
    """Detect encrypted: prefix."""

def test_parse_multiline():
    """Handle multiline values."""

def test_parse_comments():
    """Skip comment lines."""

def test_parse_empty_values():
    """Handle KEY= (empty value)."""
```

#### Validator Tests
```python
def test_validate_missing_required():
    """Detect missing required vars."""

def test_validate_extra_vars_forbid():
    """Reject extra vars when schema has extra=forbid."""

def test_validate_extra_vars_ignore():
    """Allow extra vars when schema has extra=ignore."""

def test_validate_unencrypted_secrets():
    """Detect unencrypted sensitive vars."""

def test_validate_suspicious_plaintext():
    """Warn about plaintext values matching secret patterns."""

def test_validate_type_mismatch():
    """Detect obvious type mismatches (e.g., PORT=abc)."""
```

#### Diff Tests
```python
def test_diff_added_vars():
    """Detect vars in env2 but not env1."""

def test_diff_removed_vars():
    """Detect vars in env1 but not env2."""

def test_diff_changed_values():
    """Detect changed values."""

def test_diff_mask_sensitive():
    """Mask sensitive values in output."""

def test_diff_identical():
    """No differences when files match."""
```

#### Vault Tests (Mocked)
```python
@pytest.fixture
def mock_azure_client():
    with patch("azure.keyvault.secrets.SecretClient") as mock:
        yield mock

def test_azure_get_secret(mock_azure_client):
    """Retrieve secret from Azure Key Vault."""

def test_azure_auth_failure():
    """Handle authentication failure gracefully."""

def test_aws_get_secret():
    """Retrieve secret from AWS Secrets Manager."""

def test_hashicorp_get_secret():
    """Retrieve secret from HashiCorp Vault."""
```

#### CLI Tests
```python
def test_validate_success(tmp_path):
    """Validation passes with valid env file."""

def test_validate_failure_exit_code(tmp_path):
    """Exit code 1 on validation failure in CI mode."""

def test_diff_output_format(tmp_path):
    """Diff outputs in correct format."""

def test_hook_install(tmp_path):
    """Install adds to .pre-commit-config.yaml."""
```

### 9.3 Fixtures

```python
# conftest.py
import pytest
from pathlib import Path

@pytest.fixture
def valid_env_content():
    return """
DATABASE_URL=postgres://localhost/db
API_KEY=secret123
PORT=8000
"""

@pytest.fixture
def encrypted_env_content():
    return """
DATABASE_URL="encrypted:abcd1234..."
API_KEY="encrypted:efgh5678..."
PORT=8000
"""

@pytest.fixture
def test_settings_class():
    from pydantic_settings import BaseSettings
    from pydantic import Field

    class TestSettings(BaseSettings):
        DATABASE_URL: str = Field(json_schema_extra={"sensitive": True})
        API_KEY: str = Field(json_schema_extra={"sensitive": True})
        PORT: int = 8000

    return TestSettings

@pytest.fixture
def tmp_env_file(tmp_path, valid_env_content):
    env_file = tmp_path / ".env"
    env_file.write_text(valid_env_content)
    return env_file
```

---

## 10. Migration from Shell Scripts

### Features to Port

| Shell Script | Source | Target Module | Status |
|--------------|--------|---------------|--------|
| Schema validation | `validate_env_schema.py` | `core/validator.py` | Port |
| ENV parsing | `validate_env_schema.py` | `core/parser.py` | Port |
| Encryption detection | `check-env-encrypted.sh` | `core/encryption.py` | Port |
| Key sync from Azure | `sync-all-keys.sh` | `vault/azure.py` | Port |
| Decryption test | `sync-all-keys.sh` | `integrations/dotenvx.py` | Port |
| Fix template generation | `validate_env_schema.py` | `core/validator.py` | Port |
| Secret pattern detection | `validate_env_schema.py` | `core/validator.py` | Port |

### Migration Checklist

- [ ] Port `parse_env_file()` to `EnvParser.parse()`
- [ ] Port `load_pydantic_schema()` to `SchemaLoader.load()`
- [ ] Port `validate_schema()` to `Validator.validate()`
- [ ] Port secret patterns list
- [ ] Port `generate_fix_template()`
- [ ] Port encryption detection logic from bash script
- [ ] Port Azure Key Vault fetch logic
- [ ] Port decryption test with backup/restore
- [ ] Port config file parsing (`pair.txt` → `envdrift.toml`)
- [ ] Port colored output to Rich

---

## 11. Dependencies

### Core Dependencies

```toml
[project]
dependencies = [
    "pydantic>=2.0",
    "pydantic-settings>=2.0",
    "typer>=0.9",
    "rich>=13.0",
    "python-dotenv>=1.0",
]
```

### Optional Dependencies

```toml
[project.optional-dependencies]
# Vault backends
azure = ["azure-identity>=1.15", "azure-keyvault-secrets>=4.8"]
aws = ["boto3>=1.34"]
hashicorp = ["hvac>=2.0"]

# All vault backends
vault = ["envdrift[azure,aws,hashicorp]"]

# Development
dev = [
    "ruff>=0.8.0",
    "pyrefly>=0.2.0",
    "bandit>=1.7.0",
    "pytest>=8.0",
    "pytest-cov>=4.0",
    "pytest-mock>=3.0",
    "pre-commit>=3.0",
]
```

### Installation Options

```bash
# Basic (validation only, no vault sync)
pip install envdrift

# With Azure Key Vault support
pip install envdrift[azure]

# With AWS Secrets Manager support
pip install envdrift[aws]

# With all vault backends
pip install envdrift[vault]

# Development
pip install envdrift[dev]
```

---

## 12. Milestones

### v0.1.0 - MVP (Target: 2 weeks)

**Focus:** Core validation and diff

- [ ] `envdrift validate` command
- [ ] `envdrift diff` command
- [ ] `envdrift version` command
- [ ] EnvParser with encryption detection
- [ ] SchemaLoader for Pydantic Settings
- [ ] Validator with all checks
- [ ] DiffEngine
- [ ] Rich CLI output
- [ ] Basic tests (80% coverage)
- [ ] Documentation (README)

### v0.2.0 - Pre-commit & CI (Target: +1 week)

**Focus:** Integration with development workflow

- [ ] `envdrift hook install` command
- [ ] Pre-commit hook configuration
- [ ] CI mode with proper exit codes
- [ ] `envdrift init` for schema generation
- [ ] GitHub Actions example workflow

### v0.3.0 - Multi-Vault Sync (Target: +2 weeks)

**Focus:** Cloud vault integration

- [ ] Abstract vault interface
- [ ] Azure Key Vault support
- [ ] AWS Secrets Manager support
- [ ] HashiCorp Vault support
- [ ] `envdrift sync` command
- [ ] `envdrift.toml` configuration
- [ ] Vault integration tests (mocked)

### v0.4.0 - dotenvx Integration (Target: +1 week)

**Focus:** Encryption workflow

- [ ] `envdrift encrypt` command (wrapper)
- [ ] `envdrift decrypt` command (wrapper)
- [ ] Encryption status in validation output
- [ ] dotenvx installation detection

### v1.0.0 - Stable Release

**Focus:** Polish and stability

- [ ] Complete documentation
- [ ] 90%+ test coverage
- [ ] Performance optimization
- [ ] Edge case handling
- [ ] Community feedback integration

---

## Appendix A: CLI Output Examples

### Validation Failure

```
$ envdrift validate .env.production --schema app:ProductionSettings

Validating: .env.production
Schema: app.ProductionSettings

❌ Schema validation FAILED

🔴 MISSING REQUIRED VARIABLES:
   • SENTRY_DSN
   • NEW_FEATURE_FLAG

🟡 EXTRA VARIABLES (not in schema):
   • DATABSE_URL (typo?)
   • OLD_FEATURE_FLAG

🔴 UNENCRYPTED SECRETS:
   • DATABASE_URL (marked sensitive but not encrypted)
   • API_KEY (marked sensitive but not encrypted)

⚠️  WARNINGS:
   • Line 15: STRIPE_KEY looks like a secret but is not marked sensitive

Run with --fix to generate template for missing variables.
```

### Diff Output

```
$ envdrift diff .env.development .env.production

Comparing: .env.development ↔ .env.production

┏━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┓
┃ Variable          ┃ development      ┃ production       ┃ Status   ┃
┡━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━┩
│ DATABASE_URL      │ ••••••••         │ ••••••••         │ changed  │
│ DEBUG             │ true             │ false            │ changed  │
│ NEW_FEATURE_FLAG  │ enabled          │ (missing)        │ removed  │
│ SENTRY_DSN        │ (missing)        │ https://...      │ added    │
└───────────────────┴──────────────────┴──────────────────┴──────────┘

Summary: 2 changed, 1 added, 1 removed
⚠️  Drift detected between environments
```

### Sync Output

```
$ envdrift sync --check-decryption

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔐 envdrift - Vault Key Sync
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Provider: Azure Key Vault
Vault: https://my-vault.vault.azure.net/

📁 Service: . (myapp)
   ✓ Secret fetched from Key Vault
   ✓ Values match - no update needed

🔓 Testing decryption...
   ✓ Decryption successful
   ✓ Re-encrypted successfully

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 Summary
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Services processed: 1
  ✓ Created: 0
  ↻ Updated: 0
  ✓ Decryption tests passed: 1

✅ All services synced successfully!
```

---

## Appendix B: Pre-commit Hook Configuration

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: envdrift-validate
        name: Validate env files
        entry: envdrift validate --ci
        language: system
        files: ^\.env\.(production|staging|development)$
        pass_filenames: true

  - repo: local
    hooks:
      - id: envdrift-encryption
        name: Check env encryption
        entry: envdrift encrypt --check
        language: system
        files: ^\.env\.(production|staging)$
        pass_filenames: true
```

Or using the built-in command:

```bash
$ envdrift hook install

Added envdrift hooks to .pre-commit-config.yaml:
  - envdrift-validate
  - envdrift-encryption

Run 'pre-commit install' to activate.
```
