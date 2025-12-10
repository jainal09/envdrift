# Installation

## Basic Installation

```bash
pip install envdrift
# or with uv
uv add envdrift
```

## Optional Dependencies

envdrift has optional features that require additional packages:

### Vault Backends

```bash
# Azure Key Vault
pip install envdrift[azure]

# AWS Secrets Manager
pip install envdrift[aws]

# HashiCorp Vault
pip install envdrift[hashicorp]

# All vault backends
pip install envdrift[vault]
```

### Pre-commit Integration

```bash
pip install envdrift[precommit]
```

### Everything

```bash
pip install envdrift[all]
```

## Verify Installation

```bash
envdrift version
# Output: envdrift 0.1.0
```

## Requirements

- Python 3.11 or higher
- pydantic >= 2.0
- pydantic-settings >= 2.0
