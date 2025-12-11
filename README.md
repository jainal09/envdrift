<p align="center">
  <img src="https://raw.githubusercontent.com/jainal09/envdrift/main/docs/assets/images/env-drift-logo.png" alt="envdrift logo" width="300">
</p>

# envdrift

[![PyPI version](https://badge.fury.io/py/envdrift.svg)](https://badge.fury.io/py/envdrift)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docs](https://img.shields.io/badge/docs-mkdocs-blue)](https://jainal09.github.io/envdrift)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Pyrefly](https://img.shields.io/badge/types-pyrefly-blue)](https://github.com/facebook/pyrefly)
[![codecov](https://codecov.io/gh/jainal09/envdrift/graph/badge.svg)](https://codecov.io/gh/jainal09/envdrift)

**Prevent environment variable drift between dev, staging, and production.**

## The Problem

- A missing `DATABASE_URL` in production causes a 3am outage
- Staging has `NEW_FEATURE_FLAG=true` but production doesn't
- "It works on my machine!" becomes your team's motto

## The Solution

```bash
# Validate .env against Pydantic schema
envdrift validate .env --schema config.settings:Settings

# Compare dev vs prod
envdrift diff .env.development .env.production

# Check encryption status
envdrift encrypt .env.production --check
```

## Installation

```bash
pip install envdrift
```

## Quick Start

**Define your schema:**

```python
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="forbid")

    DATABASE_URL: str = Field(json_schema_extra={"sensitive": True})
    API_KEY: str = Field(json_schema_extra={"sensitive": True})
    DEBUG: bool = False
```

**Validate:**

```bash
envdrift validate .env --schema config.settings:Settings
```

## Features

| Feature              | envdrift               |
|----------------------|------------------------|
| Schema validation    | Pydantic-based         |
| Cross-env diff       | Yes                    |
| Pre-commit hooks     | Yes                    |
| Encryption (dotenvx) | Yes                    |
| Vault integration    | Azure, AWS, HashiCorp  |
| CI/CD mode           | Yes                    |

## Documentation

Full documentation: **[jainal09.github.io/envdrift](https://jainal09.github.io/envdrift)**

## Development

```bash
git clone https://github.com/jainal09/envdrift.git
cd envdrift
make dev
make test
make docs-serve
```

## License

MIT
