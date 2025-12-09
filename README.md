# envdrift

[![PyPI version](https://badge.fury.io/py/envdrift.svg)](https://badge.fury.io/py/envdrift)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Prevent environment variable drift between dev, staging, and production.**

> 🚧 **Under Active Development** - Core features coming in v0.1.0

## The Problem

Environment variable drift is a silent killer of deployments:

- A missing `DATABASE_URL` in production causes a 3am outage
- Staging has `NEW_FEATURE_FLAG=true` but production doesn't
- Someone copies the wrong `.env` file and chaos ensues
- "It works on my machine!" becomes your team's motto

**In 2024 alone, 24 million secrets were leaked on GitHub.** Knight Capital lost **$460 million in 45 minutes** due to a configuration deployment error.

## The Solution

`envdrift` treats your environment variables with the same rigor as your code:

- **Schema Validation**: Define expected variables with Pydantic, catch mismatches at startup
- **Drift Detection**: Compare `.env.dev` vs `.env.prod` and see exactly what differs
- **Pre-commit Hooks**: Block commits if your `.env` doesn't match your schema
- **CI/CD Integration**: Fail fast in pipelines before bad config reaches production
- **Encryption Support**: Works with dotenvx for secure, committable `.env` files

## Installation

```bash
pip install envdrift
# or
uv add envdrift
```

## Quick Start

### Validate your .env against a schema

```bash
envdrift validate .env --schema myapp.config:Settings
```

### Compare environments

```bash
envdrift diff .env.dev .env.prod
```

### Generate a Settings class from existing .env

```bash
envdrift init .env --output settings.py
```

### Install pre-commit hook

```bash
envdrift hook --install
```

## Planned Features (v0.1.0)

- [ ] `envdrift validate` - Validate .env against Pydantic schema
- [ ] `envdrift diff` - Compare two .env files
- [ ] `envdrift init` - Generate Settings class from .env
- [ ] `envdrift hook` - Pre-commit hook integration
- [ ] Rich terminal output with clear error messages
- [ ] dotenvx encryption detection and support
- [ ] CI mode with proper exit codes

## Why envdrift?

| Feature | python-dotenv | dynaconf | pydantic-settings | **envdrift** |
|---------|---------------|----------|-------------------|--------------|
| Load .env | ✅ | ✅ | ✅ | ✅ |
| Type validation | ❌ | ⚠️ | ✅ | ✅ |
| Schema enforcement | ❌ | ⚠️ | ✅ | ✅ |
| Cross-env diff | ❌ | ❌ | ❌ | ✅ |
| Pre-commit hook | ❌ | ❌ | ❌ | ✅ |
| Encryption support | ❌ | ❌ | ❌ | ✅ |

## Development

```bash
# Clone the repo
git clone https://github.com/jainal09/envdrift.git
cd envdrift

# Install dev dependencies
make dev

# Run checks
make check
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Author

**Jainal Gosaliya** - [gosaliya.jainal@gmail.com](mailto:gosaliya.jainal@gmail.com)
