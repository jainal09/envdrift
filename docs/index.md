# envdrift

**Prevent environment variable drift between dev, staging, and production.**

## What is envdrift?

envdrift treats your environment variables with the same rigor as your code:

- **Schema Validation** - Define expected variables with Pydantic, catch mismatches at startup
- **Drift Detection** - Compare `.env.dev` vs `.env.prod` and see exactly what differs
- **Pre-commit Hooks** - Block commits if your `.env` doesn't match your schema
- **CI/CD Integration** - Fail fast in pipelines before bad config reaches production
- **Encryption Support** - Works with dotenvx for secure, committable `.env` files

## The Problem

Environment variable drift is a silent killer of deployments:

- A missing `DATABASE_URL` in production causes a 3am outage
- Staging has `NEW_FEATURE_FLAG=true` but production doesn't
- Someone copies the wrong `.env` file and chaos ensues

**In 2024 alone, [24 million secrets were leaked on GitHub](https://www.gitguardian.com/state-of-secrets-sprawl-report-2025).** Knight Capital lost **[$460 million in 45 minutes](https://www.sec.gov/litigation/admin/2013/34-70694.pdf)** due to a configuration deployment error.

## Quick Example

```bash
# Validate your .env against a Pydantic schema
envdrift validate .env --schema config.settings:Settings

# Compare dev vs prod
envdrift diff .env.development .env.production

# Check encryption status
envdrift encrypt .env.production --check
```

## Next Steps

- [Installation](getting-started/installation.md) - Get envdrift installed
- [Quick Start](getting-started/quickstart.md) - Your first validation in 5 minutes
- [CLI Reference](reference/cli.md) - All available commands
