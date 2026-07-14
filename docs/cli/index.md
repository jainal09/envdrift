# CLI Reference

envdrift provides a command-line interface for validating environment files
against Pydantic schemas, comparing environments, managing encryption, and
scanning for exposed secrets.

## Installation

```bash
pip install envdrift
# or with uv
uv add envdrift
```

## Commands

| Command                          | Description                                            |
| -------------------------------- | ------------------------------------------------------ |
| [validate](validate.md)          | Validate .env files against Pydantic schemas           |
| [diff](diff.md)                  | Compare two .env files and show differences            |
| [encrypt](encrypt.md)            | Check or perform encryption using dotenvx or SOPS      |
| [decrypt](decrypt.md)            | Decrypt encrypted .env files (dotenvx or SOPS)         |
| [push](push.md)                  | Encrypt and combine files (partial encryption)         |
| [pull-partial](pull-partial.md)  | Decrypt secret files for editing (partial encryption)  |
| [guard](guard.md)                | Scan for unencrypted .env files and exposed secrets    |
| [pull](pull.md)                  | Pull keys from vault and decrypt all env files         |
| [lock](lock.md)                  | Verify keys and encrypt all env files (opposite of pull) |
| [sync](sync.md)                  | Sync encryption keys from cloud vaults to local files  |
| [vault-push](vault-push.md)      | Push encryption keys from local files to cloud vaults  |
| [vault-pull](vault-pull.md)      | Pull a single key from a vault (config-free) + decrypt |
| [init](init.md)                  | Generate Pydantic Settings from .env files             |
| [hook](hook.md)                  | Manage pre-commit hook integration                     |
| [version](version.md)            | Show envdrift version                                  |

Two advanced command groups are also available: `agent` (manage the background
agent and project registration) and `install` (install optional components).
Run `envdrift agent --help` or `envdrift install --help` to see their
subcommands.

## Global Options

`--help` is available on every command:

```bash
--help                  Show help message and exit
```

The following options are available only on the top-level `envdrift` command:

```bash
--version, -V           Show version and exit
--install-completion    Install shell completion
--show-completion       Show completion script
```

## Output Streams

Human-readable command results are written to stdout. Human `[ERROR]` and
`[WARN]` diagnostics are written to stderr, so redirecting or piping stdout
does not hide failures or mix diagnostic prose into downstream input.

Machine-readable modes keep their documented stdout contracts. In particular,
`diff --format json` and `guard --json`/`guard --sarif` emit machine-readable
error documents on stdout rather than replacing them with human diagnostics.

## Quick Examples

```bash
# Validate production env against schema
envdrift validate .env.production --schema config.settings:ProductionSettings

# Compare dev vs prod environments
envdrift diff .env.development .env.production

# Check if secrets are encrypted
envdrift encrypt .env.production --check

# Guard against plaintext secrets
envdrift guard --ci --fail-on high

# Generate schema from existing .env
envdrift init .env --output settings.py
```

## Exit Codes

Exit codes are per-command. Most commands use:

| Code | Meaning                                                       |
| ---- | ------------------------------------------------------------- |
| 0    | Success                                                       |
| 1    | Validation failed, file not found, or other error             |

The [guard](guard.md) command uses severity-based exit codes, plus
dedicated codes for an incomplete scan and operational errors (see
[guard exit codes](guard.md#exit-codes)):

| Code | Meaning                                                  |
| ---- | -------------------------------------------------------- |
| 0    | No blocking findings                                     |
| 1    | Critical severity findings                               |
| 2    | High severity findings                                   |
| 3    | Medium severity findings                                 |
| 4    | Low severity findings (policy violations)                |
| 5    | Scan incomplete: a selected scanner ran but failed       |
| 6    | Operational error (bad config, invalid path or flags)    |

## Environment Variables

| Variable                     | Description                                                                                                        |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `ENVDRIFT_SCHEMA_EXTRACTION` | Set by envdrift during schema loading. Check this in your settings module to skip instantiation during validation. |

## Schema Path Format

The `--schema` option uses Python's dotted import path format:

```text
module.submodule:ClassName
```

Examples:

- `config.settings:Settings`
- `myapp.config:ProductionSettings`
- `src.config.settings:AppConfig`
