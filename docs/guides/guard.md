# Guard Scanning

Use `envdrift guard` as a last line of defense against plaintext secrets.

## What guard checks

- Unencrypted `.env` files missing dotenvx or SOPS markers
- Common secret patterns in source and config files
- High-entropy strings (optional)
- Git history for previously committed secrets (optional)

## Quick start

Run a default scan in the current directory:

```bash
envdrift guard
```

Run without external tools:

```bash
envdrift guard --native-only
```

Run in CI with a strict threshold:

```bash
envdrift guard --ci --fail-on high
```

## Choosing scanners

By default, guard runs the native scanner and gitleaks. You can enable additional
scanners with CLI flags:

```bash
envdrift guard --trufflehog --detect-secrets
```

For maximum detection including password hashes:

```bash
envdrift guard --kingfisher
```

You can also enable scanners in `envdrift.toml`:

```toml
[guard]
scanners = ["native", "gitleaks", "trufflehog", "detect-secrets", "kingfisher"]
```

### Scanner comparison

| Scanner | Strengths |
| :-- | :-- |
| native | Fast, zero dependencies, unencrypted .env detection |
| gitleaks | Great pattern coverage, fast |
| trufflehog | Service-specific tokens (GitHub, Slack, AWS) |
| detect-secrets | 27+ plugin detectors, keyword scanning |
| kingfisher | 700+ rules, password hashes, secret validation |

## Reporting and CI

Generate SARIF output for code scanning systems:

```bash
envdrift guard --ci --sarif > guard.sarif
```

See the [CI/CD Integration](cicd.md) guide for upload examples.

## Configuration

Guard configuration lives under `[guard]`:

```toml
[guard]
auto_install = true
include_history = false
check_entropy = true
entropy_threshold = 4.5
fail_on_severity = "high"
ignore_paths = ["tests/**", "*.test.py"]
```

## Tips

- `--history` requires a git repository and can be slower on large histories.
- `ignore_paths` only affects the native scanner's file walk.
- External scanners can auto-install; disable with `--no-auto-install`.
