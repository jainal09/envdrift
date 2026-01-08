# envdrift guard

Scan repositories for unencrypted `.env` files and exposed secrets.

## Synopsis

```bash
envdrift guard [OPTIONS] [PATHS]...
```

## Description

`envdrift guard` is a defense-in-depth scanner designed to catch secrets that
slip past other guardrails (hooks, CI, reviews). It detects:

- Unencrypted `.env` files missing dotenvx or SOPS markers
- Common secret patterns (tokens, API keys, credentials)
- High-entropy strings (optional, native scanner only)
- Secrets in git history (optional)

The native scanner always runs. By default, gitleaks runs too. You can enable
trufflehog or detect-secrets with flags or `envdrift.toml`. If no paths are
provided, the current directory is scanned.

## Arguments

| Argument | Description | Default |
| :-- | :-- | :-- |
| `PATHS` | Files or directories to scan | `.` |

## Options

### `--native-only`

Use only the native scanner and skip external tools.

```bash
envdrift guard --native-only
```

### `--gitleaks` / `--no-gitleaks`

Enable or disable gitleaks. Enabled by default unless `--native-only` is set.

```bash
envdrift guard --no-gitleaks
```

### `--trufflehog` / `--no-trufflehog`

Enable or disable trufflehog. Disabled by default.

```bash
envdrift guard --trufflehog
```

### `--detect-secrets` / `--no-detect-secrets`

Enable or disable detect-secrets. Disabled by default.

```bash
envdrift guard --detect-secrets
```

### `--history`, `-H`

Include git history in the scan. Requires a git repository.

```bash
envdrift guard --history
```

### `--entropy`, `-e`

Enable entropy-based detection in the native scanner.

```bash
envdrift guard --entropy
```

### `--auto-install` / `--no-auto-install`

Control auto-installation of external scanners.

```bash
envdrift guard --no-auto-install
```

### `--json`, `-j`

Output results as JSON.

```bash
envdrift guard --json > guard-report.json
```

### `--sarif`

Output results as SARIF for code scanning tools.

```bash
envdrift guard --sarif > guard.sarif
```

### `--ci`

CI mode: no colors, strict exit codes, and `--fail-on` threshold applied.

```bash
envdrift guard --ci --fail-on high
```

### `--fail-on`

Minimum severity to return a non-zero exit code in CI mode.

```bash
envdrift guard --ci --fail-on critical
```

### `--verbose`, `-v`

Show scanner info and extra details.

```bash
envdrift guard --verbose
```

### `--config`, `-c`

Specify a config file path. If omitted, envdrift searches for `envdrift.toml` or
`pyproject.toml`.

```bash
envdrift guard --config ./envdrift.toml
```

### `--staged`, `-s`

Scan only git staged files. Useful for pre-commit hooks.

```bash
envdrift guard --staged
```

### `--pr-base`

Scan only files changed since the specified base branch. Useful for CI/CD PR checks.

```bash
envdrift guard --pr-base origin/main
```

## Examples

### Basic scan

```bash
envdrift guard
```

### Scan specific directories

```bash
envdrift guard ./apps ./services
```

### Native-only scan (no external tools)

```bash
envdrift guard --native-only
```

### CI scan with SARIF output

```bash
envdrift guard --ci --sarif > guard.sarif
```

### Pre-commit hook (staged files only)

```bash
envdrift guard --staged
```

### CI/CD PR scanning

```bash
# In GitHub Actions, scan only files changed in the PR
envdrift guard --pr-base origin/main --ci --fail-on high
```

### Scan git history for leaked secrets

```bash
envdrift guard --history --trufflehog
```

## Exit Codes

`envdrift guard` uses severity-based exit codes:

| Code | Meaning |
| :-- | :-- |
| 0 | No blocking findings |
| 1 | Critical findings |
| 2 | High findings |
| 3 | Medium findings |

With `--ci`, the `--fail-on` threshold controls what counts as blocking.

## Configuration

Guard settings live under `[guard]` in `envdrift.toml` or
`[tool.envdrift.guard]` in `pyproject.toml`.

```toml
[guard]
scanners = ["native", "gitleaks", "trufflehog", "detect-secrets"]
auto_install = true
include_history = false
check_entropy = true
entropy_threshold = 4.5
fail_on_severity = "high"
ignore_paths = ["tests/**", "*.test.py"]
```

Notes:

- `scanners` controls which external scanners are enabled by default.
- `ignore_paths` applies to the native scanner's file walk.
- CLI flags override config values.
