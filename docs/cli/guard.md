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
- Password hashes (bcrypt, sha512crypt) with Kingfisher
- High-entropy strings (optional, native scanner only)
- Secrets in git history (optional)

The native scanner always runs. By default, gitleaks runs too. You can enable
trufflehog, detect-secrets, or kingfisher with flags or `envdrift.toml`. If no
paths are provided, the current directory is scanned.

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

### `--kingfisher` / `--no-kingfisher`

Enable or disable Kingfisher scanner. Disabled by default.

Kingfisher provides:

- 700+ built-in detection rules
- Password hash detection (bcrypt, sha512crypt)
- Active secret validation (checks if secrets are still valid)
- Archive extraction and binary file scanning

```bash
envdrift guard --kingfisher
```

### `--git-secrets` / `--no-git-secrets`

Enable or disable git-secrets scanner. Disabled by default.

git-secrets provides:

- AWS credential detection (access keys, secret keys)
- Pre-commit hook integration
- Custom pattern support
- Allowed patterns for false positive management

```bash
envdrift guard --git-secrets
```

### `--talisman` / `--no-talisman`

Enable or disable Talisman scanner. Disabled by default.

Talisman (from ThoughtWorks) provides:

- Entropy-based secret detection
- File content pattern analysis
- Encoded content detection (base64, hex)
- Credit card number detection
- Suspicious file name detection (.pem, .key)

```bash
envdrift guard --talisman
```

### `--trivy` / `--no-trivy`

Enable or disable Trivy scanner. Disabled by default.

Trivy (from Aqua Security) provides:

- Comprehensive multi-target security scanning
- Built-in rules for AWS, GCP, GitHub, GitLab, Slack, etc.
- Custom regex pattern support
- Severity-based filtering

```bash
envdrift guard --trivy
```

### `--infisical` / `--no-infisical`

Enable or disable Infisical scanner. Disabled by default.

Infisical provides:

- 140+ secret type detection
- Git history scanning
- Staged changes scanning
- Custom regex patterns and entropy detection

```bash
envdrift guard --infisical
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

### `--skip-clear` / `--no-skip-clear`

Control whether `.clear` files are scanned. By default, `.clear` files ARE scanned.
Use `--skip-clear` to exclude them entirely.

```bash
# Skip .clear files from scanning
envdrift guard --skip-clear

# Explicitly scan .clear files (default behavior)
envdrift guard --no-skip-clear
```

### `--skip-duplicate` / `--no-skip-duplicate`

Show only unique secrets by value, ignoring which scanner found them or where they
appear. Useful when multiple scanners detect the same secret across multiple files.

```bash
# Show each unique secret only once
envdrift guard --skip-duplicate

# Show all findings including duplicates (default behavior)
envdrift guard --no-skip-duplicate
```

### `--skip-encrypted` / `--no-skip-encrypted`

Skip findings from files that contain dotenvx or SOPS encryption markers. Enabled by
default. Encrypted files contain ciphertext that can trigger false positives from
scanners detecting high-entropy strings.

```bash
# Skip findings from encrypted files (default behavior)
envdrift guard --skip-encrypted

# Scan encrypted files too (may produce false positives)
envdrift guard --no-skip-encrypted
```

### `--skip-gitignored` / `--no-skip-gitignored`

Skip findings from files that are in `.gitignore`. This uses `git check-ignore` for
reliable detection of ignored files. Useful for filtering out findings from build
artifacts, dependencies, or other generated files.

```bash
# Skip findings from gitignored files
envdrift guard --skip-gitignored

# Scan all files including gitignored ones (default behavior)
envdrift guard --no-skip-gitignored
```

**Note:** This feature uses `git check-ignore` when git is available and the scan is
run inside a git repository. If git is not installed or the repository check fails,
the tool will log a warning and continue by returning the original findings (no
git-based filtering will be applied).

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

### Maximum detection with Kingfisher

```bash
# Kingfisher excels at finding password hashes and validating secrets
envdrift guard --kingfisher --gitleaks
```

### Find password hashes in database dumps

```bash
# Kingfisher detects bcrypt, sha512crypt, and other password hashes
envdrift guard ./db --kingfisher --native-only
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
scanners = ["native", "gitleaks", "trufflehog", "detect-secrets", "kingfisher", "git-secrets", "talisman", "trivy", "infisical"]
auto_install = true
include_history = false
check_entropy = true
entropy_threshold = 4.5
fail_on_severity = "high"
skip_clear_files = false  # Set to true to skip .clear files entirely
skip_duplicate = false  # Set to true to show only unique secrets by value
skip_encrypted_files = true  # Set to false to scan encrypted files (default: skip)
skip_gitignored = false  # Set to true to skip findings from gitignored files
ignore_paths = ["tests/**", "*.test.py"]

# Rule-specific path ignores (see Handling False Positives below)
[guard.ignore_rules]
"ftp-password" = ["**/locales/**", "**/*.json"]
"connection-string-password" = ["**/helm/**"]
```

Notes:

- `scanners` controls which external scanners are enabled by default.
- `skip_clear_files` skips `.clear` files entirely (disabled by default - they ARE scanned).
- `skip_duplicate` shows only unique secrets by value, ignoring scanner source and location.
- `skip_encrypted_files` skips findings from encrypted files with dotenvx/SOPS markers (enabled by default).
- `skip_gitignored` skips findings from gitignored files using `git check-ignore`.
- `ignore_paths` applies globally to all scanners.
- `ignore_rules` allows ignoring specific rules in specific path patterns.
- CLI flags override config values.
- `git-secrets` is ideal for AWS-heavy environments.
- `talisman` excels at entropy and encoded content detection.
- `trivy` provides comprehensive multi-target scanning.
- `infisical` supports 140+ secret types with git history scanning.

## Handling False Positives

Envdrift provides a **centralized ignore system** that works across ALL scanners
(native, gitleaks, trufflehog, detect-secrets, kingfisher, git-secrets).

### Inline Ignore Comments

Add comments directly in your source files:

```python
# Ignore all rules on this line
password = ref(false)  # envdrift:ignore

# Ignore a specific rule only
SECRET_KEY = "test-key"  # envdrift:ignore:django-secret-key

# Ignore with a reason (recommended for maintainability)
API_KEY = "xxx"  # envdrift:ignore reason="test fixture"
```

Supported comment formats:

- `# envdrift:ignore` - Python, Shell, YAML
- `// envdrift:ignore` - JavaScript, Go, C, TypeScript
- `/* envdrift:ignore */` - CSS, C-style block comments

### TOML Configuration

For bulk ignores across many files:

```toml
[guard]
# Skip entire directories
ignore_paths = [
    "**/tests/**",
    "**/fixtures/**",
    "**/locales/**",
]

# Ignore specific rules in specific paths
[guard.ignore_rules]
"ftp-password" = ["**/*.json"]  # Matches translation "Mot de passe"
"django-secret-key" = ["**/test_settings.py"]
```

### Common Rule IDs

| Rule ID | What It Detects |
| :-- | :-- |
| `aws-access-key-id` | AWS access key (AKIA...) |
| `aws-secret-access-key` | AWS secret key |
| `github-token` | GitHub PAT (ghp_, gho_, ghs_) |
| `django-secret-key` | Django SECRET_KEY |
| `laravel-app-key` | Laravel APP_KEY |
| `connection-string-password` | DB connection string password |
| `ftp-password` | Password in JSON config |
| `high-entropy-string` | High entropy value |
| `unencrypted-env-file` | .env without encryption |

Use `--verbose` or `--json` to see rule IDs for your findings.

See the [Guard Scanning Guide](../guides/guard.md#handling-false-positives) for
more details and examples.
