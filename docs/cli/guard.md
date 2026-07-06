# envdrift guard

Scan repositories for unencrypted `.env` files and exposed secrets.

## Synopsis

```bash
envdrift guard [OPTIONS] [PATHS]...
```

## Description

`envdrift guard` is a defense-in-depth scanner designed to catch secrets that
slip past other guardrails (hooks, CI, reviews). It detects:

- Unencrypted env files missing dotenvx or SOPS markers
- Common secret patterns (tokens, API keys, credentials)
- Password hashes (bcrypt, sha512crypt) with Kingfisher
- High-entropy strings (native scanner; env files by default, all files with
  `--entropy`, disable with `--no-entropy`)
- Secrets in git history (optional)

The unencrypted-file policy covers every env-file naming shape: `.env`,
`.env.<environment>` (including `.env.local` and `.env.test`), the trailing
`<name>.env` convention (`production.env`), and custom `vault.sync` mapped files.
Only the templates `.env.example`, `.env.sample`, and `.env.template` are skipped.
Files are decoded through UTF-8/UTF-16/UTF-32 BOMs (and BOM-less UTF-16), so a
UTF-16 env file written by Windows tools is scanned like its UTF-8 equivalent.

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

### `--entropy` / `--no-entropy`, `-e`

Control entropy-based detection in the native scanner. By default (no flag,
no config) entropy detection runs on **env files only**. `--entropy` extends
it to every scanned file; `--no-entropy` disables it entirely, env files
included. The flags override `check_entropy` in `envdrift.toml`.

```bash
# Scan every file for high-entropy strings
envdrift guard --entropy

# Disable entropy detection completely (overrides check_entropy = true)
envdrift guard --no-entropy
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

By default (`--no-skip-duplicate`), findings are deduplicated by file, line, rule, and
secret value: the same secret matched by the same rule at one location collapses to a
single finding, but two *distinct* secrets matching the same rule on the same line
(for example two AWS keys on one `.env` line) are both reported. Because the rule is
part of the key and each scanner namespaces its rule IDs, the same secret flagged by
two *different* scanners stays as two findings on this default path. `--skip-duplicate`
instead keys solely on the secret value, so each unique secret appears once regardless
of where or by which scanner it was found — that is the mode that collapses the same
secret across scanners.

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

Artifact URIs are emitted relative to the enclosing git repository root
(declared as `%SRCROOT%` via `originalUriBaseIds`), no matter which directory
guard runs from, so GitHub/GitLab Code Scanning maps every alert to a repo
file; a finding outside the repository falls back to an absolute `file://`
URI. Each result carries a stable fingerprint built from the rule id, the
location, and a truncated hash of the secret value — never the matched text —
so two different secrets on the same line stay separate alerts. The redacted
preview is attached as the result's `properties.secretPreview`.

### `--ci`

CI mode: no colors, strict exit codes, and `--fail-on` threshold applied.

```bash
envdrift guard --ci --fail-on high
```

### `--fail-on`

Minimum severity to return a non-zero exit code in CI mode. Accepts
`critical`, `high`, `medium`, or `low`. Any finding at or above the chosen
threshold fails CI with that severity's exit code (see [Exit Codes](#exit-codes))
— including `--fail-on low` on a LOW-only result (such as an unencrypted-file
policy violation), which exits with code `4`, distinct from HIGH's code `2`.
`INFO` findings are informational only and never fail CI.

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

`envdrift guard` uses severity-based exit codes, plus dedicated codes for an
incomplete scan and for operational errors:

| Code | Meaning |
| :-- | :-- |
| 0 | No blocking findings |
| 1 | Critical findings |
| 2 | High findings |
| 3 | Medium findings |
| 4 | Low findings (policy violations, e.g. unencrypted file) |
| 5 | Scan incomplete: a selected scanner ran but failed |
| 6 | Operational error (bad config, invalid path or flags) |

Each severity has its own code so a pipeline branching on a specific exit code
(`if [ $? -eq 2 ]`) can tell them apart — a LOW-only result never collides with
HIGH's code 2, and a missing config file (6) never looks like a critical
secret (1).

With `--ci`, the `--fail-on` threshold controls what counts as blocking. A
finding at or above the threshold fails CI with the severity-derived code above;
anything below the threshold exits 0.

A run in which a selected scanner errored never reports the all-clear 0: if no
finding blocks the run (none found, or all below the `--fail-on` threshold) but
a scanner failed, guard exits 5, because the requested scan did not complete.
Blocking findings take precedence — a critical finding plus a scanner error
still exits 1. The scanner errors are listed in the human output (Scanner
Errors panel), in `--json` under `scanner_results[].error`, and in `--sarif`
as invocation `toolExecutionNotifications`.

The machine-readable verdict fields always match the process exit code: the
`--json` document's `exit_code`/`has_blocking_findings` and the `--sarif`
invocation's `exitCode`/`executionSuccessful` are computed from the same
threshold-adjusted result the process returns.

Operational-error paths keep machine output parseable too — including a bad
or wrong-typed `[guard]` config value and git failures under
`--staged`/`--pr-base`. With `--json`, stdout is a `{"error": "..."}`
document; with `--sarif`, a schema-valid run with
`executionSuccessful: false` and the error as a tool notification.

## Configuration

Guard settings live under `[guard]` in `envdrift.toml` or
`[tool.envdrift.guard]` in `pyproject.toml`.

```toml
[guard]
scanners = ["native", "gitleaks", "trufflehog", "detect-secrets", "kingfisher", "git-secrets", "talisman", "trivy", "infisical"]
auto_install = true
include_history = false
check_entropy = false  # true = entropy scan on all files, false = off everywhere,
                       # unset = env files only (default)
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

### Built-in Default Ignores

Config and lock files (`pyproject.toml`, `envdrift.toml`, `mkdocs.yml`, `*.lock`,
`package-lock.json`, `*-lock.json`, `*.sum`, ...) only have **noisy** findings
suppressed by default: rules whose ids contain `generic`, `entropy`, or `keyword`,
which routinely false-positive on "secret"-keyword config keys and integrity hashes.
Distinctive-prefix detections (`github-pat`, `aws-access-key-id`, `pypi-token`, ...)
are never suppressed by the defaults — a real token committed in `pyproject.toml` or
a lock file is still reported. User-configured `ignore_paths` suppress everything in
the matching paths.

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
| `github-pat` | GitHub PAT (ghp_) |
| `github-oauth` | GitHub OAuth token (gho_) |
| `github-app-token` | GitHub App token (ghu_/ghs_) |
| `django-secret-key` | Django SECRET_KEY |
| `laravel-app-key` | Laravel APP_KEY |
| `connection-string-password` | DB connection string password |
| `ftp-password` | Password in JSON config |
| `high-entropy-string` | High entropy value |
| `unencrypted-env-file` | .env without encryption |
| `unencrypted-secret-file` | partial-encryption `.secret` file left plaintext |
| `committed-private-key` | dotenvx `.env.keys` tracked/staged in git |

Use `--verbose` or `--json` to see rule IDs for your findings.

See the [Guard Scanning Guide](../guides/guard.md#handling-false-positives) for
more details and examples.
