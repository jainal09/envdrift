# Guard Scanning

Use `envdrift guard` as a last line of defense against plaintext secrets.

## What guard checks

- Unencrypted env files missing dotenvx or SOPS markers
- Common secret patterns in source and config files
- High-entropy strings (optional)
- Git history for previously committed secrets (optional)

### Which files count as env files

The native scanner applies the unencrypted-file policy and the entropy scan to every
file whose name matches an env-file shape:

- `.env` and `.env.<environment>` — including `.env.local` and `.env.test`, the
  canonical real-secrets files for Next.js/Vite/CRA local development
- `<name>.env` (e.g. `production.env`, `database.env`) — the `docker --env-file`,
  direnv, and CI convention
- Custom env files declared in `vault.sync` mappings

Only the template names `.env.example`, `.env.sample`, and `.env.template` are skipped
by default, since they hold placeholder values by convention.

Env files are scanned regardless of text encoding instead of being misclassified as
binary and skipped: UTF-8, and UTF-16 (the Windows Notepad and PowerShell "Unicode"
default) whether or not it carries a BOM, are decoded before pattern matching. A
BOM-prefixed UTF-32 file is also decoded; BOM-less UTF-32 (which has no reliable byte
signature to detect) is the one encoding still treated as binary.

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

For entropy-based and encoded content detection:

```bash
envdrift guard --talisman
```

For comprehensive multi-target security scanning:

```bash
envdrift guard --trivy
```

For 140+ secret types with git history support:

```bash
envdrift guard --infisical
```

You can also enable scanners in `envdrift.toml`:

```toml
[guard]
scanners = ["native", "gitleaks", "trufflehog", "detect-secrets", "kingfisher", "talisman", "trivy", "infisical"]
```

### Scanner comparison

| Scanner | Strengths |
| :-- | :-- |
| native | Fast, zero dependencies, unencrypted .env detection |
| gitleaks | Great pattern coverage, fast |
| trufflehog | Service-specific tokens (GitHub, Slack, AWS) |
| detect-secrets | 27+ plugin detectors, keyword scanning |
| kingfisher | 700+ rules, password hashes, secret validation |
| talisman | Entropy detection, encoded content, file analysis |
| trivy | Comprehensive multi-target scanning, severity filtering |
| infisical | 140+ secret types, git history, staged changes |

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

## Handling False Positives

No secret scanner is 100% accurate. Envdrift provides a **centralized ignore system**
that works uniformly across ALL scanners (native, gitleaks, trufflehog, detect-secrets,
kingfisher, git-secrets, talisman, trivy, and infisical). This ensures you configure
ignores once and they apply everywhere.

### Inline Ignore Comments (Recommended)

Add ignore comments directly in your code. These travel with your code, are visible
in pull requests, and are the most maintainable approach:

```python
# Ignore all rules on this line
password = ref(false)  # envdrift:ignore

# Ignore a specific rule
SECRET_KEY = "test-key-for-unit-tests"  # envdrift:ignore:django-secret-key

# Ignore with a reason (best practice)
API_KEY = "test_fixture"  # envdrift:ignore reason="test data, not a real key"
```

Supported comment styles:

| Language | Syntax |
| :-- | :-- |
| Python, Shell, YAML | `# envdrift:ignore` |
| JavaScript, TypeScript, Go, C | `// envdrift:ignore` |
| CSS, C-style | `/* envdrift:ignore */` |
| JSON | Use TOML config (no comments allowed) |

### TOML Configuration for Bulk Ignores

For patterns that appear across many files (like translation files or test fixtures),
use the `ignore_rules` setting:

```toml
[guard]
# Global path ignores - skip these paths entirely
ignore_paths = [
    "**/tests/**",
    "**/fixtures/**",
    "**/locales/**",
    "**/__mocks__/**",
]

# Rule-specific path ignores - ignore specific rules in specific paths
[guard.ignore_rules]
# FTP password pattern matches "Mot de passe" in French translations
"ftp-password" = ["**/*.json", "**/locales/**"]

# Connection string pattern matches Helm value templates
"connection-string-password" = ["**/helm/**", "**/charts/**"]

# Django secret key in test settings is intentional
"django-secret-key" = ["**/test_settings.py", "**/conftest.py"]
```

### Ignore Priority

The ignore system applies in this order:

1. **Inline comments** - Checked first, most specific
2. **Rule+path ignores** - From `[guard.ignore_rules]` in TOML
3. **Built-in noisy-rule defaults** - Keyword/entropy rules only, in config/lock files
4. **Global path ignores** - From `ignore_paths` in TOML

### Built-in default ignores

Config and lock files (`pyproject.toml`, `envdrift.toml`, `mkdocs.yml`, `*.lock`,
`package-lock.json`, `*-lock.json`, `*.sum`, ...) routinely contain "secret"/"token"
keywords and high-entropy integrity hashes that false-positive the keyword- and
entropy-driven rules. Guard suppresses **only those noisy rules** (rule ids containing
`generic`, `entropy`, or `keyword` — across every scanner) in these files.

High-confidence, distinctive-prefix detections are **never** suppressed by the
defaults: a GitHub PAT (`ghp_...`), AWS access key (`AKIA...`), or PyPI token committed
inside `pyproject.toml` or a lock file is still reported. To skip such a file entirely,
add it to `ignore_paths` yourself — explicit user ignores always suppress everything.

Directory-scoped defaults (`bin/**`, `dist/**`, `vendor/**`, `node_modules/**`, ...)
apply consistently however the scan path is spelled: `envdrift guard`, `envdrift
guard .`, and a symlinked path all produce the same result set.

### Finding Rule IDs

To see which rule triggered a finding, run with `--verbose`:

```bash
envdrift guard --verbose
```

Or use JSON output:

```bash
envdrift guard --json | jq '.findings[].rule_id'
```

Common rule IDs:

| Rule ID | Description |
| :-- | :-- |
| `aws-access-key-id` | AWS access key pattern (AKIA...) |
| `aws-secret-access-key` | AWS secret key |
| `github-pat` | GitHub Personal Access Token (gitleaks findings are prefixed, e.g. `gitleaks-github-pat`) |
| `django-secret-key` | Django SECRET_KEY setting |
| `connection-string-password` | Database connection string passwords |
| `ftp-password` | FTP/SFTP password in JSON/config |
| `high-entropy-string` | High entropy value (entropy scan) |
| `unencrypted-env-file` | .env file without encryption markers |
| `unencrypted-secret-file` | partial-encryption `.secret` file left plaintext |
| `committed-private-key` | dotenvx `.env.keys` private-key file tracked or staged in git |

> **`unencrypted-secret-file` (CRITICAL).** A partial-encryption `.secret` file
> holds the sensitive half of an environment and must be dotenvx-encrypted before
> commit. A plaintext one is flagged CRITICAL (not the generic HIGH
> `unencrypted-env-file`), so `guard --staged` blocks the commit. Fix it with
> `envdrift push`, which encrypts the `.secret`. The installed pre-commit hook
> enforces the same rule — it refuses a plaintext `.secret` but leaves the
> plaintext `.clear` half (committed by design) and encrypted `.secret` files
> alone.
>
> **`committed-private-key` (CRITICAL).** dotenvx writes decryption keys to
> `.env.keys`. A local, gitignored/untracked `.env.keys` is the expected state and
> is **not** flagged. Once git tracks or stages it, guard flags it as
> `committed-private-key` — anyone with repo access could decrypt every secret it
> protects. The fix is **not** to encrypt the key file; remove it from git
> (`git rm --cached .env.keys`), rotate the exposed key(s), and add `.env.keys` to
> `.gitignore` (`envdrift push` / `pull-partial` do this automatically).

### Skipping Clear Files

By default, `.clear` files ARE scanned. This ensures all configuration files
are checked for accidentally included secrets. To skip them:

> **Note:** `skip_clear_files` takes precedence over the `partial_encryption.clear_file`
> allowlist. When enabled, ALL `.clear` files are skipped entirely--even those declared in
> `partial_encryption.environments`. The allowlist only affects behavior when `skip_clear_files=false`,
> exempting specified files from the "unencrypted-env-file" check while still scanning them for
> secret patterns.

#### Option 1: Skip all .clear files globally

```toml
[guard]
skip_clear_files = true
```

Or via CLI: `envdrift guard --skip-clear`

#### Option 2: Skip specific .clear files using ignore rules

```toml
[guard.ignore_rules]
"high-entropy-string" = ["**/config/.env.local.clear"]
```

#### Option 3: Use inline ignore comments

In your `.clear` file:

```bash
TEMPLATE_STRING="{Timestamp:G}|{Message}"  # envdrift:ignore
```

### Allowed Clear Files (Partial Encryption)

For partial encryption setups, files listed in `partial_encryption.environments`
with `clear_file` are automatically excluded from the "unencrypted env file" check
(but still scanned for secret patterns):

```toml
[[partial_encryption.environments]]
name = "production"
clear_file = "app/.env.production.clear"
secret_file = "app/.env.production.secret"
combined_file = "app/.env.production"
```

#### Precedence Example

```toml
[guard]
skip_clear_files = true  # Takes precedence

[[partial_encryption.environments]]
name = "production"
clear_file = "app/.env.production.clear"  # Will NOT be scanned when skip_clear_files=true
secret_file = "app/.env.production.secret"
combined_file = "app/.env.production"
```

With `skip_clear_files = true`: `app/.env.production.clear` is **completely skipped** from scanning.

With `skip_clear_files = false` (default): `app/.env.production.clear` is **scanned for patterns** but
exempt from the "unencrypted-env-file" check.

## Tips

- `--history` requires a git repository plus an active history-capable scanner (gitleaks, trufflehog,
  kingfisher, git-secrets, talisman, or infisical) — guard errors out rather than silently skipping
  history — and can be slower on large histories.
- `skip_clear_files` skips `.clear` files entirely (default: false, they ARE scanned).
- `ignore_paths` applies globally to all scanners.
- `ignore_rules` provides fine-grained control per rule per path pattern.
- Use inline comments for one-off ignores; use TOML for bulk patterns.
- Always provide a `reason` in inline comments for future maintainers.
- External scanners can auto-install; disable with `--no-auto-install`.
