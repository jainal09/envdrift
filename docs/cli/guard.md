# envdrift guard

Scan repositories for unencrypted `.env` files and exposed secrets.

## Synopsis

```bash
envdrift guard [OPTIONS] [paths]...
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
| `[paths]` | Files or directories to scan | `.` |

### How paths are shown

Every finding names its file relative to the directory guard runs in when its path, as given, is under
that directory, and by its absolute path otherwise. Symlinks in an absolute path are not resolved for
this, so an absolute path through a symlinked working directory (such as macOS `/tmp`) is shown
absolute. On Windows a file on another drive is always shown absolute. Every scanner uses this one
form, in the findings table, in `--json`, and in the finding messages, and so do `--staged`,
`--pr-base` and `--history`. A file outside the working directory, such as one changed by a pull
request when guard runs in a subdirectory, is shown absolute, not as `../file`. The findings table
shortens a long path at its start, so the file name and line stay visible. SARIF artifact URIs stay
relative to the repository root (see `--sarif` below).

A path you pass through a symlink is shown under the name you gave: `envdrift guard linkproj` reports
`linkproj/sub/app.env` from every scanner, including those that resolve symlinks. A symlinked
directory is scanned in its absolute form too (`envdrift guard "$PWD/linkproj"`), and a symlink to a
file is scanned through to its target and shown as the link. A `..` after a symlink names the link
target's parent: `envdrift guard linkproj/..` scans that directory and shows its files where they are.

The path shown is not always the path in a gitleaks or Infisical fingerprint. `envdrift guard` with
no path and absolute paths are fingerprinted by absolute path; see
[gitleaks and Infisical ignore files](#gitleaks-and-infisical-ignore-files).

envdrift 11.0.8 and earlier could show one file in two forms in one report. The native scanner showed
every file of a directory it scanned by its absolute path, gitleaks and Infisical showed it in the
form of the path you passed, and gitleaks showed history findings by their absolute path. gitleaks and
Infisical also reported nothing, and no error, for the absolute path of a symlinked directory (or of
one followed by `..`) and for a symlink to a file.

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

envdrift runs the `detect-secrets` package installed next to it (`python -m detect_secrets`) with every
plugin enabled, and installs the pinned version when the package is missing and auto-install is on.

**Which files it scans.** Inside a git repository detect-secrets scans the files git tracks, so a new
file is scanned once you `git add` it, and a file git ignores is not. That holds for the top level of
the repository and for any subdirectory of it: `envdrift guard sub` scans the tracked files below
`sub`, and so does `envdrift guard .` run inside it. Outside a git repository it scans every file in
the directory. Either way it skips everything below a directory named `node_modules`, `.venv`, `venv`,
`.tox`, `.nox`, `site-packages`, `__pycache__`, `.mypy_cache`, `.pytest_cache`, `.ruff_cache`, `.git`,
`dist`, `build`, `vendor` or `coverage`. Only directories count: a script called `build` is scanned, and
so is the directory you point it at, whatever it is called. A file you name is always scanned. A
directory outside git can hold more such trees than that list names; `[guard] ignore_paths` drops their
findings (see [Configuration](#configuration)), though not the time spent scanning them.

A tracked file with a non-ASCII name (`café.env`) is scanned too. envdrift runs detect-secrets with git's
`core.quotepath` off (git 2.31 or later), because with it on `git ls-files` writes that name as
`"caf\303\251.env"`, which names no file, and detect-secrets dropped the file without a word. Git quotes a
name with a double quote, a backslash or a control character whatever the setting, and detect-secrets splits
the list at U+0085, U+2028 and U+2029 as it does at a newline, so a name with one of those is lost too.
detect-secrets also fails on a name that is not valid UTF-8 anywhere in the repository when the setting is
off, even in a directory or file it would not scan, so envdrift turns the setting on (over your own git
configuration) in a repository that tracks one. A git older than 2.31 ignores the setting altogether, and so
does a `core.quotepath` in `GIT_CONFIG_PARAMETERS`, which `git -c core.quotepath=...` exports, in your
environment. envdrift does not guess which names that affects: it runs the command detect-secrets runs, under
the environment detect-secrets gets, and compares. For every file of the scan whose name is not in the list, the Scanner Warnings say "Not scanned
in ..." and list the first three, instead of letting the file pass for clean. Rename the file or scan it with
another scanner.

When git tracks nothing that detect-secrets would scan in a directory (a repository whose files are not
added yet, or a directory that is all ignored), detect-secrets prints an empty report, as for a
directory with no secret. guard says so instead of letting that pass for a clean run: the
Scanner Warnings panel, `scanner_results[].warnings` and the `--sarif` notifications carry "Scanned
nothing in ..." and the fix, `git add` the files. It is a warning, not an error, and does not
change the exit code. If git cannot list the files of the repository (a damaged index), the warning says
"Could not list the files git tracks in ...", because detect-secrets lists them with the same command and
may have scanned none. If detect-secrets cannot list the files of a directory at all, or prints a report
envdrift cannot read, the scan is an error (exit 5), never a clean run.

Older envdrift releases passed detect-secrets no flag for a directory outside a git repository: it listed
no files, printed a notice on stderr and exited 0, and envdrift reported a clean run, exit 0, for a
directory nothing had looked at ([#851](https://github.com/jainal09/envdrift/issues/851)). They also
reported a clean run for a subdirectory of a repository (`envdrift guard sub`, or `envdrift guard .`
run inside it), because detect-secrets compares the paths git lists, relative to the top level of the
repository, with the paths it finds relative to the directory it runs in, and in a subdirectory not one
of them agrees. A file called `build`, `dist`, `vendor` or `coverage` was skipped as well, as if it were
one of those directories.

**Which version.** envdrift grades detect-secrets findings by the detector names of the version it
pins in `constants.json`. Another version can rename or add detectors, and a finding from a detector
envdrift does not know is graded HIGH, so severities may be inaccurate. When the installed version is
not the pinned one, or cannot be read, guard warns, naming the installed and the pinned version, and
gives the fix: `pip install detect-secrets==<pinned version>`. The warning is a Scanner Warnings panel in
the human output, `scanner_results[].warnings` in `--json`, a `warning` entry of
`toolExecutionNotifications` in `--sarif`, and a line on stderr under `--json` and `--sarif`. It does not
change the exit code, and envdrift never installs or changes the package for it.

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

Infisical reports no severity of its own, so envdrift grades each finding by its rule ID, with the
same table as gitleaks and the other scanners: see [Severity](#severity). A custom Infisical rule
config that emits the IDs `aws-access-key-id`, `google-api-key`, `slack-token` or `stripe-api-key` is
graded CRITICAL too.

On 0.43.135, the version envdrift auto-installs, Infisical has no rule for AWS secret access keys or
Azure storage account keys and reports both as `generic-api-key`, which is HIGH. Every version does
the same for an AWS secret access key with no key ID next to it. So `--fail-on critical` does not
block these keys on Infisical's findings alone. In the working tree the native scanner still grades
them CRITICAL (its `azure-storage-key` rule, and its `aws-secret-access-key` rule for a value assigned
to a `SECRET_ACCESS_KEY` name), but it does not scan git history.

> **Note:** Infisical CLI 0.43.136 and later (the betterleaks engine) report less than earlier
> releases ([#834](https://github.com/jainal09/envdrift/issues/834)). envdrift makes up for most of it:
>
> - When `infisical scan --help` lists `--confidence`, envdrift scans with `--confidence low`. The
>   default, `medium`, hides lone AWS secret access keys, generic API keys and passwords, which only
>   the engine's low-confidence generic rules report. Releases up to 0.43.135 reject the flag, so
>   they never get it.
> - Betterleaks nests the secret access key of a paired AWS credential inside the key ID's finding.
>   envdrift reports it as its own finding, and does the same for the few other nested values that
>   are secrets (the Exoscale and Polymarket API secrets, the Polymarket passphrase, the OVH
>   consumer key and the Alibaba STS security token). The other values betterleaks nests, such as
>   Azure tenant and client IDs, usernames, account names and hosts, are not secrets, so envdrift
>   does not report them.
>
> Betterleaks still never reports an AWS access key ID that has no secret access key within a few
> lines of it: none of its built-in rules does, at any `--confidence` level. So the auto-installed
> binary stays pinned to 0.43.135, the last gitleaks-engine release. An `infisical` already on your
> `PATH` is used as-is, though: check `infisical --version` if you installed it yourself.

### `--history`, `-H`

Include git history in the scan. Requires a git repository and at least one active history-capable
scanner (gitleaks, trufflehog, kingfisher, git-secrets, talisman, or infisical). If none of the
active scanners can scan git history (for example `--history --native-only`), guard exits with an
error instead of silently skipping the history.

```bash
envdrift guard --history
```

gitleaks and infisical scan the history of the whole repository that contains each scanned path,
a file or a subdirectory alike, once per repository, so `--pr-base --history` with many changed
files runs one history scan. A path outside any git repository, or in a repository with no commits,
is a scanner error for them, never a clean history: with no blocking finding, guard exits 5 (scan
incomplete).

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

Trivy reports matches with the secret already redacted to asterisks, so envdrift
recovers the raw value from the scanned file before hashing — two *distinct* secrets
that share a variable name and length stay distinct under `--skip-duplicate`, and a
secret found by both trivy and another scanner still collapses to one finding. When
the raw value cannot be recovered (for example the file changed mid-scan, the finding
spans multiple lines, or several secrets share one line so the mask boundary is
ambiguous), each finding instead keeps a synthetic hash qualified by its file, line
span, rule and a per-location occurrence index. Distinct findings therefore never
share a fallback hash — even the byte-identical findings trivy emits for two distinct
same-rule secrets on one line — but an unrecovered finding also cannot collapse with
the same secret reported by another scanner.

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
git-based filtering will be applied). Paths exchanged with git are encoded and
decoded as UTF-8 on every platform, so non-ASCII filenames are matched correctly
regardless of the system locale (e.g. cp1252 on Windows).

### `--auto-install` / `--no-auto-install`

Control auto-installation of external scanners.

```bash
envdrift guard --no-auto-install
```

With `--no-auto-install`, a missing scanner binary is handled by how the
scanner was selected. A scanner you selected **explicitly** — its CLI flag
(e.g. `--gitleaks`) or a `[guard] scanners` list written in your config —
fails closed: the failure is recorded and the run exits `5` (scan
incomplete). A scanner active only via the built-in **default** set is
skipped instead, with a visible warning (Scanners Skipped panel, stderr
warning) and a truthful `skipped`/`skip_reason` record in `--json`; the
exit code is unaffected, so `guard --no-auto-install` stays green on a
machine that simply doesn't have the optional binary.

Auto-installed scanner binaries are verified against the upstream-published
SHA256 checksums before they are installed or executed; the install fails
closed when the checksum is missing, unreachable, or mismatched. Set
`ENVDRIFT_INSECURE_SKIP_CHECKSUM=1` to skip verification (unsafe).

### `--json`, `-j`

Output results as JSON.

```bash
envdrift guard --json > guard-report.json
```

Each entry of `scanner_results` has `name`, `files_scanned`, `duration_ms`, `error`, `skipped`,
`skip_reason` and `warnings`. `warnings` lists the non-fatal notices of a scanner that ran, such as an
unexpected detect-secrets version; it is empty when there are none, and a warning never changes
`exit_code`. `findings[].severity` is `critical`, `high`, `medium`, `low` or `info`; how a finding is
graded is described under [Severity](#severity).

### `--sarif`

Output results as SARIF for code scanning tools.

```bash
envdrift guard --sarif > guard.sarif
```

Artifact URIs are emitted relative to the enclosing git repository root
(declared as the `SRCROOT` base via `originalUriBaseIds`), percent-encoded
per RFC 3986, no matter which directory guard runs from, so GitHub/GitLab
Code Scanning maps every alert to a repo file; a finding outside the
repository falls back to an absolute `file://` URI. When the findings span
several repositories, the root is the repository guard runs in if it holds a
finding, and otherwise the first repository, by path, that does; the order
of the findings does not change it. Each result carries a
stable fingerprint built from the rule id, the location, and a truncated
hash of the secret value — never the matched text — so two different secrets
on the same line stay separate alerts. The redacted preview is attached as
the result's `properties.secretPreview`.

A failed scanner is an `error` entry of the invocation's `toolExecutionNotifications`, and the
non-fatal warnings of a scanner that ran (see `--detect-secrets`) are `warning` entries. A warning does
not change `executionSuccessful` or `exitCode`. A result's `level` is `error` for CRITICAL and HIGH
findings, `warning` for MEDIUM and `note` for LOW and INFO, and the `security-severity` of its rule is
`9.0`, `7.0`, `5.0`, `3.0` and `1.0` respectively, which is what GitHub ranks alerts by. A rule has one
`security-severity`, that of the most severe finding reported under it, so a Stripe test-mode key
(HIGH) is ranked with the `9.0` of the rule's live keys when both are found; its `level` stays per
result.

!!! note "Upgrading from older releases"
    The fingerprint format changed in this release: existing GitHub Code
    Scanning alerts created from older envdrift SARIF uploads are re-keyed
    once (closed and re-opened as new alerts) on the first upload from this
    version.

### `--ci`

CI mode: no colors, strict exit codes, and `--fail-on` threshold applied.

```bash
envdrift guard --ci --fail-on high
```

### `--fail-on`

Minimum severity to return a non-zero exit code in CI mode. Accepts
`critical`, `high`, `medium`, or `low`. Any finding at or above the chosen
threshold fails CI with that severity's exit code (see [Exit Codes](#exit-codes))
— including `--fail-on low` on a LOW-only result, which exits with code `4`,
distinct from HIGH's code `2`. An unencrypted environment file is HIGH and exits
with code `2` when it blocks the run.
`INFO` findings are informational only and never fail CI. How a finding is graded `critical`, `high`
or `medium` is described under [Severity](#severity).

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

The scan reads the staged *index* content (`git show :<path>`), not the working-tree copies, so a
secret that is staged but already edited away (or deleted) in the working tree is still caught
before the commit ships it. Findings are reported against the real repository paths. Running
`--staged` outside a git repository is an operational error (exit 6).

```bash
envdrift guard --staged
```

### `--pr-base`

Scan only files changed since the specified base branch. Useful for CI/CD PR checks.

If the base ref cannot be resolved (typo, or a shallow CI clone that never fetched it), guard exits
with an error instead of treating the failed diff as "no changed files" — a misconfigured base must
never pass the secret gate green. A failed `git fetch` of the base is reported as a warning on
stderr.

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

## Severity

Every finding has a severity. It decides the exit code (see [Exit Codes](#exit-codes)) and whether
`--fail-on` blocks the run. **The native, gitleaks, Infisical, detect-secrets, Kingfisher and
git-secrets scanners give a credential class the same severity.** None of the last five reports a
severity of its own, so envdrift grades each of their findings by the class of credential it matched,
and the native scanner's grade for a class is the reference. trufflehog, trivy and talisman are the
exception, described below the table.

| Credential class | Severity |
| :-- | :-- |
| AWS access key IDs, secret access keys, session tokens and Bedrock API keys | CRITICAL |
| Azure storage account keys, Azure AD client secrets and Azure connection strings | CRITICAL |
| GCP service-account keys, application default credentials, OAuth client secrets and Google API keys | CRITICAL |
| IBM Cloud, IBM COS, Cloudant and SoftLayer credentials | CRITICAL |
| GitHub tokens: personal access, OAuth, app, refresh and fine-grained | CRITICAL |
| GitLab tokens: personal access, pipeline trigger, runner, deploy, session cookie and others | CRITICAL |
| npm and PyPI tokens, HashiCorp Vault tokens | CRITICAL |
| Private keys: PEM, OpenSSH, PGP, PuTTY, age and wallet keys | CRITICAL |
| Password hashes (bcrypt, sha512crypt), `.netrc` credentials | CRITICAL |
| Stripe live secret and restricted keys, Square and Braintree tokens | CRITICAL |
| Slack tokens and webhook URLs, Discord bot tokens and webhook URLs, Telegram bot tokens | CRITICAL |
| OpenAI, Anthropic, SendGrid, Mailchimp, Mailgun, Heroku, Shopify, DigitalOcean, Doppler, Postman, Linear, Supabase and Facebook keys and tokens | CRITICAL |
| Generic secrets: an API key, secret, token or password assigned to a value | HIGH |
| JSON Web Tokens | HIGH |
| Credentials in a URL: database, Redis and basic-auth URLs | HIGH |
| Stripe test-mode keys (`sk_test_`, `rk_test_`), Twilio account and API key SIDs | HIGH |
| Artifactory, Docker registry, Datadog, Atlassian, Algolia and Cloudflare credentials | HIGH |
| High-entropy strings | MEDIUM |

The table lists classes, not rule IDs. A class covers every rule, detector or pattern that finds it, in
every scanner that has one, and `envdrift guard --json` shows the rule ID of each finding. A test checks
the rule IDs of gitleaks, Infisical and Kingfisher against the table, so no credential rule of a provider
in a CRITICAL class is left out by mistake; the rules for an identifier or a public value (an Azure
tenant ID, a Discord client ID, a Mailgun public key) are the only ones of such a provider left at HIGH.
A rule that no class lists, such as one a newer tool adds, is HIGH, in every scanner but git-secrets
(below). A scanner without a rule for a class can still find its secrets, but only under a generic rule,
which is HIGH: gitleaks reports an Azure storage account key as `generic-api-key`, for example, where the
native scanner's own rule grades it CRITICAL. The native scanner also grades its policy findings itself:
an unencrypted environment file is HIGH, and a plaintext partial-encryption `.secret` file or a tracked
dotenvx `.env.keys` is CRITICAL.

Some grades are judgment calls or known gaps:

- A JSON Web Token is HIGH, never lower. Some are public by design (an OIDC ID token, a Supabase anon
  key), but a bearer or session token and a Supabase `service_role` key have the same
  `eyJ...eyJ...` shape, and no rule can tell them apart, so a JWT that leaked is treated as one that
  matters. gitleaks, Infisical and detect-secrets have always graded it HIGH; the native scanner called
  it MEDIUM and now agrees with them. A JWT that is public on purpose can be kept out of the report
  with `# envdrift:ignore` on its line or by path (see [Handling False Positives](#handling-false-positives)).
- A Twilio account SID or API key SID is HIGH. It identifies an account or a key; the secret is another
  value. detect-secrets reports any `AC` or `SK` followed by 32 lower-case letters or digits as a Twilio
  API key, `CACHE_KEY=AC...` included, which is why CRITICAL would raise false alarms at the top
  severity.
- A credential in a URL is HIGH, except that the native scanner grades one in a GitHub, GitLab or
  Bitbucket URL CRITICAL. detect-secrets' basic-auth detector cannot tell the host, so it is HIGH for
  every URL.
- git-secrets reports a matching line, not a rule, so envdrift names the credential from the line. A
  line with an AWS access key ID is CRITICAL, as is a line with a secret access key (the 40-character
  value assigned to the AWS secret field itself, with `=`, `:` or `=>`) or a private key (a
  `-----BEGIN ... PRIVATE KEY` header, or a long base64 value assigned to `private_key` itself). A line that only
  names a key it does not hold (`private_key_path = ...`) is HIGH at most, and a line that names no
  credential at all is MEDIUM: this is the one place where an unclassified match is not HIGH.

A grade is looked up by the scanner's own name for the credential: the native scanner's pattern ID, the
rule ID of gitleaks and Infisical (one shared table, because they share a rule set), the detector name of
detect-secrets, and the kind of line for git-secrets. Kingfisher's main catalog is betterleaks', the rule
set of Infisical 0.43.136 and later, and its rules are named `betterleaks.<id>`, so it looks those up in
the same table as gitleaks and Infisical. Its other rules (the `veles.` ones, and rules from a custom
rules file) are CRITICAL when a keyword of a CRITICAL class appears in the rule's ID or name, and HIGH
otherwise. A test holds each of those tables to the table above, so they cannot drift apart again.

trufflehog, trivy and talisman do not use the table. trufflehog grades a finding CRITICAL when it
verified the secret with the provider and HIGH when it did not, and trivy and talisman pass the severity
their own tool reports through, so they can grade a class differently from the six scanners above.

!!! warning "Stricter severities and exit codes"
    Older envdrift releases graded every gitleaks finding HIGH, and graded the same credential
    differently in each scanner: the native scanner called a Heroku, Slack, OpenAI, SendGrid or Google
    API key CRITICAL while Infisical called it HIGH, and detect-secrets called a private key HIGH where
    the native scanner and Infisical called it CRITICAL. envdrift 11.0.7 and earlier also graded most of
    Infisical's CRITICAL rules HIGH, AWS key IDs and Stripe live keys included
    ([#844](https://github.com/jainal09/envdrift/issues/844)). Every scanner now follows the table above
    ([#850](https://github.com/jainal09/envdrift/issues/850)), which changes what blocks a run. Most
    changes make the gate stricter. Two lower a grade, a git-secrets line that only mentions `asia` and a
    detect-secrets Twilio SID, and each gives the reason the old grade was wrong:

    - `--fail-on critical` now blocks a gitleaks, Infisical, detect-secrets, Kingfisher or git-secrets
      finding in a CRITICAL class. It used to pass an AWS key ID that only gitleaks found, a private key
      that only detect-secrets found, or a Slack token that only Infisical found.
    - A run whose worst finding is one of those now exits `1`, not `2`. A pipeline that branches on the
      exit code `2` for such a credential must test for `1`; one that fails on any non-zero code is
      unaffected.
    - In `--json`, `findings[].severity`, `summary.by_severity` and `exit_code` change with the grades.
      In `--sarif`, the `security-severity` of those alerts is `9.0`, not `7.0`.
    - The native scanner now grades Discord and Telegram bot tokens, Mailchimp API keys and bcrypt and
      sha512crypt hashes CRITICAL, where it graded them HIGH, so that it agrees with detect-secrets and
      Kingfisher. It grades a JSON Web Token HIGH, where it graded it MEDIUM, to agree with gitleaks,
      Infisical and detect-secrets, which always did. A run without gitleaks (`--native-only`,
      `--no-gitleaks`) therefore exits `2` on a JWT, where it used to exit `3`, or `0` with `--ci` at the
      default `--fail-on high`.
    - detect-secrets' keyword and Artifactory detectors are HIGH, not MEDIUM, and its private key
      detector is CRITICAL, not HIGH. git-secrets grades an AWS key CRITICAL, not HIGH, a private key
      CRITICAL, not MEDIUM, and a password, token or API key HIGH, not MEDIUM.
    - Kingfisher grades its betterleaks rules like gitleaks and Infisical do, and its other rules HIGH
      unless a CRITICAL keyword names them, where it graded a rule that matched no keyword MEDIUM. A rule
      that names GitLab, OpenAI, Heroku, Discord or another provider of a CRITICAL class is CRITICAL.
    - The shared gitleaks and Infisical table grades the credential rules it used to leave to the HIGH
      fallback CRITICAL, for example the Amazon Bedrock API keys, Azure connection strings, GitLab session
      cookies and age keys, so `--fail-on critical` blocks them too.
    - git-secrets tells an AWS access key by the key ID itself (`AKIA`, `ASIA`, `ABIA`, `ACCA` or `A3T`
      plus one more character and 16 more, 20 in all), no longer by the letters `akia` or `asia`
      anywhere in the line. `password=asia-northeast1` is a password (HIGH) and not an AWS key, and a
      line such as `region=asia-south1` that git-secrets flagged for another reason is MEDIUM, not HIGH.
      Likewise a line that only names a secret access key or a private key, without holding one, is
      HIGH at most.
    - One grade went down: a detect-secrets Twilio API key is HIGH, not CRITICAL, to match the native
      scanner and every other scanner. The detector matches `AC` and `SK` followed by 32 letters or
      digits, which are account and key SIDs, identifiers whose secret is another value (it reports
      `CACHE_KEY=AC...` too), and it does not match a Twilio auth token at all. With
      `--fail-on critical`, a Twilio SID that only detect-secrets found no longer blocks the run.

## Exit Codes

`envdrift guard` uses severity-based exit codes, plus dedicated codes for an
incomplete scan and for operational errors:

| Code | Meaning |
| :-- | :-- |
| 0 | No blocking findings |
| 1 | Critical findings |
| 2 | High findings (including unencrypted environment files) |
| 3 | Medium findings |
| 4 | Low findings |
| 5 | Scan incomplete: a selected scanner ran but failed |
| 6 | Operational error (bad config, invalid path or flags) |

Each severity has its own code so a pipeline branching on a specific exit code
(`if [ $? -eq 2 ]`) can tell them apart — a LOW-only result never collides with
HIGH's code 2, and a missing config file (6) never looks like a critical
secret (1).

Collection errors are operational errors and exit `6`, reported as an error message instead
of findings: an unresolvable `--pr-base` ref, `--staged` outside a git repository, or
`--history` with no active history-capable scanner. These misconfigurations previously passed
with exit 0; a broken secret gate now fails loudly instead of green, and exit 6 (never 1)
keeps them distinct from a real critical finding for an exit-code-only pipeline.

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

Exit 5 applies to scanners you **selected** — a CLI flag or a `[guard]
scanners` list written in your config. A scanner active only via the built-in
default set whose binary is missing under `--no-auto-install` never ran and
never failed: it is skipped with a visible warning and a
`scanner_results[].skipped`/`skip_reason` record, and does not change the
exit code (see `--auto-install` above).

A scanner **warning** is neither a failure nor a skip. The scanner ran and completed, so its findings
stand and the exit code is unchanged, but they may be less reliable than they look (for example, the
installed detect-secrets is not the pinned version, see `--detect-secrets`). Warnings are listed in the
human output (Scanner Warnings panel), in `--json` under `scanner_results[].warnings`, and in `--sarif`
as `warning` entries of `toolExecutionNotifications`.

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

A pattern in `ignore_paths` or `ignore_rules` matches a file by the path guard shows, by the path
shown for its real location with symlinks resolved, and by the path the scanner reported, and also by
any trailing part of those paths (`config/settings.txt` matches `/repo/config/settings.txt`). A path
shown relative to the directory guard runs in is also matched as if it started with `/`, so
`**/tests/**` matches `tests/test_app.py`. So a relative pattern for a path inside that directory
gives one verdict for a file, whichever scanner reports it and however you spell the scan path:
`envdrift guard`, `envdrift guard .`, `envdrift guard proj`. A file scanned through a symlink matches a
pattern for the link name and one for its real location; scanned through its real location it matches
only the latter, so name the real location when you scan both ways. A pattern that is absolute, or names a
directory above the directory guard runs in (`../config/*`), is matched against the path a scanner
reported and, for a file outside that directory, the absolute path guard shows. What a scanner reports
depends on how the scan path is spelled: absolute for a directory the built-in scanner scans and for
every scanner given no path or an absolute one, `../…` for a file outside the directory (for example
`--pr-base` run from a subdirectory), relative otherwise. Such a pattern can therefore give different
verdicts for one file, so write patterns relative to the directory guard runs in. A broad glob such as
`**/build/**` also matches a directory above the checkout in the absolute paths of `envdrift guard`
with no path and of the built-in scanner, so it hides every finding of a checkout that lives under a
`build/` directory (tracked as [#859](https://github.com/jainal09/envdrift/issues/859)): avoid globs
that can match an ancestor of the checkout. Inline comments are read from the file itself.

### gitleaks and Infisical ignore files

gitleaks and Infisical also read their own ignore files, `.gitleaksignore` and `.infisicalignore`.
Each line is a fingerprint, `<file>:<rule-id>:<line>`, as the binaries print it in their own reports.
gitleaks also accepts `<commit>:<file>:<rule-id>:<line>` for a history finding. envdrift runs both
binaries in the directory guard runs in and passes each path as you gave it, so `<file>` names the
file the way `gitleaks dir <path>` run by hand from that directory does:

| How guard is run | `<file>` in the fingerprint |
| :-- | :-- |
| `envdrift guard .`, `envdrift guard <dir>`, `envdrift guard <file>` | Relative to the directory guard runs in, e.g. `config/settings.txt` |
| `envdrift guard --pr-base <ref>` | Relative to the directory guard runs in: repo-relative from the repository root, `../config/settings.txt` from a subdirectory |
| `envdrift guard` with no path | Absolute: guard passes the absolute path of the directory it runs in |
| `envdrift guard <absolute path>` | Absolute |
| `--history` | Relative to the repository root |

Where each binary looks for its ignore file:

| Scanned path | `.gitleaksignore` (gitleaks) | `.infisicalignore` (Infisical) |
| :-- | :-- | :-- |
| A directory | The directory guard runs in, and the scanned directory | The scanned directory only |
| A file, including every `--pr-base` file | The directory guard runs in | None |
| `--history` | The repository root | The repository root |

So under `--pr-base` run from the repository root, a repo-root `.gitleaksignore` with repo-relative
fingerprints covers a changed file at any depth; run from a subdirectory, gitleaks reads that
directory's `.gitleaksignore` instead. Infisical reads no ignore file when it scans a single file, so
`.infisicalignore` never applies under `--pr-base`. Under `--staged` both binaries scan temporary
copies of the staged files: their fingerprints name those copies, so no ignore-file entry matches; use
inline comments or the `[guard]` ignores instead. A symlink to a file is scanned through to its
target, and its fingerprint names the target. A directory path in which `..` follows a symlink is
passed in its physical form, which its fingerprints name.

The same paths are what the scanner configuration in a scanned directory sees: both binaries read
`.gitleaks.toml` or `.infisical-scan.toml` from the directory they scan and match its allowlist `paths`
against `<file>` as above. For `envdrift guard proj` that is `proj/sub/app.env`, so `^proj/sub/app\.env$`
matches it and `^sub/app\.env$` does not. An unanchored `(^|/)sub/app\.env$` matches either way.

`envdrift guard`, `envdrift guard .` and `--history` read the same ignore files, with the same
fingerprints, as in earlier releases. envdrift 11.0.8 ran both binaries inside the scanned directory,
or inside a scanned file's directory. gitleaks read only the `.gitleaksignore` there. Infisical read
the `.infisicalignore` of a scanned directory and, as it still does, none for a scanned file. The
fingerprints of a relative directory or file path, including every `--pr-base` file, were relative to
that directory (`settings.txt:github-pat:1` for `config/settings.txt`), and so were the paths a
scanned directory's allowlist matched. Rewrite such entries relative to the directory guard runs in,
and put gitleaks entries for a scanned file in the `.gitleaksignore` there, the only one gitleaks
reads for a file. Fingerprints of absolute paths have not changed.

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
