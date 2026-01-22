# New Guard Integration Specification

This document specifies the integration of new secret scanning tools into envdrift-guard.

## Executive Summary

| Tool | Status | Recommendation |
|------|--------|----------------|
| Talisman | Approved | CLI tool, cross-platform binary, good detection |
| Trivy | Approved | Popular scanner, JSON output, multi-target |
| Infisical | Approved | Modern CLI, 140+ secret types, JSON output |
| SEDATED | **Not Suitable** | Git server hook only, not a CLI tool |

---

## 1. Talisman Integration

### Overview

- **Source**: <https://github.com/thoughtworks/talisman>
- **Maintainer**: ThoughtWorks
- **License**: MIT
- **Purpose**: Pre-commit/pre-push secret scanner

### Detection Capabilities

- Encoded values (Base64, hex)
- File content patterns (passwords, tokens)
- File size anomalies (large binary files)
- Entropy-based detection
- Credit card numbers
- Suspicious file names (.pem, .key, .pfx)

### Installation Methods

1. **Homebrew** (macOS/Linux): `brew install talisman`
2. **Direct download**: Binary releases from GitHub
3. **Install script**: See Talisman documentation

### CLI Usage

```bash
# Scan current directory
talisman --scan

# Scan with HTML report
talisman --scanWithHtml --reportdirectory=/path/to/reports

# Scan specific files
talisman --pattern="*.py *.js"

# Scan without git history
talisman --scan --ignoreHistory
```

### Output Format

Talisman outputs a text table by default. For structured output:

- Use `--scanWithHtml` for HTML reports
- Parse JSON from report directory

### Severity Mapping

| Talisman Level | envdrift Severity |
|----------------|-------------------|
| high | CRITICAL |
| medium | HIGH |
| low | MEDIUM |

### Configuration File

`.talismanrc` in repository root:

```yaml
fileignoreconfig:
  - filename: test.pem
    checksum: <sha256>
custom_patterns:
  - pattern1
threshold: medium
```

### Integration Approach

1. Check for binary in PATH or venv
2. Auto-download binary from GitHub releases
3. Run `talisman --scan --reportdirectory=<temp>`
4. Parse JSON report file
5. Map findings to ScanFinding objects

---

## 2. Trivy Integration

### Overview

- **Source**: <https://github.com/aquasecurity/trivy>
- **Maintainer**: Aqua Security
- **License**: Apache 2.0
- **Purpose**: Comprehensive security scanner (vulnerabilities, secrets, misconfigs)

### Detection Capabilities

- AWS access keys and secrets
- GCP service account keys
- GitHub/GitLab tokens
- Slack tokens
- Private keys (RSA, DSA, EC)
- Generic API keys
- Custom regex patterns

### Installation Methods

1. **Homebrew**: `brew install trivy`
2. **Direct download**: Binary releases from GitHub
3. **Docker**: `docker pull aquasec/trivy`
4. **apt/yum**: Package manager installation

### CLI Usage

```bash
# Scan filesystem for secrets only
trivy fs --scanners secret /path/to/project

# JSON output
trivy fs --scanners secret --format json /path/to/project

# With custom config
trivy fs --scanners secret --secret-config trivy-secret.yaml /path

# Severity filter
trivy fs --scanners secret --severity HIGH,CRITICAL /path
```

### Output Format (JSON)

```json
{
  "Results": [
    {
      "Target": "path/to/file",
      "Secrets": [
        {
          "RuleID": "aws-access-key-id",
          "Category": "AWS",
          "Severity": "CRITICAL",
          "Title": "AWS Access Key ID",
          "StartLine": 10,
          "EndLine": 10,
          "Match": "AKIA..."
        }
      ]
    }
  ]
}
```

### Severity Mapping

| Trivy Severity | envdrift Severity |
|----------------|-------------------|
| CRITICAL | CRITICAL |
| HIGH | HIGH |
| MEDIUM | MEDIUM |
| LOW | LOW |

### Configuration File

`trivy-secret.yaml`:

```yaml
rules:
  - id: custom-api-key
    category: CustomSecrets
    title: Custom API Key
    severity: HIGH
    regex: 'custom_key_[a-zA-Z0-9]{32}'

enable-builtin-rules:
  - aws-access-key-id
  - github-pat

disable-rules:
  - slack-access-token
```

### Integration Approach

1. Check for `trivy` binary in PATH or venv
2. Auto-download from GitHub releases
3. Run `trivy fs --scanners secret --format json <path>`
4. Parse JSON output
5. Map findings to ScanFinding objects

---

## 3. Infisical Integration

### Overview

- **Source**: <https://github.com/Infisical/infisical>
- **Maintainer**: Infisical Inc.
- **License**: MIT
- **Purpose**: Secret management platform with scanning capabilities

### Detection Capabilities

- 140+ secret types
- Git history scanning
- Staged changes scanning
- Custom regex patterns
- Entropy-based detection

### Installation Methods

1. **Homebrew**: `brew install infisical/get-cli/infisical`
2. **npm**: `npm install -g @infisical/cli`
3. **Direct download**: Binary releases from GitHub
4. **Scoop** (Windows): `scoop install infisical`

### CLI Usage

```bash
# Scan git repository history
infisical scan

# Scan with verbose output
infisical scan --verbose

# Scan without git (filesystem only)
infisical scan --no-git

# Scan staged changes only
infisical scan git-changes --staged

# Output to JSON report
infisical scan --report-path leaks-report.json
```

### Output Format (JSON)

```json
[
  {
    "Description": "AWS Access Key ID",
    "StartLine": 15,
    "EndLine": 15,
    "StartColumn": 10,
    "EndColumn": 30,
    "Match": "AKIA...",
    "Secret": "AKIAIOSFODNN7EXAMPLE",
    "File": "config.py",
    "SymlinkFile": "",
    "Commit": "abc123",
    "Entropy": 3.5,
    "Author": "dev@example.com",
    "Email": "dev@example.com",
    "Date": "2024-01-15",
    "Message": "Add config",
    "Tags": ["key", "aws"],
    "RuleID": "aws-access-key-id",
    "Fingerprint": "config.py:aws-access-key-id:15"
  }
]
```

### Configuration File

`infisical-scan.toml`:

```toml
[allowlist]
paths = ["test/**", "docs/**"]
regexes = ["EXAMPLE", "test-"]

[[rules]]
id = "custom-secret"
description = "Custom Secret Pattern"
regex = '''custom_secret_[a-zA-Z0-9]+'''
tags = ["custom"]
```

### Integration Approach

1. Check for `infisical` binary in PATH or venv
2. Auto-download from GitHub releases
3. Run `infisical scan --report-path <temp.json> --no-git` or with git
4. Parse JSON report
5. Map findings to ScanFinding objects

---

## 4. SEDATED - Not Suitable

### Overview

- **Source**: <https://github.com/OWASP/SEDATED>
- **Maintainer**: OWASP
- **License**: BSD-3-Clause
- **Purpose**: Git server pre-receive hook

### Why Not Suitable

SEDATED is designed to run on Git servers (GitHub Enterprise, GitLab, vanilla Git servers) as a
**pre-receive hook**, not as a standalone CLI tool. Key limitations:

1. **Server-side only**: Runs as a Git hook on the server, not client-side
2. **No CLI**: No command to run scans locally
3. **Requires deployment**: Must be installed on Git server infrastructure
4. **Shell script-based**: Not a binary that can be easily distributed

### Alternative

For similar functionality, use:

- Gitleaks (already integrated)
- Trufflehog (already integrated)
- Talisman (proposed in this spec)

---

## Implementation Plan

### Phase 1: Talisman Scanner

1. Create `src/envdrift/scanner/talisman.py`
2. Implement `TalismanScanner(ScannerBackend)`
3. Add auto-install support
4. Add unit tests
5. Add CLI option `--talisman/--no-talisman`

### Phase 2: Trivy Scanner

1. Create `src/envdrift/scanner/trivy.py`
2. Implement `TrivyScanner(ScannerBackend)`
3. Add auto-install support
4. Add unit tests
5. Add CLI option `--trivy/--no-trivy`

### Phase 3: Infisical Scanner

1. Create `src/envdrift/scanner/infisical.py`
2. Implement `InfisicalScanner(ScannerBackend)`
3. Add auto-install support
4. Add unit tests
5. Add CLI option `--infisical/--no-infisical`

### Phase 4: Integration and Documentation

1. Update `engine.py` with new scanner initialization
2. Update `guard.py` CLI with new options
3. Update `constants.json` with versions and download URLs
4. Update documentation
5. Run full test suite

---

## Download URLs

### Talisman

```text
darwin_amd64: https://github.com/thoughtworks/talisman/releases/download/v{version}/talisman_darwin_amd64
darwin_arm64: https://github.com/thoughtworks/talisman/releases/download/v{version}/talisman_darwin_arm64
linux_amd64: https://github.com/thoughtworks/talisman/releases/download/v{version}/talisman_linux_amd64
linux_arm64: https://github.com/thoughtworks/talisman/releases/download/v{version}/talisman_linux_arm64
windows_amd64: https://github.com/thoughtworks/talisman/releases/download/v{version}/talisman_windows_amd64.exe
```

### Trivy

```text
darwin_amd64: https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_macOS-64bit.tar.gz
darwin_arm64: https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_macOS-ARM64.tar.gz
linux_amd64: https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_Linux-64bit.tar.gz
linux_arm64: https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_Linux-ARM64.tar.gz
windows_amd64: https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_windows-64bit.zip
```

### Infisical

```text
darwin_amd64: https://github.com/Infisical/infisical/releases/download/infisical-cli/v{version}/infisical_{version}_darwin_amd64.tar.gz
darwin_arm64: https://github.com/Infisical/infisical/releases/download/infisical-cli/v{version}/infisical_{version}_darwin_arm64.tar.gz
linux_amd64: https://github.com/Infisical/infisical/releases/download/infisical-cli/v{version}/infisical_{version}_linux_amd64.tar.gz
linux_arm64: https://github.com/Infisical/infisical/releases/download/infisical-cli/v{version}/infisical_{version}_linux_arm64.tar.gz
windows_amd64: https://github.com/Infisical/infisical/releases/download/infisical-cli/v{version}/infisical_{version}_windows_amd64.zip
```

---

## Success Criteria

1. All three scanners (Talisman, Trivy, Infisical) pass unit tests
2. Integration tests pass with actual binaries
3. Documentation is complete and accurate
4. All existing tests continue to pass
5. Pre-commit hooks pass
6. Scanner auto-installation works on macOS, Linux, Windows
