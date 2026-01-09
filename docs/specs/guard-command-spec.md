# EnvDrift Guard Command Specification

> **Status:** Implemented (Phase 1-4 Complete + detect-secrets + git-secrets)
> **Author:** Claude
> **Created:** 2025-01-06
> **Last Updated:** 2025-01-09

---

## Implementation Status Board

### Core Phases

| Phase | Description | Status | PR |
|-------|-------------|--------|-----|
| Phase 1 | Foundation + Native Scanner | ✅ Complete | #TBD |
| Phase 2 | Gitleaks Integration | ✅ Complete | #TBD |
| Phase 3 | Trufflehog Integration | ✅ Complete | #TBD |
| Phase 4 | Scan Engine + CLI + Config | ✅ Complete | #TBD |
| Bonus | detect-secrets Scanner | ✅ Complete | #TBD |
| Bonus | git-secrets Scanner | ✅ Complete | #TBD |

### Feature Checklist

| Feature | Status | Notes |
|---------|--------|-------|
| Native scanner (zero deps) | ✅ Done | 15+ secret patterns |
| Gitleaks auto-install | ✅ Done | Binary download |
| Trufflehog auto-install | ✅ Done | Binary download |
| detect-secrets auto-install | ✅ Done | pip/uv install |
| git-secrets auto-install | ✅ Done | Homebrew/source, AWS patterns |
| JSON output | ✅ Done | `--json` flag |
| SARIF output | ✅ Done | `--sarif` flag |
| Rich terminal UI | ✅ Done | Color + tables |
| Git history scanning | ✅ Done | `--history` flag |
| Entropy detection | ✅ Done | `--entropy` flag |
| Config via envdrift.toml | ✅ Done | `[guard]` section |
| CI mode | ✅ Done | `--ci` flag |
| Custom patterns in config | ❌ TODO | `[[guard.patterns]]` |
| Baseline file (ignore known) | ❌ TODO | `.envdrift-baseline` |
| Parallel scanner execution | ✅ Done | ThreadPoolExecutor |
| CI workflow examples | ❌ TODO | GitHub/GitLab |

### Scanner Coverage

| Scanner | Findings on Test | Specialization |
|---------|------------------|----------------|
| Native | 5 | Encryption markers, basic patterns |
| Gitleaks | 3 | 150+ patterns, entropy |
| Trufflehog | 1 | Verified secrets, cloud creds |
| detect-secrets | 6 | 27+ detectors, keywords, entropy |
| git-secrets | - | AWS patterns, pre-commit hooks |
| **Combined** | **14+ unique** | Defense in depth |

---

## Table of Contents

1. [Overview](#overview)
2. [Problem Statement](#problem-statement)
3. [Goals and Non-Goals](#goals-and-non-goals)
4. [Architecture](#architecture)
5. [Implementation Phases](#implementation-phases)
6. [CLI Interface](#cli-interface)
7. [Configuration](#configuration)
8. [Test Plan](#test-plan)
9. [Success Criteria](#success-criteria)
10. [Future Considerations](#future-considerations)

---

## Overview

The `envdrift guard` command provides a vendor-neutral, defense-in-depth mechanism to
detect unencrypted secrets and exposed `.env` files. It serves as the last line of
defense when other guardrails (git hooks, CI pipelines) fail.

### Key Principles

- **Vendor Neutral:** Works in any CI system (GitHub Actions, GitLab CI, Jenkins, CircleCI, Bitbucket Pipelines, etc.)
- **Zero Required Dependencies:** Native scanner works without external tools
- **Progressive Enhancement:** Optional integration with gitleaks and trufflehog for deeper scanning
- **Auto-Installation:** External tools are automatically downloaded when needed
- **CI-First Design:** Machine-readable output, strict exit codes, no interactive prompts

---

## Problem Statement

### The Failure Scenario

1. Developer is new or lazy, never installed envdrift locally
2. Receives decrypted `.env` file via Slack/email (bypassing secure key sync)
3. No git hooks installed (no `envdrift hook` ran)
4. Commits and pushes the plaintext `.env` file
5. CI pipeline has a bug or misconfiguration, fails to catch it
6. **Result:** Plaintext secrets in git history forever

### Why Existing Solutions Fall Short

| Solution | Limitation |
|----------|------------|
| `.gitignore` | Can be bypassed with `git add -f` |
| Pre-commit hooks | Requires local installation |
| GitHub Secret Scanning | GitHub-only, pattern-limited |
| GitHub Push Rules | GitHub Team/Enterprise only |
| CodeQL | Designed for code analysis, not config files |

### The Guard Solution

A CLI command that can run **anywhere** as the final safety net:

```bash
# In any CI system
envdrift guard --ci
```

---

## Goals and Non-Goals

### Goals

1. **Detect unencrypted `.env` files** in the repository
2. **Detect common secret patterns** (API keys, tokens, passwords)
3. **Integrate gitleaks** for comprehensive pattern + entropy detection
4. **Integrate trufflehog** for verified secret detection
5. **Scan git history** for previously committed secrets
6. **Provide actionable output** with file locations and remediation steps
7. **Support CI/CD pipelines** with appropriate exit codes
8. **Auto-install** external scanner binaries when needed
9. **Be configurable** via `envdrift.toml`

### Non-Goals

1. **Secret rotation:** Guard detects, not remediates
2. **Real-time monitoring:** This is a point-in-time scan
3. **Secret management:** Use vault sync for that
4. **Replacing gitleaks/trufflehog:** We wrap them, not replace them

---

## Architecture

### Component Diagram

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│                              envdrift guard                                   │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │                            ScanEngine                                   │  │
│  │  - Orchestrates multiple scanners                                       │  │
│  │  - Aggregates and deduplicates findings                                 │  │
│  │  - Manages scanner lifecycle                                            │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                    │                                          │
│       ┌────────────────┬───────────┼───────────┬────────────────┐            │
│       ▼                ▼           ▼           ▼                ▼            │
│  ┌──────────┐   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐      │
│  │  Native  │   │ Gitleaks │  │Trufflehog│  │ detect-  │  │  Future  │      │
│  │ Scanner  │   │ Scanner  │  │ Scanner  │  │ secrets  │  │ Scanner  │      │
│  ├──────────┤   ├──────────┤  ├──────────┤  ├──────────┤  ├──────────┤      │
│  │• Encrypt │   │• 150+    │  │• Verified│  │• 27+     │  │          │      │
│  │  markers │   │  patterns│  │  secrets │  │  plugins │  │          │      │
│  │• Basic   │   │• Entropy │  │• Git     │  │• Keyword │  │          │      │
│  │  patterns│   │• Git     │  │  history │  │  detect  │  │          │      │
│  │• No deps │   │  history │  │• Cloud   │  │• High    │  │          │      │
│  │          │   │          │  │  creds   │  │  entropy │  │          │      │
│  └──────────┘   └──────────┘  └──────────┘  └──────────┘  └──────────┘      │
│       │                │           │             │               │            │
│       └────────────────┴───────────┼─────────────┴───────────────┘            │
│                                    ▼                                          │
│                         ┌─────────────────┐                                   │
│                         │  ScanResult     │                                   │
│                         │  - findings[]   │                                   │
│                         │  - exit_code    │                                   │
│                         └─────────────────┘                                   │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Module Structure

```text
src/envdrift/
├── scanner/
│   ├── __init__.py           # Public API exports
│   ├── base.py               # ScannerBackend ABC, ScanFinding, ScanResult
│   ├── native.py             # NativeScanner implementation
│   ├── gitleaks.py           # GitleaksScanner + installer
│   ├── trufflehog.py         # TrufflehogScanner + installer
│   ├── detect_secrets.py     # DetectSecretsScanner + installer (NEW)
│   ├── engine.py             # ScanEngine orchestrator
│   ├── patterns.py           # Built-in secret patterns
│   └── output.py             # Output formatters (rich, json, sarif)
├── cli_commands/
│   └── guard.py              # CLI command implementation
└── constants.json            # Scanner versions (gitleaks, trufflehog, detect-secrets)
```

### Data Models

```python
# scanner/base.py

class FindingSeverity(Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"  # Confirmed secret (pattern match + context)
    HIGH = "high"          # Very likely secret (strong pattern/entropy)
    MEDIUM = "medium"      # Possibly secret (moderate entropy)
    LOW = "low"            # Policy violation (unencrypted file)
    INFO = "info"          # Informational only

@dataclass(frozen=True)
class ScanFinding:
    """A single secret or policy violation finding."""
    file_path: Path
    line_number: int | None
    column_number: int | None
    rule_id: str                    # e.g., "aws-access-key", "unencrypted-env"
    rule_description: str           # Human-readable rule name
    description: str                # Finding-specific message
    severity: FindingSeverity
    secret_preview: str             # Redacted: "AKIA****XXXX"
    scanner: str                    # Which scanner found it
    commit_sha: str | None = None   # If found in git history
    commit_author: str | None = None
    commit_date: str | None = None
    entropy: float | None = None    # Shannon entropy if calculated
    verified: bool = False          # If secret was verified (trufflehog)

@dataclass
class ScanResult:
    """Results from a single scanner."""
    scanner_name: str
    findings: list[ScanFinding]
    files_scanned: int
    duration_ms: int
    error: str | None = None

@dataclass
class AggregatedScanResult:
    """Combined results from all scanners."""
    results: list[ScanResult]
    total_findings: int
    unique_findings: list[ScanFinding]  # Deduplicated
    scanners_used: list[str]
    total_duration_ms: int

    @property
    def exit_code(self) -> int:
        """Determine exit code based on findings."""
        severities = {f.severity for f in self.unique_findings}
        if FindingSeverity.CRITICAL in severities:
            return 1
        if FindingSeverity.HIGH in severities:
            return 2
        if FindingSeverity.MEDIUM in severities:
            return 3
        return 0

    @property
    def has_blocking_findings(self) -> bool:
        """Whether findings should block CI."""
        return self.exit_code in (1, 2)
```

---

## Implementation Phases

### Phase 1: Foundation + Native Scanner

**Duration:** Core implementation
**Dependencies:** None
**Deliverables:**

1. `scanner/base.py` - Abstract base classes and data models
2. `scanner/patterns.py` - Built-in secret patterns
3. `scanner/native.py` - Native scanner implementation
4. `scanner/output.py` - Output formatters
5. `cli_commands/guard.py` - Basic CLI command
6. Unit tests for all components

#### 1.1 Base Module (`scanner/base.py`)

```python
"""Abstract base class and data models for secret scanners."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable


class FindingSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __lt__(self, other: FindingSeverity) -> bool:
        order = [self.INFO, self.LOW, self.MEDIUM, self.HIGH, self.CRITICAL]
        return order.index(self) < order.index(other)


@dataclass(frozen=True)
class ScanFinding:
    file_path: Path
    rule_id: str
    rule_description: str
    description: str
    severity: FindingSeverity
    scanner: str
    line_number: int | None = None
    column_number: int | None = None
    secret_preview: str = ""
    commit_sha: str | None = None
    commit_author: str | None = None
    commit_date: str | None = None
    entropy: float | None = None
    verified: bool = False

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "file_path": str(self.file_path),
            "rule_id": self.rule_id,
            "rule_description": self.rule_description,
            "description": self.description,
            "severity": self.severity.value,
            "scanner": self.scanner,
            "line_number": self.line_number,
            "column_number": self.column_number,
            "secret_preview": self.secret_preview,
            "commit_sha": self.commit_sha,
            "commit_author": self.commit_author,
            "commit_date": self.commit_date,
            "entropy": self.entropy,
            "verified": self.verified,
        }


@dataclass
class ScanResult:
    scanner_name: str
    findings: list[ScanFinding] = field(default_factory=list)
    files_scanned: int = 0
    duration_ms: int = 0
    error: str | None = None


class ScannerBackend(ABC):
    """Abstract interface for secret scanners."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Scanner identifier."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description."""
        ...

    @abstractmethod
    def is_installed(self) -> bool:
        """Check if scanner is available."""
        ...

    @abstractmethod
    def scan(
        self,
        paths: list[Path],
        include_git_history: bool = False,
    ) -> ScanResult:
        """Scan paths for secrets."""
        ...

    def install(
        self,
        progress_callback: Callable[[str], None] | None = None,
    ) -> Path | None:
        """Install the scanner. Returns binary path or None if not applicable."""
        return None
```

#### 1.2 Patterns Module (`scanner/patterns.py`)

```python
"""Built-in secret detection patterns."""

from __future__ import annotations

import re
from dataclasses import dataclass
from .base import FindingSeverity


@dataclass(frozen=True)
class SecretPattern:
    """A regex pattern for detecting secrets."""
    id: str
    description: str
    pattern: re.Pattern
    severity: FindingSeverity
    keywords: tuple[str, ...] = ()  # Context keywords that increase confidence

    def __post_init__(self):
        # Compile pattern if string
        if isinstance(self.pattern, str):
            object.__setattr__(self, 'pattern', re.compile(self.pattern))


# High-confidence patterns (known secret formats)
CRITICAL_PATTERNS = [
    SecretPattern(
        id="aws-access-key-id",
        description="AWS Access Key ID",
        pattern=re.compile(r"(?:^|[^A-Z0-9])((AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16})(?:[^A-Z0-9]|$)"),
        severity=FindingSeverity.CRITICAL,
        keywords=("aws", "amazon", "access_key", "access-key"),
    ),
    SecretPattern(
        id="aws-secret-access-key",
        description="AWS Secret Access Key",
        pattern=re.compile(r"(?i)(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        severity=FindingSeverity.CRITICAL,
    ),
    SecretPattern(
        id="github-pat",
        description="GitHub Personal Access Token",
        pattern=re.compile(r"(ghp_[a-zA-Z0-9]{36})"),
        severity=FindingSeverity.CRITICAL,
    ),
    SecretPattern(
        id="github-oauth",
        description="GitHub OAuth Token",
        pattern=re.compile(r"(gho_[a-zA-Z0-9]{36})"),
        severity=FindingSeverity.CRITICAL,
    ),
    SecretPattern(
        id="github-app-token",
        description="GitHub App Token",
        pattern=re.compile(r"(ghu_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36})"),
        severity=FindingSeverity.CRITICAL,
    ),
    SecretPattern(
        id="openai-api-key",
        description="OpenAI API Key",
        pattern=re.compile(r"(sk-[a-zA-Z0-9]{48})"),
        severity=FindingSeverity.CRITICAL,
    ),
    SecretPattern(
        id="anthropic-api-key",
        description="Anthropic API Key",
        pattern=re.compile(r"(sk-ant-[a-zA-Z0-9-]{93})"),
        severity=FindingSeverity.CRITICAL,
    ),
    SecretPattern(
        id="slack-bot-token",
        description="Slack Bot Token",
        pattern=re.compile(r"(xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24})"),
        severity=FindingSeverity.CRITICAL,
    ),
    SecretPattern(
        id="slack-user-token",
        description="Slack User Token",
        pattern=re.compile(r"(xoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24})"),
        severity=FindingSeverity.CRITICAL,
    ),
    SecretPattern(
        id="stripe-secret-key",
        description="Stripe Secret Key",
        pattern=re.compile(r"(sk_live_[a-zA-Z0-9]{24,})"),
        severity=FindingSeverity.CRITICAL,
    ),
    SecretPattern(
        id="stripe-restricted-key",
        description="Stripe Restricted Key",
        pattern=re.compile(r"(rk_live_[a-zA-Z0-9]{24,})"),
        severity=FindingSeverity.CRITICAL,
    ),
    SecretPattern(
        id="google-api-key",
        description="Google API Key",
        pattern=re.compile(r"(AIza[0-9A-Za-z_-]{35})"),
        severity=FindingSeverity.CRITICAL,
    ),
    SecretPattern(
        id="twilio-api-key",
        description="Twilio API Key",
        pattern=re.compile(r"(SK[a-f0-9]{32})"),
        severity=FindingSeverity.HIGH,
        keywords=("twilio",),
    ),
    SecretPattern(
        id="sendgrid-api-key",
        description="SendGrid API Key",
        pattern=re.compile(r"(SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})"),
        severity=FindingSeverity.CRITICAL,
    ),
    SecretPattern(
        id="npm-token",
        description="NPM Access Token",
        pattern=re.compile(r"(npm_[a-zA-Z0-9]{36})"),
        severity=FindingSeverity.CRITICAL,
    ),
    SecretPattern(
        id="pypi-token",
        description="PyPI API Token",
        pattern=re.compile(r"(pypi-[a-zA-Z0-9_-]{50,})"),
        severity=FindingSeverity.CRITICAL,
    ),
    SecretPattern(
        id="private-key",
        description="Private Key",
        pattern=re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        severity=FindingSeverity.CRITICAL,
    ),
]

# Medium-confidence patterns (generic secrets)
HIGH_PATTERNS = [
    SecretPattern(
        id="generic-api-key",
        description="Generic API Key",
        pattern=re.compile(r"(?i)(?:api[_-]?key|apikey)\s*[=:]\s*['\"]?([a-zA-Z0-9_-]{20,})['\"]?"),
        severity=FindingSeverity.HIGH,
    ),
    SecretPattern(
        id="generic-secret",
        description="Generic Secret",
        pattern=re.compile(r"(?i)(?:secret|token|password|passwd|pwd)\s*[=:]\s*['\"]?([a-zA-Z0-9_!@#$%^&*()-]{8,})['\"]?"),
        severity=FindingSeverity.HIGH,
    ),
    SecretPattern(
        id="basic-auth-header",
        description="Basic Auth Header",
        pattern=re.compile(r"(?i)authorization\s*[=:]\s*['\"]?basic\s+([a-zA-Z0-9+/=]+)['\"]?"),
        severity=FindingSeverity.HIGH,
    ),
    SecretPattern(
        id="bearer-token",
        description="Bearer Token",
        pattern=re.compile(r"(?i)authorization\s*[=:]\s*['\"]?bearer\s+([a-zA-Z0-9._-]+)['\"]?"),
        severity=FindingSeverity.HIGH,
    ),
    SecretPattern(
        id="database-url",
        description="Database Connection String",
        pattern=re.compile(r"(?i)(?:postgres|mysql|mongodb|redis)://[^:]+:[^@]+@[^\s]+"),
        severity=FindingSeverity.HIGH,
    ),
]

ALL_PATTERNS = CRITICAL_PATTERNS + HIGH_PATTERNS


def redact_secret(secret: str, visible_chars: int = 4) -> str:
    """Redact a secret, showing only first/last few characters."""
    if len(secret) <= visible_chars * 2:
        return "*" * len(secret)
    return f"{secret[:visible_chars]}{'*' * (len(secret) - visible_chars * 2)}{secret[-visible_chars:]}"
```

#### 1.3 Native Scanner (`scanner/native.py`)

```python
"""Native scanner - zero dependencies, checks encryption + patterns."""

from __future__ import annotations

import fnmatch
import math
import time
from pathlib import Path

from .base import (
    FindingSeverity,
    ScanFinding,
    ScannerBackend,
    ScanResult,
)
from .patterns import ALL_PATTERNS, redact_secret


# Encryption markers for supported backends
DOTENVX_MARKERS = [
    "#/---[DOTENV_PUBLIC_KEY]",
    "DOTENV_PUBLIC_KEY",
    "encrypted:",
]

SOPS_MARKERS = [
    "sops:",
    "ENC[AES256_GCM,",
]


class NativeScanner(ScannerBackend):
    """Built-in scanner with zero external dependencies.

    Checks for:
    1. Unencrypted .env files (missing dotenvx/SOPS markers)
    2. Common secret patterns in any file
    3. High-entropy strings (optional)
    """

    def __init__(
        self,
        check_entropy: bool = False,
        entropy_threshold: float = 4.5,
        ignore_patterns: list[str] | None = None,
    ):
        self._check_entropy = check_entropy
        self._entropy_threshold = entropy_threshold
        self._ignore_patterns = ignore_patterns or [
            ".env.example",
            ".env.sample",
            ".env.template",
            "*.md",
            "*.lock",
            "node_modules/**",
            ".git/**",
            "__pycache__/**",
            ".venv/**",
            "venv/**",
        ]

    @property
    def name(self) -> str:
        return "native"

    @property
    def description(self) -> str:
        return "Built-in scanner (encryption markers + secret patterns)"

    def is_installed(self) -> bool:
        return True  # Always available

    def scan(
        self,
        paths: list[Path],
        include_git_history: bool = False,
    ) -> ScanResult:
        start_time = time.time()
        findings: list[ScanFinding] = []
        files_scanned = 0

        for path in paths:
            if path.is_file():
                files_to_scan = [path]
            else:
                files_to_scan = list(path.rglob("*"))

            for file_path in files_to_scan:
                if not file_path.is_file():
                    continue
                if self._should_ignore(file_path):
                    continue

                files_scanned += 1
                findings.extend(self._scan_file(file_path))

        duration_ms = int((time.time() - start_time) * 1000)

        return ScanResult(
            scanner_name=self.name,
            findings=findings,
            files_scanned=files_scanned,
            duration_ms=duration_ms,
        )

    def _should_ignore(self, path: Path) -> bool:
        """Check if path should be ignored."""
        path_str = str(path)
        for pattern in self._ignore_patterns:
            if fnmatch.fnmatch(path_str, pattern):
                return True
            if fnmatch.fnmatch(path.name, pattern):
                return True
        return False

    def _scan_file(self, file_path: Path) -> list[ScanFinding]:
        """Scan a single file for secrets."""
        findings: list[ScanFinding] = []

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, UnicodeDecodeError):
            return findings

        # Check 1: Is this an unencrypted .env file?
        if self._is_env_file(file_path):
            if not self._is_encrypted(content):
                findings.append(ScanFinding(
                    file_path=file_path,
                    rule_id="unencrypted-env-file",
                    rule_description="Unencrypted .env File",
                    description=f"File '{file_path.name}' is not encrypted. "
                                f"Use 'envdrift encrypt' before committing.",
                    severity=FindingSeverity.HIGH,
                    scanner=self.name,
                ))

        # Check 2: Scan for secret patterns
        lines = content.splitlines()
        for line_num, line in enumerate(lines, start=1):
            for pattern in ALL_PATTERNS:
                match = pattern.pattern.search(line)
                if match:
                    # Extract the secret (first group or full match)
                    secret = match.group(1) if match.groups() else match.group(0)
                    findings.append(ScanFinding(
                        file_path=file_path,
                        line_number=line_num,
                        rule_id=pattern.id,
                        rule_description=pattern.description,
                        description=f"Potential {pattern.description} detected",
                        severity=pattern.severity,
                        secret_preview=redact_secret(secret),
                        scanner=self.name,
                    ))

        # Check 3: High-entropy strings (optional)
        if self._check_entropy:
            for line_num, line in enumerate(lines, start=1):
                entropy_findings = self._check_line_entropy(file_path, line, line_num)
                findings.extend(entropy_findings)

        return findings

    def _is_env_file(self, path: Path) -> bool:
        """Check if file is a .env file."""
        name = path.name
        return name == ".env" or name.startswith(".env.")

    def _is_encrypted(self, content: str) -> bool:
        """Check if content has encryption markers."""
        # Check dotenvx markers
        for marker in DOTENVX_MARKERS:
            if marker in content:
                return True

        # Check SOPS markers
        for marker in SOPS_MARKERS:
            if marker in content:
                return True

        return False

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0

        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1

        entropy = 0.0
        length = len(text)
        for count in freq.values():
            prob = count / length
            entropy -= prob * math.log2(prob)

        return entropy

    def _check_line_entropy(
        self,
        file_path: Path,
        line: str,
        line_num: int,
    ) -> list[ScanFinding]:
        """Check for high-entropy strings in a line."""
        findings = []

        # Look for assignment patterns: KEY=VALUE or KEY: VALUE
        import re
        assignment_pattern = re.compile(r'[A-Z_][A-Z0-9_]*\s*[=:]\s*["\']?([^"\'=\s]{16,})["\']?')

        for match in assignment_pattern.finditer(line):
            value = match.group(1)
            entropy = self._calculate_entropy(value)

            if entropy >= self._entropy_threshold:
                findings.append(ScanFinding(
                    file_path=file_path,
                    line_number=line_num,
                    rule_id="high-entropy-string",
                    rule_description="High Entropy String",
                    description=f"High-entropy string detected (entropy: {entropy:.2f})",
                    severity=FindingSeverity.MEDIUM,
                    secret_preview=redact_secret(value),
                    entropy=entropy,
                    scanner=self.name,
                ))

        return findings
```

#### 1.4 Output Formatters (`scanner/output.py`)

```python
"""Output formatters for scan results."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TextIO

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .base import AggregatedScanResult, FindingSeverity, ScanFinding


SEVERITY_COLORS = {
    FindingSeverity.CRITICAL: "red bold",
    FindingSeverity.HIGH: "red",
    FindingSeverity.MEDIUM: "yellow",
    FindingSeverity.LOW: "blue",
    FindingSeverity.INFO: "dim",
}

SEVERITY_ICONS = {
    FindingSeverity.CRITICAL: "🚨",
    FindingSeverity.HIGH: "❌",
    FindingSeverity.MEDIUM: "⚠️",
    FindingSeverity.LOW: "ℹ️",
    FindingSeverity.INFO: "💡",
}


def format_rich(result: AggregatedScanResult, console: Console) -> None:
    """Format results using Rich for terminal output."""

    if not result.unique_findings:
        console.print(Panel(
            "[green]✅ No secrets or policy violations detected[/green]",
            title="envdrift guard",
            border_style="green",
        ))
        return

    # Summary
    severity_counts = {}
    for finding in result.unique_findings:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

    summary_parts = []
    for severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH,
                     FindingSeverity.MEDIUM, FindingSeverity.LOW]:
        count = severity_counts.get(severity, 0)
        if count > 0:
            color = SEVERITY_COLORS[severity]
            summary_parts.append(f"[{color}]{count} {severity.value}[/{color}]")

    console.print(Panel(
        " | ".join(summary_parts) if summary_parts else "No findings",
        title="envdrift guard - Summary",
        border_style="red" if result.has_blocking_findings else "yellow",
    ))

    # Findings table
    table = Table(show_header=True, header_style="bold")
    table.add_column("Severity", width=10)
    table.add_column("File", style="cyan")
    table.add_column("Rule", style="magenta")
    table.add_column("Description")
    table.add_column("Preview", style="dim")

    for finding in sorted(result.unique_findings,
                          key=lambda f: f.severity, reverse=True):
        severity_text = Text(finding.severity.value.upper())
        severity_text.stylize(SEVERITY_COLORS[finding.severity])

        location = str(finding.file_path)
        if finding.line_number:
            location += f":{finding.line_number}"

        table.add_row(
            f"{SEVERITY_ICONS[finding.severity]} {finding.severity.value}",
            location,
            finding.rule_id,
            finding.description,
            finding.secret_preview or "-",
        )

    console.print(table)

    # Scanners used
    console.print(f"\n[dim]Scanners: {', '.join(result.scanners_used)} | "
                  f"Duration: {result.total_duration_ms}ms | "
                  f"Files: {sum(r.files_scanned for r in result.results)}[/dim]")


def format_json(result: AggregatedScanResult) -> str:
    """Format results as JSON."""
    return json.dumps({
        "findings": [f.to_dict() for f in result.unique_findings],
        "summary": {
            "total": result.total_findings,
            "unique": len(result.unique_findings),
            "by_severity": {
                s.value: sum(1 for f in result.unique_findings if f.severity == s)
                for s in FindingSeverity
            },
        },
        "scanners": result.scanners_used,
        "duration_ms": result.total_duration_ms,
        "exit_code": result.exit_code,
    }, indent=2)


def format_sarif(result: AggregatedScanResult) -> str:
    """Format results as SARIF for GitHub/GitLab integration."""
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "envdrift guard",
                    "informationUri": "https://github.com/your-org/envdrift",
                    "rules": [],
                }
            },
            "results": [],
        }]
    }

    rules_seen = set()
    for finding in result.unique_findings:
        if finding.rule_id not in rules_seen:
            sarif["runs"][0]["tool"]["driver"]["rules"].append({
                "id": finding.rule_id,
                "name": finding.rule_description,
                "shortDescription": {"text": finding.rule_description},
            })
            rules_seen.add(finding.rule_id)

        sarif["runs"][0]["results"].append({
            "ruleId": finding.rule_id,
            "level": _severity_to_sarif_level(finding.severity),
            "message": {"text": finding.description},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": str(finding.file_path)},
                    "region": {
                        "startLine": finding.line_number or 1,
                    },
                }
            }],
        })

    return json.dumps(sarif, indent=2)


def _severity_to_sarif_level(severity: FindingSeverity) -> str:
    """Map severity to SARIF level."""
    mapping = {
        FindingSeverity.CRITICAL: "error",
        FindingSeverity.HIGH: "error",
        FindingSeverity.MEDIUM: "warning",
        FindingSeverity.LOW: "note",
        FindingSeverity.INFO: "note",
    }
    return mapping[severity]
```

---

### Phase 2: Gitleaks Integration

**Duration:** After Phase 1
**Dependencies:** Phase 1 complete
**Deliverables:**

1. `scanner/gitleaks.py` - Gitleaks wrapper with auto-install
2. Update `constants.json` with gitleaks version
3. Integration tests

#### 2.1 Gitleaks Scanner (`scanner/gitleaks.py`)

```python
"""Gitleaks scanner integration with auto-installation."""

from __future__ import annotations

import json
import platform
import shutil
import stat
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Callable

from .base import (
    FindingSeverity,
    ScanFinding,
    ScannerBackend,
    ScanResult,
)


# Version pinned for reproducibility
GITLEAKS_VERSION = "8.18.4"

DOWNLOAD_URLS = {
    ("Darwin", "arm64"): f"https://github.com/gitleaks/gitleaks/releases/download/v{GITLEAKS_VERSION}/gitleaks_{GITLEAKS_VERSION}_darwin_arm64.tar.gz",
    ("Darwin", "x86_64"): f"https://github.com/gitleaks/gitleaks/releases/download/v{GITLEAKS_VERSION}/gitleaks_{GITLEAKS_VERSION}_darwin_amd64.tar.gz",
    ("Linux", "x86_64"): f"https://github.com/gitleaks/gitleaks/releases/download/v{GITLEAKS_VERSION}/gitleaks_{GITLEAKS_VERSION}_linux_amd64.tar.gz",
    ("Linux", "aarch64"): f"https://github.com/gitleaks/gitleaks/releases/download/v{GITLEAKS_VERSION}/gitleaks_{GITLEAKS_VERSION}_linux_arm64.tar.gz",
    ("Windows", "AMD64"): f"https://github.com/gitleaks/gitleaks/releases/download/v{GITLEAKS_VERSION}/gitleaks_{GITLEAKS_VERSION}_windows_amd64.zip",
}

SEVERITY_MAP = {
    "CRITICAL": FindingSeverity.CRITICAL,
    "HIGH": FindingSeverity.HIGH,
    "MEDIUM": FindingSeverity.MEDIUM,
    "LOW": FindingSeverity.LOW,
    "INFO": FindingSeverity.INFO,
}


class GitleaksScanner(ScannerBackend):
    """Gitleaks scanner with automatic binary installation."""

    def __init__(
        self,
        auto_install: bool = True,
        version: str = GITLEAKS_VERSION,
    ):
        self._auto_install = auto_install
        self._version = version
        self._binary_path: Path | None = None

    @property
    def name(self) -> str:
        return "gitleaks"

    @property
    def description(self) -> str:
        return "Gitleaks secret scanner (patterns + entropy)"

    def is_installed(self) -> bool:
        try:
            self._find_binary()
            return True
        except FileNotFoundError:
            return False

    def _find_binary(self) -> Path:
        """Find gitleaks binary, auto-installing if enabled."""
        if self._binary_path and self._binary_path.exists():
            return self._binary_path

        # Check common locations
        binary_name = "gitleaks.exe" if platform.system() == "Windows" else "gitleaks"

        # Check system PATH
        system_path = shutil.which("gitleaks")
        if system_path:
            self._binary_path = Path(system_path)
            return self._binary_path

        # Check .venv/bin
        venv_path = Path.cwd() / ".venv" / "bin" / binary_name
        if venv_path.exists():
            self._binary_path = venv_path
            return self._binary_path

        # Auto-install
        if self._auto_install:
            return self.install()

        raise FileNotFoundError("gitleaks not found")

    def install(
        self,
        progress_callback: Callable[[str], None] | None = None,
    ) -> Path:
        """Download and install gitleaks binary."""
        progress = progress_callback or (lambda x: None)

        system = platform.system()
        machine = platform.machine()

        # Normalize architecture
        if machine in ("AMD64", "amd64"):
            machine = "AMD64" if system == "Windows" else "x86_64"
        elif machine in ("arm64", "aarch64"):
            machine = "arm64" if system == "Darwin" else "aarch64"

        key = (system, machine)
        if key not in DOWNLOAD_URLS:
            raise RuntimeError(f"Unsupported platform: {system} {machine}")

        url = DOWNLOAD_URLS[key]
        progress(f"Downloading gitleaks v{self._version}...")

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            archive_name = url.split("/")[-1]
            archive_path = tmp_path / archive_name

            # Download
            urllib.request.urlretrieve(url, archive_path)

            progress("Extracting...")

            # Extract
            if archive_name.endswith(".tar.gz"):
                import tarfile
                with tarfile.open(archive_path, "r:gz") as tar:
                    tar.extractall(tmp_path)
            elif archive_name.endswith(".zip"):
                import zipfile
                with zipfile.ZipFile(archive_path, "r") as zip_ref:
                    zip_ref.extractall(tmp_path)

            # Find binary
            binary_name = "gitleaks.exe" if system == "Windows" else "gitleaks"
            extracted = None
            for f in tmp_path.rglob(binary_name):
                if f.is_file():
                    extracted = f
                    break

            if not extracted:
                raise RuntimeError("Binary not found in archive")

            # Install to .venv/bin or ~/.local/bin
            target_dir = Path.cwd() / ".venv" / "bin"
            if not target_dir.exists():
                target_dir = Path.home() / ".local" / "bin"
            target_dir.mkdir(parents=True, exist_ok=True)

            target_path = target_dir / binary_name
            shutil.copy2(extracted, target_path)

            if system != "Windows":
                target_path.chmod(target_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

            progress(f"Installed to {target_path}")
            self._binary_path = target_path
            return target_path

    def scan(
        self,
        paths: list[Path],
        include_git_history: bool = False,
    ) -> ScanResult:
        start_time = time.time()
        binary = self._find_binary()

        all_findings: list[ScanFinding] = []
        files_scanned = 0

        for path in paths:
            args = [
                str(binary),
                "detect",
                "--source", str(path),
                "--report-format", "json",
                "--exit-code", "0",  # Don't fail on findings
            ]

            if not include_git_history:
                args.append("--no-git")

            try:
                result = subprocess.run(
                    args,
                    capture_output=True,
                    text=True,
                    timeout=300,
                )

                if result.stdout:
                    findings_data = json.loads(result.stdout)
                    if findings_data:
                        for item in findings_data:
                            all_findings.append(self._parse_finding(item))

            except subprocess.TimeoutExpired:
                return ScanResult(
                    scanner_name=self.name,
                    error="Scan timed out",
                    duration_ms=int((time.time() - start_time) * 1000),
                )
            except json.JSONDecodeError:
                pass  # No findings or invalid output

        return ScanResult(
            scanner_name=self.name,
            findings=all_findings,
            files_scanned=files_scanned,
            duration_ms=int((time.time() - start_time) * 1000),
        )

    def _parse_finding(self, item: dict) -> ScanFinding:
        """Parse a gitleaks finding into our format."""
        return ScanFinding(
            file_path=Path(item.get("File", "")),
            line_number=item.get("StartLine"),
            rule_id=item.get("RuleID", "unknown"),
            rule_description=item.get("Description", ""),
            description=item.get("Description", ""),
            severity=SEVERITY_MAP.get(
                item.get("Severity", "HIGH").upper(),
                FindingSeverity.HIGH
            ),
            secret_preview=item.get("Match", "")[:20] + "..." if item.get("Match") else "",
            commit_sha=item.get("Commit"),
            commit_author=item.get("Author"),
            commit_date=item.get("Date"),
            entropy=item.get("Entropy"),
            scanner=self.name,
        )
```

---

### Phase 3: Trufflehog Integration

**Duration:** After Phase 2
**Dependencies:** Phase 2 complete
**Deliverables:**

1. `scanner/trufflehog.py` - Trufflehog wrapper with auto-install
2. Update `constants.json` with trufflehog version
3. Integration tests

#### 3.1 Trufflehog Scanner (`scanner/trufflehog.py`)

```python
"""Trufflehog scanner integration with auto-installation."""

from __future__ import annotations

import json
import platform
import shutil
import stat
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Callable

from .base import (
    FindingSeverity,
    ScanFinding,
    ScannerBackend,
    ScanResult,
)


TRUFFLEHOG_VERSION = "3.82.13"

DOWNLOAD_URLS = {
    ("Darwin", "arm64"): f"https://github.com/trufflesecurity/trufflehog/releases/download/v{TRUFFLEHOG_VERSION}/trufflehog_{TRUFFLEHOG_VERSION}_darwin_arm64.tar.gz",
    ("Darwin", "x86_64"): f"https://github.com/trufflesecurity/trufflehog/releases/download/v{TRUFFLEHOG_VERSION}/trufflehog_{TRUFFLEHOG_VERSION}_darwin_amd64.tar.gz",
    ("Linux", "x86_64"): f"https://github.com/trufflesecurity/trufflehog/releases/download/v{TRUFFLEHOG_VERSION}/trufflehog_{TRUFFLEHOG_VERSION}_linux_amd64.tar.gz",
    ("Linux", "aarch64"): f"https://github.com/trufflesecurity/trufflehog/releases/download/v{TRUFFLEHOG_VERSION}/trufflehog_{TRUFFLEHOG_VERSION}_linux_arm64.tar.gz",
    ("Windows", "AMD64"): f"https://github.com/trufflesecurity/trufflehog/releases/download/v{TRUFFLEHOG_VERSION}/trufflehog_{TRUFFLEHOG_VERSION}_windows_amd64.tar.gz",
}


class TrufflehogScanner(ScannerBackend):
    """Trufflehog scanner with automatic binary installation.

    Trufflehog specializes in:
    - Verified secret detection (actually tests if secrets are valid)
    - Cloud credential detection (AWS, GCP, Azure)
    - Git history scanning
    """

    def __init__(
        self,
        auto_install: bool = True,
        version: str = TRUFFLEHOG_VERSION,
        verify_secrets: bool = True,
    ):
        self._auto_install = auto_install
        self._version = version
        self._verify_secrets = verify_secrets
        self._binary_path: Path | None = None

    @property
    def name(self) -> str:
        return "trufflehog"

    @property
    def description(self) -> str:
        return "Trufflehog scanner (verified secrets + cloud creds)"

    def is_installed(self) -> bool:
        try:
            self._find_binary()
            return True
        except FileNotFoundError:
            return False

    def _find_binary(self) -> Path:
        """Find trufflehog binary, auto-installing if enabled."""
        if self._binary_path and self._binary_path.exists():
            return self._binary_path

        binary_name = "trufflehog.exe" if platform.system() == "Windows" else "trufflehog"

        # Check system PATH
        system_path = shutil.which("trufflehog")
        if system_path:
            self._binary_path = Path(system_path)
            return self._binary_path

        # Check .venv/bin
        venv_path = Path.cwd() / ".venv" / "bin" / binary_name
        if venv_path.exists():
            self._binary_path = venv_path
            return self._binary_path

        # Auto-install
        if self._auto_install:
            return self.install()

        raise FileNotFoundError("trufflehog not found")

    def install(
        self,
        progress_callback: Callable[[str], None] | None = None,
    ) -> Path:
        """Download and install trufflehog binary."""
        # Similar implementation to GitleaksScanner.install()
        # ... (same pattern as gitleaks)
        pass

    def scan(
        self,
        paths: list[Path],
        include_git_history: bool = False,
    ) -> ScanResult:
        start_time = time.time()
        binary = self._find_binary()

        all_findings: list[ScanFinding] = []

        for path in paths:
            if include_git_history and (path / ".git").exists():
                # Git mode - scans history
                args = [str(binary), "git", str(path), "--json"]
            else:
                # Filesystem mode - current files only
                args = [str(binary), "filesystem", str(path), "--json"]

            if not self._verify_secrets:
                args.append("--no-verification")

            try:
                result = subprocess.run(
                    args,
                    capture_output=True,
                    text=True,
                    timeout=600,  # Longer timeout for verification
                )

                # Trufflehog outputs one JSON object per line
                for line in result.stdout.strip().split("\n"):
                    if line:
                        try:
                            item = json.loads(line)
                            all_findings.append(self._parse_finding(item))
                        except json.JSONDecodeError:
                            continue

            except subprocess.TimeoutExpired:
                return ScanResult(
                    scanner_name=self.name,
                    error="Scan timed out",
                    duration_ms=int((time.time() - start_time) * 1000),
                )

        return ScanResult(
            scanner_name=self.name,
            findings=all_findings,
            duration_ms=int((time.time() - start_time) * 1000),
        )

    def _parse_finding(self, item: dict) -> ScanFinding:
        """Parse a trufflehog finding into our format."""
        source_metadata = item.get("SourceMetadata", {}).get("Data", {})
        filesystem_data = source_metadata.get("Filesystem", {})
        git_data = source_metadata.get("Git", {})

        # Determine file path and line
        file_path = filesystem_data.get("file") or git_data.get("file", "")
        line_number = filesystem_data.get("line") or git_data.get("line")

        # Check if verified
        verified = item.get("Verified", False)

        return ScanFinding(
            file_path=Path(file_path),
            line_number=line_number,
            rule_id=item.get("DetectorName", "unknown"),
            rule_description=item.get("DetectorType", ""),
            description=f"{'Verified ' if verified else ''}{item.get('DetectorType', 'Secret')} detected",
            severity=FindingSeverity.CRITICAL if verified else FindingSeverity.HIGH,
            secret_preview=item.get("Redacted", ""),
            commit_sha=git_data.get("commit"),
            commit_author=git_data.get("email"),
            commit_date=git_data.get("timestamp"),
            verified=verified,
            scanner=self.name,
        )
```

---

### Phase 4: Scan Engine + CLI

**Duration:** After Phase 3
**Dependencies:** Phases 1-3 complete
**Deliverables:**

1. `scanner/engine.py` - Orchestrator
2. `cli_commands/guard.py` - CLI command
3. Configuration support in `envdrift.toml`
4. End-to-end tests

#### 4.1 Scan Engine (`scanner/engine.py`)

```python
"""Scan engine - orchestrates multiple scanners."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from .base import (
    AggregatedScanResult,
    FindingSeverity,
    ScanFinding,
    ScannerBackend,
    ScanResult,
)
from .native import NativeScanner
from .gitleaks import GitleaksScanner
from .trufflehog import TrufflehogScanner


@dataclass
class GuardConfig:
    """Configuration for the guard command."""
    use_native: bool = True
    use_gitleaks: bool = True
    use_trufflehog: bool = False
    auto_install: bool = True
    include_git_history: bool = False
    check_entropy: bool = False
    entropy_threshold: float = 4.5
    ignore_paths: list[str] = field(default_factory=list)
    fail_on_severity: FindingSeverity = FindingSeverity.HIGH

    @classmethod
    def from_toml(cls, config: dict) -> GuardConfig:
        """Create config from envdrift.toml [guard] section."""
        guard_config = config.get("guard", {})

        scanners = guard_config.get("scanners", ["native", "gitleaks"])

        return cls(
            use_native="native" in scanners,
            use_gitleaks="gitleaks" in scanners,
            use_trufflehog="trufflehog" in scanners,
            auto_install=guard_config.get("auto_install", True),
            include_git_history=guard_config.get("include_history", False),
            check_entropy=guard_config.get("check_entropy", False),
            entropy_threshold=guard_config.get("entropy_threshold", 4.5),
            ignore_paths=guard_config.get("ignore_paths", []),
            fail_on_severity=FindingSeverity(
                guard_config.get("fail_on_severity", "high")
            ),
        )


class ScanEngine:
    """Orchestrates multiple secret scanners."""

    def __init__(self, config: GuardConfig):
        self.config = config
        self.scanners: list[ScannerBackend] = []

        # Initialize scanners based on config
        if config.use_native:
            self.scanners.append(NativeScanner(
                check_entropy=config.check_entropy,
                entropy_threshold=config.entropy_threshold,
                ignore_patterns=config.ignore_paths,
            ))

        if config.use_gitleaks:
            scanner = GitleaksScanner(auto_install=config.auto_install)
            if scanner.is_installed() or config.auto_install:
                self.scanners.append(scanner)

        if config.use_trufflehog:
            scanner = TrufflehogScanner(auto_install=config.auto_install)
            if scanner.is_installed() or config.auto_install:
                self.scanners.append(scanner)

    def scan(self, paths: list[Path]) -> AggregatedScanResult:
        """Run all scanners and aggregate results."""
        start_time = time.time()
        results: list[ScanResult] = []

        for scanner in self.scanners:
            result = scanner.scan(
                paths=paths,
                include_git_history=self.config.include_git_history,
            )
            results.append(result)

        # Aggregate findings
        all_findings = []
        for result in results:
            all_findings.extend(result.findings)

        # Deduplicate (same file + line + rule from different scanners)
        unique_findings = self._deduplicate(all_findings)

        return AggregatedScanResult(
            results=results,
            total_findings=len(all_findings),
            unique_findings=unique_findings,
            scanners_used=[s.name for s in self.scanners],
            total_duration_ms=int((time.time() - start_time) * 1000),
        )

    def _deduplicate(self, findings: list[ScanFinding]) -> list[ScanFinding]:
        """Remove duplicate findings (same location, keep highest severity)."""
        seen: dict[tuple, ScanFinding] = {}

        for finding in findings:
            key = (finding.file_path, finding.line_number, finding.rule_id)

            if key not in seen:
                seen[key] = finding
            elif finding.severity > seen[key].severity:
                # Keep higher severity
                seen[key] = finding
            elif finding.verified and not seen[key].verified:
                # Prefer verified findings
                seen[key] = finding

        return sorted(seen.values(), key=lambda f: f.severity, reverse=True)
```

#### 4.2 CLI Command (`cli_commands/guard.py`)

```python
"""Guard command - scan for secrets and policy violations."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from ..config import load_config
from ..scanner.base import FindingSeverity
from ..scanner.engine import GuardConfig, ScanEngine
from ..scanner.output import format_json, format_rich, format_sarif


app = typer.Typer()
console = Console()


@app.command()
def guard(
    paths: Annotated[
        list[Path],
        typer.Argument(
            help="Paths to scan (default: current directory)",
            exists=True,
        ),
    ] = None,
    # Scanner selection
    gitleaks: Annotated[
        bool,
        typer.Option("--gitleaks/--no-gitleaks", help="Use gitleaks scanner"),
    ] = True,
    trufflehog: Annotated[
        bool,
        typer.Option("--trufflehog/--no-trufflehog", help="Use trufflehog scanner"),
    ] = False,
    native_only: Annotated[
        bool,
        typer.Option("--native-only", help="Only use native scanner (no external tools)"),
    ] = False,
    # Scan options
    history: Annotated[
        bool,
        typer.Option("--history", "-H", help="Scan git history"),
    ] = False,
    entropy: Annotated[
        bool,
        typer.Option("--entropy", "-e", help="Enable entropy-based detection"),
    ] = False,
    # Installation
    auto_install: Annotated[
        bool,
        typer.Option("--auto-install/--no-auto-install", help="Auto-install missing scanners"),
    ] = True,
    # Output options
    json_output: Annotated[
        bool,
        typer.Option("--json", "-j", help="Output as JSON"),
    ] = False,
    sarif: Annotated[
        bool,
        typer.Option("--sarif", help="Output as SARIF (for GitHub/GitLab)"),
    ] = False,
    ci: Annotated[
        bool,
        typer.Option("--ci", help="CI mode: strict exit codes, no colors"),
    ] = False,
    # Severity threshold
    fail_on: Annotated[
        str,
        typer.Option("--fail-on", help="Minimum severity to fail on (critical|high|medium|low)"),
    ] = "high",
) -> None:
    """Scan for unencrypted secrets and policy violations.

    This command provides defense-in-depth by detecting:

    - Unencrypted .env files (missing dotenvx/SOPS markers)
    - Common secret patterns (API keys, tokens, passwords)
    - High-entropy strings (potential secrets)
    - Previously committed secrets (in git history)

    Exit codes:

    - 0: No blocking findings
    - 1: Critical severity findings
    - 2: High severity findings
    - 3: Medium severity findings

    Examples:

        envdrift guard                    # Basic scan
        envdrift guard --gitleaks         # With gitleaks
        envdrift guard --history          # Include git history
        envdrift guard --ci --json        # CI mode with JSON output
    """
    # Default to current directory
    if not paths:
        paths = [Path.cwd()]

    # Load config from envdrift.toml if present
    try:
        toml_config = load_config()
        config = GuardConfig.from_toml(toml_config)
    except FileNotFoundError:
        config = GuardConfig()

    # Override with CLI options
    if native_only:
        config.use_gitleaks = False
        config.use_trufflehog = False
    else:
        config.use_gitleaks = gitleaks
        config.use_trufflehog = trufflehog

    config.auto_install = auto_install
    config.include_git_history = history
    config.check_entropy = entropy
    config.fail_on_severity = FindingSeverity(fail_on)

    # Suppress colors in CI mode
    if ci:
        console._force_terminal = False

    # Run scan
    engine = ScanEngine(config)
    result = engine.scan(paths)

    # Output results
    if sarif:
        print(format_sarif(result))
    elif json_output:
        print(format_json(result))
    else:
        format_rich(result, console)

    # Exit with appropriate code
    exit_code = result.exit_code

    # In CI mode, only fail if severity >= fail_on threshold
    if ci:
        threshold_severities = {
            "critical": [FindingSeverity.CRITICAL],
            "high": [FindingSeverity.CRITICAL, FindingSeverity.HIGH],
            "medium": [FindingSeverity.CRITICAL, FindingSeverity.HIGH, FindingSeverity.MEDIUM],
            "low": [FindingSeverity.CRITICAL, FindingSeverity.HIGH, FindingSeverity.MEDIUM, FindingSeverity.LOW],
        }

        blocking_severities = threshold_severities.get(fail_on, threshold_severities["high"])
        has_blocking = any(f.severity in blocking_severities for f in result.unique_findings)

        if not has_blocking:
            exit_code = 0

    raise typer.Exit(exit_code)
```

---

## CLI Interface

### Command Syntax

```bash
envdrift guard [OPTIONS] [PATHS]...
```

### Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--gitleaks/--no-gitleaks` | | `--gitleaks` | Use gitleaks scanner |
| `--trufflehog/--no-trufflehog` | | `--no-trufflehog` | Use trufflehog scanner |
| `--native-only` | | `false` | Only use native scanner |
| `--history` | `-H` | `false` | Scan git history |
| `--entropy` | `-e` | `false` | Enable entropy detection |
| `--auto-install/--no-auto-install` | | `--auto-install` | Auto-install missing scanners |
| `--json` | `-j` | `false` | JSON output |
| `--sarif` | | `false` | SARIF output |
| `--ci` | | `false` | CI mode |
| `--fail-on` | | `high` | Minimum severity to fail |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No blocking findings |
| 1 | Critical severity findings detected |
| 2 | High severity findings detected |
| 3 | Medium severity findings detected |

### Usage Examples

```bash
# Basic scan (native + gitleaks)
envdrift guard

# Native only (no external dependencies)
envdrift guard --native-only

# Full scan with all tools
envdrift guard --gitleaks --trufflehog --history --entropy

# CI pipeline
envdrift guard --ci --fail-on high

# JSON output for automation
envdrift guard --json > findings.json

# SARIF for GitHub Code Scanning
envdrift guard --sarif > results.sarif

# Specific directories
envdrift guard ./apps ./services --no-gitleaks
```

---

## Configuration

### `envdrift.toml` Schema

```toml
[guard]
# Which scanners to enable
# Options: "native", "gitleaks", "trufflehog"
scanners = ["native", "gitleaks"]

# Auto-install missing scanner binaries
auto_install = true

# Scan git history by default
include_history = false

# Enable entropy-based detection
check_entropy = false
entropy_threshold = 4.5

# Minimum severity to cause non-zero exit
# Options: "critical", "high", "medium", "low"
fail_on_severity = "high"

# Enable trufflehog secret verification (checks if secrets are valid)
verify_secrets = false

# Paths to ignore (glob patterns)
ignore_paths = [
    ".env.example",
    ".env.sample",
    ".env.template",
    "tests/fixtures/**",
    "docs/**",
]

# Custom secret patterns
[[guard.patterns]]
id = "internal-api-key"
description = "Internal API Key"
pattern = "MYCOMPANY_[A-Z0-9]{32}"
severity = "critical"

[[guard.patterns]]
id = "internal-token"
description = "Internal Service Token"
pattern = "svc_[a-z0-9]{24}"
severity = "high"
```

---

## Test Plan

### Phase 1 Tests: Foundation + Native Scanner

#### Unit Tests

```python
# tests/scanner/test_base.py

class TestFindingSeverity:
    def test_severity_ordering(self):
        assert FindingSeverity.CRITICAL > FindingSeverity.HIGH
        assert FindingSeverity.HIGH > FindingSeverity.MEDIUM
        assert FindingSeverity.MEDIUM > FindingSeverity.LOW
        assert FindingSeverity.LOW > FindingSeverity.INFO

class TestScanFinding:
    def test_to_dict_serialization(self):
        finding = ScanFinding(
            file_path=Path(".env"),
            rule_id="test-rule",
            rule_description="Test Rule",
            description="Test finding",
            severity=FindingSeverity.HIGH,
            scanner="native",
        )
        data = finding.to_dict()
        assert data["rule_id"] == "test-rule"
        assert data["severity"] == "high"

class TestAggregatedScanResult:
    def test_exit_code_critical(self):
        result = AggregatedScanResult(
            results=[],
            total_findings=1,
            unique_findings=[
                ScanFinding(..., severity=FindingSeverity.CRITICAL, ...)
            ],
            scanners_used=["native"],
            total_duration_ms=100,
        )
        assert result.exit_code == 1

    def test_exit_code_no_findings(self):
        result = AggregatedScanResult(
            results=[],
            total_findings=0,
            unique_findings=[],
            scanners_used=["native"],
            total_duration_ms=100,
        )
        assert result.exit_code == 0
```

```python
# tests/scanner/test_patterns.py

class TestSecretPatterns:
    @pytest.mark.parametrize("secret,pattern_id", [
        ("AKIAIOSFODNN7EXAMPLE", "aws-access-key-id"),
        ("ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "github-pat"),
        ("sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "openai-api-key"),
        ("xoxb-000000000000-000000000000-TESTTOKEN000000000000", "slack-bot-token"),
        ("sk_live_TESTKEY00000000000000000", "stripe-secret-key"),
    ])
    def test_critical_patterns_match(self, secret, pattern_id):
        pattern = next(p for p in CRITICAL_PATTERNS if p.id == pattern_id)
        assert pattern.pattern.search(secret)

    @pytest.mark.parametrize("non_secret", [
        "hello_world",
        "my_variable_name",
        "SOME_CONFIG_VALUE",
        "12345",
    ])
    def test_no_false_positives(self, non_secret):
        for pattern in ALL_PATTERNS:
            assert not pattern.pattern.fullmatch(non_secret)

class TestRedactSecret:
    def test_redact_long_secret(self):
        assert redact_secret("AKIAIOSFODNN7EXAMPLE") == "AKIA************MPLE"

    def test_redact_short_secret(self):
        assert redact_secret("short") == "*****"
```

```python
# tests/scanner/test_native.py

class TestNativeScanner:
    @pytest.fixture
    def scanner(self):
        return NativeScanner()

    @pytest.fixture
    def temp_env_file(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("DATABASE_URL=postgres://user:pass@localhost/db\n")
        return env_file

    def test_detects_unencrypted_env_file(self, scanner, temp_env_file):
        result = scanner.scan([temp_env_file.parent])
        assert any(f.rule_id == "unencrypted-env-file" for f in result.findings)

    def test_ignores_encrypted_dotenvx_file(self, scanner, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text('''#/---[DOTENV_PUBLIC_KEY]---/
DOTENV_PUBLIC_KEY="abc123"
DATABASE_URL="encrypted:xyz789"
''')
        result = scanner.scan([tmp_path])
        assert not any(f.rule_id == "unencrypted-env-file" for f in result.findings)

    def test_ignores_encrypted_sops_file(self, scanner, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text('''DATABASE_URL=ENC[AES256_GCM,data:xyz789]
sops:
    version: 3.7.0
''')
        result = scanner.scan([tmp_path])
        assert not any(f.rule_id == "unencrypted-env-file" for f in result.findings)

    def test_detects_aws_key(self, scanner, tmp_path):
        config_file = tmp_path / "config.py"
        config_file.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        result = scanner.scan([tmp_path])
        assert any(f.rule_id == "aws-access-key-id" for f in result.findings)

    def test_ignores_env_example(self, scanner, tmp_path):
        env_example = tmp_path / ".env.example"
        env_example.write_text("DATABASE_URL=\n")
        result = scanner.scan([tmp_path])
        assert len(result.findings) == 0

    def test_respects_ignore_patterns(self, tmp_path):
        scanner = NativeScanner(ignore_patterns=["*.test"])
        test_file = tmp_path / "secrets.test"
        test_file.write_text('API_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        result = scanner.scan([tmp_path])
        assert len(result.findings) == 0

class TestEntropyDetection:
    @pytest.fixture
    def scanner(self):
        return NativeScanner(check_entropy=True, entropy_threshold=4.0)

    def test_detects_high_entropy_string(self, scanner, tmp_path):
        config = tmp_path / "config.py"
        config.write_text('SECRET = "aB3$xK9#mN2@pQ5&vR8!tY1*wZ4"\n')
        result = scanner.scan([tmp_path])
        assert any(f.rule_id == "high-entropy-string" for f in result.findings)

    def test_ignores_low_entropy_string(self, scanner, tmp_path):
        config = tmp_path / "config.py"
        config.write_text('VALUE = "aaaaaaaaaaaaaaaa"\n')
        result = scanner.scan([tmp_path])
        assert not any(f.rule_id == "high-entropy-string" for f in result.findings)
```

```python
# tests/scanner/test_output.py

class TestOutputFormatters:
    @pytest.fixture
    def sample_result(self):
        return AggregatedScanResult(
            results=[],
            total_findings=2,
            unique_findings=[
                ScanFinding(
                    file_path=Path(".env"),
                    rule_id="unencrypted-env-file",
                    rule_description="Unencrypted .env File",
                    description="File is not encrypted",
                    severity=FindingSeverity.HIGH,
                    scanner="native",
                ),
                ScanFinding(
                    file_path=Path("config.py"),
                    line_number=10,
                    rule_id="aws-access-key-id",
                    rule_description="AWS Access Key ID",
                    description="AWS key detected",
                    severity=FindingSeverity.CRITICAL,
                    secret_preview="AKIA****MPLE",
                    scanner="native",
                ),
            ],
            scanners_used=["native"],
            total_duration_ms=50,
        )

    def test_json_output_structure(self, sample_result):
        output = format_json(sample_result)
        data = json.loads(output)
        assert "findings" in data
        assert "summary" in data
        assert len(data["findings"]) == 2
        assert data["exit_code"] == 1  # CRITICAL finding

    def test_sarif_output_structure(self, sample_result):
        output = format_sarif(sample_result)
        data = json.loads(output)
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1
        assert len(data["runs"][0]["results"]) == 2
```

#### Integration Tests

```python
# tests/scanner/test_native_integration.py

@pytest.mark.integration
class TestNativeScannerIntegration:
    """Integration tests using real file system."""

    def test_scan_real_project_structure(self, tmp_path):
        """Test scanning a realistic project structure."""
        # Create project structure
        (tmp_path / "src").mkdir()
        (tmp_path / "tests").mkdir()
        (tmp_path / ".env").write_text("SECRET_KEY=mysecretkey123\n")
        (tmp_path / ".env.example").write_text("SECRET_KEY=\n")
        (tmp_path / "src" / "config.py").write_text('API_KEY = "sk_live_TESTKEY00000000"\n')

        scanner = NativeScanner()
        result = scanner.scan([tmp_path])

        # Should find unencrypted .env and API key in config
        assert len(result.findings) >= 2
        assert result.files_scanned > 0

    def test_scan_empty_directory(self, tmp_path):
        scanner = NativeScanner()
        result = scanner.scan([tmp_path])
        assert len(result.findings) == 0
        assert result.files_scanned == 0

    def test_scan_nonexistent_path(self):
        scanner = NativeScanner()
        result = scanner.scan([Path("/nonexistent/path")])
        assert len(result.findings) == 0
```

---

### Phase 2 Tests: Gitleaks Integration

```python
# tests/scanner/test_gitleaks.py

class TestGitleaksScanner:
    @pytest.fixture
    def scanner(self):
        return GitleaksScanner(auto_install=False)

    def test_is_installed_returns_false_when_missing(self, scanner, monkeypatch):
        monkeypatch.setattr(shutil, "which", lambda x: None)
        assert not scanner.is_installed()

    @pytest.mark.skipif(not shutil.which("gitleaks"), reason="gitleaks not installed")
    def test_scan_detects_secrets(self, scanner, tmp_path):
        secret_file = tmp_path / "secrets.txt"
        secret_file.write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"\n')

        result = scanner.scan([tmp_path])
        assert len(result.findings) > 0

class TestGitleaksInstaller:
    @pytest.mark.slow
    def test_install_downloads_binary(self, tmp_path, monkeypatch):
        """Test actual binary download (slow, network required)."""
        monkeypatch.setenv("HOME", str(tmp_path))

        scanner = GitleaksScanner(auto_install=True)
        scanner.install()

        assert scanner.is_installed()

@pytest.mark.integration
@pytest.mark.gitleaks
class TestGitleaksIntegration:
    """Integration tests requiring gitleaks to be installed."""

    @pytest.fixture(autouse=True)
    def skip_if_not_installed(self):
        if not shutil.which("gitleaks"):
            pytest.skip("gitleaks not installed")

    def test_scan_git_repository(self, tmp_path):
        """Test scanning a git repository with history."""
        # Initialize git repo
        subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=tmp_path)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_path)

        # Add a file with a secret
        secret_file = tmp_path / "config.py"
        secret_file.write_text('API_KEY = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"\n')
        subprocess.run(["git", "add", "."], cwd=tmp_path)
        subprocess.run(["git", "commit", "-m", "initial"], cwd=tmp_path)

        # Remove the secret
        secret_file.write_text('API_KEY = ""\n')
        subprocess.run(["git", "add", "."], cwd=tmp_path)
        subprocess.run(["git", "commit", "-m", "remove secret"], cwd=tmp_path)

        scanner = GitleaksScanner()

        # Without history - should find nothing
        result = scanner.scan([tmp_path], include_git_history=False)
        # With history - should find the secret
        result_with_history = scanner.scan([tmp_path], include_git_history=True)

        assert len(result_with_history.findings) > len(result.findings)
```

---

### Phase 3 Tests: Trufflehog Integration

```python
# tests/scanner/test_trufflehog.py

class TestTrufflehogScanner:
    @pytest.fixture
    def scanner(self):
        return TrufflehogScanner(auto_install=False)

    def test_is_installed_returns_false_when_missing(self, scanner, monkeypatch):
        monkeypatch.setattr(shutil, "which", lambda x: None)
        assert not scanner.is_installed()

@pytest.mark.integration
@pytest.mark.trufflehog
class TestTrufflehogIntegration:
    """Integration tests requiring trufflehog to be installed."""

    @pytest.fixture(autouse=True)
    def skip_if_not_installed(self):
        if not shutil.which("trufflehog"):
            pytest.skip("trufflehog not installed")

    def test_scan_filesystem(self, tmp_path):
        secret_file = tmp_path / "aws.txt"
        secret_file.write_text('AKIAIOSFODNN7EXAMPLE\n')

        scanner = TrufflehogScanner()
        result = scanner.scan([tmp_path])

        # Trufflehog should detect the AWS key
        assert any("aws" in f.rule_id.lower() for f in result.findings)
```

---

### Phase 4 Tests: Engine + CLI

```python
# tests/scanner/test_engine.py

class TestScanEngine:
    def test_native_only_config(self):
        config = GuardConfig(
            use_native=True,
            use_gitleaks=False,
            use_trufflehog=False,
        )
        engine = ScanEngine(config)
        assert len(engine.scanners) == 1
        assert engine.scanners[0].name == "native"

    def test_deduplication(self, tmp_path):
        """Test that duplicate findings are merged."""
        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)

        # Create file that triggers multiple patterns
        secret_file = tmp_path / ".env"
        secret_file.write_text('AWS_KEY="AKIAIOSFODNN7EXAMPLE"\n')

        result = engine.scan([tmp_path])

        # Should have unique findings (no duplicates)
        file_line_rules = [
            (f.file_path, f.line_number, f.rule_id)
            for f in result.unique_findings
        ]
        assert len(file_line_rules) == len(set(file_line_rules))

    def test_config_from_toml(self):
        toml_config = {
            "guard": {
                "scanners": ["native", "trufflehog"],
                "auto_install": False,
                "include_history": True,
                "fail_on_severity": "critical",
            }
        }
        config = GuardConfig.from_toml(toml_config)

        assert config.use_native is True
        assert config.use_gitleaks is False
        assert config.use_trufflehog is True
        assert config.auto_install is False
        assert config.include_git_history is True
        assert config.fail_on_severity == FindingSeverity.CRITICAL

# tests/cli_commands/test_guard.py

class TestGuardCommand:
    def test_guard_no_findings_exits_zero(self, tmp_path, cli_runner):
        (tmp_path / "README.md").write_text("# Hello\n")

        result = cli_runner.invoke(app, ["guard", str(tmp_path), "--native-only"])
        assert result.exit_code == 0

    def test_guard_with_secrets_exits_nonzero(self, tmp_path, cli_runner):
        (tmp_path / ".env").write_text("SECRET=value\n")

        result = cli_runner.invoke(app, ["guard", str(tmp_path), "--native-only"])
        assert result.exit_code != 0

    def test_guard_json_output(self, tmp_path, cli_runner):
        (tmp_path / ".env").write_text("SECRET=value\n")

        result = cli_runner.invoke(app, ["guard", str(tmp_path), "--native-only", "--json"])

        data = json.loads(result.stdout)
        assert "findings" in data
        assert "summary" in data

    def test_guard_ci_mode_respects_fail_on(self, tmp_path, cli_runner):
        # Create a medium-severity finding
        (tmp_path / "config.py").write_text('KEY = "some_api_key_value_here"\n')

        # Should pass with --fail-on critical
        result = cli_runner.invoke(app, [
            "guard", str(tmp_path), "--native-only", "--ci", "--fail-on", "critical"
        ])
        assert result.exit_code == 0
```

---

### End-to-End Tests

```python
# tests/e2e/test_guard_e2e.py

@pytest.mark.e2e
class TestGuardEndToEnd:
    """End-to-end tests for the guard command."""

    def test_full_workflow_unencrypted_env(self, tmp_path):
        """Test detecting and fixing an unencrypted .env file."""
        # Setup: Create unencrypted .env
        env_file = tmp_path / ".env"
        env_file.write_text("DATABASE_URL=postgres://localhost/db\n")

        # Step 1: Guard detects the issue
        result = subprocess.run(
            ["envdrift", "guard", "--native-only"],
            cwd=tmp_path,
            capture_output=True,
        )
        assert result.returncode != 0
        assert b"unencrypted" in result.stdout.lower()

        # Step 2: Encrypt the file
        subprocess.run(["envdrift", "encrypt"], cwd=tmp_path)

        # Step 3: Guard passes
        result = subprocess.run(
            ["envdrift", "guard", "--native-only"],
            cwd=tmp_path,
            capture_output=True,
        )
        assert result.returncode == 0

    @pytest.mark.skipif(not shutil.which("gitleaks"), reason="gitleaks not installed")
    def test_guard_with_gitleaks(self, tmp_path):
        """Test guard with gitleaks integration."""
        # Create a secret
        (tmp_path / "config.py").write_text(
            'GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"\n'
        )

        result = subprocess.run(
            ["envdrift", "guard", "--gitleaks"],
            cwd=tmp_path,
            capture_output=True,
        )

        assert result.returncode != 0
        assert b"github" in result.stdout.lower()
```

---

## Success Criteria

### Phase 1 Complete When

- [ ] `envdrift guard` runs without external dependencies
- [ ] Detects unencrypted `.env` files (missing dotenvx/SOPS markers)
- [ ] Detects 15+ common secret patterns
- [ ] Outputs Rich terminal UI, JSON, and SARIF formats
- [ ] Exit codes work correctly
- [ ] 90%+ test coverage for scanner module

### Phase 2 Complete When

- [ ] Gitleaks auto-installs on first use
- [ ] Gitleaks findings parsed correctly
- [ ] Git history scanning works
- [ ] Findings deduplicated between native and gitleaks

### Phase 3 Complete When

- [ ] Trufflehog auto-installs on first use
- [ ] Trufflehog findings parsed correctly
- [ ] Verified secrets flagged appropriately
- [ ] All three scanners work together

### Phase 4 Complete When

- [ ] Full CLI with all options working
- [ ] Configuration via `envdrift.toml` working
- [ ] Documentation complete
- [ ] CI examples for GitHub Actions, GitLab CI, etc.

---

## Future Considerations

### Potential Enhancements

1. **Pre-receive hook script** - For self-hosted Git servers
2. **Baseline file** - Ignore known/accepted findings
3. **Custom rules** - User-defined patterns in config
4. **IDE integration** - Real-time scanning in VS Code extension
5. **Slack/webhook notifications** - Alert on findings
6. **Secret rotation integration** - Suggest rotation for found secrets

### Performance Optimization

1. **Parallel scanning** - Run scanners concurrently
2. **Incremental scanning** - Only scan changed files
3. **Caching** - Cache scan results for unchanged files

### Compliance Features

1. **Audit logging** - Record all scans for compliance
2. **Policy enforcement** - Block commits with specific patterns
3. **Reporting** - Generate compliance reports

---

## Appendix

### A. Secret Pattern Sources

- [gitleaks rules](https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml)
- [trufflehog detectors](https://github.com/trufflesecurity/trufflehog/tree/main/pkg/detectors)
- [detect-secrets](https://github.com/Yelp/detect-secrets)

### B. SARIF Specification

- [SARIF 2.1.0 Schema](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)

### C. Exit Code Conventions

Following Unix conventions and CI best practices:

- 0 = Success
- 1-125 = Application-specific errors
- 126-127 = Shell errors
- 128+ = Signal termination
