"""Abstract base class and data models for secret scanners."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class FindingSeverity(Enum):
    """Severity levels for scan findings.

    Ordered from most to least severe:
    - CRITICAL: Confirmed secret (high-confidence pattern match)
    - HIGH: Very likely a secret (strong pattern or high entropy)
    - MEDIUM: Possibly a secret (moderate confidence)
    - LOW: Policy violation (e.g., unencrypted file)
    - INFO: Informational only
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __lt__(self, other: object) -> bool:
        """Compare severities for sorting (higher severity = greater)."""
        if not isinstance(other, FindingSeverity):
            return NotImplemented
        order = [
            FindingSeverity.INFO,
            FindingSeverity.LOW,
            FindingSeverity.MEDIUM,
            FindingSeverity.HIGH,
            FindingSeverity.CRITICAL,
        ]
        return order.index(self) < order.index(other)

    def __le__(self, other: object) -> bool:
        """Compare severities for sorting."""
        if not isinstance(other, FindingSeverity):
            return NotImplemented
        return self == other or self < other

    def __gt__(self, other: object) -> bool:
        """Compare severities for sorting."""
        if not isinstance(other, FindingSeverity):
            return NotImplemented
        return not self <= other

    def __ge__(self, other: object) -> bool:
        """Compare severities for sorting."""
        if not isinstance(other, FindingSeverity):
            return NotImplemented
        return not self < other


@dataclass(frozen=True)
class ScanFinding:
    """A single secret or policy violation finding.

    Attributes:
        file_path: Path to the file containing the finding.
        rule_id: Unique identifier for the detection rule (e.g., "aws-access-key-id").
        rule_description: Human-readable name of the rule.
        description: Finding-specific message describing the issue.
        severity: Severity level of the finding.
        scanner: Name of the scanner that found this (e.g., "native", "gitleaks").
        line_number: Line number where the finding was detected (1-indexed).
        column_number: Column number where the finding starts (1-indexed).
        secret_preview: Redacted preview of the secret (e.g., "AKIA****XXXX").
        secret_hash: SHA-256 hash of the full secret value for accurate deduplication.
        commit_sha: Git commit SHA if found in history.
        commit_author: Git commit author if found in history.
        commit_date: Git commit date if found in history.
        entropy: Shannon entropy value if calculated.
        verified: Whether the secret was verified as valid (trufflehog feature).
    """

    file_path: Path
    rule_id: str
    rule_description: str
    description: str
    severity: FindingSeverity
    scanner: str
    line_number: int | None = None
    column_number: int | None = None
    secret_preview: str = ""
    secret_hash: str = ""  # SHA-256 hash of full secret for deduplication
    commit_sha: str | None = None
    commit_author: str | None = None
    commit_date: str | None = None
    entropy: float | None = None
    verified: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization.

        Returns:
            Dictionary representation suitable for JSON encoding.
        """
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

    @property
    def location(self) -> str:
        """Get formatted location string (file:line:col)."""
        loc = str(self.file_path)
        if self.line_number is not None:
            loc += f":{self.line_number}"
            if self.column_number is not None:
                loc += f":{self.column_number}"
        return loc


@dataclass
class ScanResult:
    """Results from a single scanner run.

    Attributes:
        scanner_name: Name of the scanner that produced these results.
        findings: List of findings detected by the scanner.
        files_scanned: Number of files that were scanned.
        duration_ms: Time taken to complete the scan in milliseconds.
        error: Error message if the scan failed, None otherwise.
    """

    scanner_name: str
    findings: list[ScanFinding] = field(default_factory=list)
    files_scanned: int = 0
    duration_ms: int = 0
    error: str | None = None

    @property
    def success(self) -> bool:
        """Check if the scan completed without errors."""
        return self.error is None


@dataclass
class AggregatedScanResult:
    """Combined results from all scanners.

    This is the final result returned by the ScanEngine after running
    all configured scanners and deduplicating findings.

    Attributes:
        results: Individual results from each scanner.
        total_findings: Total number of findings before deduplication.
        unique_findings: Deduplicated findings sorted by severity.
        scanners_used: Names of scanners that were used.
        total_duration_ms: Total time for all scans in milliseconds.
    """

    results: list[ScanResult]
    total_findings: int
    unique_findings: list[ScanFinding]
    scanners_used: list[str]
    total_duration_ms: int

    @property
    def exit_code(self) -> int:
        """Determine exit code based on highest severity finding.

        Returns:
            0: No findings
            1: Critical severity findings
            2: High severity findings
            3: Medium severity findings
        """
        if not self.unique_findings:
            return 0

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
        """Check if there are findings that should block CI.

        Returns:
            True if there are CRITICAL or HIGH severity findings.
        """
        return self.exit_code in (1, 2)

    @property
    def findings_by_severity(self) -> dict[FindingSeverity, list[ScanFinding]]:
        """Group findings by severity level.

        Returns:
            Dictionary mapping severity to list of findings.
        """
        result: dict[FindingSeverity, list[ScanFinding]] = {}
        for finding in self.unique_findings:
            if finding.severity not in result:
                result[finding.severity] = []
            result[finding.severity].append(finding)
        return result

    def get_summary(self) -> dict[str, int]:
        """Get count of findings by severity.

        Returns:
            Dictionary mapping severity name to count.
        """
        return {
            severity.value: sum(1 for f in self.unique_findings if f.severity == severity)
            for severity in FindingSeverity
        }


class ScannerBackend(ABC):
    """Abstract interface for secret scanners.

    All scanner implementations must inherit from this class and implement
    the required abstract methods. Scanners should be safe for concurrent use.

    Example:
        class MyScanner(ScannerBackend):
            @property
            def name(self) -> str:
                return "my-scanner"

            @property
            def description(self) -> str:
                return "My custom scanner"

            def is_installed(self) -> bool:
                return True

            def scan(self, paths, include_git_history=False) -> ScanResult:
                # Implementation here
                pass
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for this scanner.

        Returns:
            Short name like "native", "gitleaks", "trufflehog".
        """
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of the scanner.

        Returns:
            Description of what this scanner does.
        """
        ...

    @abstractmethod
    def is_installed(self) -> bool:
        """Check if the scanner is available for use.

        For native scanners, this always returns True.
        For external tools, this checks if the binary is installed.

        Returns:
            True if the scanner can be used, False otherwise.
        """
        ...

    @abstractmethod
    def scan(
        self,
        paths: list[Path],
        include_git_history: bool = False,
    ) -> ScanResult:
        """Scan the given paths for secrets.

        Args:
            paths: List of files or directories to scan.
            include_git_history: If True, also scan git history for secrets.

        Returns:
            ScanResult containing all findings.
        """
        ...

    def install(
        self,
        progress_callback: Callable[[str], None] | None = None,
    ) -> Path | None:
        """Install the scanner binary if applicable.

        This is optional - native scanners don't need installation.
        External scanners (gitleaks, trufflehog) override this to
        download and install their binaries.

        Args:
            progress_callback: Optional callback for progress updates.

        Returns:
            Path to the installed binary, or None if not applicable.
        """
        return None

    def get_version(self) -> str | None:
        """Get the version of the installed scanner.

        Returns:
            Version string, or None if not applicable/installed.
        """
        return None
