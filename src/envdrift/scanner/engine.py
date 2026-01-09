"""Scan engine - orchestrates multiple secret scanners.

The ScanEngine is responsible for:
- Initializing and managing scanner instances
- Running scans across multiple scanners in parallel
- Aggregating and deduplicating findings
- Handling scanner failures gracefully
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from envdrift.scanner.base import (
    AggregatedScanResult,
    FindingSeverity,
    ScanFinding,
    ScannerBackend,
    ScanResult,
)
from envdrift.scanner.native import NativeScanner

if TYPE_CHECKING:
    pass


@dataclass
class GuardConfig:
    """Configuration for the guard command and scan engine.

    Attributes:
        use_native: Enable the native scanner (always recommended).
        use_gitleaks: Enable gitleaks scanner (if available).
        use_trufflehog: Enable trufflehog scanner (if available).
        use_detect_secrets: Enable detect-secrets scanner - the "final boss".
        use_kingfisher: Enable Kingfisher scanner (700+ rules, password hashes).
        auto_install: Auto-install missing external scanners.
        include_git_history: Scan git history for secrets.
        check_entropy: Enable entropy-based secret detection.
        entropy_threshold: Minimum entropy to flag as potential secret.
        ignore_paths: Glob patterns for paths to ignore.
        fail_on_severity: Minimum severity to cause non-zero exit.
        allowed_clear_files: Files that are intentionally unencrypted (from partial_encryption config).
    """

    use_native: bool = True
    use_gitleaks: bool = True
    use_trufflehog: bool = False
    use_detect_secrets: bool = False
    use_kingfisher: bool = False
    auto_install: bool = True
    include_git_history: bool = False
    check_entropy: bool = False
    entropy_threshold: float = 4.5
    ignore_paths: list[str] = field(default_factory=list)
    fail_on_severity: FindingSeverity = FindingSeverity.HIGH
    allowed_clear_files: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, config: dict) -> GuardConfig:
        """Create config from a dictionary (e.g., from envdrift.toml).

        Args:
            config: Dictionary with guard configuration.

        Returns:
            GuardConfig instance.
        """
        guard_config = config.get("guard", {})

        # Parse scanners list
        scanners = guard_config.get("scanners", ["native", "gitleaks"])
        if isinstance(scanners, str):
            scanners = [scanners]

        # Parse severity
        fail_on = guard_config.get("fail_on_severity", "high")
        try:
            fail_severity = FindingSeverity(fail_on.lower())
        except ValueError:
            fail_severity = FindingSeverity.HIGH

        return cls(
            use_native="native" in scanners,
            use_gitleaks="gitleaks" in scanners,
            use_trufflehog="trufflehog" in scanners,
            use_detect_secrets="detect-secrets" in scanners,
            use_kingfisher="kingfisher" in scanners,
            auto_install=guard_config.get("auto_install", True),
            include_git_history=guard_config.get("include_history", False),
            check_entropy=guard_config.get("check_entropy", False),
            entropy_threshold=guard_config.get("entropy_threshold", 4.5),
            ignore_paths=guard_config.get("ignore_paths", []),
            fail_on_severity=fail_severity,
        )


class ScanEngine:
    """Orchestrates multiple secret scanners.

    The engine manages scanner lifecycle, runs scans in parallel,
    and aggregates results from all scanners.

    Example:
        config = GuardConfig(use_native=True, use_gitleaks=False)
        engine = ScanEngine(config)
        result = engine.scan([Path(".")])
        print(f"Found {len(result.unique_findings)} issues")
    """

    def __init__(self, config: GuardConfig | None = None) -> None:
        """Initialize the scan engine.

        Args:
            config: Configuration for scanners. Uses defaults if None.
        """
        self.config = config or GuardConfig()
        self.scanners: list[ScannerBackend] = []

        self._initialize_scanners()

    def _run_scanner(
        self, scanner: ScannerBackend, paths: list[Path], include_git_history: bool
    ) -> ScanResult:
        """Run a single scanner (for parallel execution).

        Args:
            scanner: The scanner to run.
            paths: Paths to scan.
            include_git_history: Whether to include git history.

        Returns:
            ScanResult from the scanner.
        """
        try:
            return scanner.scan(
                paths=paths,
                include_git_history=include_git_history,
            )
        except Exception as e:
            return ScanResult(
                scanner_name=scanner.name,
                error=str(e),
            )

    def _initialize_scanners(self) -> None:
        """Initialize scanner instances based on configuration."""
        # Native scanner (always available)
        if self.config.use_native:
            self.scanners.append(
                NativeScanner(
                    check_entropy=self.config.check_entropy,
                    entropy_threshold=self.config.entropy_threshold,
                    additional_ignore_patterns=self.config.ignore_paths,
                    allowed_clear_files=self.config.allowed_clear_files,
                )
            )

        # Gitleaks scanner (Phase 2)
        if self.config.use_gitleaks:
            try:
                from envdrift.scanner.gitleaks import GitleaksScanner

                scanner = GitleaksScanner(auto_install=self.config.auto_install)
                if scanner.is_installed() or self.config.auto_install:
                    self.scanners.append(scanner)
            except ImportError:
                pass  # Gitleaks not yet implemented

        # Trufflehog scanner (Phase 3)
        if self.config.use_trufflehog:
            try:
                from envdrift.scanner.trufflehog import TrufflehogScanner

                scanner = TrufflehogScanner(auto_install=self.config.auto_install)
                if scanner.is_installed() or self.config.auto_install:
                    self.scanners.append(scanner)
            except ImportError:
                pass  # Trufflehog not yet implemented

        # Detect-secrets scanner - the "final boss"
        if self.config.use_detect_secrets:
            try:
                from envdrift.scanner.detect_secrets import DetectSecretsScanner

                scanner = DetectSecretsScanner(auto_install=self.config.auto_install)
                if scanner.is_installed() or self.config.auto_install:
                    self.scanners.append(scanner)
            except ImportError:
                pass  # detect-secrets not yet implemented

        # Kingfisher scanner - 700+ rules, password hashes, validation
        if self.config.use_kingfisher:
            try:
                from envdrift.scanner.kingfisher import KingfisherScanner

                scanner = KingfisherScanner(
                    auto_install=self.config.auto_install,
                    validate_secrets=True,
                    confidence="low",  # Maximum detection
                    scan_binary_files=True,
                    extract_archives=True,
                )
                if scanner.is_installed() or self.config.auto_install:
                    self.scanners.append(scanner)
            except ImportError:
                pass  # Kingfisher not available

    def scan(self, paths: list[Path]) -> AggregatedScanResult:
        """Run all configured scanners on the given paths in parallel.

        Scanners run concurrently to improve performance on large repositories.
        Each scanner has its own timeout and error handling.

        Args:
            paths: List of files or directories to scan.

        Returns:
            AggregatedScanResult with deduplicated findings.
        """
        start_time = time.time()
        results: list[ScanResult] = []

        # Early return if no scanners configured
        if not self.scanners:
            return AggregatedScanResult(
                results=[],
                total_findings=0,
                unique_findings=[],
                scanners_used=[],
                total_duration_ms=int((time.time() - start_time) * 1000),
            )

        # Run scanners in parallel using ThreadPoolExecutor
        # Use at most 4 workers to avoid overwhelming the system
        max_workers = min(len(self.scanners), 4)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all scanner tasks
            future_to_scanner = {
                executor.submit(
                    self._run_scanner, scanner, paths, self.config.include_git_history
                ): scanner
                for scanner in self.scanners
            }

            # Collect results as they complete
            for future in as_completed(future_to_scanner):
                scanner = future_to_scanner[future]
                try:
                    result = future.result(timeout=600)  # 10 minute per-scanner timeout
                    results.append(result)
                except Exception as e:
                    # Record scanner failure but continue with others
                    results.append(
                        ScanResult(
                            scanner_name=scanner.name,
                            error=f"Scanner failed: {e!s}",
                        )
                    )

        # Collect all findings
        all_findings: list[ScanFinding] = []
        for result in results:
            all_findings.extend(result.findings)

        # Deduplicate findings
        unique_findings = self._deduplicate(all_findings)

        total_duration = int((time.time() - start_time) * 1000)

        return AggregatedScanResult(
            results=results,
            total_findings=len(all_findings),
            unique_findings=unique_findings,
            scanners_used=[s.name for s in self.scanners],
            total_duration_ms=total_duration,
        )

    def _deduplicate(self, findings: list[ScanFinding]) -> list[ScanFinding]:
        """Remove duplicate findings, keeping the highest severity.

        Duplicates are identified by file path, line number, and rule ID.
        When duplicates are found:
        - Keep the one with highest severity
        - Prefer verified findings over unverified

        Args:
            findings: List of all findings from all scanners.

        Returns:
            Deduplicated list sorted by severity (highest first).
        """
        seen: dict[tuple, ScanFinding] = {}

        for finding in findings:
            key = (finding.file_path, finding.line_number, finding.rule_id)

            if key not in seen:
                seen[key] = finding
            else:
                existing = seen[key]
                # Keep higher severity
                if finding.severity > existing.severity or (
                    finding.verified and not existing.verified
                ):
                    seen[key] = finding

        # Sort by severity (highest first), then by file path
        return sorted(
            seen.values(),
            key=lambda f: (f.severity, str(f.file_path), f.line_number or 0),
            reverse=True,
        )

    def get_scanner_info(self) -> list[dict]:
        """Get information about configured scanners.

        Returns:
            List of scanner info dictionaries.
        """
        return [
            {
                "name": s.name,
                "description": s.description,
                "installed": s.is_installed(),
                "version": s.get_version(),
            }
            for s in self.scanners
        ]
