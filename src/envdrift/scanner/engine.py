"""Scan engine - orchestrates multiple secret scanners.

The ScanEngine is responsible for:
- Initializing and managing scanner instances
- Running scans across multiple scanners in parallel
- Aggregating and deduplicating findings
- Handling scanner failures gracefully
"""

from __future__ import annotations

import time
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
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
from envdrift.scanner.ignores import IgnoreConfig, IgnoreFilter
from envdrift.scanner.native import DOTENVX_MARKERS, SOPS_MARKERS, NativeScanner

if TYPE_CHECKING:
    pass

import logging

logger = logging.getLogger(__name__)


@dataclass
class GuardConfig:
    """Configuration for the guard command and scan engine.

    Attributes:
        use_native: Enable the native scanner (always recommended).
        use_gitleaks: Enable gitleaks scanner (if available).
        use_trufflehog: Enable trufflehog scanner (if available).
        use_detect_secrets: Enable detect-secrets scanner - the "final boss".
        use_kingfisher: Enable Kingfisher scanner (700+ rules, password hashes).
        use_git_secrets: Enable git-secrets scanner (AWS credential detection).
        use_talisman: Enable Talisman scanner (ThoughtWorks secret scanner).
        use_trivy: Enable Trivy scanner (Aqua Security comprehensive scanner).
        use_infisical: Enable Infisical scanner (140+ secret types).
        auto_install: Auto-install missing external scanners.
        include_git_history: Scan git history for secrets.
        check_entropy: Enable entropy-based secret detection.
        entropy_threshold: Minimum entropy to flag as potential secret.
        skip_clear_files: Skip .clear files from scanning entirely.
        skip_encrypted_files: Skip findings from files with dotenvx/SOPS encryption markers.
        skip_duplicate: Show only unique findings by secret value (ignore scanner source).
        skip_gitignored: Skip findings from files that are in .gitignore.
        ignore_paths: Glob patterns for paths to ignore.
        ignore_rules: Rule ID -> list of path patterns where that rule is ignored.
        fail_on_severity: Minimum severity to cause non-zero exit.
        allowed_clear_files: Files that are intentionally unencrypted (from partial_encryption config).
        combined_files: Combined files from partial_encryption config (secret + clear merged).
    """

    use_native: bool = True
    use_gitleaks: bool = True
    use_trufflehog: bool = False
    use_detect_secrets: bool = False
    use_kingfisher: bool = False
    use_git_secrets: bool = False
    use_talisman: bool = False
    use_trivy: bool = False
    use_infisical: bool = False
    auto_install: bool = True
    include_git_history: bool = False
    check_entropy: bool = False
    entropy_threshold: float = 4.5
    skip_clear_files: bool = False
    skip_encrypted_files: bool = True  # Default True - skip findings from encrypted files
    skip_duplicate: bool = False
    skip_gitignored: bool = False  # Optional: skip findings from gitignored files
    ignore_paths: list[str] = field(default_factory=list)
    ignore_rules: dict[str, list[str]] = field(default_factory=dict)
    fail_on_severity: FindingSeverity = FindingSeverity.HIGH
    allowed_clear_files: list[str] = field(default_factory=list)
    combined_files: list[str] = field(
        default_factory=list
    )  # Combined files from partial_encryption

    @classmethod
    def from_dict(cls, config: dict) -> GuardConfig:
        """
        Construct a GuardConfig from a parsed configuration dictionary (for example, from envdrift.toml).

        Parses the "guard" section to enable scanner flags, normalization of the "scanners" entry (accepts a string or list; defaults to ["native", "gitleaks"]), and reads other guard settings such as auto_install, include_history, entropy checks, ignore paths/rules, and skip_clear_files. Interprets "fail_on_severity" case-insensitively and falls back to FindingSeverity.HIGH on invalid values.

        Parameters:
            config (dict): Configuration dictionary that may contain a "guard" mapping.

        Returns:
            GuardConfig: A GuardConfig populated from the provided dictionary.
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
            use_git_secrets="git-secrets" in scanners,
            use_talisman="talisman" in scanners,
            use_trivy="trivy" in scanners,
            use_infisical="infisical" in scanners,
            auto_install=guard_config.get("auto_install", True),
            include_git_history=guard_config.get("include_history", False),
            check_entropy=guard_config.get("check_entropy", False),
            entropy_threshold=guard_config.get("entropy_threshold", 4.5),
            skip_clear_files=guard_config.get("skip_clear_files", False),
            skip_encrypted_files=guard_config.get("skip_encrypted_files", True),
            skip_duplicate=guard_config.get("skip_duplicate", False),
            skip_gitignored=guard_config.get("skip_gitignored", False),
            ignore_paths=guard_config.get("ignore_paths", []),
            ignore_rules=guard_config.get("ignore_rules", {}),
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

    # Default paths to always ignore across all scanners
    # These are config/build files that contain "secret" keywords but not actual secrets
    DEFAULT_GLOBAL_IGNORE_PATHS = [
        "envdrift.toml",
        "pyproject.toml",
        "mkdocs.yml",
        "mkdocs.yaml",
        "*.lock",
        "package-lock.json",
        "yarn.lock",
        "poetry.lock",
    ]

    def __init__(self, config: GuardConfig | None = None) -> None:
        """Initialize the scan engine.

        Args:
            config: Configuration for scanners. Uses defaults if None.
        """
        self.config = config or GuardConfig()
        self.scanners: list[ScannerBackend] = []

        # Merge default global ignores with user-configured ignores
        all_ignore_paths = list(self.DEFAULT_GLOBAL_IGNORE_PATHS) + list(self.config.ignore_paths)

        # Initialize centralized ignore filter for post-scan filtering
        ignore_config = IgnoreConfig(
            ignore_paths=all_ignore_paths,
            ignore_rules=self.config.ignore_rules,
        )
        self._ignore_filter = IgnoreFilter(ignore_config)

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
                    skip_clear_files=self.config.skip_clear_files,
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
                    jobs=1,  # deterministic results over speed
                )
                if scanner.is_installed() or self.config.auto_install:
                    self.scanners.append(scanner)
            except ImportError:
                logger.debug("Kingfisher scanner not available - module not found")

        # git-secrets scanner - AWS credential detection + pre-commit hooks
        if self.config.use_git_secrets:
            try:
                from envdrift.scanner.git_secrets import GitSecretsScanner

                scanner = GitSecretsScanner(
                    auto_install=self.config.auto_install,
                    register_aws=True,  # Register AWS patterns by default
                )
                if scanner.is_installed() or self.config.auto_install:
                    self.scanners.append(scanner)
            except ImportError:
                logger.debug("git-secrets scanner not available - module not found")

        # Talisman scanner - ThoughtWorks secret scanner
        if self.config.use_talisman:
            try:
                from envdrift.scanner.talisman import TalismanScanner

                scanner = TalismanScanner(auto_install=self.config.auto_install)
                if scanner.is_installed() or self.config.auto_install:
                    self.scanners.append(scanner)
            except ImportError:
                logger.debug("Talisman scanner not available - module not found")

        # Trivy scanner - Aqua Security comprehensive scanner
        if self.config.use_trivy:
            try:
                from envdrift.scanner.trivy import TrivyScanner

                scanner = TrivyScanner(auto_install=self.config.auto_install)
                if scanner.is_installed() or self.config.auto_install:
                    self.scanners.append(scanner)
            except ImportError:
                logger.debug("Trivy scanner not available - module not found")

        # Infisical scanner - 140+ secret types
        if self.config.use_infisical:
            try:
                from envdrift.scanner.infisical import InfisicalScanner

                scanner = InfisicalScanner(auto_install=self.config.auto_install)
                if scanner.is_installed() or self.config.auto_install:
                    self.scanners.append(scanner)
            except ImportError:
                logger.debug("Infisical scanner not available - module not found")

    def scan(
        self,
        paths: list[Path],
        on_scanner_complete: Callable[[str, int, int, ScanResult | None], None] | None = None,
    ) -> AggregatedScanResult:
        """
        Run all configured scanners against the given file system paths, aggregate their findings, and apply deduplication and centralized filtering.

        Parameters:
            paths (list[Path]): Files or directories to scan.
            on_scanner_complete: Optional callback called when each scanner completes.
                                 Signature: (scanner_name: str, completed: int, total: int, result: ScanResult) -> None

        Returns:
            AggregatedScanResult: Aggregated scan outcome containing:
                - results: list of per-scanner ScanResult objects (including errors).
                - total_findings: total number of findings collected before deduplication/filtering.
                - unique_findings: deduplicated and filtered list of ScanFinding objects.
                - scanners_used: list of scanner names that were executed.
                - total_duration_ms: total scan duration in milliseconds.
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
        total_scanners = len(self.scanners)
        completed_count = 0
        per_scanner_timeout_s = 600

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all scanner tasks
            future_to_scanner = {
                executor.submit(
                    self._run_scanner, scanner, paths, self.config.include_git_history
                ): scanner
                for scanner in self.scanners
            }

            start_times = {future: time.time() for future in future_to_scanner}
            pending = set(future_to_scanner)

            # Collect results as they complete, while enforcing per-scanner timeouts
            while pending:
                done, pending = wait(pending, timeout=1, return_when=FIRST_COMPLETED)

                for future in done:
                    scanner = future_to_scanner[future]
                    try:
                        scan_result = future.result()
                    except Exception as e:
                        # Record scanner failure but continue with others
                        scan_result = ScanResult(
                            scanner_name=scanner.name,
                            error=f"Scanner failed: {e!s}",
                        )
                    results.append(scan_result)

                    # Notify progress callback
                    completed_count += 1
                    if on_scanner_complete:
                        on_scanner_complete(
                            scanner.name,
                            completed_count,
                            total_scanners,
                            scan_result,
                        )

                # Mark long-running scanners as timed out
                now = time.time()
                timed_out = [
                    future
                    for future in pending
                    if now - start_times[future] > per_scanner_timeout_s
                ]
                for future in timed_out:
                    scanner = future_to_scanner[future]
                    future.cancel()
                    scan_result = ScanResult(
                        scanner_name=scanner.name,
                        error=f"Scanner timed out after {per_scanner_timeout_s}s",
                    )
                    results.append(scan_result)
                    completed_count += 1
                    if on_scanner_complete:
                        on_scanner_complete(
                            scanner.name,
                            completed_count,
                            total_scanners,
                            scan_result,
                        )
                    pending.remove(future)

        # Collect all findings (sort results by scanner name for deterministic order)
        results.sort(key=lambda r: r.scanner_name)
        all_findings: list[ScanFinding] = []
        for result in results:
            all_findings.extend(result.findings)
            logger.debug(
                f"Scanner {result.scanner_name}: {len(result.findings)} findings"
            )

        # Apply centralized filtering BEFORE deduplication so ignored/filtered findings
        # do not suppress valid findings from other locations.
        filtered_findings: list[ScanFinding] = list(all_findings)

        # Filter out .clear file findings if skip_clear_files is enabled
        # This applies centrally to ALL scanners (gitleaks, trufflehog, git-secrets, etc.)
        if self.config.skip_clear_files:
            filtered_findings = self._filter_clear_files(filtered_findings)

        # Filter out findings from encrypted files (dotenvx/SOPS markers)
        # Encrypted files contain ciphertext that triggers false positives
        if self.config.skip_encrypted_files:
            filtered_findings = self._filter_encrypted_files(filtered_findings)

        # Filter out dotenvx public keys (EC keys starting with 02/03)
        # These are meant to be public and should not be flagged as secrets
        filtered_findings = self._filter_public_keys(filtered_findings)

        # Filter out findings from gitignored files if enabled
        # Uses git check-ignore for reliable detection
        if self.config.skip_gitignored:
            filtered_findings = self._filter_gitignored_files(filtered_findings)

        # Apply centralized ignore filter (inline comments + TOML config rules)
        # This works across ALL scanners (native, gitleaks, trufflehog, etc.)
        filtered_findings = self._ignore_filter.filter(filtered_findings)

        # Deduplicate findings (after filtering for deterministic, correct results)
        unique_findings = self._deduplicate(filtered_findings)

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

        By default, duplicates are identified by file path, line number, and rule ID.
        When skip_duplicate is enabled, duplicates are identified by secret value only,
        showing each unique secret only once regardless of where/how it was found.

        When duplicates are found:
        - Keep the one with highest severity
        - Prefer verified findings over unverified

        Args:
            findings: List of all findings from all scanners.

        Returns:
            Deduplicated list sorted by severity (highest first).
        """
        seen: dict[tuple, ScanFinding] = {}

        def _tie_key(finding: ScanFinding) -> tuple:
            """Deterministic tie-breaker for duplicate findings."""
            return (
                str(finding.file_path),
                finding.line_number or 0,
                finding.rule_id,
                finding.scanner,
            )

        for finding in findings:
            if self.config.skip_duplicate:
                # Deduplicate by secret value only - same secret = one finding.
                # Prefer secret_hash (accurate) over secret_preview (may have collisions).
                # If neither is present (policy findings), fall back to location-based key.
                if finding.secret_hash:
                    key = (finding.secret_hash,)
                elif finding.secret_preview:
                    key = (finding.secret_preview,)
                else:
                    key = (finding.file_path, finding.line_number, finding.rule_id)
            else:
                # Default: deduplicate by file, line, and rule
                key = (finding.file_path, finding.line_number, finding.rule_id)

            if key not in seen:
                seen[key] = finding
            else:
                existing = seen[key]
                # Keep higher severity
                if finding.severity > existing.severity:
                    seen[key] = finding
                elif finding.severity == existing.severity:
                    # Prefer verified over unverified
                    if finding.verified and not existing.verified:
                        seen[key] = finding
                    elif finding.verified == existing.verified:
                        # Prefer findings with a real secret_hash for accuracy
                        if bool(finding.secret_hash) and not bool(existing.secret_hash):
                            seen[key] = finding
                        elif bool(finding.secret_hash) == bool(existing.secret_hash):
                            # Deterministic tie-breaker to avoid run-to-run drift
                            if _tie_key(finding) < _tie_key(existing):
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

    def _filter_clear_files(self, findings: list[ScanFinding]) -> list[ScanFinding]:
        """Filter out findings from .clear files.

        .clear files are used by partial encryption to store non-sensitive
        configuration values. When skip_clear_files is enabled, all findings
        from these files should be excluded.

        This applies centrally to ALL scanners (native, gitleaks, trufflehog,
        detect-secrets, kingfisher, git-secrets).

        Args:
            findings: List of findings to filter.

        Returns:
            Filtered list excluding .clear file findings.
        """
        return [finding for finding in findings if not finding.file_path.name.endswith(".clear")]

    def _filter_encrypted_files(self, findings: list[ScanFinding]) -> list[ScanFinding]:
        """Filter out findings from files with encryption markers (dotenvx/SOPS).

        Encrypted files contain ciphertext which can trigger false positives
        from external scanners (detect-secrets, infisical, etc.) that detect
        high-entropy strings or hex patterns in the encrypted values.

        This applies centrally to ALL scanners.

        Args:
            findings: List of findings to filter.

        Returns:
            Filtered list excluding findings from encrypted files.
        """
        # Cache file encryption status
        encrypted_files: set[str] = set()
        checked_files: set[str] = set()

        def is_file_encrypted(file_path: str) -> bool:
            if file_path in encrypted_files:
                return True
            if file_path in checked_files:
                return False

            checked_files.add(file_path)
            try:
                with open(file_path, encoding="utf-8", errors="ignore") as f:
                    # Read first 2KB to check for markers
                    content = f.read(2048)
                    # Use markers from native scanner
                    for marker in DOTENVX_MARKERS + SOPS_MARKERS:
                        if marker in content:
                            encrypted_files.add(file_path)
                            return True
            except OSError:
                pass
            return False

        return [finding for finding in findings if not is_file_encrypted(str(finding.file_path))]

    def _filter_public_keys(self, findings: list[ScanFinding]) -> list[ScanFinding]:
        """Filter out findings that are dotenvx public keys.

        Dotenvx public keys are EC secp256k1 keys that start with 02 or 03
        followed by 64 hex characters. These are meant to be public and
        should not be flagged as secrets.

        Args:
            findings: List of findings to filter.

        Returns:
            Filtered list excluding public key findings.
        """
        # Note: ec_pubkey_pattern is not used - we rely on simpler checks below
        # that can handle truncated previews with redaction markers

        def is_public_key(finding: ScanFinding) -> bool:
            preview = finding.secret_preview
            if not preview:
                return False
            # Remove redaction markers (****) and check the full pattern
            # EC secp256k1 compressed public keys are exactly 66 hex chars (33 bytes)
            clean = preview.replace("*", "")
            if clean.startswith(("02", "03")) and len(clean) == 66:
                # Check if remaining chars are hex
                try:
                    int(clean, 16)
                    logger.debug("Filtering dotenvx public key finding")
                    return True
                except ValueError:
                    pass
            return False

        before_count = len(findings)
        filtered = [finding for finding in findings if not is_public_key(finding)]
        after_count = len(filtered)
        if before_count != after_count:
            logger.info(f"Filtered {before_count - after_count} public key findings")
        return filtered

    def _filter_gitignored_files(self, findings: list[ScanFinding]) -> list[ScanFinding]:
        """Filter out findings from files that are in .gitignore.

        Uses `git check-ignore` to reliably determine if files are gitignored.
        This is the safest approach as it respects all .gitignore rules including
        nested .gitignore files and global gitignore configurations.

        Args:
            findings: List of findings to filter.

        Returns:
            Filtered list excluding findings from gitignored files.
        """
        import subprocess  # nosec B404

        if not findings:
            return findings

        # Group file paths by git root for accurate check-ignore behavior
        file_paths = {Path(f.file_path).resolve() for f in findings}
        if not file_paths:
            return findings

        def find_git_root(path: Path) -> Path | None:
            current = path if path.is_dir() else path.parent
            for parent in [current, *current.parents]:
                if (parent / ".git").exists():
                    return parent
            return None

        paths_by_root: dict[Path, list[Path]] = {}
        for path in file_paths:
            root = find_git_root(path)
            if root is None:
                continue
            paths_by_root.setdefault(root, []).append(path)

        gitignored_files: set[Path] = set()

        for root, paths in paths_by_root.items():
            # Use git check-ignore to check all files at once (relative to repo root)
            rel_paths: list[str] = []
            for p in paths:
                try:
                    rel_paths.append(str(p.relative_to(root)))
                except ValueError:
                    # Path is outside this repo root
                    continue

            if not rel_paths:
                continue

            try:
                result = subprocess.run(  # nosec B603, B607
                    ["git", "check-ignore", "--stdin", "-z"],
                    input="\0".join(rel_paths) + "\0",
                    capture_output=True,
                    text=True,
                    timeout=30,
                    cwd=str(root),
                )
                if result.returncode not in (0, 1):
                    logger.warning(
                        "git check-ignore failed in %s (code %s): %s",
                        root,
                        result.returncode,
                        result.stderr.strip()[:200],
                    )
                    continue

                if result.stdout:
                    ignored = [p for p in result.stdout.split("\0") if p]
                    for rel in ignored:
                        gitignored_files.add((root / rel).resolve())
            except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError) as e:
                logger.warning(f"Could not check gitignore status: {e}")
                continue

        if not gitignored_files:
            return findings

        before_count = len(findings)
        filtered = [
            finding for finding in findings
            if Path(finding.file_path).resolve() not in gitignored_files
        ]
        after_count = len(filtered)

        if before_count != after_count:
            logger.info(f"Filtered {before_count - after_count} findings from gitignored files")

        return filtered

    def check_combined_files_security(self) -> list[str]:
        """Check if combined files from partial_encryption are in .gitignore.

        Combined files contain merged secret + clear content and should ALWAYS
        be in .gitignore to prevent accidental commits of sensitive data.

        Returns:
            List of security warnings for combined files not in gitignore.
        """
        import subprocess  # nosec B404

        warnings: list[str] = []

        if not self.config.combined_files:
            return warnings

        try:
            # Use batched stdin approach for consistency with _filter_gitignored_files
            result = subprocess.run(  # nosec B603, B607
                ["git", "check-ignore", "--stdin"],
                input="\n".join(self.config.combined_files),
                capture_output=True,
                text=True,
                timeout=30,
            )
            gitignored = set(result.stdout.strip().split("\n")) if result.stdout.strip() else set()

            for combined_file in self.config.combined_files:
                if combined_file not in gitignored:
                    # File is NOT in gitignore - this is a security risk!
                    warnings.append(
                        f"⚠️  SECURITY WARNING: Combined file '{combined_file}' is NOT in .gitignore! "
                        f"This file contains sensitive secrets and may be accidentally committed. "
                        f"Add '{combined_file}' to .gitignore immediately."
                    )
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError) as e:
            logger.warning(f"Could not check gitignore for combined files: {e}")

        return warnings
