"""Scan engine - orchestrates multiple secret scanners.

The ScanEngine is responsible for:
- Initializing and managing scanner instances
- Running scans across multiple scanners in parallel
- Aggregating and deduplicating findings
- Handling scanner failures gracefully
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from envdrift.env_files import resolve_custom_env_file
from envdrift.scanner.base import (
    AggregatedScanResult,
    FindingSeverity,
    ScanFinding,
    ScannerBackend,
    ScanResult,
)
from envdrift.scanner.ignores import IgnoreConfig, IgnoreFilter
from envdrift.scanner.native import (
    NativeScanner,
    _content_is_encrypted,
    _is_encrypted_value_line,
)
from envdrift.scanner.patterns import hash_secret

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
        mapped_env_files: Custom env files from vault.sync mappings.
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
    mapped_env_files: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, config: dict) -> GuardConfig:
        """
        Construct a GuardConfig from a parsed configuration dictionary (for example, from envdrift.toml).

        Parses the "guard" section to enable scanner flags, normalization of the "scanners" entry (accepts a string or list; defaults to ["native", "gitleaks"]), and reads other guard settings such as auto_install, include_history, entropy checks, ignore paths/rules, and skip_clear_files. Interprets "fail_on_severity" case-insensitively and falls back to FindingSeverity.HIGH on invalid values.

        Also reads partial-encryption awareness fields so SDK callers get the same
        false-positive/false-negative protection as the CLI: ``allowed_clear_files``
        and ``combined_files`` are pulled from ``partial_encryption.environments``,
        and ``mapped_env_files`` from ``vault.sync.mappings`` (resolved relative to
        each mapping's ``folder_path``, mirroring the CLI construction).

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

        allowed_clear_files, combined_files, mapped_env_files = cls._partial_encryption_files(
            config
        )

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
            allowed_clear_files=allowed_clear_files,
            combined_files=combined_files,
            mapped_env_files=mapped_env_files,
        )

    @staticmethod
    def _partial_encryption_files(
        config: dict,
    ) -> tuple[list[str], list[str], list[str]]:
        """Extract partial-encryption-aware file lists from a raw config dict.

        Mirrors the CLI construction in ``cli_commands/guard.py`` so SDK callers
        that build a config via :meth:`from_dict` keep the same awareness of
        intentionally-unencrypted ``.clear`` files, combined files, and custom
        mapped env files.

        Returns:
            A tuple of ``(allowed_clear_files, combined_files, mapped_env_files)``.
        """
        allowed_clear_files: list[str] = []
        combined_files: list[str] = []
        mapped_env_files: list[str] = []

        partial = config.get("partial_encryption", {})
        if partial.get("enabled", False):
            for env in partial.get("environments", []):
                # Skip malformed entries (None/str/list) so a bad SDK config is
                # ignored rather than crashing this pure constructor.
                if not isinstance(env, dict):
                    continue
                clear_file = env.get("clear_file")
                if clear_file:
                    allowed_clear_files.append(clear_file)
                combined_file = env.get("combined_file")
                if combined_file:
                    combined_files.append(combined_file)

        mappings = config.get("vault", {}).get("sync", {}).get("mappings", [])
        for mapping in mappings:
            if not isinstance(mapping, dict):
                continue
            env_file = mapping.get("env_file")
            folder_path = mapping.get("folder_path")
            if not env_file or not folder_path:
                continue
            try:
                resolved = resolve_custom_env_file(Path(folder_path), env_file).resolve()
            except (TypeError, ValueError):
                # Invalid env_file (escapes folder_path); skip rather than crash.
                # The CLI surfaces this as an error, but from_dict is a pure
                # constructor for SDK callers and must not raise here.
                continue
            mapped_env_files.append(str(resolved))

        return allowed_clear_files, combined_files, mapped_env_files


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
                    mapped_env_files=self.config.mapped_env_files,
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
            logger.debug(f"Scanner {result.scanner_name}: {len(result.findings)} findings")

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

        By default, duplicates are identified by file path, line number, rule ID,
        and the secret's hash (when present). Including the hash means two
        *distinct* secrets that match the same rule on the same line (e.g. two
        AWS keys on one ``.env`` line, #348) are both reported, while the same
        secret matched by the same rule at one location still collapses to one
        finding. Because the rule ID is part of the key and each scanner
        namespaces its rule IDs, the *same* secret flagged by two *different*
        scanners keeps two findings on this default path; cross-scanner
        same-secret collapse happens only under ``skip_duplicate`` (which keys on
        the secret hash alone). Findings without a secret value (policy findings)
        fall back to the location-only key so they continue to deduplicate by
        location.
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
        for finding in findings:
            key = self._dedup_key(finding)
            existing = seen.get(key)
            if existing is None or self._should_replace(finding, existing):
                seen[key] = finding

        survivors = list(seen.values())
        if not self.config.skip_duplicate:
            survivors = self._drop_hashless_duplicates(survivors)

        # Sort by severity (highest first), then by file path
        return sorted(
            survivors,
            key=lambda f: (f.severity, str(f.file_path), f.line_number or 0),
            reverse=True,
        )

    def _dedup_key(self, finding: ScanFinding) -> tuple:
        """Build the dedup key for ``finding`` under the active config.

        ``skip_duplicate``: key on the secret value only -- the secret hash when
        present (accurate), else the preview (may collide), else the location for
        policy findings with no secret value. This is the only mode that collapses
        the same secret across scanners.

        Default: ``(file, line, rule, secret_hash)``. Two distinct secrets matching
        the same rule on one line have different hashes, so both survive (#348);
        the same secret matched by the same rule at one location shares a hash and
        collapses. Rule IDs are scanner-namespaced (e.g. ``gitleaks-...`` vs native
        bare ids), so the same secret found by two different scanners has different
        rule IDs and is *not* collapsed here. Policy findings carry no secret_hash
        and keep the historical location-only key.
        """
        if self.config.skip_duplicate:
            if finding.secret_hash:
                return (finding.secret_hash,)
            if finding.secret_preview:
                return (finding.secret_preview,)
            return (finding.file_path, finding.line_number, finding.rule_id)
        return (
            finding.file_path,
            finding.line_number,
            finding.rule_id,
            finding.secret_hash or None,
        )

    @staticmethod
    def _tie_key(finding: ScanFinding) -> tuple:
        """Deterministic tie-breaker for otherwise-equal duplicate findings."""
        return (
            str(finding.file_path),
            finding.line_number or 0,
            finding.rule_id,
            finding.scanner,
        )

    @classmethod
    def _should_replace(cls, finding: ScanFinding, existing: ScanFinding) -> bool:
        """Whether ``finding`` should replace ``existing`` at the same dedup key.

        Preference order, most significant first: higher severity, then verified
        over unverified, then a real ``secret_hash`` over none, then a stable
        tie-break so dedup is deterministic across runs.
        """
        if finding.severity != existing.severity:
            return finding.severity > existing.severity
        if finding.verified != existing.verified:
            return finding.verified
        if bool(finding.secret_hash) != bool(existing.secret_hash):
            return bool(finding.secret_hash)
        return cls._tie_key(finding) < cls._tie_key(existing)

    @staticmethod
    def _drop_hashless_duplicates(survivors: list[ScanFinding]) -> list[ScanFinding]:
        """Drop hashless findings that merely duplicate a co-located hashed one.

        A hashless finding (no extractable secret value) at the same
        ``(file, line, rule)`` as one or more hashed findings is the less
        precise duplicate of a hashed one -- drop it so we keep the hashed
        finding(s). This preserves "prefer the hashed finding" for the
        one-secret case without merging *distinct* hashed secrets that
        legitimately share a line (#348), since those each keep their own
        hashed key.

        A hashless finding is kept when it carries *higher* severity than every
        co-located hashed finding, so pruning never lowers the severity reported
        at a location (the hashed finding is more precise, but the hashless one
        may flag a more serious problem -- keep both rather than lose signal).
        """
        # Highest severity among hashed findings at each (file, line, rule).
        hashed_max_severity: dict[tuple, FindingSeverity] = {}
        for f in survivors:
            if not f.secret_hash:
                continue
            loc = (f.file_path, f.line_number, f.rule_id)
            current = hashed_max_severity.get(loc)
            if current is None or f.severity > current:
                hashed_max_severity[loc] = f.severity

        kept: list[ScanFinding] = []
        for f in survivors:
            if f.secret_hash:
                kept.append(f)
                continue
            co_located = hashed_max_severity.get((f.file_path, f.line_number, f.rule_id))
            if co_located is None or f.severity > co_located:
                kept.append(f)
        return kept

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
        """Filter out findings from the *encrypted portions* of files.

        Encrypted files contain ciphertext which can trigger false positives
        from external scanners (detect-secrets, infisical, etc.) that detect
        high-entropy strings or hex patterns in the encrypted values.

        The filter is line-aware so it does not discard real findings on the
        cleartext portion of a *combined* partial-encryption file (which
        interleaves dotenvx-encrypted secret lines with plaintext config). A
        finding survives when it points at a specific line that is NOT itself an
        encrypted value; a finding on a ciphertext line, or one with no line
        information (e.g. a blob flagged by an external scanner), is dropped.

        This applies centrally to ALL scanners.

        Args:
            findings: List of findings to filter.

        Returns:
            Filtered list excluding findings on encrypted content.
        """
        # Cache per-file encryption status and (lazily) split lines.
        encrypted_files: set[str] = set()
        checked_files: set[str] = set()
        lines_cache: dict[str, list[str]] = {}

        def is_file_encrypted(file_path: str) -> bool:
            if file_path in encrypted_files:
                return True
            if file_path in checked_files:
                return False

            checked_files.add(file_path)
            try:
                with open(file_path, encoding="utf-8", errors="ignore") as f:
                    # Read the whole file (#368): the dotenvx ``encrypted:`` marker
                    # is a *value* prefix that can sit far past the first 2KB in a
                    # combined file (cleartext config first, encrypted secrets
                    # after). A 2KB window misjudged such files as unencrypted and
                    # leaked their ciphertext as findings. This matches line_at()
                    # and the native scanner, which both read full content.
                    content = f.read()
                    # Structure-aware encryption check (#348): require the dotenvx
                    # marker in value position / canonical SOPS envelopes, not a bare
                    # substring (which misfired on plaintext mentioning "encrypted:").
                    if _content_is_encrypted(content):
                        encrypted_files.add(file_path)
                        return True
            except OSError:
                pass
            return False

        def line_at(file_path: str, line_number: int) -> str:
            if file_path not in lines_cache:
                try:
                    with open(file_path, encoding="utf-8", errors="ignore") as f:
                        lines_cache[file_path] = f.read().splitlines()
                except OSError:
                    lines_cache[file_path] = []
            lines = lines_cache[file_path]
            if 1 <= line_number <= len(lines):
                return lines[line_number - 1]
            return ""

        def keep(finding: ScanFinding) -> bool:
            file_path = str(finding.file_path)
            if not is_file_encrypted(file_path):
                return True
            # File has encryption markers. Keep findings on a specific cleartext
            # line; drop findings on a ciphertext line or with no line info.
            if finding.line_number is None:
                return False
            return not _is_encrypted_value_line(line_at(file_path, finding.line_number))

        return [finding for finding in findings if keep(finding)]

    def _filter_public_keys(self, findings: list[ScanFinding]) -> list[ScanFinding]:
        """Filter out findings that are dotenvx public keys.

        Dotenvx public keys are EC secp256k1 compressed keys (``02``/``03`` + 64
        hex chars). They are public by definition and should not be flagged as
        secrets.

        Production findings only carry a *redacted* ``secret_preview`` (the
        middle is collapsed to ``*``) and a one-way ``secret_hash`` — never the
        full secret. The previous implementation compared the preview's length to
        66, which is never true after redaction, so the filter was dead on real
        data (#370). The native scanner now drops these keys at detection by
        value shape; this central filter salvages cross-scanner coverage
        (gitleaks/trufflehog/native, all of which hash with ``hash_secret``) by
        matching each finding's ``secret_hash`` against the hash of the public
        key declared in its own file's ``DOTENV_PUBLIC_KEY*`` line.

        Args:
            findings: List of findings to filter.

        Returns:
            Filtered list excluding public key findings.
        """
        pubkey_hashes_by_file = self._collect_public_key_hashes(findings)
        if not pubkey_hashes_by_file:
            return findings

        def is_public_key(finding: ScanFinding) -> bool:
            # Per-file: a finding is only a public key if ITS OWN file declares
            # that value on a DOTENV_PUBLIC_KEY line. A global set would let a key
            # in file A suppress a same-hash finding in file B (cross-file FN).
            if not finding.secret_hash:
                return False
            file_hashes = pubkey_hashes_by_file.get(str(finding.file_path))
            if file_hashes and finding.secret_hash in file_hashes:
                logger.debug("Filtering dotenvx public key finding by hash")
                return True
            return False

        before_count = len(findings)
        filtered = [finding for finding in findings if not is_public_key(finding)]
        after_count = len(filtered)
        if before_count != after_count:
            logger.info(f"Filtered {before_count - after_count} public key findings")
        return filtered

    # Matches a dotenvx public-key assignment and captures the compressed EC key.
    _DOTENV_PUBLIC_KEY_RE = re.compile(
        r'^\s*DOTENV_PUBLIC_KEY[A-Za-z0-9_]*\s*=\s*["\']?(0[23][0-9a-fA-F]{64})["\']?'
    )

    def _collect_public_key_hashes(self, findings: list[ScanFinding]) -> dict[str, set[str]]:
        """Map each referenced file to the ``hash_secret`` values of the dotenvx
        public keys declared IN THAT FILE.

        The public key is present, in cleartext, on the file's
        ``DOTENV_PUBLIC_KEY*`` line. We hash it the same way scanners hash the
        secret they report, so a finding whose value *is* that file's public key
        matches by ``secret_hash`` and gets dropped. Per-file (not a global set)
        so a key in one file can't suppress findings in another. Each file is
        parsed once.
        """
        by_file: dict[str, set[str]] = {}
        for finding in findings:
            file_path = str(finding.file_path)
            if file_path in by_file:
                continue
            hashes: set[str] = set()
            try:
                with open(file_path, encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        match = self._DOTENV_PUBLIC_KEY_RE.match(line)
                        if match:
                            hashes.add(hash_secret(match.group(1)))
            except OSError:
                hashes = set()
            by_file[file_path] = hashes
        return by_file

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
                # Explicit UTF-8: ``text=True`` alone decodes (and encodes the
                # stdin paths) with the platform locale codec — cp1252 on Windows
                # — which mis-handles non-ASCII filenames (#453). ``-z`` already
                # makes git print paths verbatim (no core.quotepath quoting).
                result = subprocess.run(  # nosec B603, B607
                    ["git", "check-ignore", "--stdin", "-z"],
                    input="\0".join(rel_paths) + "\0",
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
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
            finding
            for finding in findings
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

        from envdrift.utils.git import get_git_root

        warnings: list[str] = []

        if not self.config.combined_files:
            return warnings

        # Config-relative combined-file paths resolve against the repo root, so run
        # git check-ignore with cwd there (mirrors _filter_gitignored_files) — not
        # the process cwd, which may be a subdirectory and mis-resolve the paths.
        # Outside a git repo there is no .gitignore to consult, so skip the check
        # rather than emit a false "NOT in .gitignore" warning for every file (#413).
        git_root = get_git_root(Path.cwd())
        if git_root is None:
            logger.warning("Not in a git repository; skipping combined-file .gitignore check")
            return warnings

        try:
            # Use batched stdin approach for consistency with _filter_gitignored_files.
            # Explicit UTF-8: ``text=True`` alone uses the platform locale codec
            # (cp1252 on Windows), which mis-handles non-ASCII filenames (#453).
            # ``core.quotepath=false`` makes git echo non-ASCII paths verbatim
            # instead of C-quoted ("\347..." octal escapes), so the stdout lines
            # compare equal to the configured combined-file names.
            result = subprocess.run(  # nosec B603, B607
                ["git", "-c", "core.quotepath=false", "check-ignore", "--stdin"],
                input="\n".join(self.config.combined_files),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
                cwd=str(git_root),
            )
            # git check-ignore exits 0 (some paths ignored) or 1 (none ignored) on
            # success; anything else (e.g. 128) is an error reported on stderr with
            # no exception raised. Skip on error so an empty stdout is not mistaken
            # for "nothing ignored", which would flag every file (#413).
            if result.returncode not in (0, 1):
                logger.warning(
                    "git check-ignore failed in %s (code %s): %s",
                    git_root,
                    result.returncode,
                    result.stderr.strip()[:200],
                )
                return warnings

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
