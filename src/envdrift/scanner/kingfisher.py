"""Kingfisher scanner integration with Homebrew installation support.

Kingfisher is a high-performance secret scanner by MongoDB that features:
- Over 700 built-in detection rules
- Active secret validation (checks if secrets are still valid)
- Password hash detection (bcrypt, sha512crypt, etc.)
- Language-aware parsing using Tree-sitter
- Entropy-based detection

This module provides:
- Automatic Homebrew installation on macOS and Linux
- JSON output parsing into ScanFinding objects
- Secret validation status tracking
"""

from __future__ import annotations

import json
import platform
import shutil
import subprocess  # nosec B404
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from envdrift.scanner.base import (
    FindingSeverity,
    ScanFinding,
    ScannerBackend,
    ScanResult,
)
from envdrift.scanner.patterns import redact_secret

if TYPE_CHECKING:
    from collections.abc import Callable


class KingfisherNotFoundError(Exception):
    """Kingfisher binary not found."""


class KingfisherInstallError(Exception):
    """Failed to install Kingfisher."""


# Severity mapping based on rule types
# Kingfisher doesn't have explicit severity, we map based on rule patterns
HIGH_SEVERITY_RULES = {
    "privatekey",
    "private-key",
    "private_key",
    "github",
    "slack",
    "aws",
    "azure",
    "gcp",
    "mongodb",
    "jdbc",
    "docker",
    "npm",
    "mailchimp",
    "stripe",
    "twilio",
    "sendgrid",
    "api-key",
    "api_key",
    "apikey",
    "secret-key",
    "secret_key",
    "password",
    "token",
    "credential",
}

CRITICAL_SEVERITY_RULES = {
    "password-hash",
    "password_hash",
    "bcrypt",
    "sha512crypt",
    "shadow",
    "netrc",
}


def _map_severity(rule_id: str, rule_name: str) -> FindingSeverity:
    """Map Kingfisher rule to severity level.

    Args:
        rule_id: The rule ID from Kingfisher.
        rule_name: The rule name from Kingfisher.

    Returns:
        Appropriate FindingSeverity.
    """
    combined = f"{rule_id} {rule_name}".lower()

    for pattern in CRITICAL_SEVERITY_RULES:
        if pattern in combined:
            return FindingSeverity.CRITICAL

    for pattern in HIGH_SEVERITY_RULES:
        if pattern in combined:
            return FindingSeverity.HIGH

    return FindingSeverity.MEDIUM


class KingfisherScanner(ScannerBackend):
    """Kingfisher scanner with automatic Homebrew installation.

    Kingfisher is MongoDB's secret scanner that excels at:
    - Password hash detection (bcrypt, sha512crypt, etc.)
    - Active secret validation
    - High-performance scanning with Rust + Hyperscan
    - Language-aware parsing
    - 700+ built-in detection rules

    Example:
        scanner = KingfisherScanner(auto_install=True)
        result = scanner.scan([Path(".")])
        for finding in result.findings:
            print(f"{finding.severity}: {finding.description}")
    """

    def __init__(
        self,
        auto_install: bool = True,
        validate_secrets: bool = True,
        confidence: str = "low",
        scan_binary_files: bool = True,
        extract_archives: bool = True,
        min_entropy: float | None = None,
        max_file_size_mb: int = 256,
    ) -> None:
        """Initialize the Kingfisher scanner with maximum detection options.

        Args:
            auto_install: Automatically install Kingfisher via Homebrew if not found.
            validate_secrets: Enable active secret validation (checks if secrets work).
            confidence: Minimum confidence level for reporting ('low', 'medium', 'high').
                       Use 'low' for maximum detection.
            scan_binary_files: Scan binary files for secrets.
            extract_archives: Extract and scan archive files (zip, tar, etc.).
            min_entropy: Override minimum entropy threshold. Lower = more findings.
            max_file_size_mb: Maximum file size to scan in MB.
        """
        self._auto_install = auto_install
        self._validate_secrets = validate_secrets
        self._confidence = confidence
        self._scan_binary_files = scan_binary_files
        self._extract_archives = extract_archives
        self._min_entropy = min_entropy
        self._max_file_size_mb = max_file_size_mb
        self._binary_path: Path | None = None

    @property
    def name(self) -> str:
        """Return scanner identifier."""
        return "kingfisher"

    @property
    def description(self) -> str:
        """Return scanner description."""
        return "Kingfisher secret scanner (700+ rules, password hashes, validation)"

    def is_installed(self) -> bool:
        """Check if Kingfisher is available."""
        try:
            self._find_binary()
            return True
        except KingfisherNotFoundError:
            return False

    def get_version(self) -> str | None:
        """Get installed Kingfisher version."""
        try:
            binary = self._find_binary()
            result = subprocess.run(  # nosec B603
                [str(binary), "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            # Output format: "kingfisher 1.73.0"
            if result.returncode == 0:
                parts = result.stdout.strip().split()
                return parts[-1] if parts else None
            return None
        except Exception:
            return None

    def _find_binary(self) -> Path:
        """Find the Kingfisher binary, installing if necessary.

        Returns:
            Path to the Kingfisher binary.

        Raises:
            KingfisherNotFoundError: If binary cannot be found or installed.
        """
        if self._binary_path and self._binary_path.exists():
            return self._binary_path

        # Check system PATH
        system_path = shutil.which("kingfisher")
        if system_path:
            self._binary_path = Path(system_path)
            return self._binary_path

        # Auto-install if enabled
        if self._auto_install:
            try:
                installed_path = self._install_via_homebrew()
                if installed_path:
                    self._binary_path = installed_path
                    return self._binary_path
            except KingfisherInstallError:
                pass

        raise KingfisherNotFoundError("Kingfisher not found. Install with: brew install kingfisher")

    def _install_via_homebrew(self) -> Path | None:
        """Install Kingfisher via Homebrew.

        Returns:
            Path to installed binary or None if installation failed.

        Raises:
            KingfisherInstallError: If Homebrew is not available or installation fails.
        """
        if platform.system() not in ("Darwin", "Linux"):
            raise KingfisherInstallError("Homebrew installation only supported on macOS and Linux")

        # Check if Homebrew is available
        brew_path = shutil.which("brew")
        if not brew_path:
            raise KingfisherInstallError("Homebrew not found. Install from https://brew.sh")

        try:
            # Run brew install
            result = subprocess.run(  # nosec B603
                [brew_path, "install", "kingfisher"],
                capture_output=True,
                text=True,
                timeout=120,  # 2 minute timeout
            )

            if result.returncode != 0:
                # Check if already installed (may be in stdout or stderr)
                combined_output = (result.stdout + result.stderr).lower()
                if "already installed" in combined_output:
                    pass  # Continue to find the binary
                else:
                    raise KingfisherInstallError(f"Homebrew install failed: {result.stderr}")

            # Find the installed binary
            kingfisher_path = shutil.which("kingfisher")
            if kingfisher_path:
                return Path(kingfisher_path)

            raise KingfisherInstallError("Installation succeeded but binary not found")

        except subprocess.TimeoutExpired as e:
            raise KingfisherInstallError("Installation timed out") from e
        except Exception as e:
            raise KingfisherInstallError(f"Installation failed: {e}") from e

    def install(
        self,
        progress_callback: Callable[[str], None] | None = None,
    ) -> Path | None:
        """Install Kingfisher binary via Homebrew.

        Args:
            progress_callback: Optional callback for progress updates.

        Returns:
            Path to the installed binary.
        """
        if progress_callback:
            progress_callback("Installing Kingfisher via Homebrew...")

        try:
            path = self._install_via_homebrew()
            if progress_callback and path:
                progress_callback(f"Installed Kingfisher to {path}")
            return path
        except KingfisherInstallError:
            return None

    def scan(
        self,
        paths: list[Path],
        include_git_history: bool = False,
    ) -> ScanResult:
        """Scan paths for secrets using Kingfisher.

        Args:
            paths: List of files or directories to scan.
            include_git_history: If True, scan git history as well.

        Returns:
            ScanResult containing all findings.
        """
        start_time = time.time()

        try:
            binary = self._find_binary()
        except KingfisherNotFoundError as e:
            return ScanResult(
                scanner_name=self.name,
                error=str(e),
                duration_ms=int((time.time() - start_time) * 1000),
            )

        all_findings: list[ScanFinding] = []
        total_files = 0

        for path in paths:
            if not path.exists():
                continue

            # Create temp file for JSON output
            report_path = None
            try:
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".json", delete=False
                ) as report_file:
                    report_path = Path(report_file.name)
            except OSError as e:
                return ScanResult(
                    scanner_name=self.name,
                    findings=all_findings,
                    error=f"Failed to create temp file: {e}",
                    duration_ms=int((time.time() - start_time) * 1000),
                )

            try:
                # Build command with maximum detection options
                args = [
                    str(binary),
                    "scan",
                    str(path),
                    "--format",
                    "json",
                    "-o",
                    str(report_path),
                    # Use ALL rules for maximum detection
                    "--rule",
                    "all",
                    # Set confidence level (default: low for max detection)
                    "--confidence",
                    self._confidence,
                    # Set max file size
                    "--max-file-size",
                    str(self._max_file_size_mb),
                    # Suppress progress output
                    "--quiet",
                    # Disable update checks for performance
                    "--no-update-check",
                    # Exclude common non-secret directories for performance
                    "--exclude",
                    ".venv",
                    "--exclude",
                    "venv",
                    "--exclude",
                    "node_modules",
                    "--exclude",
                    ".git",
                    "--exclude",
                    "__pycache__",
                    "--exclude",
                    ".pytest_cache",
                    "--exclude",
                    "*.pyc",
                    "--exclude",
                    "dist",
                    "--exclude",
                    "build",
                    "--exclude",
                    ".tox",
                    "--exclude",
                    ".nox",
                    "--exclude",
                    "coverage",
                    "--exclude",
                    ".mypy_cache",
                    "--exclude",
                    ".ruff_cache",
                ]

                # Git history scanning
                if include_git_history:
                    args.extend(["--git-history", "full"])
                else:
                    args.extend(["--git-history", "none"])

                # Secret validation
                if not self._validate_secrets:
                    args.append("--no-validate")

                # Binary file scanning
                if not self._scan_binary_files:
                    args.append("--no-binary")

                # Archive extraction
                if not self._extract_archives:
                    args.append("--no-extract-archives")

                # Custom entropy threshold
                if self._min_entropy is not None:
                    args.extend(["--min-entropy", str(self._min_entropy)])

                # Run scan
                # Note: Kingfisher uses exit code 200 for "findings detected"
                result = subprocess.run(  # nosec B603
                    args,
                    capture_output=True,
                    text=True,
                    timeout=600,  # 10 minute timeout for thorough scanning
                )

                # Exit codes: 0 = no findings, 200 = findings detected, others = error
                if result.returncode not in (0, 200):
                    error_msg = (
                        result.stderr.strip() if result.stderr else f"Exit code {result.returncode}"
                    )
                    return ScanResult(
                        scanner_name=self.name,
                        findings=all_findings,
                        error=f"Kingfisher error: {error_msg}",
                        duration_ms=int((time.time() - start_time) * 1000),
                    )

                # Parse JSON output from report file
                if report_path.exists() and report_path.stat().st_size > 0:
                    try:
                        findings_data = json.loads(report_path.read_text())
                        findings_list = findings_data.get("findings", [])

                        if findings_list and isinstance(findings_list, list):
                            # Count unique files with findings
                            files_with_findings = {
                                item.get("finding", {}).get("path")
                                for item in findings_list
                                if item.get("finding", {}).get("path")
                            }
                            total_files += len(files_with_findings)

                            for item in findings_list:
                                finding = self._parse_finding(item, path)
                                if finding:
                                    all_findings.append(finding)
                    except json.JSONDecodeError:
                        # Not valid JSON, might be empty or error message
                        pass

            except subprocess.TimeoutExpired:
                return ScanResult(
                    scanner_name=self.name,
                    findings=all_findings,
                    error=f"Scan timed out for {path}",
                    duration_ms=int((time.time() - start_time) * 1000),
                )
            except Exception as e:
                return ScanResult(
                    scanner_name=self.name,
                    findings=all_findings,
                    error=f"{type(e).__name__}: {e}",
                    duration_ms=int((time.time() - start_time) * 1000),
                )
            finally:
                # Clean up temp report file
                if report_path and report_path.exists():
                    report_path.unlink()

        return ScanResult(
            scanner_name=self.name,
            findings=all_findings,
            files_scanned=total_files,
            duration_ms=int((time.time() - start_time) * 1000),
        )

    def _parse_finding(self, item: dict[str, Any], base_path: Path) -> ScanFinding | None:
        """Parse a Kingfisher finding into our format.

        Args:
            item: Raw finding from Kingfisher JSON output.
            base_path: Base path for resolving relative paths.

        Returns:
            ScanFinding or None if parsing fails.
        """
        try:
            rule = item.get("rule", {})
            finding = item.get("finding", {})

            # Get file path and resolve relative paths
            file_path_str = finding.get("path", "")
            if file_path_str:
                file_path = Path(file_path_str)
                if not file_path.is_absolute():
                    file_path = (base_path / file_path_str).resolve()
            else:
                file_path = base_path

            # Get the secret snippet and redact it
            snippet = finding.get("snippet", "")
            redacted = redact_secret(snippet) if snippet else ""

            # Get rule info
            rule_id = rule.get("id", "unknown")
            rule_name = rule.get("name", rule_id)

            # Map severity based on rule type
            severity = _map_severity(rule_id, rule_name)

            # Get validation status - use allowlist for verified status
            validation = finding.get("validation", {})
            validation_status = validation.get("status", "unknown").lower()
            is_verified = validation_status in (
                "valid",
                "validated",
                "verified",
                "active",
                "successful",
                "passed",
            )

            # Get confidence and entropy
            confidence = finding.get("confidence", "medium")
            entropy_str = finding.get("entropy")
            entropy = float(entropy_str) if entropy_str else None

            return ScanFinding(
                file_path=file_path,
                line_number=finding.get("line"),
                column_number=finding.get("column_start"),
                rule_id=f"kingfisher-{rule_id}",
                rule_description=rule_name,
                description=f"Secret detected: {rule_name} (confidence: {confidence})",
                severity=severity,
                secret_preview=redacted,
                entropy=entropy,
                verified=is_verified,
                scanner=self.name,
            )
        except Exception:
            return None
