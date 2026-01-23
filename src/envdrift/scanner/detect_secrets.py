"""Yelp's detect-secrets scanner integration with auto-installation.

detect-secrets is an enterprise-grade secret detection tool with:
- 27+ built-in detectors (AWS, Azure, GitHub, JWT, etc.)
- High entropy string detection
- Keyword-based detection
- Baseline management for false positive handling

This module provides:
- Automatic pip installation
- All plugins enabled by default ("final boss" mode)
- JSON output parsing into ScanFinding objects
"""

from __future__ import annotations

import json
import shutil
import subprocess  # nosec B404
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from envdrift.scanner.base import (
    FindingSeverity,
    ScanFinding,
    ScannerBackend,
    ScanResult,
)

if TYPE_CHECKING:
    from collections.abc import Callable


def _load_constants() -> dict:
    """Load constants from the package's constants.json."""
    constants_path = Path(__file__).parent.parent / "constants.json"
    with open(constants_path) as f:
        return json.load(f)


def _get_detect_secrets_version() -> str:
    """Get the pinned detect-secrets version from constants."""
    return _load_constants().get("detect_secrets_version", "1.5.0")


class DetectSecretsNotFoundError(Exception):
    """detect-secrets not found."""

    pass


class DetectSecretsInstallError(Exception):
    """Failed to install detect-secrets."""

    pass


class DetectSecretsError(Exception):
    """detect-secrets command failed."""

    pass


# Severity mapping based on detector type (using output format names)
DETECTOR_SEVERITY: dict[str, FindingSeverity] = {
    # Critical - cloud provider credentials
    "AWS Access Key": FindingSeverity.CRITICAL,
    "Azure Storage Account access key": FindingSeverity.CRITICAL,
    "Cloudant": FindingSeverity.CRITICAL,
    "IBM Cloud IAM Key": FindingSeverity.CRITICAL,
    "IBM COS HMAC Credentials": FindingSeverity.CRITICAL,
    "SoftLayer Credentials": FindingSeverity.CRITICAL,
    # Critical - authentication tokens
    "GitHub Token": FindingSeverity.CRITICAL,
    "GitLab Token": FindingSeverity.CRITICAL,
    "Discord Bot Token": FindingSeverity.CRITICAL,
    "Slack Token": FindingSeverity.CRITICAL,
    "Stripe Access Key": FindingSeverity.CRITICAL,
    "Twilio API Key": FindingSeverity.CRITICAL,
    "Mailchimp Access Key": FindingSeverity.CRITICAL,
    "npm credentials": FindingSeverity.CRITICAL,
    "SendGrid API Key": FindingSeverity.CRITICAL,
    "Square OAuth Secret": FindingSeverity.CRITICAL,
    "OpenAI API Key": FindingSeverity.CRITICAL,
    "PyPI upload token": FindingSeverity.CRITICAL,
    "Telegram Bot Token": FindingSeverity.CRITICAL,
    # High - cryptographic keys
    "Private Key": FindingSeverity.HIGH,
    "JSON Web Token": FindingSeverity.HIGH,
    "Basic Auth Credentials": FindingSeverity.HIGH,
    # Medium - generic patterns
    "Artifactory Credentials": FindingSeverity.MEDIUM,
    "Secret Keyword": FindingSeverity.MEDIUM,
    "Base64 High Entropy String": FindingSeverity.MEDIUM,
    "Hex High Entropy String": FindingSeverity.MEDIUM,
}


class DetectSecretsInstaller:
    """Installer for detect-secrets Python package."""

    def __init__(
        self,
        version: str | None = None,
        progress_callback: Callable[[str], None] | None = None,
    ) -> None:
        """Initialize installer.

        Args:
            version: detect-secrets version to install. Uses pinned version if None.
            progress_callback: Optional callback for progress updates.
        """
        self.version = version or _get_detect_secrets_version()
        self.progress = progress_callback or (lambda x: None)

    def install(self, force: bool = False) -> bool:
        """Install detect-secrets via uv or pip.

        Args:
            force: Reinstall even if already installed.

        Returns:
            True if installation succeeded.

        Raises:
            DetectSecretsInstallError: If installation fails.
        """
        # Check if already installed
        if not force and self._is_installed():
            self.progress(f"detect-secrets v{self.version} already installed")
            return True

        self.progress(f"Installing detect-secrets v{self.version}...")

        try:
            # Try uv first (preferred in uv-managed projects)
            uv_path = shutil.which("uv")
            if uv_path:
                cmd = [
                    uv_path,
                    "pip",
                    "install",
                    "--quiet",
                    f"detect-secrets=={self.version}",
                ]
            else:
                # Fall back to pip
                cmd = [
                    sys.executable,
                    "-m",
                    "pip",
                    "install",
                    "--quiet",
                    f"detect-secrets=={self.version}",
                ]

            result = subprocess.run(  # nosec B603
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.returncode != 0:
                raise DetectSecretsInstallError(f"Install failed: {result.stderr}")

            self.progress(f"Installed detect-secrets v{self.version}")
            return True

        except subprocess.TimeoutExpired as e:
            raise DetectSecretsInstallError("Installation timed out") from e
        except Exception as e:
            raise DetectSecretsInstallError(f"Installation failed: {e}") from e

    def _is_installed(self) -> bool:
        """Check if detect-secrets is installed."""
        try:
            result = subprocess.run(  # nosec B603
                [sys.executable, "-m", "detect_secrets", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except Exception:
            return False


class DetectSecretsScanner(ScannerBackend):
    """Yelp's detect-secrets scanner - the "final boss" of secret detection.

    detect-secrets provides enterprise-grade secret detection with:
    - 27+ specialized detectors for various secret types
    - High entropy string detection (Base64 and Hex)
    - Keyword-based detection for common secret variable names
    - Configurable plugins for maximum coverage

    This scanner runs with ALL plugins enabled for maximum detection.

    Example:
        scanner = DetectSecretsScanner(auto_install=True)
        result = scanner.scan([Path(".")])
        for finding in result.findings:
            print(f"{finding.severity}: {finding.description}")
    """

    # All available plugins for "final boss" mode
    ALL_PLUGINS: ClassVar[list[str]] = [
        "ArtifactoryDetector",
        "AWSKeyDetector",
        "AzureStorageKeyDetector",
        "BasicAuthDetector",
        "CloudantDetector",
        "DiscordBotTokenDetector",
        "GitHubTokenDetector",
        "GitLabTokenDetector",
        "Base64HighEntropyString",
        "HexHighEntropyString",
        "IbmCloudIamDetector",
        "IbmCosHmacDetector",
        "JwtTokenDetector",
        "KeywordDetector",
        "MailchimpDetector",
        "NpmDetector",
        "OpenAIDetector",
        "PrivateKeyDetector",
        "PypiTokenDetector",
        "SendGridDetector",
        "SlackDetector",
        "SoftlayerDetector",
        "SquareOAuthDetector",
        "StripeDetector",
        "TelegramBotTokenDetector",
        "TwilioKeyDetector",
    ]

    def __init__(
        self,
        auto_install: bool = True,
        version: str | None = None,
    ) -> None:
        """Initialize the detect-secrets scanner.

        Args:
            auto_install: Automatically install detect-secrets if not found.
            version: Specific version to use. Uses pinned version if None.
        """
        self._auto_install = auto_install
        self._version = version or _get_detect_secrets_version()
        self._installed: bool | None = None

    @property
    def name(self) -> str:
        """Return scanner identifier."""
        return "detect-secrets"

    @property
    def description(self) -> str:
        """Return scanner description."""
        return "Yelp detect-secrets (27+ detectors, entropy, keywords)"

    def is_installed(self) -> bool:
        """Check if detect-secrets is available."""
        if self._installed is not None:
            return self._installed

        try:
            result = subprocess.run(  # nosec B603
                [sys.executable, "-m", "detect_secrets", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self._installed = result.returncode == 0
            return self._installed
        except Exception:
            self._installed = False
            return False

    def get_version(self) -> str | None:
        """Get installed detect-secrets version."""
        try:
            result = subprocess.run(  # nosec B603
                [sys.executable, "-m", "detect_secrets", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                # Output format: "detect-secrets 1.5.0"
                return result.stdout.strip().split()[-1]
            return None
        except Exception:
            return None

    def _ensure_installed(self) -> bool:
        """Ensure detect-secrets is installed.

        Returns:
            True if installed or installation succeeded.

        Raises:
            DetectSecretsNotFoundError: If not installed and auto-install disabled/failed.
        """
        if self.is_installed():
            return True

        if not self._auto_install:
            raise DetectSecretsNotFoundError(
                "detect-secrets not found. Install with: pip install detect-secrets "
                "or enable auto_install=True"
            )

        try:
            installer = DetectSecretsInstaller(version=self._version)
            installer.install()
            self._installed = True
            return True
        except DetectSecretsInstallError as e:
            raise DetectSecretsNotFoundError(
                f"detect-secrets not found and auto-install failed: {e}"
            ) from e

    def install(
        self,
        progress_callback: Callable[[str], None] | None = None,
    ) -> Path | None:
        """Install detect-secrets package.

        Args:
            progress_callback: Optional callback for progress updates.

        Returns:
            None on success (detect-secrets is a pip package, not a binary).
            Raises exception on failure.
        """
        installer = DetectSecretsInstaller(
            version=self._version,
            progress_callback=progress_callback,
        )
        installer.install()
        self._installed = True
        return None  # No binary path for pip packages

    def scan(
        self,
        paths: list[Path],
        include_git_history: bool = False,
    ) -> ScanResult:
        """Scan paths for secrets using detect-secrets.

        Args:
            paths: List of files or directories to scan.
            include_git_history: Not supported by detect-secrets (ignored).

        Returns:
            ScanResult containing all findings.
        """
        # Note: detect-secrets doesn't support git history scanning
        _ = include_git_history  # intentionally ignored (interface compatibility)
        start_time = time.time()

        try:
            self._ensure_installed()
        except DetectSecretsNotFoundError as e:
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

            try:
                # Build command with all plugins enabled ("final boss" mode)
                # When scanning a directory, use "." as path since cwd is set to the directory
                # When scanning a file, use the filename since cwd is set to parent
                if path.is_dir():
                    scan_path = "."
                    working_dir = str(path)
                else:
                    scan_path = path.name
                    working_dir = str(path.parent)

                args = [
                    sys.executable,
                    "-m",
                    "detect_secrets",
                    "scan",
                    # Default: only scan git tracked files (fast, respects .gitignore)
                    "--force-use-all-plugins",  # Enable ALL 27+ detectors
                    "--exclude-files",
                    r"(^|.*/)(node_modules|\.venv|\.git|__pycache__|\.min\.|dist|build|vendor|coverage)(/.*|$)",
                    scan_path,
                ]

                result = subprocess.run(  # nosec B603
                    args,
                    capture_output=True,
                    text=True,
                    timeout=300,  # 5 minute timeout
                    cwd=working_dir,
                )

                # detect-secrets outputs JSON baseline to stdout
                if result.stdout.strip():
                    try:
                        baseline = json.loads(result.stdout)
                        findings = self._parse_baseline(baseline, path)
                        all_findings.extend(findings)
                        total_files += len(baseline.get("results", {}))
                    except json.JSONDecodeError:
                        # Log stderr for debugging if JSON parsing fails
                        if result.stderr:
                            return ScanResult(
                                scanner_name=self.name,
                                findings=all_findings,
                                error=f"detect-secrets output error: {result.stderr[:200]}",
                                duration_ms=int((time.time() - start_time) * 1000),
                            )

                if result.returncode != 0:
                    error_msg = (
                        result.stderr.strip()
                        or result.stdout.strip()
                        or f"detect-secrets scan failed for {path} (exit code {result.returncode})"
                    )
                    return ScanResult(
                        scanner_name=self.name,
                        findings=all_findings,
                        error=error_msg,
                        duration_ms=int((time.time() - start_time) * 1000),
                    )

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
                    error=str(e),
                    duration_ms=int((time.time() - start_time) * 1000),
                )

        return ScanResult(
            scanner_name=self.name,
            findings=all_findings,
            files_scanned=total_files,
            duration_ms=int((time.time() - start_time) * 1000),
        )

    def _parse_baseline(self, baseline: dict[str, Any], base_path: Path) -> list[ScanFinding]:
        """Parse detect-secrets baseline into findings.

        Args:
            baseline: The detect-secrets baseline JSON.
            base_path: Base path for resolving relative paths.

        Returns:
            List of ScanFinding objects.
        """
        findings: list[ScanFinding] = []
        results = baseline.get("results", {})

        for file_path_str, secrets in results.items():
            # Resolve file path - handle both directory and file base paths
            file_path = Path(file_path_str)
            if not file_path.is_absolute():
                # If base_path is a file, paths are relative to its parent directory
                if base_path.is_file():
                    file_path = base_path.parent / file_path
                else:
                    file_path = base_path / file_path

            for secret in secrets:
                finding = self._parse_secret(secret, file_path)
                if finding:
                    findings.append(finding)

        return findings

    def _parse_secret(self, secret: dict[str, Any], file_path: Path) -> ScanFinding | None:
        """Parse a single secret entry into a finding.

        Args:
            secret: Secret entry from baseline.
            file_path: Path to the file containing the secret.

        Returns:
            ScanFinding or None if parsing fails.
        """
        try:
            detector_type = secret.get("type", "unknown")
            line_number = secret.get("line_number")

            # Get severity based on detector type
            severity = DETECTOR_SEVERITY.get(detector_type, FindingSeverity.HIGH)

            # Get the hashed secret (detect-secrets doesn't expose raw secrets)
            hashed_secret = secret.get("hashed_secret", "")
            # Use first 8 chars of hash as preview
            preview = f"[hash:{hashed_secret[:8]}...]" if hashed_secret else ""

            # Check if it's been verified as false positive
            is_false_positive = secret.get("is_secret") is False

            return ScanFinding(
                file_path=file_path,
                line_number=line_number,
                rule_id=f"detect-secrets-{detector_type.lower().replace(' ', '-')}",
                rule_description=detector_type,
                description=f"Secret detected by {detector_type}",
                severity=severity if not is_false_positive else FindingSeverity.INFO,
                secret_preview=preview,
                secret_hash=hashed_secret,
                scanner=self.name,
            )
        except Exception:
            return None
