"""Trivy scanner integration with auto-installation.

Trivy is a comprehensive security scanner from Aqua Security.
This module provides:
- Automatic binary download and installation
- Cross-platform support (macOS, Linux, Windows)
- JSON output parsing into ScanFinding objects
- Filesystem secret scanning
"""

from __future__ import annotations

import json
import platform
import shutil
import stat
import subprocess  # nosec B404
import tarfile
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from envdrift.scanner.base import (
    FindingSeverity,
    ScanFinding,
    ScannerBackend,
    ScanResult,
)
from envdrift.scanner.patterns import redact_secret
from envdrift.scanner.platform_utils import (
    get_platform_info,
    get_venv_bin_dir,
    safe_extract_tar,
    safe_extract_zip,
)

if TYPE_CHECKING:
    from collections.abc import Callable


def _load_constants() -> dict:
    """Load constants from the package's constants.json."""
    constants_path = Path(__file__).parent.parent / "constants.json"
    with open(constants_path) as f:
        return json.load(f)


def _get_trivy_version() -> str:
    """Get the pinned trivy version from constants."""
    return _load_constants().get("trivy_version", "0.58.0")


def _get_trivy_download_urls() -> dict[str, str]:
    """Get download URL templates from constants."""
    return _load_constants().get("trivy_download_urls", {})


# Severity mapping from trivy to our severity levels
SEVERITY_MAP: dict[str, FindingSeverity] = {
    "CRITICAL": FindingSeverity.CRITICAL,
    "HIGH": FindingSeverity.HIGH,
    "MEDIUM": FindingSeverity.MEDIUM,
    "LOW": FindingSeverity.LOW,
    "UNKNOWN": FindingSeverity.INFO,
}


class TrivyNotFoundError(Exception):
    """Trivy binary not found."""

    pass


class TrivyInstallError(Exception):
    """Failed to install trivy."""

    pass


class TrivyError(Exception):
    """Trivy command failed."""

    pass


def get_trivy_path() -> Path:
    """Get the expected path to the trivy binary.

    Returns:
        Path where trivy should be installed.
    """
    bin_dir = get_venv_bin_dir()
    binary_name = "trivy.exe" if platform.system() == "Windows" else "trivy"
    return bin_dir / binary_name


class TrivyInstaller:
    """Installer for trivy binary."""

    # Download URLs by platform
    DOWNLOAD_URL_TEMPLATE = (
        "https://github.com/aquasecurity/trivy/releases/download/"
        "v{version}/trivy_{version}_{os}-{arch}.{ext}"
    )

    PLATFORM_MAP: ClassVar[dict[tuple[str, str], tuple[str, str, str]]] = {
        ("Darwin", "x86_64"): ("macOS", "64bit", "tar.gz"),
        ("Darwin", "arm64"): ("macOS", "ARM64", "tar.gz"),
        ("Linux", "x86_64"): ("Linux", "64bit", "tar.gz"),
        ("Linux", "arm64"): ("Linux", "ARM64", "tar.gz"),
        ("Windows", "x86_64"): ("windows", "64bit", "zip"),
    }

    def __init__(
        self,
        version: str | None = None,
        progress_callback: Callable[[str], None] | None = None,
    ) -> None:
        """Initialize installer.

        Args:
            version: Trivy version to install. Uses pinned version if None.
            progress_callback: Optional callback for progress updates.
        """
        self.version = version or _get_trivy_version()
        self.progress = progress_callback or (lambda x: None)

    def get_download_url(self) -> str:
        """Get the platform-specific download URL.

        Returns:
            URL to download trivy for the current platform.

        Raises:
            TrivyInstallError: If platform is not supported.
        """
        system, machine = get_platform_info()
        key = (system, machine)

        if key not in self.PLATFORM_MAP:
            supported = ", ".join(f"{s}/{m}" for s, m in self.PLATFORM_MAP)
            raise TrivyInstallError(
                f"Unsupported platform: {system} {machine}. Supported: {supported}"
            )

        os_name, arch, ext = self.PLATFORM_MAP[key]

        # Check if we have custom URLs in constants
        custom_urls = _get_trivy_download_urls()
        url_key = f"{system.lower()}_{machine.lower().replace('x86_64', 'amd64')}"
        if url_key in custom_urls:
            return custom_urls[url_key].format(version=self.version)

        return self.DOWNLOAD_URL_TEMPLATE.format(
            version=self.version,
            os=os_name,
            arch=arch,
            ext=ext,
        )

    def download_and_extract(self, target_path: Path) -> None:
        """Download and extract trivy to the target path.

        Args:
            target_path: Where to install the trivy binary.

        Raises:
            TrivyInstallError: If download or extraction fails.
        """
        url = self.get_download_url()
        self.progress(f"Downloading trivy v{self.version}...")

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            archive_name = url.split("/")[-1]
            archive_path = tmp_path / archive_name

            # Download
            try:
                urllib.request.urlretrieve(url, archive_path)  # nosec B310
            except Exception as e:
                raise TrivyInstallError(f"Download failed: {e}") from e

            self.progress("Extracting...")

            # Extract based on archive type
            if archive_name.endswith(".tar.gz"):
                self._extract_tar_gz(archive_path, tmp_path)
            elif archive_name.endswith(".zip"):
                self._extract_zip(archive_path, tmp_path)
            else:
                raise TrivyInstallError(f"Unknown archive format: {archive_name}")

            # Find the binary
            binary_name = "trivy.exe" if platform.system() == "Windows" else "trivy"
            extracted_binary = None

            for f in tmp_path.rglob(binary_name):
                if f.is_file():
                    extracted_binary = f
                    break

            if not extracted_binary:
                raise TrivyInstallError(f"Binary '{binary_name}' not found in archive")

            # Ensure target directory exists
            target_path.parent.mkdir(parents=True, exist_ok=True)

            # Copy to target
            shutil.copy2(extracted_binary, target_path)

            # Make executable (Unix)
            if platform.system() != "Windows":
                target_path.chmod(
                    target_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
                )

            self.progress(f"Installed to {target_path}")

    def _extract_tar_gz(self, archive_path: Path, target_dir: Path) -> None:
        """Extract a tar.gz archive with path traversal protection."""
        with tarfile.open(archive_path, "r:gz") as tar:
            safe_extract_tar(tar, target_dir, TrivyInstallError)

    def _extract_zip(self, archive_path: Path, target_dir: Path) -> None:
        """Extract a zip archive with path traversal protection."""
        with zipfile.ZipFile(archive_path, "r") as zip_ref:
            safe_extract_zip(zip_ref, target_dir, TrivyInstallError)

    def install(self, force: bool = False) -> Path:
        """Install trivy binary.

        Args:
            force: Reinstall even if already installed.

        Returns:
            Path to the installed binary.
        """
        target_path = get_trivy_path()

        if target_path.exists() and not force:
            # Verify version
            try:
                result = subprocess.run(  # nosec B603
                    [str(target_path), "version", "--format", "json"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if self.version in result.stdout:
                    self.progress(f"trivy v{self.version} already installed")
                    return target_path
            except Exception:
                # Version check failed (binary corrupt or incompatible), will reinstall
                pass

        self.download_and_extract(target_path)
        return target_path


class TrivyScanner(ScannerBackend):
    """Trivy scanner with automatic binary installation.

    Trivy detects secrets using:
    - Pattern matching against known secret formats (AWS, GCP, GitHub, etc.)
    - Custom regex rules
    - Multiple target types (filesystem, images, repos)

    Example:
        scanner = TrivyScanner(auto_install=True)
        result = scanner.scan([Path(".")])
        for finding in result.findings:
            print(f"{finding.severity}: {finding.description}")
    """

    def __init__(
        self,
        auto_install: bool = True,
        version: str | None = None,
    ) -> None:
        """Initialize the trivy scanner.

        Args:
            auto_install: Automatically install trivy if not found.
            version: Specific version to use. Uses pinned version if None.
        """
        self._auto_install = auto_install
        self._version = version or _get_trivy_version()
        self._binary_path: Path | None = None

    @property
    def name(self) -> str:
        """Return scanner identifier."""
        return "trivy"

    @property
    def description(self) -> str:
        """Return scanner description."""
        return "Trivy secret scanner (comprehensive multi-target security scanner)"

    def is_installed(self) -> bool:
        """Check if trivy is available."""
        try:
            self._find_binary()
            return True
        except TrivyNotFoundError:
            return False

    def get_version(self) -> str | None:
        """Get installed trivy version."""
        try:
            binary = self._find_binary()
            result = subprocess.run(  # nosec B603
                [str(binary), "version", "--format", "json"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                try:
                    data = json.loads(result.stdout)
                    return data.get("Version", None)
                except json.JSONDecodeError:
                    pass
            return None
        except Exception:
            return None

    def _find_binary(self) -> Path:
        """Find the trivy binary, installing if necessary.

        Returns:
            Path to the trivy binary.

        Raises:
            TrivyNotFoundError: If binary cannot be found or installed.
        """
        if self._binary_path and self._binary_path.exists():
            return self._binary_path

        # Check in venv first
        venv_path = get_trivy_path()
        if venv_path.exists():
            self._binary_path = venv_path
            return venv_path

        # Check system PATH
        system_path = shutil.which("trivy")
        if system_path:
            self._binary_path = Path(system_path)
            return self._binary_path

        # Auto-install if enabled
        if self._auto_install:
            try:
                installer = TrivyInstaller(version=self._version)
                self._binary_path = installer.install()
                return self._binary_path
            except TrivyInstallError as e:
                raise TrivyNotFoundError(f"trivy not found and auto-install failed: {e}") from e

        raise TrivyNotFoundError(
            "trivy not found. Install with: brew install trivy or enable auto_install=True"
        )

    def install(
        self,
        progress_callback: Callable[[str], None] | None = None,
    ) -> Path | None:
        """Install trivy binary.

        Args:
            progress_callback: Optional callback for progress updates.

        Returns:
            Path to the installed binary.
        """
        installer = TrivyInstaller(
            version=self._version,
            progress_callback=progress_callback,
        )
        self._binary_path = installer.install()
        return self._binary_path

    def scan(
        self,
        paths: list[Path],
        include_git_history: bool = False,
    ) -> ScanResult:
        """Scan paths for secrets using trivy.

        Args:
            paths: List of files or directories to scan.
            include_git_history: If True, scan git repository. Note: trivy fs
                                 doesn't scan git history by default.

        Returns:
            ScanResult containing all findings.
        """
        start_time = time.time()

        try:
            binary = self._find_binary()
        except TrivyNotFoundError as e:
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
                # Build command for filesystem scan with secret scanner
                args = [
                    str(binary),
                    "fs",
                    "--scanners",
                    "secret",
                    "--format",
                    "json",
                    "--quiet",  # Suppress progress output
                    str(path),
                ]

                result = subprocess.run(  # nosec B603
                    args,
                    capture_output=True,
                    text=True,
                    timeout=300,  # 5 minute timeout
                )

                # Check for non-zero exit code indicating an error
                # Note: trivy returns non-zero only for actual errors (not for found secrets)
                if result.returncode != 0 and not result.stdout.strip():
                    error_msg = (
                        result.stderr.strip()
                        or result.stdout.strip()
                        or f"trivy scan failed for {path}"
                    )
                    return ScanResult(
                        scanner_name=self.name,
                        findings=all_findings,
                        error=error_msg,
                        duration_ms=int((time.time() - start_time) * 1000),
                    )

                # Parse JSON output
                if result.stdout.strip():
                    try:
                        scan_data = json.loads(result.stdout)
                        findings, files = self._parse_output(scan_data, path)
                        all_findings.extend(findings)
                        total_files += files
                    except json.JSONDecodeError:
                        # Not valid JSON, might be error message
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
                    error=str(e),
                    duration_ms=int((time.time() - start_time) * 1000),
                )

        return ScanResult(
            scanner_name=self.name,
            findings=all_findings,
            files_scanned=total_files,
            duration_ms=int((time.time() - start_time) * 1000),
        )

    def _parse_output(
        self, scan_data: dict[str, Any], base_path: Path
    ) -> tuple[list[ScanFinding], int]:
        """Parse trivy JSON output into findings.

        Args:
            scan_data: Parsed JSON output from trivy.
            base_path: Base path for resolving relative paths.

        Returns:
            Tuple of (findings list, files scanned count).
        """
        findings: list[ScanFinding] = []
        files_scanned = 0

        # Trivy output structure: { "Results": [...] }
        results = scan_data.get("Results", [])

        for result in results:
            target = result.get("Target", "")
            if target:
                files_scanned += 1

            # Get secrets from result
            secrets = result.get("Secrets", [])
            for secret in secrets:
                finding = self._parse_secret(secret, target, base_path)
                if finding:
                    findings.append(finding)

        return findings, files_scanned

    def _parse_secret(
        self, secret: dict[str, Any], target: str, base_path: Path
    ) -> ScanFinding | None:
        """Parse a single trivy secret into a ScanFinding.

        Args:
            secret: Secret data from trivy output.
            target: Target file path.
            base_path: Base path for resolving relative paths.

        Returns:
            ScanFinding or None if parsing fails.
        """
        try:
            # Get file path
            file_path = Path(target)
            if not file_path.is_absolute():
                # If base_path is a file, paths are relative to its parent directory
                if base_path.is_file():
                    file_path = base_path.parent / file_path
                else:
                    file_path = base_path / file_path

            # Get the secret match and redact it
            matched = secret.get("Match", "")
            redacted = redact_secret(matched) if matched else ""

            # Map rule ID
            rule_id: str = secret.get("RuleID", "unknown")
            category: str = secret.get("Category", "Secret")
            title: str = secret.get("Title", rule_id)

            # Map severity
            severity_str = secret.get("Severity", "HIGH")
            severity = SEVERITY_MAP.get(severity_str.upper(), FindingSeverity.HIGH)

            return ScanFinding(
                file_path=file_path,
                line_number=secret.get("StartLine"),
                column_number=None,
                rule_id=f"trivy-{rule_id}",
                rule_description=title,
                description=f"{category}: {title}",
                severity=severity,
                secret_preview=redacted,
                commit_sha=None,
                commit_author=None,
                commit_date=None,
                entropy=None,
                scanner=self.name,
            )
        except Exception:
            return None
