"""Talisman scanner integration with auto-installation.

Talisman is a pre-commit tool from ThoughtWorks that scans for secrets.
This module provides:
- Automatic binary download and installation
- Cross-platform support (macOS, Linux, Windows)
- JSON report parsing into ScanFinding objects
- Git history scanning support
"""

from __future__ import annotations

import json
import platform
import shutil
import stat
import subprocess  # nosec B404
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from envdrift.scanner.base import (
    FindingSeverity,
    ScanFinding,
    ScannerBackend,
    ScanResult,
)
from envdrift.scanner.patterns import redact_secret
from envdrift.scanner.platform_utils import get_platform_info, get_venv_bin_dir

if TYPE_CHECKING:
    from collections.abc import Callable


def _load_constants() -> dict:
    """Load constants from the package's constants.json."""
    constants_path = Path(__file__).parent.parent / "constants.json"
    with open(constants_path) as f:
        return json.load(f)


def _get_talisman_version() -> str:
    """Get the pinned talisman version from constants."""
    return _load_constants().get("talisman_version", "1.32.0")


def _get_talisman_download_urls() -> dict[str, str]:
    """Get download URL templates from constants."""
    return _load_constants().get("talisman_download_urls", {})


# Severity mapping from talisman to our severity levels
SEVERITY_MAP: dict[str, FindingSeverity] = {
    "high": FindingSeverity.CRITICAL,
    "medium": FindingSeverity.HIGH,
    "low": FindingSeverity.MEDIUM,
}


class TalismanNotFoundError(Exception):
    """Talisman binary not found."""

    pass


class TalismanInstallError(Exception):
    """Failed to install talisman."""

    pass


class TalismanError(Exception):
    """Talisman command failed."""

    pass


def get_talisman_path() -> Path:
    """Get the expected path to the talisman binary.

    Returns:
        Path where talisman should be installed.
    """
    bin_dir = get_venv_bin_dir()
    binary_name = "talisman.exe" if platform.system() == "Windows" else "talisman"
    return bin_dir / binary_name


class TalismanInstaller:
    """Installer for talisman binary."""

    # Download URLs by platform - talisman uses direct binary downloads (not archives)
    DOWNLOAD_URL_TEMPLATE = (
        "https://github.com/thoughtworks/talisman/releases/download/"
        "v{version}/talisman_{os}_{arch}{ext}"
    )

    PLATFORM_MAP: ClassVar[dict[tuple[str, str], tuple[str, str, str]]] = {
        ("Darwin", "x86_64"): ("darwin", "amd64", ""),
        ("Darwin", "arm64"): ("darwin", "arm64", ""),
        ("Linux", "x86_64"): ("linux", "amd64", ""),
        ("Linux", "arm64"): ("linux", "arm64", ""),
        ("Windows", "x86_64"): ("windows", "amd64", ".exe"),
    }

    def __init__(
        self,
        version: str | None = None,
        progress_callback: Callable[[str], None] | None = None,
    ) -> None:
        """Initialize installer.

        Args:
            version: Talisman version to install. Uses pinned version if None.
            progress_callback: Optional callback for progress updates.
        """
        self.version = version or _get_talisman_version()
        self.progress = progress_callback or (lambda x: None)

    def get_download_url(self) -> str:
        """Get the platform-specific download URL.

        Returns:
            URL to download talisman for the current platform.

        Raises:
            TalismanInstallError: If platform is not supported.
        """
        system, machine = get_platform_info()
        key = (system, machine)

        if key not in self.PLATFORM_MAP:
            supported = ", ".join(f"{s}/{m}" for s, m in self.PLATFORM_MAP)
            raise TalismanInstallError(
                f"Unsupported platform: {system} {machine}. Supported: {supported}"
            )

        os_name, arch, ext = self.PLATFORM_MAP[key]

        # Check if we have custom URLs in constants
        custom_urls = _get_talisman_download_urls()
        url_key = f"{os_name}_{arch}"
        if url_key in custom_urls:
            return custom_urls[url_key].format(version=self.version)

        return self.DOWNLOAD_URL_TEMPLATE.format(
            version=self.version,
            os=os_name,
            arch=arch,
            ext=ext,
        )

    def download_binary(self, target_path: Path) -> None:
        """Download talisman binary directly to target path.

        Talisman releases are direct binaries, not archives.

        Args:
            target_path: Where to install the talisman binary.

        Raises:
            TalismanInstallError: If download fails.
        """
        url = self.get_download_url()
        self.progress(f"Downloading talisman v{self.version}...")

        # Ensure target directory exists
        target_path.parent.mkdir(parents=True, exist_ok=True)

        # Download directly
        try:
            urllib.request.urlretrieve(url, target_path)  # nosec B310
        except Exception as e:
            raise TalismanInstallError(f"Download failed: {e}") from e

        # Make executable (Unix)
        if platform.system() != "Windows":
            target_path.chmod(
                target_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
            )

        self.progress(f"Installed to {target_path}")

    def install(self, force: bool = False) -> Path:
        """Install talisman binary.

        Args:
            force: Reinstall even if already installed.

        Returns:
            Path to the installed binary.
        """
        target_path = get_talisman_path()

        if target_path.exists() and not force:
            # Verify version
            try:
                result = subprocess.run(  # nosec B603
                    [str(target_path), "--version"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if self.version in result.stdout or self.version in result.stderr:
                    self.progress(f"talisman v{self.version} already installed")
                    return target_path
            except Exception:
                pass  # Version check failed, will reinstall

        self.download_binary(target_path)
        return target_path


class TalismanScanner(ScannerBackend):
    """Talisman scanner with automatic binary installation.

    Talisman detects secrets using:
    - Pattern matching against known secret formats
    - Entropy-based detection
    - File name analysis
    - Encoded content detection (base64, hex)
    - Credit card number detection

    Example:
        scanner = TalismanScanner(auto_install=True)
        result = scanner.scan([Path(".")])
        for finding in result.findings:
            print(f"{finding.severity}: {finding.description}")
    """

    def __init__(
        self,
        auto_install: bool = True,
        version: str | None = None,
    ) -> None:
        """Initialize the talisman scanner.

        Args:
            auto_install: Automatically install talisman if not found.
            version: Specific version to use. Uses pinned version if None.
        """
        self._auto_install = auto_install
        self._version = version or _get_talisman_version()
        self._binary_path: Path | None = None

    @property
    def name(self) -> str:
        """Return scanner identifier."""
        return "talisman"

    @property
    def description(self) -> str:
        """Return scanner description."""
        return "Talisman secret scanner (patterns + entropy + file analysis)"

    def is_installed(self) -> bool:
        """Check if talisman is available."""
        try:
            self._find_binary()
            return True
        except TalismanNotFoundError:
            return False

    def get_version(self) -> str | None:
        """Get installed talisman version."""
        try:
            binary = self._find_binary()
            result = subprocess.run(  # nosec B603
                [str(binary), "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            # Output format varies, try to extract version
            output = result.stdout.strip() or result.stderr.strip()
            if output:
                # Look for version pattern
                for part in output.split():
                    if part and part[0].isdigit():
                        return part
            return None
        except Exception:
            return None

    def _find_binary(self) -> Path:
        """Find the talisman binary, installing if necessary.

        Returns:
            Path to the talisman binary.

        Raises:
            TalismanNotFoundError: If binary cannot be found or installed.
        """
        if self._binary_path and self._binary_path.exists():
            return self._binary_path

        # Check in venv first
        venv_path = get_talisman_path()
        if venv_path.exists():
            self._binary_path = venv_path
            return venv_path

        # Check system PATH
        system_path = shutil.which("talisman")
        if system_path:
            self._binary_path = Path(system_path)
            return self._binary_path

        # Auto-install if enabled
        if self._auto_install:
            try:
                installer = TalismanInstaller(version=self._version)
                self._binary_path = installer.install()
                return self._binary_path
            except TalismanInstallError as e:
                raise TalismanNotFoundError(
                    f"talisman not found and auto-install failed: {e}"
                ) from e

        raise TalismanNotFoundError(
            "talisman not found. Install with: brew install talisman or enable auto_install=True"
        )

    def install(
        self,
        progress_callback: Callable[[str], None] | None = None,
    ) -> Path | None:
        """Install talisman binary.

        Args:
            progress_callback: Optional callback for progress updates.

        Returns:
            Path to the installed binary.
        """
        installer = TalismanInstaller(
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
        """Scan paths for secrets using talisman.

        Args:
            paths: List of files or directories to scan.
            include_git_history: If True, scan git history as well.

        Returns:
            ScanResult containing all findings.
        """
        start_time = time.time()

        try:
            binary = self._find_binary()
        except TalismanNotFoundError as e:
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

            # Create temp directory for JSON report
            with tempfile.TemporaryDirectory() as report_dir:
                report_path = Path(report_dir)

                try:
                    # Build command
                    # Talisman --scan scans the directory and outputs to report directory
                    args = [
                        str(binary),
                        "--scan",
                        "--reportDirectory",
                        str(report_path),
                    ]

                    # If not scanning git history, use --ignoreHistory
                    if not include_git_history:
                        args.append("--ignoreHistory")

                    # Run talisman from the target directory
                    work_dir = path if path.is_dir() else path.parent
                    result = subprocess.run(  # nosec B603
                        args,
                        capture_output=True,
                        text=True,
                        timeout=300,  # 5 minute timeout
                        cwd=str(work_dir),
                    )

                    # Parse JSON report if it exists
                    # Talisman creates talisman_report/talisman_reports/data/report.json
                    possible_report_files = [
                        report_path / "talisman_reports" / "data" / "report.json",
                        report_path / "report.json",
                        report_path / "talisman_report.json",
                    ]

                    report_found = False
                    for report_file in possible_report_files:
                        if report_file.exists():
                            try:
                                report_data = json.loads(report_file.read_text())
                                findings, files = self._parse_report(report_data, path)
                                all_findings.extend(findings)
                                total_files += files
                                report_found = True
                                break
                            except json.JSONDecodeError:
                                # Invalid JSON in report file, try next possible location
                                continue

                    # Check for execution errors: non-zero exit code without valid report
                    if result.returncode != 0 and not report_found:
                        # Prefer stderr over stdout for error messages
                        stderr_msg = result.stderr.strip()
                        stdout_msg = result.stdout.strip()
                        error_msg = stderr_msg or stdout_msg or f"talisman scan failed for {path}"
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

    def _parse_report(
        self, report_data: dict[str, Any], base_path: Path
    ) -> tuple[list[ScanFinding], int]:
        """Parse talisman JSON report into findings.

        Args:
            report_data: Parsed JSON report from talisman.
            base_path: Base path for resolving relative paths.

        Returns:
            Tuple of (findings list, files scanned count).
        """
        findings: list[ScanFinding] = []
        files_scanned = 0

        # Talisman report structure varies, handle different formats
        results = report_data.get("results", [])
        if not results and isinstance(report_data, list):
            results = report_data

        for result in results:
            filename = result.get("filename", "")
            if filename:
                files_scanned += 1

            file_path = Path(filename)
            if not file_path.is_absolute():
                # If base_path is a file, paths are relative to its parent directory
                if base_path.is_file():
                    file_path = base_path.parent / file_path
                else:
                    file_path = base_path / file_path

            # Parse failures/warnings in result
            for failure in result.get("failures", []):
                finding = self._parse_failure(failure, file_path)
                if finding:
                    findings.append(finding)

            for warning in result.get("warnings", []):
                finding = self._parse_failure(warning, file_path, is_warning=True)
                if finding:
                    findings.append(finding)

            # Also check for ignores that are still flagged
            for _ignore in result.get("ignores", []):
                # These are acknowledged but still noted
                pass

        return findings, files_scanned

    def _parse_failure(
        self,
        failure: dict[str, Any],
        file_path: Path,
        is_warning: bool = False,
    ) -> ScanFinding | None:
        """Parse a single talisman failure into a ScanFinding.

        Args:
            failure: Failure data from talisman report.
            file_path: Path to the file with the finding.
            is_warning: If True, this is a warning not a failure.

        Returns:
            ScanFinding or None if parsing fails.
        """
        try:
            # Get the type of detection
            failure_type = failure.get("type", "unknown")
            message = failure.get("message", "Secret detected")
            severity_str = failure.get("severity", "high" if not is_warning else "medium")

            # Map severity
            severity = SEVERITY_MAP.get(severity_str.lower(), FindingSeverity.HIGH)
            if is_warning:
                severity = FindingSeverity.MEDIUM

            # Get the matched content if available
            matched = failure.get("match", "")
            redacted = redact_secret(matched) if matched else ""

            # Build rule ID from type
            rule_id = f"talisman-{failure_type.lower().replace(' ', '-')}"

            return ScanFinding(
                file_path=file_path,
                line_number=failure.get("line_number"),
                column_number=None,
                rule_id=rule_id,
                rule_description=failure_type,
                description=message,
                severity=severity,
                secret_preview=redacted,
                commit_sha=failure.get("commit"),
                commit_author=failure.get("author"),
                commit_date=failure.get("date"),
                entropy=failure.get("entropy"),
                scanner=self.name,
            )
        except Exception:
            return None
