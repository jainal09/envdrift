"""Gitleaks scanner integration with auto-installation.

Gitleaks is a SAST tool for detecting hardcoded secrets in git repos.
This module provides:
- Automatic binary download and installation
- Cross-platform support (macOS, Linux, Windows)
- JSON output parsing into ScanFinding objects
- Git history scanning support
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
from envdrift.scanner.patterns import hash_secret, redact_secret

if TYPE_CHECKING:
    from collections.abc import Callable


def _load_constants() -> dict:
    """Load constants from the package's constants.json."""
    constants_path = Path(__file__).parent.parent / "constants.json"
    with open(constants_path) as f:
        return json.load(f)


def _get_gitleaks_version() -> str:
    """Get the pinned gitleaks version from constants."""
    return _load_constants().get("gitleaks_version", "8.21.2")


def _get_gitleaks_download_urls() -> dict[str, str]:
    """Get download URL templates from constants."""
    return _load_constants().get("gitleaks_download_urls", {})


# Severity mapping from gitleaks to our severity levels
SEVERITY_MAP: dict[str, FindingSeverity] = {
    "CRITICAL": FindingSeverity.CRITICAL,
    "HIGH": FindingSeverity.HIGH,
    "MEDIUM": FindingSeverity.MEDIUM,
    "LOW": FindingSeverity.LOW,
    "INFO": FindingSeverity.INFO,
    # Gitleaks doesn't have severity in output, default to HIGH
}


class GitleaksNotFoundError(Exception):
    """Gitleaks binary not found."""

    pass


class GitleaksInstallError(Exception):
    """Failed to install gitleaks."""

    pass


class GitleaksError(Exception):
    """Gitleaks command failed."""

    pass


def get_platform_info() -> tuple[str, str]:
    """Get current platform and architecture.

    Returns:
        Tuple of (system, machine) normalized for download URLs.
    """
    system = platform.system()
    machine = platform.machine()

    # Normalize architecture names
    if machine in ("AMD64", "amd64"):
        machine = "x86_64"
    elif machine in ("arm64", "aarch64"):
        machine = "arm64"
    elif machine == "x86_64":
        pass  # Keep as is

    return system, machine


def get_venv_bin_dir() -> Path:
    """Get the virtual environment's bin directory.

    Returns:
        Path to the bin directory where binaries should be installed.
    """
    import os
    import sys

    # Check for virtual environment
    venv_path = os.environ.get("VIRTUAL_ENV")
    if venv_path:
        venv = Path(venv_path)
        if platform.system() == "Windows":
            return venv / "Scripts"
        return venv / "bin"

    # Try to find venv relative to the package
    for path in sys.path:
        p = Path(path)
        if ".venv" in p.parts or "venv" in p.parts:
            while p.name not in (".venv", "venv") and p.parent != p:
                p = p.parent
            if p.name in (".venv", "venv"):
                if platform.system() == "Windows":
                    return p / "Scripts"
                return p / "bin"

    # Default to .venv in current directory
    cwd_venv = Path.cwd() / ".venv"
    if cwd_venv.exists():
        if platform.system() == "Windows":
            return cwd_venv / "Scripts"
        return cwd_venv / "bin"

    # Fallback to user bin directory
    if platform.system() == "Windows":
        appdata = os.environ.get("APPDATA")
        if appdata:
            user_scripts = Path(appdata) / "Python" / "Scripts"
            user_scripts.mkdir(parents=True, exist_ok=True)
            return user_scripts
    else:
        user_bin = Path.home() / ".local" / "bin"
        user_bin.mkdir(parents=True, exist_ok=True)
        return user_bin

    raise RuntimeError("Cannot find suitable bin directory for installation")


def get_gitleaks_path() -> Path:
    """Get the expected path to the gitleaks binary.

    Returns:
        Path where gitleaks should be installed.
    """
    bin_dir = get_venv_bin_dir()
    binary_name = "gitleaks.exe" if platform.system() == "Windows" else "gitleaks"
    return bin_dir / binary_name


class GitleaksInstaller:
    """Installer for gitleaks binary."""

    # Download URLs by platform
    DOWNLOAD_URL_TEMPLATE = (
        "https://github.com/gitleaks/gitleaks/releases/download/"
        "v{version}/gitleaks_{version}_{os}_{arch}.{ext}"
    )

    PLATFORM_MAP: ClassVar[dict[tuple[str, str], tuple[str, str, str]]] = {
        ("Darwin", "x86_64"): ("darwin", "amd64", "tar.gz"),
        ("Darwin", "arm64"): ("darwin", "arm64", "tar.gz"),
        ("Linux", "x86_64"): ("linux", "amd64", "tar.gz"),
        ("Linux", "arm64"): ("linux", "arm64", "tar.gz"),
        ("Windows", "x86_64"): ("windows", "amd64", "zip"),
    }

    def __init__(
        self,
        version: str | None = None,
        progress_callback: Callable[[str], None] | None = None,
    ) -> None:
        """Initialize installer.

        Args:
            version: Gitleaks version to install. Uses pinned version if None.
            progress_callback: Optional callback for progress updates.
        """
        self.version = version or _get_gitleaks_version()
        self.progress = progress_callback or (lambda x: None)

    def get_download_url(self) -> str:
        """Get the platform-specific download URL.

        Returns:
            URL to download gitleaks for the current platform.

        Raises:
            GitleaksInstallError: If platform is not supported.
        """
        system, machine = get_platform_info()
        key = (system, machine)

        if key not in self.PLATFORM_MAP:
            supported = ", ".join(f"{s}/{m}" for s, m in self.PLATFORM_MAP)
            raise GitleaksInstallError(
                f"Unsupported platform: {system} {machine}. Supported: {supported}"
            )

        os_name, arch, ext = self.PLATFORM_MAP[key]

        # Check if we have custom URLs in constants
        custom_urls = _get_gitleaks_download_urls()
        url_key = f"{os_name}_{arch}"
        if url_key in custom_urls:
            return custom_urls[url_key].format(version=self.version)

        return self.DOWNLOAD_URL_TEMPLATE.format(
            version=self.version,
            os=os_name,
            arch=arch,
            ext=ext,
        )

    def download_and_extract(self, target_path: Path) -> None:
        """Download and extract gitleaks to the target path.

        Args:
            target_path: Where to install the gitleaks binary.

        Raises:
            GitleaksInstallError: If download or extraction fails.
        """
        url = self.get_download_url()
        self.progress(f"Downloading gitleaks v{self.version}...")

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            archive_name = url.split("/")[-1]
            archive_path = tmp_path / archive_name

            # Download
            try:
                urllib.request.urlretrieve(url, archive_path)  # nosec B310
            except Exception as e:
                raise GitleaksInstallError(f"Download failed: {e}") from e

            self.progress("Extracting...")

            # Extract based on archive type
            if archive_name.endswith(".tar.gz"):
                self._extract_tar_gz(archive_path, tmp_path)
            elif archive_name.endswith(".zip"):
                self._extract_zip(archive_path, tmp_path)
            else:
                raise GitleaksInstallError(f"Unknown archive format: {archive_name}")

            # Find the binary
            binary_name = "gitleaks.exe" if platform.system() == "Windows" else "gitleaks"
            extracted_binary = None

            for f in tmp_path.rglob(binary_name):
                if f.is_file():
                    extracted_binary = f
                    break

            if not extracted_binary:
                raise GitleaksInstallError(f"Binary '{binary_name}' not found in archive")

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
        """Extract a tar.gz archive."""
        with tarfile.open(archive_path, "r:gz") as tar:
            # Security: check for path traversal
            for member in tar.getmembers():
                member_path = target_dir / member.name
                if not member_path.resolve().is_relative_to(target_dir.resolve()):
                    raise GitleaksInstallError(f"Unsafe path in archive: {member.name}")
            tar.extractall(target_dir, filter="data")  # nosec B202

    def _extract_zip(self, archive_path: Path, target_dir: Path) -> None:
        """Extract a zip archive."""
        with zipfile.ZipFile(archive_path, "r") as zip_ref:
            # Security: check for path traversal
            for name in zip_ref.namelist():
                member_path = target_dir / name
                if not member_path.resolve().is_relative_to(target_dir.resolve()):
                    raise GitleaksInstallError(f"Unsafe path in archive: {name}")
            zip_ref.extractall(target_dir)  # nosec B202

    def install(self, force: bool = False) -> Path:
        """Install gitleaks binary.

        Args:
            force: Reinstall even if already installed.

        Returns:
            Path to the installed binary.
        """
        target_path = get_gitleaks_path()

        if target_path.exists() and not force:
            # Verify version
            try:
                result = subprocess.run(  # nosec B603
                    [str(target_path), "version"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if self.version in result.stdout:
                    self.progress(f"gitleaks v{self.version} already installed")
                    return target_path
            except Exception:
                pass  # Version check failed, will reinstall

        self.download_and_extract(target_path)
        return target_path


class GitleaksScanner(ScannerBackend):
    """Gitleaks scanner with automatic binary installation.

    Gitleaks detects secrets using:
    - Pattern matching against known secret formats
    - Entropy-based detection
    - Git history scanning

    Example:
        scanner = GitleaksScanner(auto_install=True)
        result = scanner.scan([Path(".")])
        for finding in result.findings:
            print(f"{finding.severity}: {finding.description}")
    """

    def __init__(
        self,
        auto_install: bool = True,
        version: str | None = None,
    ) -> None:
        """Initialize the gitleaks scanner.

        Args:
            auto_install: Automatically install gitleaks if not found.
            version: Specific version to use. Uses pinned version if None.
        """
        self._auto_install = auto_install
        self._version = version or _get_gitleaks_version()
        self._binary_path: Path | None = None

    @property
    def name(self) -> str:
        """Return scanner identifier."""
        return "gitleaks"

    @property
    def description(self) -> str:
        """Return scanner description."""
        return "Gitleaks secret scanner (patterns + entropy + git history)"

    def is_installed(self) -> bool:
        """Check if gitleaks is available."""
        try:
            self._find_binary()
            return True
        except GitleaksNotFoundError:
            return False

    def get_version(self) -> str | None:
        """Get installed gitleaks version."""
        try:
            binary = self._find_binary()
            result = subprocess.run(  # nosec B603
                [str(binary), "version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            # Output format: "gitleaks version 8.21.2"
            return result.stdout.strip().split()[-1] if result.returncode == 0 else None
        except Exception:
            return None

    def _find_binary(self) -> Path:
        """Find the gitleaks binary, installing if necessary.

        Returns:
            Path to the gitleaks binary.

        Raises:
            GitleaksNotFoundError: If binary cannot be found or installed.
        """
        if self._binary_path and self._binary_path.exists():
            return self._binary_path

        # Check in venv first
        venv_path = get_gitleaks_path()
        if venv_path.exists():
            self._binary_path = venv_path
            return venv_path

        # Check system PATH
        system_path = shutil.which("gitleaks")
        if system_path:
            self._binary_path = Path(system_path)
            return self._binary_path

        # Auto-install if enabled
        if self._auto_install:
            try:
                installer = GitleaksInstaller(version=self._version)
                self._binary_path = installer.install()
                return self._binary_path
            except GitleaksInstallError as e:
                raise GitleaksNotFoundError(
                    f"gitleaks not found and auto-install failed: {e}"
                ) from e

        raise GitleaksNotFoundError(
            "gitleaks not found. Install with: brew install gitleaks or enable auto_install=True"
        )

    def install(
        self,
        progress_callback: Callable[[str], None] | None = None,
    ) -> Path | None:
        """Install gitleaks binary.

        Args:
            progress_callback: Optional callback for progress updates.

        Returns:
            Path to the installed binary.
        """
        installer = GitleaksInstaller(
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
        """Scan paths for secrets using gitleaks.

        Args:
            paths: List of files or directories to scan.
            include_git_history: If True, scan git history as well.

        Returns:
            ScanResult containing all findings.
        """
        start_time = time.time()

        try:
            binary = self._find_binary()
        except GitleaksNotFoundError as e:
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

            # Create temp file for JSON output (gitleaks requires --report-path for JSON)
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as report_file:
                report_path = Path(report_file.name)

            try:
                # Build command
                args = [
                    str(binary),
                    "detect",
                    "--source",
                    str(path),
                    "--report-format",
                    "json",
                    "--report-path",
                    str(report_path),
                    "--exit-code",
                    "0",  # Don't fail on findings, we handle that
                ]

                # If not scanning git history, use --no-git
                if not include_git_history:
                    args.append("--no-git")

                result = subprocess.run(  # nosec B603
                    args,
                    capture_output=True,
                    text=True,
                    timeout=300,  # 5 minute timeout
                    cwd=str(path) if path.is_dir() else str(path.parent),
                )

                if result.returncode != 0:
                    error_msg = (
                        result.stderr.strip()
                        or result.stdout.strip()
                        or f"gitleaks scan failed for {path} (exit code {result.returncode})"
                    )
                    return ScanResult(
                        scanner_name=self.name,
                        findings=all_findings,
                        error=error_msg,
                        duration_ms=int((time.time() - start_time) * 1000),
                    )

                # Parse JSON output from report file
                if report_path.exists() and report_path.stat().st_size > 0:
                    try:
                        findings_data = json.loads(report_path.read_text())
                        if findings_data and isinstance(findings_data, list):
                            # Count unique files with findings
                            files_with_findings = {
                                item.get("File") for item in findings_data if item.get("File")
                            }
                            total_files += len(files_with_findings)
                            for item in findings_data:
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
                    error=str(e),
                    duration_ms=int((time.time() - start_time) * 1000),
                )
            finally:
                # Clean up temp report file
                if report_path.exists():
                    report_path.unlink()

        return ScanResult(
            scanner_name=self.name,
            findings=all_findings,
            files_scanned=total_files,
            duration_ms=int((time.time() - start_time) * 1000),
        )

    def _parse_finding(self, item: dict[str, Any], base_path: Path) -> ScanFinding | None:
        """Parse a gitleaks finding into our format.

        Args:
            item: Raw finding from gitleaks JSON output.
            base_path: Base path for resolving relative paths.

        Returns:
            ScanFinding or None if parsing fails.
        """
        try:
            # Get file path
            file_path_str = item.get("File", "")
            if file_path_str:
                file_path = Path(file_path_str)
                if not file_path.is_absolute():
                    file_path = base_path / file_path
            else:
                file_path = base_path

            # Get the secret match and redact it
            secret = item.get("Secret", item.get("Match", ""))
            redacted = redact_secret(secret) if secret else ""
            secret_hash = hash_secret(secret) if secret else ""

            # Map rule ID
            rule_id: str = str(item.get("RuleID", "unknown"))
            rule_description: str = str(item.get("Description") or rule_id)

            # Gitleaks doesn't provide severity, default based on rule
            severity = FindingSeverity.HIGH

            return ScanFinding(
                file_path=file_path,
                line_number=item.get("StartLine"),
                column_number=item.get("StartColumn"),
                rule_id=f"gitleaks-{rule_id}",
                rule_description=rule_description,
                description=f"Secret detected: {rule_description}",
                severity=severity,
                secret_preview=redacted,
                secret_hash=secret_hash,
                commit_sha=item.get("Commit"),
                commit_author=item.get("Author"),
                commit_date=item.get("Date"),
                entropy=item.get("Entropy"),
                scanner=self.name,
            )
        except Exception:
            return None
