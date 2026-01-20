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

if TYPE_CHECKING:
    from collections.abc import Callable


def _load_constants() -> dict:
    """Load constants from the package's constants.json."""
    constants_path = Path(__file__).parent.parent / "constants.json"
    with open(constants_path) as f:
        return json.load(f)


def _get_trivy_version() -> str:
    """
    Return the pinned Trivy version from the bundled constants, defaulting to "0.58.0" if missing.
    
    Returns:
        version (str): Trivy version string from constants.json, or "0.58.0" when not specified.
    """
    return _load_constants().get("trivy_version", "0.58.0")


def _get_trivy_download_urls() -> dict[str, str]:
    """
    Retrieve custom Trivy download URL templates from the package constants.
    
    Returns:
        A dict mapping string keys to URL template strings for Trivy downloads.
        Returns an empty dict if no custom download URLs are configured.
    """
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


def get_platform_info() -> tuple[str, str]:
    """
    Return the current OS and normalized architecture for download URL selection.
    
    Returns:
        tuple: (system, machine) where `system` is the OS name from platform.system() and `machine` is the architecture normalized to a value suitable for download URLs (e.g., "x86_64", "arm64", or the original machine string).
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
    """
    Determine the appropriate bin (or Scripts on Windows) directory to install user-local binaries for the current environment.
    
    Search order:
    - If VIRTUAL_ENV is set, return its "bin" (or "Scripts" on Windows).
    - Search sys.path for a parent ".venv" or "venv" and return its "bin"/"Scripts".
    - If a ".venv" exists in the current working directory, return its "bin"/"Scripts".
    - Fall back to a user-level directory (Windows: %APPDATA%/Python/Scripts, non-Windows: ~/.local/bin) and create it if missing.
    
    Returns:
        Path: Path to the directory where binaries should be installed.
    
    Raises:
        RuntimeError: If no suitable directory can be determined.
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


def get_trivy_path() -> Path:
    """
    Return the expected filesystem path to the Trivy executable based on the current environment.
    
    Returns:
        Path: Path to the trivy executable inside the determined virtualenv or user bin directory (for example, '.../trivy' or '.../trivy.exe').
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
        """
        Initialize a TrivyInstaller.
        
        Parameters:
            version: Trivy version to install; defaults to the pinned version from constants if None.
            progress_callback: Optional callable that receives progress messages as strings.
        """
        self.version = version or _get_trivy_version()
        self.progress = progress_callback or (lambda x: None)

    def get_download_url(self) -> str:
        """
        Determine the platform-specific Trivy download URL.
        
        Returns:
            The download URL for the Trivy archive for the current platform with `{version}` substituted.
        
        Raises:
            TrivyInstallError: If the current platform/architecture is not supported.
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
        """
        Extracts a .tar.gz archive into the given target directory while preventing path traversal.
        
        Parameters:
            archive_path (Path): Path to the .tar.gz archive to extract.
            target_dir (Path): Directory where archive members will be extracted.
        
        Raises:
            TrivyInstallError: If the archive contains any member whose resolved path would be outside `target_dir`.
        """
        with tarfile.open(archive_path, "r:gz") as tar:
            # Security: check for path traversal
            for member in tar.getmembers():
                member_path = target_dir / member.name
                if not member_path.resolve().is_relative_to(target_dir.resolve()):
                    raise TrivyInstallError(f"Unsafe path in archive: {member.name}")
            tar.extractall(target_dir, filter="data")  # nosec B202

    def _extract_zip(self, archive_path: Path, target_dir: Path) -> None:
        """
        Extract a zip archive into the target directory while preventing path traversal.
        
        Performs a safety check on each archive member to ensure its resolved path is inside `target_dir`; raises an error if any member would extract outside the target directory.
        
        Raises:
            TrivyInstallError: If the archive contains a member with an unsafe path that would escape `target_dir`.
        """
        with zipfile.ZipFile(archive_path, "r") as zip_ref:
            # Security: check for path traversal
            for name in zip_ref.namelist():
                member_path = target_dir / name
                if not member_path.resolve().is_relative_to(target_dir.resolve()):
                    raise TrivyInstallError(f"Unsafe path in archive: {name}")
            zip_ref.extractall(target_dir)  # nosec B202

    def install(self, force: bool = False) -> Path:
        """
        Install the Trivy CLI binary to the configured installation path.
        
        If a binary matching the configured version already exists and `force` is False, the existing binary is left in place; otherwise the appropriate archive for the current platform is downloaded, extracted, and the Trivy binary is installed to the target path.
        
        Parameters:
            force (bool): If True, reinstall even when a matching version is already installed.
        
        Returns:
            Path: Path to the installed Trivy binary.
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
                pass  # Version check failed, will reinstall

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
        """
        Create a TrivyScanner configured to optionally auto-install the Trivy binary.
        
        Parameters:
        	auto_install (bool): If True, attempt to install Trivy automatically when not found.
        	version (str | None): Specific Trivy version to use; when None the pinned default is used.
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
        """
        Human-readable description of the Trivy scanner.
        
        Returns:
            description (str): The scanner description string, e.g. "Trivy secret scanner (comprehensive multi-target security scanner)"
        """
        return "Trivy secret scanner (comprehensive multi-target security scanner)"

    def is_installed(self) -> bool:
        """
        Determine whether the Trivy binary can be located for use.
        
        Returns:
            bool: `True` if the Trivy binary is available and discoverable, `False` otherwise.
        """
        try:
            self._find_binary()
            return True
        except TrivyNotFoundError:
            return False

    def get_version(self) -> str | None:
        """
        Retrieve the installed Trivy CLI version.
        
        Returns:
            version (str | None): The version string (for example, "0.58.0") if determinable, `None` otherwise.
        """
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
        """
        Install the Trivy binary into the environment and cache its path.
        
        Parameters:
            progress_callback (Callable[[str], None] | None): Optional callback invoked with status messages during installation.
        
        Returns:
            Path | None: Path to the installed Trivy binary, or `None` if installation did not complete.
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
        """
        Scan the provided filesystem paths for secrets using the Trivy filesystem scanner.
        
        Paths that do not exist are skipped. The `include_git_history` flag is accepted for API compatibility but is not used because `trivy fs` does not scan Git history. Results from all paths are aggregated into a single ScanResult.
        
        Parameters:
            paths (list[Path]): Files or directories to scan.
            include_git_history (bool): Ignored for filesystem scans; kept for compatibility.
        
        Returns:
            ScanResult: Aggregated scan results including `findings`, `files_scanned`, `duration_ms`, and an `error` message if the scan or binary lookup failed.
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
        """
        Convert a single Trivy secret entry into a ScanFinding.
        
        Parameters:
            secret (dict[str, Any]): A single secret entry from Trivy JSON output.
            target (str): The target path reported by Trivy; relative paths are resolved against base_path.
            base_path (Path): Base directory used to resolve relative target paths.
        
        Returns:
            ScanFinding | None: A ScanFinding populated from the secret entry, or `None` if parsing fails.
        """
        try:
            # Get file path
            file_path = Path(target)
            if not file_path.is_absolute():
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