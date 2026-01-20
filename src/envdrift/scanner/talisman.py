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

if TYPE_CHECKING:
    from collections.abc import Callable


def _load_constants() -> dict:
    """
    Load package constants from the package's constants.json file.
    
    Returns:
        dict: Dictionary of constants parsed from the package's constants.json.
    """
    constants_path = Path(__file__).parent.parent / "constants.json"
    with open(constants_path) as f:
        return json.load(f)


def _get_talisman_version() -> str:
    """
    Retrieve the pinned Talisman version defined in the package constants.
    
    Returns:
        version (str): The configured `talisman_version` value from constants, or "1.32.0" if not set.
    """
    return _load_constants().get("talisman_version", "1.32.0")


def _get_talisman_download_urls() -> dict[str, str]:
    """
    Retrieve custom Talisman download URL templates from package constants.
    
    Returns:
        dict[str, str]: Mapping of platform keys to URL template strings; empty dict if no custom URLs are configured.
    """
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


def get_platform_info() -> tuple[str, str]:
    """
    Return the current OS name and a normalized CPU architecture suitable for download URL selection.
    
    The architecture is normalized as follows: "AMD64" or "amd64" -> "x86_64"; "arm64" or "aarch64" -> "arm64". Other values are returned unchanged.
    
    Returns:
        tuple(system, machine): 
            system (str): OS name as returned by platform.system().
            machine (str): Normalized CPU architecture string.
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
    Determine the filesystem path where binaries should be installed for the active or default virtual environment.
    
    Selection order:
    1. Active virtual environment from `VIRTUAL_ENV`.
    2. A `.venv` or `venv` directory discovered on `sys.path`.
    3. A `.venv` directory in the current working directory.
    4. A user-level bin directory (`~/.local/bin` on non-Windows, or `%APPDATA%\Python\Scripts` on Windows).
    
    The function will create the user-level bin directory if it is selected and does not exist.
    
    Returns:
        Path: The resolved bin directory to use for installing binaries.
    
    Raises:
        RuntimeError: If no suitable bin directory can be determined.
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


def get_talisman_path() -> Path:
    """
    Compute the expected filesystem path for the talisman executable within the resolved bin directory.
    
    The returned path points to the platform-specific talisman filename (e.g., "talisman" or "talisman.exe") located inside the bin directory determined by get_venv_bin_dir().
    
    Returns:
        Path: Path to the expected talisman binary.
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
        """
        Create a TalismanInstaller configured with the target version and an optional progress callback.
        
        Parameters:
            version (str | None): Specific talisman version to install; if None the pinned version from package constants is used.
            progress_callback (Callable[[str], None] | None): Optional callable invoked with status messages during installation; if None no progress is reported.
        """
        self.version = version or _get_talisman_version()
        self.progress = progress_callback or (lambda x: None)

    def get_download_url(self) -> str:
        """
        Determine the platform-specific download URL for the configured Talisman version.
        
        If a custom download URL template exists for the detected OS/architecture it will be used; otherwise the default download template is formatted for the detected platform.
        
        Returns:
            str: The download URL for the talisman binary for the detected platform and configured version.
        
        Raises:
            TalismanInstallError: If the current system/architecture is not supported.
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
        """
        Ensure the talisman binary is installed at the configured location.
        
        If a binary exists and `force` is False, verifies the installed version and returns the existing path when it matches; otherwise downloads and installs the requested version.
        
        Parameters:
            force (bool): If True, reinstall even when a matching binary is already present.
        
        Returns:
            Path: Path to the installed talisman binary.
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
        """
        Initialize the TalismanScanner with installation behavior and version selection.
        
        Parameters:
            auto_install (bool): If True, attempt to auto-install the talisman binary when not found.
            version (str | None): Specific talisman version to use; when None, the pinned version from package constants is used.
        """
        self._auto_install = auto_install
        self._version = version or _get_talisman_version()
        self._binary_path: Path | None = None

    @property
    def name(self) -> str:
        """
        Provide the scanner identifier for Talisman.
        
        Returns:
            identifier (str): The literal string 'talisman'.
        """
        return "talisman"

    @property
    def description(self) -> str:
        """
        Human-readable description of the Talisman scanner.
        
        Returns:
            description (str): A string identifying the scanner and its analysis methods: "Talisman secret scanner (patterns + entropy + file analysis)".
        """
        return "Talisman secret scanner (patterns + entropy + file analysis)"

    def is_installed(self) -> bool:
        """
        Determine whether the talisman binary can be located (or installed when auto-install is enabled).
        
        Returns:
            `true` if the talisman binary is available, `false` otherwise.
        """
        try:
            self._find_binary()
            return True
        except TalismanNotFoundError:
            return False

    def get_version(self) -> str | None:
        """
        Determine the installed talisman CLI version.
        
        Returns:
            str: The first version-like token extracted from the talisman CLI output, or `None` if the binary is not available or no version token can be determined.
        """
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
        """
        Install the talisman binary and cache its path.
        
        Parameters:
            progress_callback (Callable[[str], None] | None): Optional callback invoked with progress messages during installation.
        
        Returns:
            installed_path (Path | None): Path to the installed binary, or `None` if installation did not complete.
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
        """
        Scan the given files or directories for secrets using the talisman binary.
        
        Scans each existing path and aggregates findings from talisman's JSON report files into a single ScanResult. Non-existent paths are skipped. Each individual scan has a 5-minute timeout; on timeout or other errors the function returns a ScanResult with the collected findings so far and the error message set.
        
        Parameters:
            paths (list[Path]): Files or directories to scan.
            include_git_history (bool): If True, include repository history in the scan; otherwise history is ignored.
        
        Returns:
            ScanResult: Contains aggregated `findings`, `files_scanned`, and `duration_ms`; on error the `error` field is populated and partial findings may be returned.
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
                        "--reportdirectory",
                        str(report_path),
                    ]

                    # If not scanning git history, use --ignoreHistory
                    if not include_git_history:
                        args.append("--ignoreHistory")

                    # Run talisman from the target directory
                    work_dir = path if path.is_dir() else path.parent
                    subprocess.run(  # nosec B603
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

                    for report_file in possible_report_files:
                        if report_file.exists():
                            try:
                                report_data = json.loads(report_file.read_text())
                                findings, files = self._parse_report(report_data, path)
                                all_findings.extend(findings)
                                total_files += files
                                break
                            except json.JSONDecodeError:
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

    def _parse_report(
        self, report_data: dict[str, Any], base_path: Path
    ) -> tuple[list[ScanFinding], int]:
        """
        Convert a Talisman JSON report into ScanFinding objects and count files referenced by the report.
        
        Parameters:
            report_data (dict[str, Any]): Parsed JSON report produced by Talisman. May be a mapping with a "results" key or a top-level list of result objects.
            base_path (Path): Base directory used to resolve relative filenames found in the report entries.
        
        Returns:
            tuple[list[ScanFinding], int]: A tuple where the first element is the list of parsed ScanFinding objects and the second element is the number of files referenced (entries that include a filename).
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
        """
        Convert a single talisman failure entry into a ScanFinding.
        
        Parameters:
            failure (dict[str, Any]): A single failure object from a talisman JSON report.
            file_path (Path): Path to the file associated with the finding.
            is_warning (bool): When True, treat the entry as a warning (lower severity).
        
        Returns:
            ScanFinding: A populated ScanFinding for the provided failure, or None if the failure cannot be parsed.
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