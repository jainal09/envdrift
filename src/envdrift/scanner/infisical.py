"""Infisical scanner integration with auto-installation.

Infisical CLI includes secret scanning capabilities to detect secrets.
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
from envdrift.scanner.patterns import redact_secret

if TYPE_CHECKING:
    from collections.abc import Callable


def _load_constants() -> dict:
    """
    Load constant values from the package's constants.json.
    
    Returns:
        dict: Parsed JSON object containing package constants.
    """
    constants_path = Path(__file__).parent.parent / "constants.json"
    with open(constants_path) as f:
        return json.load(f)


def _get_infisical_version() -> str:
    """
    Return the pinned Infisical CLI version configured in package constants.
    
    Returns:
        str: Version string from constants, or "0.31.1" if not present.
    """
    return _load_constants().get("infisical_version", "0.31.1")


def _get_infisical_download_urls() -> dict[str, str]:
    """
    Retrieve custom download URL templates for Infisical from package constants.
    
    Returns:
        download_urls (dict[str, str]): Mapping of template keys to download URL templates (e.g. custom URL formats keyed by platform or name). Returns an empty dict if no custom templates are defined.
    """
    return _load_constants().get("infisical_download_urls", {})


# Severity mapping - Infisical doesn't have built-in severity, so we map by rule type
RULE_SEVERITY_MAP: dict[str, FindingSeverity] = {
    "aws-access-key-id": FindingSeverity.CRITICAL,
    "aws-secret-access-key": FindingSeverity.CRITICAL,
    "github-pat": FindingSeverity.CRITICAL,
    "github-oauth": FindingSeverity.CRITICAL,
    "gitlab-pat": FindingSeverity.CRITICAL,
    "google-api-key": FindingSeverity.HIGH,
    "slack-token": FindingSeverity.HIGH,
    "stripe-api-key": FindingSeverity.CRITICAL,
    "private-key": FindingSeverity.CRITICAL,
    "generic-api-key": FindingSeverity.HIGH,
}


class InfisicalNotFoundError(Exception):
    """Infisical binary not found."""

    pass


class InfisicalInstallError(Exception):
    """Failed to install infisical."""

    pass


class InfisicalError(Exception):
    """Infisical command failed."""

    pass


def get_platform_info() -> tuple[str, str]:
    """
    Return the current OS and normalized CPU architecture for forming download URLs.
    
    Returns:
        (system, machine): `system` is the value from platform.system(); `machine` is a normalized architecture string (for example, "x86_64" or "arm64").
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
    Determine an appropriate directory to install executables for the current environment.
    
    Checks, in order:
    - The active virtual environment referenced by the `VIRTUAL_ENV` environment variable.
    - Any `venv` or `.venv` directories referenced in `sys.path`.
    - A `.venv` directory in the current working directory.
    - A user-level bin directory (POSIX: `~/.local/bin`, Windows: `%APPDATA%/Python/Scripts`).
    
    On Windows this returns the `Scripts` folder; on other platforms it returns the `bin` folder. The returned path is created if necessary for the user-level fallback.
    
    Returns:
        Path: Directory where binaries should be installed.
    
    Raises:
        RuntimeError: If no suitable installation directory can be determined.
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


def get_infisical_path() -> Path:
    """
    Compute the expected filesystem path for the Infisical executable within the active virtual environment or the selected user bin directory.
    
    Returns:
        Path to the expected Infisical executable location (the file may not exist).
    """
    bin_dir = get_venv_bin_dir()
    binary_name = "infisical.exe" if platform.system() == "Windows" else "infisical"
    return bin_dir / binary_name


class InfisicalInstaller:
    """Installer for infisical binary."""

    # Download URLs by platform
    DOWNLOAD_URL_TEMPLATE = (
        "https://github.com/Infisical/infisical/releases/download/"
        "infisical-cli/v{version}/infisical_{version}_{os}_{arch}.{ext}"
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
        """
        Create an InfisicalInstaller configured with an optional version and progress callback.
        
        Parameters:
            version (str | None): Infisical version to install; when None the pinned package version is used.
            progress_callback (Callable[[str], None] | None): Optional callable invoked with progress messages.
        """
        self.version = version or _get_infisical_version()
        self.progress = progress_callback or (lambda x: None)

    def get_download_url(self) -> str:
        """
        Return the download URL for the Infisical binary for the current platform.
        
        If a custom download URL template exists in package constants for the detected OS/architecture, that template is formatted with the selected version and returned; otherwise the default download URL template is used.
        
        Returns:
            str: The URL to download the Infisical archive for the current platform.
        
        Raises:
            InfisicalInstallError: If the current platform/architecture is not supported.
        """
        system, machine = get_platform_info()
        key = (system, machine)

        if key not in self.PLATFORM_MAP:
            supported = ", ".join(f"{s}/{m}" for s, m in self.PLATFORM_MAP)
            raise InfisicalInstallError(
                f"Unsupported platform: {system} {machine}. Supported: {supported}"
            )

        os_name, arch, ext = self.PLATFORM_MAP[key]

        # Check if we have custom URLs in constants
        custom_urls = _get_infisical_download_urls()
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
        """
        Download the Infisical archive for the configured version and install its binary at the given path.
        
        Parameters:
            target_path (Path): Destination path for the installed Infisical binary.
        
        Raises:
            InfisicalInstallError: If the download fails, the archive format is unsupported,
                extraction fails, or the expected binary is not found in the archive.
        """
        url = self.get_download_url()
        self.progress(f"Downloading infisical v{self.version}...")

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            archive_name = url.split("/")[-1]
            archive_path = tmp_path / archive_name

            # Download
            try:
                urllib.request.urlretrieve(url, archive_path)  # nosec B310
            except Exception as e:
                raise InfisicalInstallError(f"Download failed: {e}") from e

            self.progress("Extracting...")

            # Extract based on archive type
            if archive_name.endswith(".tar.gz"):
                self._extract_tar_gz(archive_path, tmp_path)
            elif archive_name.endswith(".zip"):
                self._extract_zip(archive_path, tmp_path)
            else:
                raise InfisicalInstallError(f"Unknown archive format: {archive_name}")

            # Find the binary
            binary_name = "infisical.exe" if platform.system() == "Windows" else "infisical"
            extracted_binary = None

            for f in tmp_path.rglob(binary_name):
                if f.is_file():
                    extracted_binary = f
                    break

            if not extracted_binary:
                raise InfisicalInstallError(f"Binary '{binary_name}' not found in archive")

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
        Extracts a tar.gz archive into the given target directory.
        
        Validates each archive member to prevent path traversal attacks and raises
        InfisicalInstallError if any entry would extract outside the target directory.
        
        Parameters:
            archive_path (Path): Path to the tar.gz archive to extract.
            target_dir (Path): Destination directory where archive contents will be extracted.
        """
        with tarfile.open(archive_path, "r:gz") as tar:
            # Security: check for path traversal
            for member in tar.getmembers():
                member_path = target_dir / member.name
                if not member_path.resolve().is_relative_to(target_dir.resolve()):
                    raise InfisicalInstallError(f"Unsafe path in archive: {member.name}")
            tar.extractall(target_dir, filter="data")  # nosec B202

    def _extract_zip(self, archive_path: Path, target_dir: Path) -> None:
        """
        Extracts a zip archive into the given target directory while preventing path traversal.
        
        Performs a safety check for each archive member to ensure no extracted path would escape the target directory; if a path traversal attempt is detected, raises InfisicalInstallError. On success, extracts all archive contents into target_dir.
         
        Raises:
            InfisicalInstallError: If the archive contains a member whose extraction path would be outside target_dir.
        """
        with zipfile.ZipFile(archive_path, "r") as zip_ref:
            # Security: check for path traversal
            for name in zip_ref.namelist():
                member_path = target_dir / name
                if not member_path.resolve().is_relative_to(target_dir.resolve()):
                    raise InfisicalInstallError(f"Unsafe path in archive: {name}")
            zip_ref.extractall(target_dir)  # nosec B202

    def install(self, force: bool = False) -> Path:
        """
        Install the Infisical CLI binary into the environment's bin directory, optionally forcing a reinstall.
        
        Parameters:
        	force (bool): If True, reinstall even when a binary is already present.
        
        Returns:
        	installed_path (Path): Filesystem path to the installed Infisical binary.
        """
        target_path = get_infisical_path()

        if target_path.exists() and not force:
            # Verify version
            try:
                result = subprocess.run(  # nosec B603
                    [str(target_path), "--version"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if self.version in result.stdout:
                    self.progress(f"infisical v{self.version} already installed")
                    return target_path
            except Exception:
                pass  # Version check failed, will reinstall

        self.download_and_extract(target_path)
        return target_path


class InfisicalScanner(ScannerBackend):
    """Infisical scanner with automatic binary installation.

    Infisical detects 140+ secret types using:
    - Pattern matching against known secret formats
    - Entropy-based detection
    - Git history scanning

    Example:
        scanner = InfisicalScanner(auto_install=True)
        result = scanner.scan([Path(".")])
        for finding in result.findings:
            print(f"{finding.severity}: {finding.description}")
    """

    def __init__(
        self,
        auto_install: bool = True,
        version: str | None = None,
    ) -> None:
        """Initialize the infisical scanner.

        Args:
            auto_install: Automatically install infisical if not found.
            version: Specific version to use. Uses pinned version if None.
        """
        self._auto_install = auto_install
        self._version = version or _get_infisical_version()
        self._binary_path: Path | None = None

    @property
    def name(self) -> str:
        """
        Scanner identifier for this scanner backend.
        
        Returns:
            str: The scanner identifier "infisical".
        """
        return "infisical"

    @property
    def description(self) -> str:
        """
        Human-readable description of the Infisical scanner.
        
        Returns:
            str: Short description stating supported secret types and git history scanning.
        """
        return "Infisical secret scanner (140+ secret types, git history)"

    def is_installed(self) -> bool:
        """
        Determine whether the Infisical CLI binary can be located.
        
        Returns:
            bool: `True` if the Infisical binary is found, `False` otherwise.
        """
        try:
            self._find_binary()
            return True
        except InfisicalNotFoundError:
            return False

    def get_version(self) -> str | None:
        """
        Return the installed Infisical CLI version string if available.
        
        Returns:
            version (str | None): The version token extracted from `infisical --version` (e.g., "0.31.1"), or `None` when the binary is not found or the version cannot be determined.
        """
        try:
            binary = self._find_binary()
            result = subprocess.run(  # nosec B603
                [str(binary), "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            # Output format: "infisical version X.Y.Z"
            output = result.stdout.strip()
            if output:
                parts = output.split()
                for part in parts:
                    if part and part[0].isdigit():
                        return part
            return None
        except Exception:
            return None

    def _find_binary(self) -> Path:
        """Find the infisical binary, installing if necessary.

        Returns:
            Path to the infisical binary.

        Raises:
            InfisicalNotFoundError: If binary cannot be found or installed.
        """
        if self._binary_path and self._binary_path.exists():
            return self._binary_path

        # Check in venv first
        venv_path = get_infisical_path()
        if venv_path.exists():
            self._binary_path = venv_path
            return venv_path

        # Check system PATH
        system_path = shutil.which("infisical")
        if system_path:
            self._binary_path = Path(system_path)
            return self._binary_path

        # Auto-install if enabled
        if self._auto_install:
            try:
                installer = InfisicalInstaller(version=self._version)
                self._binary_path = installer.install()
                return self._binary_path
            except InfisicalInstallError as e:
                raise InfisicalNotFoundError(
                    f"infisical not found and auto-install failed: {e}"
                ) from e

        raise InfisicalNotFoundError(
            "infisical not found. Install with: brew install infisical/get-cli/infisical "
            "or enable auto_install=True"
        )

    def install(
        self,
        progress_callback: Callable[[str], None] | None = None,
    ) -> Path | None:
        """
        Install the Infisical CLI binary and return its installed path.
        
        Parameters:
            progress_callback (Callable[[str], None] | None): Optional callback invoked with human-readable progress messages during download and installation.
        
        Returns:
            Path | None: Filesystem path to the installed Infisical binary, or `None` if installation did not produce a path.
        """
        installer = InfisicalInstaller(
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
        Scan the given files or directories for secrets using the Infisical CLI.
        
        Scans each provided path, optionally including Git history, aggregates findings into ScanFinding objects, and returns a ScanResult containing findings, number of files with findings, and elapsed duration. If the Infisical binary is not available or a scan fails (including timeouts), the returned ScanResult will include an error message and any findings gathered up to that point.
        
        Parameters:
            paths (list[Path]): Files or directories to scan.
            include_git_history (bool): If True, include Git history in the scan; if False, skip Git history.
        
        Returns:
            ScanResult: Result object containing `findings` (list of ScanFinding), `files_scanned` (count of unique files with findings), `duration_ms` (elapsed time in milliseconds), and `error` when applicable.
        """
        start_time = time.time()

        try:
            binary = self._find_binary()
        except InfisicalNotFoundError as e:
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

            # Create temp file for JSON report
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as report_file:
                report_path = Path(report_file.name)

            try:
                # Build command
                args = [
                    str(binary),
                    "scan",
                    "--report-path",
                    str(report_path),
                ]

                # If not scanning git history, use --no-git
                if not include_git_history:
                    args.append("--no-git")

                # Run infisical from the target directory
                work_dir = path if path.is_dir() else path.parent
                subprocess.run(  # nosec B603
                    args,
                    capture_output=True,
                    text=True,
                    timeout=300,  # 5 minute timeout
                    cwd=str(work_dir),
                )

                # Parse JSON report
                if report_path.exists() and report_path.stat().st_size > 0:
                    try:
                        report_data = json.loads(report_path.read_text())
                        if report_data and isinstance(report_data, list):
                            # Count unique files
                            files_with_findings = {
                                item.get("File") for item in report_data if item.get("File")
                            }
                            total_files += len(files_with_findings)
                            for item in report_data:
                                finding = self._parse_finding(item, path)
                                if finding:
                                    all_findings.append(finding)
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
        """
        Convert a single raw Infisical JSON finding into a ScanFinding.
        
        Parameters:
            item (dict[str, Any]): Raw finding object from Infisical scan output.
            base_path (Path): Base directory used to resolve relative file paths in the finding.
        
        Returns:
            ScanFinding or None: A populated ScanFinding representing the finding, or `None` if the item cannot be parsed.
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

            # Map rule ID
            rule_id: str = str(item.get("RuleID", "unknown"))
            description: str = str(item.get("Description") or rule_id)

            # Map severity based on rule type
            severity = RULE_SEVERITY_MAP.get(rule_id.lower(), FindingSeverity.HIGH)

            return ScanFinding(
                file_path=file_path,
                line_number=item.get("StartLine"),
                column_number=item.get("StartColumn"),
                rule_id=f"infisical-{rule_id}",
                rule_description=description,
                description=f"Secret detected: {description}",
                severity=severity,
                secret_preview=redacted,
                commit_sha=item.get("Commit"),
                commit_author=item.get("Author") or item.get("Email"),
                commit_date=item.get("Date"),
                entropy=item.get("Entropy"),
                scanner=self.name,
            )
        except Exception:
            return None