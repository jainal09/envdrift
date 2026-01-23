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
from envdrift.scanner.patterns import hash_secret, redact_secret
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


def _get_infisical_version() -> str:
    """Get the pinned infisical version from constants."""
    return _load_constants().get("infisical_version", "0.31.1")


def _get_infisical_download_urls() -> dict[str, str]:
    """Get download URL templates from constants."""
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


def get_infisical_path() -> Path:
    """Get the expected path to the infisical binary.

    Returns:
        Path where infisical should be installed.
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
        """Initialize installer.

        Args:
            version: Infisical version to install. Uses pinned version if None.
            progress_callback: Optional callback for progress updates.
        """
        self.version = version or _get_infisical_version()
        self.progress = progress_callback or (lambda x: None)

    def get_download_url(self) -> str:
        """Get the platform-specific download URL.

        Returns:
            URL to download infisical for the current platform.

        Raises:
            InfisicalInstallError: If platform is not supported.
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
        """Download and extract infisical to the target path.

        Args:
            target_path: Where to install the infisical binary.

        Raises:
            InfisicalInstallError: If download or extraction fails.
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
        """Extract a tar.gz archive with path traversal protection."""
        with tarfile.open(archive_path, "r:gz") as tar:
            safe_extract_tar(tar, target_dir, InfisicalInstallError)

    def _extract_zip(self, archive_path: Path, target_dir: Path) -> None:
        """Extract a zip archive with path traversal protection."""
        with zipfile.ZipFile(archive_path, "r") as zip_ref:
            safe_extract_zip(zip_ref, target_dir, InfisicalInstallError)

    def install(self, force: bool = False) -> Path:
        """Install infisical binary.

        Args:
            force: Reinstall even if already installed.

        Returns:
            Path to the installed binary.
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
                # Version check failed (binary corrupt or incompatible), will reinstall
                pass

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
        """Return scanner identifier."""
        return "infisical"

    @property
    def description(self) -> str:
        """Return scanner description."""
        return "Infisical secret scanner (140+ secret types, git history)"

    def is_installed(self) -> bool:
        """Check if infisical is available."""
        try:
            self._find_binary()
            return True
        except InfisicalNotFoundError:
            return False

    def get_version(self) -> str | None:
        """Get installed infisical version."""
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
        """Install infisical binary.

        Args:
            progress_callback: Optional callback for progress updates.

        Returns:
            Path to the installed binary.
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
        """Scan paths for secrets using infisical.

        Args:
            paths: List of files or directories to scan.
            include_git_history: If True, scan git history as well.

        Returns:
            ScanResult containing all findings.
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
            report_path: Path | None = None
            try:
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".json", delete=False
                ) as report_file:
                    report_path = Path(report_file.name)
                # Build command with explicit source path
                work_dir = path if path.is_dir() else path.parent
                args = [
                    str(binary),
                    "scan",
                    "--report-path",
                    str(report_path),
                    "--source",
                    str(path),
                ]

                # If not scanning git history, use --no-git
                if not include_git_history:
                    args.append("--no-git")

                # Run infisical scan
                result = subprocess.run(  # nosec B603
                    args,
                    capture_output=True,
                    text=True,
                    timeout=300,  # 5 minute timeout
                    cwd=str(work_dir),
                )

                # Infisical returns non-zero when leaks are found, so only treat as
                # error if no report was generated.
                if result.returncode != 0 and (
                    not report_path.exists() or report_path.stat().st_size == 0
                ):
                    error_msg = (
                        result.stderr.strip()
                        or result.stdout.strip()
                        or f"infisical scan failed for {path} (exit code {result.returncode})"
                    )
                    return ScanResult(
                        scanner_name=self.name,
                        findings=all_findings,
                        error=error_msg,
                        duration_ms=int((time.time() - start_time) * 1000),
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
                            # Use work_dir as base for relative path resolution
                            base_dir = work_dir
                            for item in report_data:
                                finding = self._parse_finding(item, base_dir)
                                if finding:
                                    all_findings.append(finding)
                    except json.JSONDecodeError:
                        # Invalid JSON in report, skip findings for this path
                        continue


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
                if report_path is not None and report_path.exists():
                    report_path.unlink()

        return ScanResult(
            scanner_name=self.name,
            findings=all_findings,
            files_scanned=total_files,
            duration_ms=int((time.time() - start_time) * 1000),
        )

    def _parse_finding(self, item: dict[str, Any], base_path: Path) -> ScanFinding | None:
        """Parse an infisical finding into our format.

        Args:
            item: Raw finding from infisical JSON output.
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
                secret_hash=secret_hash,
                commit_sha=item.get("Commit"),
                commit_author=item.get("Author") or item.get("Email"),
                commit_date=item.get("Date"),
                entropy=item.get("Entropy"),
                scanner=self.name,
            )
        except Exception:
            return None
