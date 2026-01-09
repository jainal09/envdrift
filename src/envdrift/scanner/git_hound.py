"""GitHound scanner integration with auto-installation.

GitHound is a fast GitHub recon tool that scans for leaked secrets across
all of GitHub using GitHub dorks, pattern matching, and entropy detection.

This module provides:
- Automatic binary download and installation
- Cross-platform support (macOS, Linux)
- JSON output parsing into ScanFinding objects
- Support for custom regex rules

Note: GitHound is primarily designed for scanning GitHub (remote) for exposed
secrets, but can also be used to scan local files with --dig-files flag.
For local repository scanning, gitleaks or trufflehog are more appropriate.

See: https://github.com/tillson/git-hound
"""

from __future__ import annotations

import json
import platform
import shutil
import stat
import subprocess
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


def _get_git_hound_version() -> str:
    """Get the pinned git-hound version from constants."""
    return _load_constants().get("git_hound_version", "3.3.1")


# Severity mapping based on finding type
SEVERITY_MAP: dict[str, FindingSeverity] = {
    "CRITICAL": FindingSeverity.CRITICAL,
    "HIGH": FindingSeverity.HIGH,
    "MEDIUM": FindingSeverity.MEDIUM,
    "LOW": FindingSeverity.LOW,
    "INFO": FindingSeverity.INFO,
}


class GitHoundNotFoundError(Exception):
    """GitHound binary not found."""

    pass


class GitHoundInstallError(Exception):
    """Failed to install GitHound."""

    pass


class GitHoundError(Exception):
    """GitHound command failed."""

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


def get_git_hound_path() -> Path:
    """Get the expected path to the git-hound binary.

    Returns:
        Path where git-hound should be installed.
    """
    bin_dir = get_venv_bin_dir()
    binary_name = "git-hound.exe" if platform.system() == "Windows" else "git-hound"
    return bin_dir / binary_name


class GitHoundInstaller:
    """Installer for git-hound binary."""

    # Download URLs by platform (git-hound releases)
    DOWNLOAD_URL_TEMPLATE = (
        "https://github.com/tillson/git-hound/releases/download/"
        "v{version}/git-hound_{version}_{os}_{arch}.{ext}"
    )

    PLATFORM_MAP: ClassVar[dict[tuple[str, str], tuple[str, str, str]]] = {
        ("Darwin", "x86_64"): ("darwin", "amd64", "tar.gz"),
        ("Darwin", "arm64"): ("darwin", "arm64", "tar.gz"),
        ("Linux", "x86_64"): ("linux", "amd64", "tar.gz"),
        ("Linux", "arm64"): ("linux", "arm64", "tar.gz"),
        # Note: git-hound doesn't have Windows releases
    }

    def __init__(
        self,
        version: str | None = None,
        progress_callback: Callable[[str], None] | None = None,
    ) -> None:
        """Initialize installer.

        Args:
            version: GitHound version to install. Uses pinned version if None.
            progress_callback: Optional callback for progress updates.
        """
        self.version = version or _get_git_hound_version()
        self.progress = progress_callback or (lambda x: None)

    def get_download_url(self) -> str:
        """Get the platform-specific download URL.

        Returns:
            URL to download git-hound for the current platform.

        Raises:
            GitHoundInstallError: If platform is not supported.
        """
        system, machine = get_platform_info()
        key = (system, machine)

        if key not in self.PLATFORM_MAP:
            supported = ", ".join(f"{s}/{m}" for s, m in self.PLATFORM_MAP)
            raise GitHoundInstallError(
                f"Unsupported platform: {system} {machine}. Supported: {supported}"
            )

        os_name, arch, ext = self.PLATFORM_MAP[key]

        return self.DOWNLOAD_URL_TEMPLATE.format(
            version=self.version,
            os=os_name,
            arch=arch,
            ext=ext,
        )

    def download_and_extract(self, target_path: Path) -> None:
        """Download and extract git-hound to the target path.

        Args:
            target_path: Where to install the git-hound binary.

        Raises:
            GitHoundInstallError: If download or extraction fails.
        """
        url = self.get_download_url()
        self.progress(f"Downloading git-hound v{self.version}...")

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            archive_name = url.split("/")[-1]
            archive_path = tmp_path / archive_name

            # Download
            try:
                urllib.request.urlretrieve(url, archive_path)  # nosec B310
            except Exception as e:
                raise GitHoundInstallError(f"Download failed: {e}") from e

            self.progress("Extracting...")

            # Extract based on archive type
            if archive_name.endswith(".tar.gz"):
                self._extract_tar_gz(archive_path, tmp_path)
            elif archive_name.endswith(".zip"):
                self._extract_zip(archive_path, tmp_path)
            else:
                raise GitHoundInstallError(f"Unknown archive format: {archive_name}")

            # Find the binary
            binary_name = "git-hound"
            extracted_binary = None

            for f in tmp_path.rglob(binary_name):
                if f.is_file():
                    extracted_binary = f
                    break

            # Also check for 'githound' without hyphen
            if not extracted_binary:
                for f in tmp_path.rglob("githound"):
                    if f.is_file():
                        extracted_binary = f
                        break

            if not extracted_binary:
                raise GitHoundInstallError(f"Binary '{binary_name}' not found in archive")

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
                    raise GitHoundInstallError(f"Unsafe path in archive: {member.name}")
            tar.extractall(target_dir, filter="data")  # nosec B202

    def _extract_zip(self, archive_path: Path, target_dir: Path) -> None:
        """Extract a zip archive."""
        with zipfile.ZipFile(archive_path, "r") as zip_ref:
            # Security: check for path traversal
            for name in zip_ref.namelist():
                member_path = target_dir / name
                if not member_path.resolve().is_relative_to(target_dir.resolve()):
                    raise GitHoundInstallError(f"Unsafe path in archive: {name}")
            zip_ref.extractall(target_dir)  # nosec B202

    def install(self, force: bool = False) -> Path:
        """Install git-hound binary.

        Args:
            force: Reinstall even if already installed.

        Returns:
            Path to the installed binary.
        """
        target_path = get_git_hound_path()

        if target_path.exists() and not force:
            # Verify version
            try:
                result = subprocess.run(
                    [str(target_path), "--version"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if self.version in result.stdout or self.version in result.stderr:
                    self.progress(f"git-hound v{self.version} already installed")
                    return target_path
            except Exception:
                pass  # Version check failed, will reinstall

        self.download_and_extract(target_path)
        return target_path


class GitHoundScanner(ScannerBackend):
    """GitHound scanner with automatic binary installation.

    GitHound is primarily designed for:
    - Scanning GitHub for exposed secrets via GitHub dorks
    - Pattern matching with Gitleaks rules
    - Entropy-based detection
    - Commit history digging

    Note: For local repository scanning, consider using gitleaks or trufflehog
    instead. GitHound is best used for organization-wide GitHub secret discovery.

    Example:
        scanner = GitHoundScanner(auto_install=True)
        result = scanner.scan([Path(".")], query="example.com")
        for finding in result.findings:
            print(f"{finding.severity}: {finding.description}")
    """

    def __init__(
        self,
        auto_install: bool = True,
        version: str | None = None,
        config_path: Path | None = None,
    ) -> None:
        """Initialize the git-hound scanner.

        Args:
            auto_install: Automatically install git-hound if not found.
            version: Specific version to use. Uses pinned version if None.
            config_path: Path to config.yml file for git-hound.
        """
        self._auto_install = auto_install
        self._version = version or _get_git_hound_version()
        self._config_path = config_path
        self._binary_path: Path | None = None

    @property
    def name(self) -> str:
        """Return scanner identifier."""
        return "git-hound"

    @property
    def description(self) -> str:
        """Return scanner description."""
        return "GitHound secret scanner (GitHub dorks + patterns + entropy)"

    def is_installed(self) -> bool:
        """Check if git-hound is available."""
        try:
            self._find_binary()
            return True
        except GitHoundNotFoundError:
            return False

    def get_version(self) -> str | None:
        """Get installed git-hound version."""
        try:
            binary = self._find_binary()
            result = subprocess.run(
                [str(binary), "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            # Parse version from output
            output = result.stdout.strip() or result.stderr.strip()
            if output:
                # Try to extract version number
                import re

                match = re.search(r"(\d+\.\d+\.\d+)", output)
                if match:
                    return match.group(1)
            return None
        except Exception:
            return None

    def _find_binary(self) -> Path:
        """Find the git-hound binary, installing if necessary.

        Returns:
            Path to the git-hound binary.

        Raises:
            GitHoundNotFoundError: If binary cannot be found or installed.
        """
        if self._binary_path and self._binary_path.exists():
            return self._binary_path

        # Check in venv first
        venv_path = get_git_hound_path()
        if venv_path.exists():
            self._binary_path = venv_path
            return venv_path

        # Check system PATH
        system_path = shutil.which("git-hound") or shutil.which("githound")
        if system_path:
            self._binary_path = Path(system_path)
            return self._binary_path

        # Auto-install if enabled
        if self._auto_install:
            try:
                installer = GitHoundInstaller(version=self._version)
                self._binary_path = installer.install()
                return self._binary_path
            except GitHoundInstallError as e:
                raise GitHoundNotFoundError(
                    f"git-hound not found and auto-install failed: {e}"
                ) from e

        raise GitHoundNotFoundError(
            "git-hound not found. Download from https://github.com/tillson/git-hound/releases"
        )

    def install(
        self,
        progress_callback: Callable[[str], None] | None = None,
    ) -> Path | None:
        """Install git-hound binary.

        Args:
            progress_callback: Optional callback for progress updates.

        Returns:
            Path to the installed binary.
        """
        installer = GitHoundInstaller(
            version=self._version,
            progress_callback=progress_callback,
        )
        self._binary_path = installer.install()
        return self._binary_path

    def scan(
        self,
        paths: list[Path],
        include_git_history: bool = False,
        query: str | None = None,
    ) -> ScanResult:
        """Scan paths for secrets using git-hound.

        Note: GitHound is primarily designed for GitHub-wide scanning.
        For local file scanning, it uses --dig-files mode.

        Args:
            paths: List of files or directories to scan.
            include_git_history: If True, dig through commits (--dig-commits).
            query: Optional query string for GitHub search mode.

        Returns:
            ScanResult containing all findings.
        """
        start_time = time.time()

        try:
            binary = self._find_binary()
        except GitHoundNotFoundError as e:
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
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as report_file:
                report_path = Path(report_file.name)

            try:
                # Build command for local file scanning
                # GitHound can scan local files in a repo with specific flags
                args = [
                    str(binary),
                    "--json",  # JSON output
                    "--dig-files",  # Dig through files in repo
                ]

                if include_git_history:
                    args.append("--dig-commits")

                if self._config_path and self._config_path.exists():
                    args.extend(["--config-file", str(self._config_path)])

                # For local scanning, we need to set the query or use stdin
                # GitHound expects a query via stdin or --query flag
                if query:
                    args.extend(["--query", query])
                else:
                    # Use repo path as context
                    args.extend(["--query", str(path)])

                result = subprocess.run(
                    args,
                    capture_output=True,
                    text=True,
                    timeout=300,  # 5 minute timeout
                    cwd=str(path) if path.is_dir() else str(path.parent),
                )

                # Parse JSON output from stdout
                if result.stdout:
                    try:
                        # GitHound outputs one JSON object per line
                        findings_data = []
                        for line in result.stdout.strip().split("\n"):
                            if line.strip():
                                try:
                                    findings_data.append(json.loads(line))
                                except json.JSONDecodeError:
                                    continue

                        for item in findings_data:
                            finding = self._parse_finding(item, path)
                            if finding:
                                all_findings.append(finding)
                                total_files += 1
                    except Exception:
                        pass  # Parsing failed, continue

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
        """Parse a git-hound finding into our format.

        Args:
            item: Raw finding from git-hound JSON output.
            base_path: Base path for resolving relative paths.

        Returns:
            ScanFinding or None if parsing fails.
        """
        try:
            # GitHound output format includes:
            # - file: file path
            # - line: line number
            # - match: the matched secret
            # - rule: rule that matched
            # - entropy: entropy score

            file_path_str = item.get("file", item.get("File", ""))
            if file_path_str:
                file_path = Path(file_path_str)
                if not file_path.is_absolute():
                    file_path = (base_path / file_path).resolve()
            else:
                file_path = base_path

            # Get the secret match and redact it
            secret = item.get("match", item.get("Match", item.get("secret", "")))
            redacted = redact_secret(secret) if secret else ""

            # Map rule ID
            rule_id = item.get("rule", item.get("Rule", item.get("type", "unknown")))
            rule_description = item.get("description", rule_id)

            # Determine severity based on entropy or rule
            entropy = item.get("entropy", item.get("Entropy"))
            if entropy and float(entropy) > 4.5:
                severity = FindingSeverity.HIGH
            else:
                severity = FindingSeverity.MEDIUM

            return ScanFinding(
                file_path=file_path,
                line_number=item.get("line", item.get("Line")),
                column_number=item.get("column", item.get("Column")),
                rule_id=f"git-hound-{rule_id}",
                rule_description=rule_description,
                description=f"Secret detected by GitHound: {rule_description}",
                severity=severity,
                secret_preview=redacted,
                commit_sha=item.get("commit", item.get("Commit")),
                commit_author=item.get("author", item.get("Author")),
                commit_date=item.get("date", item.get("Date")),
                entropy=entropy,
                scanner=self.name,
            )
        except Exception:
            return None

    def scan_github(
        self,
        query: str,
        dig_commits: bool = False,
        dig_files: bool = True,
        many_results: bool = False,
        pages: int = 10,
    ) -> ScanResult:
        """Scan GitHub using GitHub dorks for exposed secrets.

        This is GitHound's primary use case - searching across all of GitHub
        for secrets related to a specific domain or organization.

        Args:
            query: GitHub dork query (e.g., "example.com", "AKIA").
            dig_commits: Dig through commit history.
            dig_files: Dig through repo files.
            many_results: Use filtering hack for >100 pages.
            pages: Maximum pages to search (default 100).

        Returns:
            ScanResult containing all findings.
        """
        start_time = time.time()

        try:
            binary = self._find_binary()
        except GitHoundNotFoundError as e:
            return ScanResult(
                scanner_name=self.name,
                error=str(e),
                duration_ms=int((time.time() - start_time) * 1000),
            )

        all_findings: list[ScanFinding] = []

        try:
            args = [
                str(binary),
                "--query",
                query,
                "--json",
                "--pages",
                str(pages),
            ]

            if dig_commits:
                args.append("--dig-commits")
            if dig_files:
                args.append("--dig-files")
            if many_results:
                args.append("--many-results")

            if self._config_path and self._config_path.exists():
                args.extend(["--config-file", str(self._config_path)])

            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=600,  # 10 minute timeout for GitHub scanning
            )

            if result.stdout:
                for line in result.stdout.strip().split("\n"):
                    if line.strip():
                        try:
                            item = json.loads(line)
                            finding = self._parse_finding(item, Path.cwd())
                            if finding:
                                all_findings.append(finding)
                        except json.JSONDecodeError:
                            continue

        except subprocess.TimeoutExpired:
            return ScanResult(
                scanner_name=self.name,
                findings=all_findings,
                error="GitHub scan timed out",
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
            files_scanned=len(all_findings),
            duration_ms=int((time.time() - start_time) * 1000),
        )
