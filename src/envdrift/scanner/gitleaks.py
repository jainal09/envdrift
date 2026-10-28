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
import subprocess  # nosec B404
import tarfile
import tempfile
import time
import zipfile
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from envdrift.install_integrity import (
    DOWNLOAD_TIMEOUT_SECONDS,
    ChecksumVerificationError,
    atomic_install,
    download_file,
    verify_download,
)
from envdrift.scanner.base import (
    ScanFinding,
    ScannerBackend,
    ScanResult,
    exception_message,
    parsed_finding,
)
from envdrift.scanner.patterns import hash_secret, redact_secret
from envdrift.scanner.platform_utils import scan_argument, symlinked_file
from envdrift.scanner.rule_severity import rule_severity
from envdrift.utils.git import get_git_root, has_git_head
from envdrift.utils.text import strip_ansi

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


def _get_gitleaks_checksums_url() -> str:
    """Get the upstream checksums file URL template from constants."""
    return _load_constants().get("gitleaks_checksums_url", "")


class GitleaksNotFoundError(Exception):
    """Gitleaks binary not found."""

    pass


def _git_history_target(path: Path) -> tuple[Path | None, str | None]:
    """Resolve and validate the repository Gitleaks must scan for ``path``."""
    git_root = get_git_root(path)
    if git_root is None:
        return None, f"Cannot scan Git history for {path}: not inside a Git repository"
    if not has_git_head(git_root):
        return None, f"Cannot scan Git history for {path}: the Git repository has no commits"
    return git_root, None


def _prepare_scan_targets(
    paths: list[Path], *, include_git_history: bool
) -> tuple[list[Path], list[str]]:
    """Build the unique command targets for one Gitleaks run.

    Preflight failures are collected PER TARGET: a path that cannot be
    history-scanned (outside a git repository, or a repository with no
    commits) yields a diagnostic without discarding the other, valid targets.
    One bad argument used to abort the whole run — regardless of argument
    order — and suppress the valid repository's history findings (#641).
    """
    targets: list[Path] = []
    errors: list[str] = []
    seen_history_roots: set[Path] = set()
    for path in paths:
        if not path.exists():
            continue
        if not include_git_history:
            targets.append(path)
            continue

        history_target, error = _git_history_target(path)
        if error is not None or history_target is None:
            errors.append(error or f"Cannot scan Git history for {path}")
            continue
        resolved_target = history_target.resolve()
        if resolved_target in seen_history_roots:
            continue
        seen_history_roots.add(resolved_target)
        targets.append(history_target)
    return targets, errors


def _combined_error(run_error: str | None, target_errors: list[str]) -> str | None:
    """Join a run failure with the per-target preflight diagnostics (#641)."""
    parts = ([run_error] if run_error is not None else []) + target_errors
    return "; ".join(parts) if parts else None


def _load_findings(report_path: Path) -> list[Any] | None:
    """The findings in a gitleaks JSON report, or None when the report cannot be read.

    gitleaks writes ``[]``, or no report at all, when it finds nothing, so a missing or
    empty report holds no findings, and so does ``null``, which Go writes for an empty
    list. Anything else that is not a JSON list (a partly written file, or a message where
    the report should be) leaves the findings unknown, not absent, so it is not a clean
    scan (#874). gitleaks writes UTF-8 whatever the platform's encoding is (#873).
    """
    if not report_path.exists() or report_path.stat().st_size == 0:
        return []
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if report is None:
        return []
    return report if isinstance(report, list) else None


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

    def get_checksums_url(self) -> str:
        """Get the URL of the upstream-published checksums file for this version."""
        template = _get_gitleaks_checksums_url()
        return template.format(version=self.version) if template else ""

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
                download_file(url, archive_path, timeout=DOWNLOAD_TIMEOUT_SECONDS)
            except Exception as e:
                raise GitleaksInstallError(f"Download failed: {e}") from e

            # Verify against the published checksums before extracting anything.
            self.progress("Verifying checksum...")
            try:
                verify_download(archive_path, archive_name, self.get_checksums_url(), "gitleaks")
            except ChecksumVerificationError as e:
                raise GitleaksInstallError(str(e)) from e

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

            # Stage next to the target and atomically replace it, so an
            # interrupted copy (disk full, crash) can never corrupt a working
            # binary or leave a partial write behind (#490).
            try:
                atomic_install(extracted_binary, target_path)
            except OSError as e:
                raise GitleaksInstallError(f"Failed to install binary: {e}") from e

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
                    encoding="utf-8",
                    errors="replace",
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

    # Scans git history when ``include_git_history`` is set (#476).
    supports_git_history = True

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
                encoding="utf-8",
                errors="replace",
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
        all_findings: list[ScanFinding] = []
        total_files = 0

        # Per-target preflight: invalid history targets become diagnostics,
        # the valid ones still get scanned. Every returned ScanResult carries
        # the diagnostics in its error so an invalid argument keeps the run
        # truthfully incomplete without suppressing real findings (#641).
        scan_targets, target_errors = _prepare_scan_targets(
            paths, include_git_history=include_git_history
        )
        if target_errors and not scan_targets:
            return ScanResult(
                scanner_name=self.name,
                error=_combined_error(None, target_errors),
                duration_ms=int((time.time() - start_time) * 1000),
            )

        try:
            binary = self._find_binary()
        except GitleaksNotFoundError as e:
            return ScanResult(
                scanner_name=self.name,
                error=_combined_error(exception_message(e), target_errors),
                duration_ms=int((time.time() - start_time) * 1000),
            )

        for scan_target in scan_targets:
            # Create temp file for JSON output (gitleaks requires --report-path for JSON)
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as report_file:
                report_path = Path(report_file.name)

            try:
                # Build command. A directory scan runs in our cwd on the target
                # as given, so ``File`` is a path from our cwd and fingerprints
                # match a by-hand ``gitleaks dir <target>`` (#854). A history
                # scan runs in the repository root, its target, as it always
                # has: gitleaks also reads the .gitleaksignore in its cwd (its
                # --gitleaks-ignore-path defaults to "."), whose entries would
                # be matched against repo-relative history fingerprints. Its
                # ``File`` is relative to that root, so findings are joined
                # onto it.
                if include_git_history:
                    command, work_dir, target_arg = "git", scan_target, "."
                else:
                    command, work_dir, target_arg = "dir", None, scan_argument(scan_target)
                finding_base = scan_target if include_git_history else Path()
                file_link = symlinked_file(scan_target)
                args = [
                    str(binary),
                    command,
                    "--no-banner",
                    "--report-format",
                    "json",
                    "--report-path",
                    str(report_path),
                    "--exit-code",
                    "0",  # Don't fail on findings, we handle that
                    # A path is not an option, whatever it starts with: a
                    # changed file named ``--report-path=x`` must not redirect
                    # the report and pass the scan clean.
                    "--",
                    target_arg,
                ]

                result = subprocess.run(  # nosec B603
                    args,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=300,  # 5 minute timeout
                    cwd=work_dir,
                )

                if result.returncode != 0:
                    # zerolog colors its log lines even on a pipe, and this
                    # message lands in --json/SARIF output (#843).
                    error_msg = (
                        strip_ansi(result.stderr).strip()
                        or strip_ansi(result.stdout).strip()
                        or f"gitleaks scan failed for {scan_target} (exit code {result.returncode})"
                    )
                    return ScanResult(
                        scanner_name=self.name,
                        findings=all_findings,
                        error=_combined_error(error_msg, target_errors),
                        duration_ms=int((time.time() - start_time) * 1000),
                    )

                findings_data = _load_findings(report_path)
                if findings_data is None:
                    return ScanResult(
                        scanner_name=self.name,
                        findings=all_findings,
                        error=_combined_error(
                            f"gitleaks wrote a report for {scan_target} that envdrift cannot parse",
                            target_errors,
                        ),
                        duration_ms=int((time.time() - start_time) * 1000),
                    )
                # Count unique files with findings
                files_with_findings = {
                    item.get("File") for item in findings_data if item.get("File")
                }
                total_files += len(files_with_findings)
                for item in findings_data:
                    finding = parsed_finding(
                        self._parse_finding(item, finding_base),
                        f"gitleaks wrote a report for {scan_target} that envdrift cannot parse",
                    )
                    if file_link is not None:
                        # Scanned as its target; reported as the link.
                        finding = replace(finding, file_path=file_link)
                    all_findings.append(finding)

            except subprocess.TimeoutExpired:
                return ScanResult(
                    scanner_name=self.name,
                    findings=all_findings,
                    error=_combined_error(f"Scan timed out for {scan_target}", target_errors),
                    duration_ms=int((time.time() - start_time) * 1000),
                )
            except Exception as e:
                return ScanResult(
                    scanner_name=self.name,
                    findings=all_findings,
                    error=_combined_error(exception_message(e), target_errors),
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
            error=_combined_error(None, target_errors),
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

            # Gitleaks reports no severity, so grade by the rule that matched. This used
            # to be a flat HIGH, which let ``--fail-on critical`` through for an AWS key
            # ID or a private key (#850).
            severity = rule_severity(rule_id, str(secret))

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
