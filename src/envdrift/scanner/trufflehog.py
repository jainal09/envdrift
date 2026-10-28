"""Trufflehog scanner integration with auto-installation.

Trufflehog is a secret detection tool that can:
- Detect secrets using pattern matching and entropy
- Verify secrets against live services (optional)
- Scan git history for leaked secrets

This module provides:
- Automatic binary download and installation
- Cross-platform support (macOS, Linux, Windows)
- JSON output parsing into ScanFinding objects
- Git history scanning support
- Secret verification support
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess  # nosec B404
import tarfile
import tempfile
import time
import zipfile
from dataclasses import replace
from pathlib import Path, PurePath
from typing import TYPE_CHECKING, Any, ClassVar
from urllib.parse import quote

from envdrift.install_integrity import (
    DOWNLOAD_TIMEOUT_SECONDS,
    ChecksumVerificationError,
    atomic_install,
    download_file,
    verify_download,
)
from envdrift.scanner.base import (
    FindingSeverity,
    ScanFinding,
    ScannerBackend,
    ScanResult,
    exception_message,
    parsed_finding,
)
from envdrift.scanner.patterns import hash_secret, redact_secret
from envdrift.utils.deadline import run_tool
from envdrift.utils.git import get_git_root, has_git_head

if TYPE_CHECKING:
    from collections.abc import Callable


def _load_constants() -> dict:
    """Load constants from the package's constants.json."""
    constants_path = Path(__file__).parent.parent / "constants.json"
    with open(constants_path) as f:
        return json.load(f)


def _get_trufflehog_version() -> str:
    """Get the pinned trufflehog version from constants."""
    return _load_constants().get("trufflehog_version", "3.88.3")


def _get_trufflehog_download_urls() -> dict[str, str]:
    """Get download URL templates from constants."""
    return _load_constants().get("trufflehog_download_urls", {})


def _get_trufflehog_checksums_url() -> str:
    """Get the upstream checksums file URL template from constants."""
    return _load_constants().get("trufflehog_checksums_url", "")


class TrufflehogNotFoundError(Exception):
    """Trufflehog binary not found."""

    pass


class TrufflehogInstallError(Exception):
    """Failed to install trufflehog."""

    pass


class TrufflehogError(Exception):
    """Trufflehog command failed."""

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


def get_trufflehog_path() -> Path:
    """Get the expected path to the trufflehog binary.

    Returns:
        Path where trufflehog should be installed.
    """
    bin_dir = get_venv_bin_dir()
    binary_name = "trufflehog.exe" if platform.system() == "Windows" else "trufflehog"
    return bin_dir / binary_name


def _load_findings(output: str) -> tuple[list[Any], bool]:
    """The findings trufflehog printed, one JSON object per line, and whether all were read.

    A line that is not JSON is progress output and is skipped. A line that starts as a JSON
    object but does not parse is a finding cut short, and a line of JSON that is not an
    object is no finding at all; either leaves the findings unknown, not absent (#874): the
    findings that parse are returned, with False. Lines are split on ``\\n`` only, as
    trufflehog writes them; a secret may hold other line breaks.
    """
    findings: list[Any] = []
    complete = True
    for line in output.split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            finding = json.loads(line)
        except json.JSONDecodeError:
            if line.startswith("{"):
                complete = False
            continue
        if isinstance(finding, dict):
            findings.append(finding)
        else:
            complete = False
    return findings, complete


def _history_target(path: Path) -> tuple[Path | None, str | None]:
    """The root of the Git repository whose history trufflehog scans for ``path``.

    The root comes back in the form of ``path``, relative to the cwd for a relative one, so
    relative scan paths keep reporting relative findings.

    Returns:
        Tuple of (repository root, None), or (None, error message).
    """
    git_root = get_git_root(path)
    if git_root is None:
        return None, f"Cannot scan Git history for {path}: not inside a Git repository"
    if not has_git_head(git_root):
        return None, f"Cannot scan Git history for {path}: the Git repository has no commits"
    if path.is_absolute():
        return git_root, None
    try:
        return Path(os.path.relpath(git_root, Path.cwd())), None
    except ValueError:
        # Windows: a root on another drive than the cwd has no relative form.
        return git_root, None


def _scan_targets(paths: list[Path], *, include_git_history: bool) -> tuple[list[Path], list[str]]:
    """The targets to run trufflehog on, and why any path cannot be scanned.

    In history mode every path maps to its repository root, and paths in the same repository
    share one scan. A path whose history cannot be scanned (outside a repository, or in one
    without commits) is an error, never a quiet scan of its files instead (#906), and does not
    keep the other paths from being scanned.
    """
    targets: list[Path] = []
    errors: list[str] = []
    seen_roots: set[Path] = set()
    for path in paths:
        if not path.exists():
            continue
        if not include_git_history:
            targets.append(path)
            continue
        root, error = _history_target(path)
        if root is None:
            errors.append(error or f"Cannot scan Git history for {path}")
            continue
        if root.resolve() not in seen_roots:
            seen_roots.add(root.resolve())
            targets.append(root)
    return targets, errors


def _git_uri(root: PurePath) -> str:
    """The ``file://`` URI of the repository at ``root``, for ``trufflehog git``.

    trufflehog parses it with Go's url.Parse, then joins its host and path back into a path. So the
    path is written with forward slashes and percent-encoded: a ``#``, ``%`` or ``?`` in a directory
    name stays in the path, and a Windows drive lands in the host, the form git takes as well
    (``file://C:/projects/repo``). ``file://C:\\...`` did not parse, and trufflehog tried it as an
    SSH URL, so no history scan ran on Windows.
    """
    return "file://" + quote(root.as_posix(), safe="/:")


def _under(target: Path, physical: Path, reported: Path) -> Path:
    """``reported``, a file trufflehog found below ``physical``, named under ``target``.

    trufflehog scans ``physical``, the resolved form of ``target``, and names each file it walks
    by that path. A path relative to a repository root was already joined onto ``target`` and is
    returned as is.
    """
    try:
        return target / reported.relative_to(physical)
    except ValueError:
        return reported


def _logged_error(stderr: str) -> str:
    """The errors trufflehog logged on ``stderr``, as ``message: error``.

    Under ``--json`` trufflehog logs JSON lines, and the error of a failed run is in an entry of
    level ``error``. Output that is no JSON log at all is returned as it is. A log without an
    error entry returns an empty string.
    """
    errors: list[str] = []
    logged = False
    for line in stderr.splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(entry, dict):
            continue
        logged = True
        if entry.get("level") == "error":
            errors.append(": ".join(str(entry[key]) for key in ("msg", "error") if entry.get(key)))
    if errors:
        return "; ".join(errors)
    return "" if logged else stderr.strip()


class TrufflehogInstaller:
    """Installer for trufflehog binary."""

    # Download URL template
    DOWNLOAD_URL_TEMPLATE = (
        "https://github.com/trufflesecurity/trufflehog/releases/download/"
        "v{version}/trufflehog_{version}_{os}_{arch}.{ext}"
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
            version: Trufflehog version to install. Uses pinned version if None.
            progress_callback: Optional callback for progress updates.
        """
        self.version = version or _get_trufflehog_version()
        self.progress = progress_callback or (lambda x: None)

    def get_download_url(self) -> str:
        """Get the platform-specific download URL.

        Returns:
            URL to download trufflehog for the current platform.

        Raises:
            TrufflehogInstallError: If platform is not supported.
        """
        system, machine = get_platform_info()
        key = (system, machine)

        if key not in self.PLATFORM_MAP:
            supported = ", ".join(f"{s}/{m}" for s, m in self.PLATFORM_MAP)
            raise TrufflehogInstallError(
                f"Unsupported platform: {system} {machine}. Supported: {supported}"
            )

        os_name, arch, ext = self.PLATFORM_MAP[key]

        # Check if we have custom URLs in constants
        custom_urls = _get_trufflehog_download_urls()
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
        template = _get_trufflehog_checksums_url()
        return template.format(version=self.version) if template else ""

    def download_and_extract(self, target_path: Path) -> None:
        """Download, verify, and extract trufflehog to the target path.

        The downloaded archive's SHA256 is checked against the upstream
        checksums file before extraction; verification fails closed (#490).

        Args:
            target_path: Where to install the trufflehog binary.

        Raises:
            TrufflehogInstallError: If download, verification, or extraction fails.
        """
        url = self.get_download_url()
        self.progress(f"Downloading trufflehog v{self.version}...")

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            archive_name = url.split("/")[-1]
            archive_path = tmp_path / archive_name

            # Download
            try:
                download_file(url, archive_path, timeout=DOWNLOAD_TIMEOUT_SECONDS)
            except Exception as e:
                raise TrufflehogInstallError(f"Download failed: {e}") from e

            # Verify against the published checksums before extracting anything.
            self.progress("Verifying checksum...")
            try:
                verify_download(archive_path, archive_name, self.get_checksums_url(), "trufflehog")
            except ChecksumVerificationError as e:
                raise TrufflehogInstallError(str(e)) from e

            self.progress("Extracting...")

            # Extract based on archive type
            if archive_name.endswith(".tar.gz"):
                self._extract_tar_gz(archive_path, tmp_path)
            elif archive_name.endswith(".zip"):
                self._extract_zip(archive_path, tmp_path)
            else:
                raise TrufflehogInstallError(f"Unknown archive format: {archive_name}")

            # Find the binary
            binary_name = "trufflehog.exe" if platform.system() == "Windows" else "trufflehog"
            extracted_binary = None

            for f in tmp_path.rglob(binary_name):
                if f.is_file():
                    extracted_binary = f
                    break

            if not extracted_binary:
                raise TrufflehogInstallError(f"Binary '{binary_name}' not found in archive")

            # Stage next to the target and atomically replace it, so an
            # interrupted copy (disk full, crash) can never corrupt a working
            # binary or leave a partial write behind (#490).
            try:
                atomic_install(extracted_binary, target_path)
            except OSError as e:
                raise TrufflehogInstallError(f"Failed to install binary: {e}") from e

            self.progress(f"Installed to {target_path}")

    def _extract_tar_gz(self, archive_path: Path, target_dir: Path) -> None:
        """Extract a tar.gz archive."""
        with tarfile.open(archive_path, "r:gz") as tar:
            # Security: check for path traversal
            for member in tar.getmembers():
                member_path = target_dir / member.name
                if not member_path.resolve().is_relative_to(target_dir.resolve()):
                    raise TrufflehogInstallError(f"Unsafe path in archive: {member.name}")
            tar.extractall(target_dir, filter="data")  # nosec B202

    def _extract_zip(self, archive_path: Path, target_dir: Path) -> None:
        """Extract a zip archive."""
        with zipfile.ZipFile(archive_path, "r") as zip_ref:
            # Security: check for path traversal
            for name in zip_ref.namelist():
                member_path = target_dir / name
                if not member_path.resolve().is_relative_to(target_dir.resolve()):
                    raise TrufflehogInstallError(f"Unsafe path in archive: {name}")
            zip_ref.extractall(target_dir)  # nosec B202

    def install(self, force: bool = False) -> Path:
        """Install trufflehog binary.

        Args:
            force: Reinstall even if already installed.

        Returns:
            Path to the installed binary.
        """
        target_path = get_trufflehog_path()

        if target_path.exists() and not force:
            # Verify version
            try:
                result = run_tool(
                    [str(target_path), "--version"],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=10,
                )
                if self.version in result.stdout:
                    self.progress(f"trufflehog v{self.version} already installed")
                    return target_path
            except Exception:
                pass  # Version check failed, will reinstall

        self.download_and_extract(target_path)
        return target_path


class TrufflehogScanner(ScannerBackend):
    """Trufflehog scanner with automatic binary installation.

    Trufflehog detects secrets using:
    - Pattern matching against 800+ detector types
    - Entropy-based detection
    - Git history scanning
    - Secret verification (optional)

    Example:
        scanner = TrufflehogScanner(auto_install=True, verify=True)
        result = scanner.scan([Path(".")])
        for finding in result.findings:
            status = "VERIFIED" if finding.verified else "unverified"
            print(f"{finding.severity} ({status}): {finding.description}")
    """

    def __init__(
        self,
        auto_install: bool = True,
        version: str | None = None,
        verify: bool = False,
    ) -> None:
        """Initialize the trufflehog scanner.

        Args:
            auto_install: Automatically install trufflehog if not found.
            version: Specific version to use. Uses pinned version if None.
            verify: Verify secrets against live services.
        """
        self._auto_install = auto_install
        self._version = version or _get_trufflehog_version()
        self._verify = verify
        self._binary_path: Path | None = None

    # Scans git history when ``include_git_history`` is set (#476).
    supports_git_history = True

    @property
    def name(self) -> str:
        """Return scanner identifier."""
        return "trufflehog"

    @property
    def description(self) -> str:
        """Return scanner description."""
        desc = "Trufflehog secret scanner (800+ detectors + git history)"
        if self._verify:
            desc += " with verification"
        return desc

    def is_installed(self) -> bool:
        """Check if trufflehog is available."""
        try:
            self._find_binary()
            return True
        except TrufflehogNotFoundError:
            return False

    def get_version(self) -> str | None:
        """Get installed trufflehog version."""
        try:
            binary = self._find_binary()
            result = run_tool(
                [str(binary), "--version"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
            )
            # Output format: "trufflehog 3.88.3"
            return result.stdout.strip().split()[-1] if result.returncode == 0 else None
        except Exception:
            return None

    def _find_binary(self) -> Path:
        """Find the trufflehog binary, installing if necessary.

        Returns:
            Path to the trufflehog binary.

        Raises:
            TrufflehogNotFoundError: If binary cannot be found or installed.
        """
        if self._binary_path and self._binary_path.exists():
            return self._binary_path

        # Check in venv first
        venv_path = get_trufflehog_path()
        if venv_path.exists():
            self._binary_path = venv_path
            return venv_path

        # Check system PATH
        system_path = shutil.which("trufflehog")
        if system_path:
            self._binary_path = Path(system_path)
            return self._binary_path

        # Auto-install if enabled
        if self._auto_install:
            try:
                installer = TrufflehogInstaller(version=self._version)
                self._binary_path = installer.install()
                return self._binary_path
            except TrufflehogInstallError as e:
                raise TrufflehogNotFoundError(
                    f"trufflehog not found and auto-install failed: {e}"
                ) from e

        raise TrufflehogNotFoundError(
            "trufflehog not found. Install with: brew install trufflehog "
            "or enable auto_install=True"
        )

    def install(
        self,
        progress_callback: Callable[[str], None] | None = None,
    ) -> Path | None:
        """Install trufflehog binary.

        Args:
            progress_callback: Optional callback for progress updates.

        Returns:
            Path to the installed binary.
        """
        installer = TrufflehogInstaller(
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
        """Scan paths for secrets using trufflehog.

        Args:
            paths: List of files or directories to scan.
            include_git_history: If True, scan the history of their Git repositories instead.

        Returns:
            ScanResult containing all findings.
        """
        start_time = time.time()

        try:
            binary = self._find_binary()
        except TrufflehogNotFoundError as e:
            return ScanResult(
                scanner_name=self.name,
                error=exception_message(e),
                duration_ms=int((time.time() - start_time) * 1000),
            )

        targets, errors = _scan_targets(paths, include_git_history=include_git_history)
        all_findings: list[ScanFinding] = []
        total_files = 0
        for target in targets:
            findings, files, error = self._scan_target(binary, target, include_git_history)
            all_findings.extend(findings)
            total_files += files
            if error is not None:
                errors.insert(0, error)
                break

        return ScanResult(
            scanner_name=self.name,
            findings=all_findings,
            files_scanned=total_files,
            error="; ".join(errors) if errors else None,
            duration_ms=int((time.time() - start_time) * 1000),
        )

    def _scan_target(
        self, binary: Path, target: Path, include_git_history: bool
    ) -> tuple[list[ScanFinding], int, str | None]:
        """Run trufflehog on one target: its findings, the files they are in, and its error.

        trufflehog follows no symlink at the root it is given, and cleans that root lexically, so
        a symlinked directory or file, or ``..`` after a symlink, scanned as nothing (#906). It is
        given the physical path instead, names every file by it, and each file is named under
        ``target`` again. A history target is a repository root: trufflehog clones it, and names
        each file relative to it.
        """
        physical = target.resolve()
        if include_git_history:
            args = [str(binary), "git", _git_uri(physical), "--json"]
        else:
            args = [str(binary), "filesystem", str(physical), "--json"]

        # Without --no-update, every scan runs trufflehog's self-updater, which writes any newer
        # release from oss.trufflehog.org over the pinned, checksum-verified binary (#907).
        args.append("--no-update")

        # Add verification flag if enabled
        if not self._verify:
            args.append("--no-verification")

        unparsable = f"trufflehog printed a finding for {target} that envdrift cannot parse"
        findings: list[ScanFinding] = []
        try:
            result = run_tool(
                args,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=600,  # 10 minute timeout (trufflehog can be slow)
            )
            # Parse JSON lines output (trufflehog outputs one JSON per line)
            items, complete = _load_findings(result.stdout)
            for item in items:
                finding = parsed_finding(self._parse_finding(item, target), unparsable)
                file_path = _under(target, physical, finding.file_path)
                findings.append(replace(finding, file_path=file_path))
        except subprocess.TimeoutExpired:
            return findings, 0, f"Scan timed out for {target}"
        except Exception as e:
            return findings, 0, exception_message(e)

        files = len({finding.file_path for finding in findings})
        if result.returncode != 0:
            # Not stdout: the findings there hold the raw secrets.
            failure = f"trufflehog scan failed for {target} (exit code {result.returncode})"
            return findings, files, _logged_error(result.stderr) or failure
        if not complete:
            return findings, files, unparsable
        return findings, files, None

    def _parse_finding(self, item: dict[str, Any], base_path: Path) -> ScanFinding | None:
        """Parse a trufflehog finding into our format.

        Args:
            item: Raw finding from trufflehog JSON output.
            base_path: Base path for resolving relative paths.

        Returns:
            ScanFinding or None if parsing fails.
        """
        try:
            # Get source metadata
            source_metadata = item.get("SourceMetadata", {})
            data = source_metadata.get("Data", {})

            # Try to get file path from various locations
            file_path_str = ""

            # For filesystem scans
            filesystem_data = data.get("Filesystem", {})
            if filesystem_data:
                file_path_str = filesystem_data.get("file", "")

            # For git scans
            git_data = data.get("Git", {})
            if git_data:
                file_path_str = git_data.get("file", "")

            # Resolve path
            if file_path_str:
                file_path = Path(file_path_str)
                if not file_path.is_absolute():
                    file_path = base_path / file_path
            else:
                file_path = base_path

            # Get the secret and redact it
            raw_secret = item.get("Raw", "")
            redacted = redact_secret(raw_secret) if raw_secret else ""
            secret_hash = hash_secret(raw_secret) if raw_secret else ""

            # Get detector info
            detector_name = item.get("DetectorName", "unknown")

            # Determine severity based on verification status
            verified = item.get("Verified", False)
            severity = FindingSeverity.CRITICAL if verified else FindingSeverity.HIGH

            # Get line number from source metadata
            line_number = None
            if filesystem_data:
                line_number = filesystem_data.get("line")
            elif git_data:
                line_number = git_data.get("line")

            # Get commit info for git scans
            commit_sha = git_data.get("commit") if git_data else None
            commit_author = git_data.get("email") if git_data else None
            commit_date = git_data.get("timestamp") if git_data else None

            return ScanFinding(
                file_path=file_path,
                line_number=line_number,
                rule_id=f"trufflehog-{detector_name.lower().replace(' ', '-')}",
                rule_description=detector_name,
                description=f"{'Verified ' if verified else ''}Secret detected: {detector_name}",
                severity=severity,
                secret_preview=redacted,
                secret_hash=secret_hash,
                commit_sha=commit_sha,
                commit_author=commit_author,
                commit_date=commit_date,
                verified=verified,
                scanner=self.name,
            )
        except Exception:
            return None
