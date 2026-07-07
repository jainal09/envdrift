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
import subprocess  # nosec B404
import tarfile
import tempfile
import time
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from envdrift.install_integrity import (
    ChecksumVerificationError,
    atomic_install,
    verify_download,
)
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


def _get_trivy_version() -> str:
    """Get the pinned trivy version from constants."""
    return _load_constants().get("trivy_version", "0.58.0")


def _get_trivy_download_urls() -> dict[str, str]:
    """Get download URL templates from constants."""
    return _load_constants().get("trivy_download_urls", {})


def _get_trivy_checksums_url() -> str:
    """Get the upstream checksums file URL template from constants."""
    return _load_constants().get("trivy_checksums_url", "")


# Severity mapping from trivy to our severity levels
SEVERITY_MAP: dict[str, FindingSeverity] = {
    "CRITICAL": FindingSeverity.CRITICAL,
    "HIGH": FindingSeverity.HIGH,
    "MEDIUM": FindingSeverity.MEDIUM,
    "LOW": FindingSeverity.LOW,
    "UNKNOWN": FindingSeverity.INFO,
}


@dataclass
class _ParseState:
    """Shared state for parsing one trivy JSON document.

    ``fallback_counts`` assigns occurrence indices to byte-identical
    unrecoverable findings (two distinct same-rule secrets on ONE line
    produce identical trivy dicts) so they never share a fallback hash;
    ``line_cache`` lets n findings in one file cost a single read.
    """

    fallback_counts: dict[tuple[str, str, str, str, str], int] = field(default_factory=dict)
    line_cache: dict[Path, list[str] | None] = field(default_factory=dict)


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

    def get_checksums_url(self) -> str:
        """Get the URL of the upstream-published checksums file for this version."""
        template = _get_trivy_checksums_url()
        return template.format(version=self.version) if template else ""

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

            # Verify against the published checksums before extracting anything.
            self.progress("Verifying checksum...")
            try:
                verify_download(archive_path, archive_name, self.get_checksums_url(), "trivy")
            except ChecksumVerificationError as e:
                raise TrivyInstallError(str(e)) from e

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

            # Stage next to the target and atomically replace it, so an
            # interrupted copy (disk full, crash) can never corrupt a working
            # binary or leave a partial write behind (#490).
            try:
                atomic_install(extracted_binary, target_path)
            except OSError as e:
                raise TrivyInstallError(f"Failed to install binary: {e}") from e

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
                    encoding="utf-8",
                    errors="replace",
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
                encoding="utf-8",
                errors="replace",
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
                    encoding="utf-8",
                    errors="replace",
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
        state = _ParseState()

        # Trivy output structure: { "Results": [...] }
        results = scan_data.get("Results", [])

        for result in results:
            target = result.get("Target", "")
            if target:
                files_scanned += 1

            # Get secrets from result
            secrets = result.get("Secrets", [])
            for secret in secrets:
                finding = self._parse_secret(secret, target, base_path, state)
                if finding:
                    findings.append(finding)

        return findings, files_scanned

    def _parse_secret(
        self,
        secret: dict[str, Any],
        target: str,
        base_path: Path,
        state: _ParseState | None = None,
    ) -> ScanFinding | None:
        """Parse a single trivy secret into a ScanFinding.

        Args:
            secret: Secret data from trivy output.
            target: Target file path.
            base_path: Base path for resolving relative paths.
            state: Shared per-parse state (see :class:`_ParseState`).
                ``None`` (direct call) behaves as a fresh parse.

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

            # Map rule ID
            rule_id: str = secret.get("RuleID", "unknown")
            category: str = secret.get("Category", "Secret")
            title: str = secret.get("Title", rule_id)

            secret_hash, redacted = self._hash_and_preview(
                secret, file_path, rule_id, state if state is not None else _ParseState()
            )

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
                secret_hash=secret_hash,
                commit_sha=None,
                commit_author=None,
                commit_date=None,
                entropy=None,
                scanner=self.name,
            )
        except Exception:
            return None

    def _hash_and_preview(
        self, secret: dict[str, Any], file_path: Path, rule_id: str, state: _ParseState
    ) -> tuple[str, str]:
        """Compute ``(secret_hash, secret_preview)`` for a trivy secret dict.

        Trivy emits ``Match`` with the secret already redacted to a
        same-length ``*`` run (``Secret`` is never populated), so the Match
        line must never be hashed as if it were the secret: two distinct
        secrets of the same shape would collide and the engine's
        ``--skip-duplicate`` dedup would silently drop one (#479). Recover
        the raw value from the scanned file when the redacted line still
        aligns; otherwise fall back to an occurrence-qualified location hash
        that cannot collapse distinct findings.
        """
        matched = secret.get("Match", "")
        raw_secret = self._recover_secret_value(file_path, secret, state.line_cache)
        if raw_secret is not None:
            return hash_secret(raw_secret), redact_secret(raw_secret)
        if not matched:
            # Empty placeholders (not passwords), kept for historical behavior.
            return "", ""  # nosec B105
        key = (
            str(file_path),
            str(secret.get("StartLine") or 0),
            str(secret.get("EndLine") or 0),
            rule_id,
            matched,
        )
        occurrence = state.fallback_counts.get(key, 0)
        state.fallback_counts[key] = occurrence + 1
        return self._location_qualified_hash(key, occurrence), redact_secret(matched)

    @staticmethod
    def _read_lines(
        file_path: Path, line_cache: dict[Path, list[str] | None] | None
    ) -> list[str] | None:
        """Read a file's lines through the per-parse cache.

        Returns ``None`` when the file cannot be read; the (possibly
        ``None``) result is cached so n findings in one file cost a single
        read. The cache lives for one parse only, so a file changing between
        scans can never serve stale lines.
        """
        if line_cache is not None and file_path in line_cache:
            return line_cache[file_path]
        try:
            lines: list[str] | None = file_path.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()
        except OSError:
            lines = None
        if line_cache is not None:
            line_cache[file_path] = lines
        return lines

    @staticmethod
    def _recover_secret_value(
        file_path: Path,
        secret: dict[str, Any],
        line_cache: dict[Path, list[str] | None] | None = None,
    ) -> str | None:
        """Recover the raw secret value that trivy redacted in ``Match``.

        Trivy replaces the matched secret inside ``Match`` with a same-length
        run of ``*``. Re-read the flagged line from the scanned file and align
        it with ``Match`` (see :meth:`_align_redacted_match`).

        Returns ``None`` whenever the alignment cannot be validated --
        multi-line findings (including an explicit ``EndLine: null``),
        truncated matches, a mask boundary made ambiguous by literal ``*``
        characters, a file that changed since the scan or cannot be read --
        in which case the caller falls back to a location-qualified hash
        instead.

        Args:
            file_path: The scanned file the finding points at.
            secret: Secret data from trivy output.
            line_cache: Optional shared cache of ``splitlines()`` results
                (``None`` for unreadable files) so several findings in one
                file cost a single read.
        """
        match = secret.get("Match") or ""
        start_line = secret.get("StartLine")
        end_line = secret.get("EndLine", start_line)
        if (
            not match
            or "*" not in match
            or not isinstance(start_line, int)
            or start_line < 1
            # An explicit ``EndLine: null`` leaves the span unknown -- treat
            # it as multi-line rather than assuming it equals StartLine.
            or not isinstance(end_line, int)
            or end_line != start_line
        ):
            return None
        lines = TrivyScanner._read_lines(file_path, line_cache)
        if lines is None or start_line > len(lines):
            return None
        return TrivyScanner._align_redacted_match(lines[start_line - 1], match)

    @staticmethod
    def _align_redacted_match(raw_line: str, match: str) -> str | None:
        """Align a raw file line with trivy's redacted ``Match`` line.

        The longest common prefix and suffix bound the masked span; the
        corresponding span of the raw line is the secret. Returns ``None``
        when the lines cannot be aligned or the mask boundary is ambiguous.
        """
        length = len(match)
        if len(raw_line) != length or raw_line == match:
            return None
        prefix = 0
        while prefix < length and raw_line[prefix] == match[prefix]:
            prefix += 1
        suffix = 0
        while (
            suffix < length - prefix and raw_line[length - 1 - suffix] == match[length - 1 - suffix]
        ):
            suffix += 1
        # A ``*`` immediately before/after the differing span is ambiguous:
        # it may be unmasked context or a masked secret character that
        # happens to be ``*`` (a secret with literal leading/trailing ``*``),
        # in which case the scan walked INTO the masked span and the
        # candidate below would be a silently truncated secret. Fall back.
        if (prefix > 0 and match[prefix - 1] == "*") or (
            suffix > 0 and match[length - suffix] == "*"
        ):
            return None
        masked_span = match[prefix : length - suffix]
        candidate = raw_line[prefix : length - suffix]
        if not candidate or set(masked_span) != {"*"}:
            return None
        return candidate

    @staticmethod
    def _location_qualified_hash(key: tuple[str, str, str, str, str], occurrence: int) -> str:
        """Hash for findings whose raw secret value could not be recovered.

        The redacted ``Match`` line alone is identical for two distinct
        secrets of the same shape, so ``key`` qualifies it with the finding's
        file, line span and rule, and ``occurrence`` adds a per-location
        index (two distinct same-rule secrets on ONE line produce
        byte-identical trivy dicts): distinct findings then can never
        collapse under the engine's hash-keyed ``--skip-duplicate`` dedup,
        while re-scans of the same finding stay stable because trivy reports
        findings in a deterministic order. The constant prefix and NUL
        separators keep this synthetic key from ever colliding with a real
        secret's ``hash_secret`` value.

        Args:
            key: ``(file, start line, end line, rule id, redacted Match)``
                fallback identity, as built by :meth:`_hash_and_preview`.
            occurrence: Zero-based index of this finding among identical
                ``key`` occurrences within one parse.
        """
        return hash_secret("\x00".join(("envdrift-trivy-redacted", *key, str(occurrence))))
