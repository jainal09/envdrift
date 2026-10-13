"""Infisical scanner integration with auto-installation.

Infisical CLI includes secret scanning capabilities to detect secrets.
This module provides:
- Automatic binary download and installation
- Cross-platform support (macOS, Linux, Windows)
- JSON output parsing into ScanFinding objects
- Git history scanning support
"""

from __future__ import annotations

import functools
import json
import logging
import os
import platform
import re
import shutil
import subprocess  # nosec B404
import tarfile
import tempfile
import time
import zipfile
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
    scan_location,
)
from envdrift.utils.git import get_git_root, has_git_head
from envdrift.utils.text import strip_ansi

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)


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


def _get_infisical_checksums_url() -> str:
    """Get the generic upstream checksums file URL template from constants."""
    return _load_constants().get("infisical_checksums_url", "")


def _parse_version_tokens(output: str) -> set[str]:
    """Extract whole version tokens from ``<binary> --version`` output.

    Used instead of a substring test so that a pinned ``0.43.11`` is not
    considered satisfied by a binary reporting ``0.43.116``.

    A token must not be followed by another version character, so a prerelease
    build like ``0.43.116-rc.1`` does not yield a bare ``0.43.116`` and thus
    cannot pass for the released version.
    """
    return set(re.findall(r"(?<![\w.-])\d+(?:\.\d+)+(?![\w.-])", output))


def _get_infisical_checksums_urls() -> dict[str, str]:
    """Get per-platform checksums URL template overrides from constants.

    Upstream publishes macOS digests in a separate ``checksums-darwin.txt``;
    the generic ``checksums.txt`` contains no darwin entries at all. Platforms
    absent from this map fall back to the generic URL.
    """
    return _load_constants().get("infisical_checksums_urls", {})


# Infisical reports no severity, so findings are graded by rule ID. The keys are
# the IDs the CLI actually emits, read from real reports of both engines (0.43.135
# gitleaks, 0.43.136+ betterleaks). The original keys matched none of them, so AWS
# key IDs and Stripe keys fell back to HIGH and passed ``--fail-on critical``
# (#844). CRITICAL covers AWS, Azure storage, GitHub/GitLab, npm/PyPI and Stripe
# live credentials plus private keys, which the native scanner grades CRITICAL
# too. Every other rule is HIGH. Some of those (Heroku, Slack, OpenAI, SendGrid,
# Google API keys) are CRITICAL in the native scanner; aligning the scanners'
# severity policy is tracked in #850, so those HIGH grades are not a decision.
RULE_SEVERITY_MAP: dict[str, FindingSeverity] = {
    # Both engines report AWS access key IDs (AKIA, ASIA, ...) under
    # ``aws-access-token``. From 0.43.136 that happens only next to a secret
    # access key, which betterleaks nests as ``aws-secret-access-key``. Upstream
    # betterleaks#410 makes that secret optional, which brings lone key IDs back
    # under ``aws-access-token``. 0.43.135 has no secret access key rule, and every
    # version reports a lone secret access key only as ``generic-api-key`` (HIGH).
    "aws-access-token": FindingSeverity.CRITICAL,
    "aws-secret-access-key": FindingSeverity.CRITICAL,
    # Other cloud keys. Only betterleaks has ``azure-storage-account-key``: 0.43.135
    # reports those keys as ``generic-api-key`` (HIGH). A GCP service-account match
    # always spans the account's private key, which the ``private-key`` rule of
    # both engines also reports as CRITICAL.
    "azure-storage-account-key": FindingSeverity.CRITICAL,
    "gcp-service-account": FindingSeverity.CRITICAL,
    # Source control and package registries.
    "github-app-token": FindingSeverity.CRITICAL,
    "github-fine-grained-pat": FindingSeverity.CRITICAL,
    "github-oauth": FindingSeverity.CRITICAL,
    "github-pat": FindingSeverity.CRITICAL,
    "github-refresh-token": FindingSeverity.CRITICAL,
    "gitlab-pat": FindingSeverity.CRITICAL,
    "gitlab-pat-routable": FindingSeverity.CRITICAL,
    "gitlab-pat-routable-versioned": FindingSeverity.CRITICAL,
    "npm-access-token": FindingSeverity.CRITICAL,
    "pypi-upload-token": FindingSeverity.CRITICAL,
    # Stripe secret and restricted keys; see ``_rule_severity`` for test-mode keys.
    "stripe-access-token": FindingSeverity.CRITICAL,
    # Any ``-----BEGIN ... PRIVATE KEY-----`` block: PEM, OpenSSH or PGP.
    "private-key": FindingSeverity.CRITICAL,
    # These match the HIGH fallback and are listed only to make the choice explicit.
    "gcp-api-key": FindingSeverity.HIGH,
    "generic-api-key": FindingSeverity.HIGH,
    "slack-bot-token": FindingSeverity.HIGH,
    "slack-user-token": FindingSeverity.HIGH,
    "slack-webhook-url": FindingSeverity.HIGH,
    # The original keys. No built-in rule uses them, but a custom rules config may.
    "aws-access-key-id": FindingSeverity.CRITICAL,
    "google-api-key": FindingSeverity.HIGH,
    "slack-token": FindingSeverity.HIGH,
    "stripe-api-key": FindingSeverity.CRITICAL,
}

# ``stripe-access-token`` also matches test-mode keys (``sk_test_``, ``rk_test_``),
# which cannot move money. The native and detect-secrets scanners flag only live
# keys, so a test-mode key keeps the HIGH grade it had before #844.
_STRIPE_TEST_KEY_RE = re.compile(r"[rs]k_test_")


def _rule_severity(rule_id: str, secret: str) -> FindingSeverity:
    """The severity of a finding under ``rule_id`` whose matched value is ``secret``."""
    rule = rule_id.lower()
    if rule == "stripe-access-token" and _STRIPE_TEST_KEY_RE.match(secret):
        return FindingSeverity.HIGH
    return RULE_SEVERITY_MAP.get(rule, FindingSeverity.HIGH)


# Infisical CLI 0.43.136 swapped its gitleaks engine for betterleaks, which
# drops every finding rated below ``--confidence`` (default "medium"). Its
# ``generic-api-key`` and ``generic-password`` rules are rated "low", and they
# are the only rules that report a lone AWS secret access key (the dedicated
# ``aws-secret-access-key`` rule is never reported on its own), a generic API
# key or a password, so the default silently loses them (#834). Releases up to
# 0.43.135 reject the flag with a usage error and write no report, so it is
# passed only when the binary's own ``scan --help`` lists it.
_CONFIDENCE_ARGS = ("--confidence", "low")
_CONFIDENCE_FLAG_RE = re.compile(r"^\s*(?:-\w,\s+)?--confidence(?![\w-])", re.MULTILINE)
_HELP_PROBE_TIMEOUT_SECONDS = 10


def _confidence_args(binary: Path, paths: list[Path]) -> list[str]:
    """The ``--confidence`` arguments for one scan of ``paths``.

    Probed once per scan (and cached per binary), not once per path, and only
    when there is something to scan.
    """
    if any(path.exists() for path in paths) and _supports_confidence_flag(binary):
        return list(_CONFIDENCE_ARGS)
    return []


class _ProbeError(Exception):
    """The ``scan --help`` probe did not run to completion."""


@functools.cache
def _probe_confidence_flag(binary: str, _mtime_ns: int, _size: int) -> bool:
    """Whether ``<binary> scan --help`` advertises a ``--confidence`` flag.

    Cached per binary; the mtime and size in the key make a binary replaced in
    place (an upgrade or reinstall) probe again. A probe that cannot run,
    times out or exits non-zero raises ``_ProbeError`` instead of returning,
    so the transient failure is not cached and the next scan probes again.
    """
    try:
        result = subprocess.run(  # nosec B603
            [binary, "scan", "--help"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_HELP_PROBE_TIMEOUT_SECONDS,
        )
    except Exception as e:
        raise _ProbeError(str(e) or type(e).__name__) from e
    if result.returncode != 0:
        raise _ProbeError(f"exit code {result.returncode}")
    return bool(_CONFIDENCE_FLAG_RE.search(f"{result.stdout}\n{result.stderr}"))


def _supports_confidence_flag(binary: Path) -> bool:
    """Whether the infisical binary at ``binary`` accepts ``scan --confidence``.

    Never breaks the scan: when the probe fails, the scan runs on the
    flag-less command line every release accepts, and the failure is logged
    because a 0.43.136+ binary then reports only medium-confidence findings.
    """
    try:
        resolved = binary.resolve()
        stat = resolved.stat()
        return _probe_confidence_flag(str(resolved), stat.st_mtime_ns, stat.st_size)
    except (OSError, _ProbeError) as e:
        logger.warning(
            "Could not check whether %s supports `scan --confidence` (%s); scanning "
            "without it, so Infisical CLI 0.43.136+ drops low-confidence findings (#834)",
            binary,
            e,
        )
        return False


def _history_target(path: Path) -> tuple[Path | None, str | None]:
    """The repository root Infisical must scan for ``path`` in history mode.

    Without ``--no-git`` Infisical scans the history of the whole repository
    that contains ``--source`` and reports ``File`` relative to its root, but
    it cannot scan a file, a directory outside a repository or a repository
    with no commits: for each it writes the empty ``[]`` report of a clean
    scan (#843). So history scans run on the root, which a finding's ``File``
    is joined onto, and a path that cannot be history-scanned is an error, as
    for gitleaks (#641).

    The root comes back in the form of ``path``, relative to the cwd for a
    relative one, so relative scan paths keep reporting relative findings.

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


def _prepare_scan_targets(
    paths: list[Path], *, include_git_history: bool
) -> tuple[list[Path], list[str]]:
    """Build the unique ``--source`` targets for one Infisical run.

    In history mode every path maps to its repository root, and paths in the
    same repository share one scan, so ``guard --pr-base --history`` with N
    changed files runs one history scan instead of N. Preflight failures are
    collected per target, so one bad path does not discard the valid ones.
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

        history_target, error = _history_target(path)
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
    """Join a run failure with the per-target preflight diagnostics."""
    parts = ([run_error] if run_error else []) + target_errors
    return "; ".join(parts) if parts else None


def _load_findings(report_path: Path) -> list[Any]:
    """The findings in an Infisical JSON report, or ``[]`` when it holds none.

    A missing, empty, unparsable or non-list report holds no findings.
    """
    if not report_path.exists() or report_path.stat().st_size == 0:
        return []
    try:
        report_data = json.loads(report_path.read_text())
    except json.JSONDecodeError:
        return []
    return report_data if isinstance(report_data, list) else []


# Betterleaks composite rules nest their paired values under ``ComponentSets``
# rather than reporting them (#834). Most of those components are not secrets
# at all: tenant and client IDs, usernames, account names, hosts and URLs that
# a rule only uses to validate its primary match. In 0.43.141 that is 25 of
# the 31 component rules its 26 composite rules use, the OVH application key
# among them, since it only identifies the app. Only the components below are
# secret material the engine would otherwise hide, so only they are reported.
# Any other component, including one a future release adds, stays unreported
# until it is reviewed and listed here; its parent finding is still reported.
_SECRET_COMPONENT_RULES = frozenset(
    {
        "alibaba-sts-security-token",
        "aws-secret-access-key",
        "exoscale-api-secret",
        "ovh-consumer-key",
        "polymarket-api-secret",
        "polymarket-passphrase",
    }
)


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
    # NOTE: no hardcoded URL template. constants.json is the single
    # Renovate-managed source of release metadata; a second copy in Python is
    # exactly how this integration broke before (the CLI moved repo, tag format
    # and asset prefix, and an inlined template kept 404ing). A missing platform
    # key now fails loudly instead of silently downloading from a stale URL.

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

        os_name, arch, _ext = self.PLATFORM_MAP[key]
        url_key = f"{os_name}_{arch}"

        templates = _get_infisical_download_urls()
        template = templates.get(url_key)
        if not template:
            raise InfisicalInstallError(
                f"No infisical download URL configured for {url_key}. "
                f"Add it to infisical_download_urls in constants.json "
                f"(configured: {sorted(templates) or 'none'})."
            )
        return template.format(version=self.version)

    def get_checksums_url(self) -> str:
        """Get the URL of the upstream-published checksums file for this version.

        Platform-aware: upstream splits macOS digests into a separate
        ``checksums-darwin.txt`` and the generic ``checksums.txt`` carries no
        darwin entries. Since :func:`verify_download` fails closed, resolving
        the generic file on macOS would make every install abort. Platforms
        without an override fall back to the generic URL, so a future upstream
        re-consolidation degrades gracefully instead of breaking.
        """
        overrides = _get_infisical_checksums_urls()
        if overrides:
            system, machine = get_platform_info()
            entry = self.PLATFORM_MAP.get((system, machine))
            if entry is not None:
                os_name, arch, _ext = entry
                template = overrides.get(f"{os_name}_{arch}")
                if template:
                    return template.format(version=self.version)

        template = _get_infisical_checksums_url()
        return template.format(version=self.version) if template else ""

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
                download_file(url, archive_path, timeout=DOWNLOAD_TIMEOUT_SECONDS)
            except Exception as e:
                raise InfisicalInstallError(f"Download failed: {e}") from e

            # Verify against the published checksums before extracting anything.
            self.progress("Verifying checksum...")
            try:
                verify_download(archive_path, archive_name, self.get_checksums_url(), "infisical")
            except ChecksumVerificationError as e:
                raise InfisicalInstallError(str(e)) from e

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

            # Stage next to the target and atomically replace it, so an
            # interrupted copy (disk full, crash) can never corrupt a working
            # binary or leave a partial write behind (#490).
            try:
                atomic_install(extracted_binary, target_path)
            except OSError as e:
                raise InfisicalInstallError(f"Failed to install binary: {e}") from e

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
                    encoding="utf-8",
                    errors="replace",
                    timeout=10,
                )
                # Exact token match, not a substring: upstream version numbers
                # carry large patch components, so `0.43.11 in "... 0.43.116"`
                # would be true and would skip reinstalling a wrong binary.
                # A non-zero exit means the binary did not report a version at
                # all; whatever landed on stdout must not count as "installed".
                if result.returncode == 0 and self.version in _parse_version_tokens(result.stdout):
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

    # Scans git history when ``include_git_history`` is set (#476).
    supports_git_history = True

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
                encoding="utf-8",
                errors="replace",
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

        # Per-target preflight, as for gitleaks (#641): a path that cannot be
        # history-scanned is an error, and the valid ones are still scanned.
        # Every returned ScanResult carries those errors so the run stays
        # truthfully incomplete.
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
        except InfisicalNotFoundError as e:
            return ScanResult(
                scanner_name=self.name,
                error=_combined_error(str(e), target_errors),
                duration_ms=int((time.time() - start_time) * 1000),
            )

        all_findings: list[ScanFinding] = []
        total_files = 0
        confidence_args = _confidence_args(binary, scan_targets)

        for path in scan_targets:
            # Create temp file for JSON report
            report_path: Path | None = None
            try:
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".json", delete=False
                ) as report_file:
                    report_path = Path(report_file.name)
                # Build command with explicit source path. ``File`` comes back
                # relative to the directory infisical runs in, the repository
                # root in history mode, so findings are joined onto it.
                work_dir, source_arg = scan_location(path)
                args = [
                    str(binary),
                    "scan",
                    "--report-path",
                    str(report_path),
                    "--source",
                    source_arg,
                ]

                # If not scanning git history, use --no-git
                if not include_git_history:
                    args.append("--no-git")

                args.extend(confidence_args)

                # Run infisical scan
                result = subprocess.run(  # nosec B603
                    args,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=300,  # 5 minute timeout
                    cwd=str(work_dir),
                )

                report_data = _load_findings(report_path)

                # Infisical exits non-zero when it reports leaks, so a non-zero
                # exit that reported none is a failed scan. A scan that cannot
                # run still writes an empty ``[]`` report, which used to pass as
                # clean (#843).
                if result.returncode != 0 and not report_data:
                    # zerolog colors its log lines even on a pipe, and this
                    # message lands in --json/SARIF output (#843).
                    error_msg = (
                        strip_ansi(result.stderr).strip()
                        or strip_ansi(result.stdout).strip()
                        or f"infisical scan failed for {path} (exit code {result.returncode})"
                    )
                    return ScanResult(
                        scanner_name=self.name,
                        findings=all_findings,
                        error=_combined_error(error_msg, target_errors),
                        duration_ms=int((time.time() - start_time) * 1000),
                    )

                if report_data:
                    # Count unique files
                    files_with_findings = {
                        item.get("File") for item in report_data if item.get("File")
                    }
                    total_files += len(files_with_findings)
                    for item in report_data:
                        finding = self._parse_finding(item, work_dir)
                        if finding:
                            all_findings.append(finding)
                    all_findings.extend(self._parse_components(report_data, work_dir, all_findings))

            except subprocess.TimeoutExpired:
                return ScanResult(
                    scanner_name=self.name,
                    findings=all_findings,
                    error=_combined_error(f"Scan timed out for {path}", target_errors),
                    duration_ms=int((time.time() - start_time) * 1000),
                )
            except Exception as e:
                return ScanResult(
                    scanner_name=self.name,
                    findings=all_findings,
                    error=_combined_error(str(e), target_errors),
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
            error=_combined_error(None, target_errors),
            duration_ms=int((time.time() - start_time) * 1000),
        )

    def _parse_components(
        self,
        report_data: list[Any],
        base_path: Path,
        existing: list[ScanFinding],
    ) -> list[ScanFinding]:
        """Surface the secret components that betterleaks nests in a finding.

        From 0.43.136 a composite rule (``aws-access-token``) reports only its
        primary match, the AWS access key ID, and moves the paired secret
        access key into ``ComponentSets[].components[]`` instead of reporting
        it as a finding of its own (#834). Only components listed in
        ``_SECRET_COMPONENT_RULES`` are reported; the rest (tenant and client
        IDs, usernames, hosts) are not secrets. A component carries its own
        rule, position and secret but no file or commit context, so it
        inherits those from the parent finding. A component that several
        findings share (one secret near two key IDs), or that a finding under
        the same rule already covers, is reported once. Duplicates are keyed by
        rule like the engine's own dedup, so a CRITICAL component is never
        dropped in favour of a weaker finding of another rule on the same line.
        The engine keeps both under its default (rule-keyed) dedup and, under
        ``skip_duplicate``, collapses them to the higher severity.

        Args:
            report_data: Raw findings from the infisical JSON report.
            base_path: Base path for resolving relative paths.
            existing: Findings already parsed, used to skip duplicates.

        Returns:
            One ScanFinding per distinct component.
        """
        seen = {(f.file_path, f.line_number, f.rule_id, f.secret_hash) for f in existing}
        components: list[ScanFinding] = []
        for item in report_data:
            for flattened in self._flatten_components(item):
                finding = self._parse_finding(flattened, base_path)
                if finding is None:
                    continue
                key = (finding.file_path, finding.line_number, finding.rule_id, finding.secret_hash)
                if key in seen:
                    continue
                seen.add(key)
                components.append(finding)
        return components

    @staticmethod
    def _flatten_components(item: Any) -> list[dict[str, Any]]:
        """Turn one finding's secret ``ComponentSets`` into standalone report items.

        Args:
            item: Raw finding from infisical JSON output.

        Returns:
            One report item per component whose rule is in
            ``_SECRET_COMPONENT_RULES``, in the shape ``_parse_finding`` reads.
        """
        if not isinstance(item, dict):
            return []
        context = {
            key: item[key] for key in ("File", "Commit", "Author", "Email", "Date") if key in item
        }
        parent_rule = item.get("RuleID", "unknown")
        flattened: list[dict[str, Any]] = []
        for component in InfisicalScanner._secret_components(item.get("ComponentSets")):
            entry = dict(context)
            entry.update(
                (key, component[key])
                for key in ("RuleID", "StartLine", "StartColumn", "Secret", "Match")
                if key in component
            )
            entry["Description"] = f"{entry.get('RuleID', 'unknown')} (paired with {parent_rule})"
            flattened.append(entry)
        return flattened

    @staticmethod
    def _secret_components(component_sets: Any) -> list[dict[str, Any]]:
        """The well-formed members of ``ComponentSets`` whose rule is a secret.

        Args:
            component_sets: The ``ComponentSets`` value of one raw finding.

        Returns:
            Every component dict whose ``RuleID`` is in ``_SECRET_COMPONENT_RULES``;
            malformed sets and members are skipped.
        """
        sets = component_sets if isinstance(component_sets, list) else []
        members = (
            member
            for component_set in sets
            if isinstance(component_set, dict) and isinstance(component_set.get("components"), list)
            for member in component_set["components"]
        )
        return [
            member
            for member in members
            if isinstance(member, dict)
            and str(member.get("RuleID", "")).lower() in _SECRET_COMPONENT_RULES
        ]

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
            severity = _rule_severity(rule_id, str(secret))

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
