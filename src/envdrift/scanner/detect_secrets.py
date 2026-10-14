"""Yelp's detect-secrets scanner integration with auto-installation.

detect-secrets is an enterprise-grade secret detection tool with:
- 27+ built-in detectors (AWS, Azure, GitHub, JWT, etc.)
- High entropy string detection
- Keyword-based detection
- Baseline management for false positive handling

This module provides:
- Automatic pip installation
- All plugins enabled by default ("final boss" mode)
- JSON output parsing into ScanFinding objects
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess  # nosec B404
import sys
import time
from dataclasses import dataclass
from pathlib import Path, PurePath
from typing import TYPE_CHECKING, Any, ClassVar

from envdrift.scanner.base import (
    FindingSeverity,
    ScanFinding,
    ScannerBackend,
    ScanResult,
)
from envdrift.utils.git import get_git_root
from envdrift.utils.text import strip_ansi

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping


def _load_constants() -> dict:
    """Load constants from the package's constants.json."""
    constants_path = Path(__file__).parent.parent / "constants.json"
    with open(constants_path) as f:
        return json.load(f)


def _get_detect_secrets_version() -> str:
    """Get the pinned detect-secrets version from constants."""
    return _load_constants().get("detect_secrets_version", "1.5.0")


class DetectSecretsNotFoundError(Exception):
    """detect-secrets not found."""

    pass


class DetectSecretsInstallError(Exception):
    """Failed to install detect-secrets."""

    pass


class DetectSecretsError(Exception):
    """detect-secrets command failed."""

    pass


# Severity mapping keyed on the exact ``type`` string each detect-secrets plugin
# emits (its ``secret_type``). A key that matches no emitted name is dead and its
# findings silently fall back to HIGH, so take names from a real scan. The names
# are those of the pinned version (constants.json): another version can rename or
# add detectors, which is why ``scan`` warns when the installed version differs.
# The grades follow the severity policy of the scanners that grade by credential class
# (see "Severity" in docs/cli/guard.md); a test fails when this table drifts from it.
DETECTOR_SEVERITY: dict[str, FindingSeverity] = {
    # Critical - cloud provider credentials
    "AWS Access Key": FindingSeverity.CRITICAL,
    "Azure Storage Account access key": FindingSeverity.CRITICAL,
    "Cloudant Credentials": FindingSeverity.CRITICAL,
    "IBM Cloud IAM Key": FindingSeverity.CRITICAL,
    "IBM COS HMAC Credentials": FindingSeverity.CRITICAL,
    "SoftLayer Credentials": FindingSeverity.CRITICAL,
    # Critical - authentication tokens and cryptographic keys
    "GitHub Token": FindingSeverity.CRITICAL,
    "GitLab Token": FindingSeverity.CRITICAL,
    "Discord Bot Token": FindingSeverity.CRITICAL,
    "Slack Token": FindingSeverity.CRITICAL,
    "Stripe Access Key": FindingSeverity.CRITICAL,
    "Mailchimp Access Key": FindingSeverity.CRITICAL,
    "NPM tokens": FindingSeverity.CRITICAL,
    "SendGrid API Key": FindingSeverity.CRITICAL,
    "Square OAuth Secret": FindingSeverity.CRITICAL,
    "OpenAI Token": FindingSeverity.CRITICAL,
    "PyPI Token": FindingSeverity.CRITICAL,
    "Telegram Bot Token": FindingSeverity.CRITICAL,
    "Private Key": FindingSeverity.CRITICAL,
    # High - generic credentials. The Twilio detector matches an account or API key
    # SID, which is an identifier whose secret is another value, so it is HIGH. A JWT is
    # HIGH too: some are public by design, but a bearer token looks the same (as in gitleaks
    # and Infisical, where it always was HIGH).
    "Twilio API Key": FindingSeverity.HIGH,
    "Basic Auth Credentials": FindingSeverity.HIGH,
    "Artifactory Credentials": FindingSeverity.HIGH,
    "Secret Keyword": FindingSeverity.HIGH,
    "JSON Web Token": FindingSeverity.HIGH,
    # Medium - entropy is a weak signal
    "Base64 High Entropy String": FindingSeverity.MEDIUM,
    "Hex High Entropy String": FindingSeverity.MEDIUM,
}

# Directories whose files detect-secrets must not scan: dependencies, build output and
# caches. A directory with one of these names excludes everything below it. A file with one
# of the names (a script called ``build``) is still scanned, and so is the directory you
# point detect-secrets at, whatever it is called.
_EXCLUDED_DIRECTORIES = (
    "node_modules",
    ".venv",
    "venv",
    ".tox",
    ".nox",
    "site-packages",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".git",
    "dist",
    "build",
    "vendor",
    "coverage",
)


def _exclude_files_regex(skip: int = 0) -> str:
    """The ``--exclude-files`` pattern: a path with an excluded directory below ``skip`` levels.

    detect-secrets searches it in the path of each file relative to the directory it runs in.
    git lists that path with ``/`` but a scan of all files (``--all-files``) builds it with the
    OS separator, so either one separates the components. ``skip`` leading components are
    never looked at: they are the way from the directory detect-secrets runs in (the top
    level of a repository) to the directory you asked it to scan, which names where you
    pointed it and not what is inside.
    """
    names = "|".join(re.escape(name) for name in _EXCLUDED_DIRECTORIES)
    lead = rf"(?:[^\\/]+[\\/]){{{skip}}}" if skip else ""
    return rf"^{lead}(?:.*[\\/])?(?:{names})[\\/]"


# Printed (to stderr, with exit 0) when detect-secrets finds no git work tree to list
# the files of a directory from.
_NO_GIT_REPOSITORY_NOTICE = "Did not detect git repository"

# No leading components to drop from the file names in a report (see ``_ScanPlan.prefix``).
_NO_PREFIX = PurePath()

_VERSION_PROBE_TIMEOUT_SECONDS = 10

# The installed version per interpreter, successful probes only: the probe runs once per
# process, a failed one is retried by the next scan, and a package auto-installed in
# between is seen.
_installed_versions: dict[str, str] = {}


class _VersionProbeError(Exception):
    """``python -m detect_secrets --version`` did not report a version."""


def _run_version_probe() -> subprocess.CompletedProcess[str]:
    """Run ``python -m detect_secrets --version`` in envdrift's interpreter."""
    return subprocess.run(  # nosec B603
        [sys.executable, "-m", "detect_secrets", "--version"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=_VERSION_PROBE_TIMEOUT_SECONDS,
    )


def _remember_version(output: str) -> str | None:
    """The version in the output of a successful probe, remembered for the process."""
    tokens = output.split() if isinstance(output, str) else []
    if not tokens:
        return None
    _installed_versions[sys.executable] = tokens[-1]
    return tokens[-1]


def _installed_version() -> str:
    """The detect-secrets version ``python -m detect_secrets`` reports (probed once)."""
    cached = _installed_versions.get(sys.executable)
    if cached is not None:
        return cached
    try:
        result = _run_version_probe()
    except (OSError, ValueError, TypeError, subprocess.SubprocessError) as exc:
        # Whatever stops the probe from running, the answer is a warning, not a failed scan.
        raise _VersionProbeError(f"{type(exc).__name__}: {exc}") from exc
    version = _remember_version(result.stdout) if result.returncode == 0 else None
    if version is None:
        detail = strip_ansi(result.stderr).strip()[:200] or "no version in its output"
        raise _VersionProbeError(f"exit code {result.returncode}: {detail}")
    return version


def _release(version: str) -> tuple[int, ...] | None:
    """``1.5.0`` as ``(1, 5)``, trailing zeros dropped; None unless a plain release."""
    if re.fullmatch(r"\d+(?:\.\d+)*", version) is None:
        return None
    parts = [int(part) for part in version.split(".")]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def _versions_match(installed: str, pinned: str) -> bool:
    """Whether ``installed`` is the ``pinned`` release (``1.5`` is ``1.5.0``).

    A version that is not a plain release (``1.5.0.dev1``, ``1.5.0+local``) only matches
    itself: it may carry other detector names than the release it is named after.
    """
    installed_release, pinned_release = _release(installed), _release(pinned)
    if installed_release is None or pinned_release is None:
        return installed == pinned
    return installed_release == pinned_release


def _version_warnings() -> list[str]:
    """Warnings about the installed detect-secrets not being the pinned version.

    ``DETECTOR_SEVERITY`` is keyed on the detector names of the pinned version. Another
    version can rename a detector, so its findings fall back to HIGH, or add one, so
    its findings are graded by name only if envdrift knows it. The installed package is
    never changed: this only says what to run. A probe that fails is a warning too, not
    an error, since the scan itself may still be fine.
    """
    pinned = _get_detect_secrets_version()
    fix = f"Install the pinned version: pip install detect-secrets=={pinned}"
    try:
        installed = _installed_version()
    except _VersionProbeError as exc:
        return [
            f"Could not read the installed version ({exc}). envdrift grades findings "
            f"against version {pinned}, so severities may be inaccurate if another version "
            f"is installed. {fix}"
        ]
    if _versions_match(installed, pinned):
        return []
    return [
        f"The installed version is {installed}, but envdrift grades findings against "
        f"version {pinned}. Another version can rename or add detectors, so severities may "
        f"be inaccurate. {fix}"
    ]


def _with_unquoted_git_paths(environ: Mapping[str, str]) -> dict[str, str]:
    """A copy of ``environ`` that makes git write non-ASCII file names as they are.

    detect-secrets lists the files to scan with ``git ls-files``. Under git's default
    ``core.quotepath`` that writes ``café.env`` as the quoted escape sequence
    ``"caf\\303\\251.env"``, which names no file, so detect-secrets dropped the file from the
    scan without a word and the run read as clean. The setting goes in through
    ``GIT_CONFIG_COUNT`` (git 2.31 and later), after any entries the caller already exports,
    because detect-secrets runs the git command itself and gives it no other way in.
    """
    env = dict(environ)
    try:
        count = max(int(env.get("GIT_CONFIG_COUNT", "0")), 0)
    except ValueError:
        count = 0
    env[f"GIT_CONFIG_KEY_{count}"] = "core.quotepath"
    env[f"GIT_CONFIG_VALUE_{count}"] = "false"
    env["GIT_CONFIG_COUNT"] = str(count + 1)
    return env


@dataclass(frozen=True)
class _ScanPlan:
    """How detect-secrets is run over one path.

    Attributes:
        cwd: The directory detect-secrets runs in. The file names in its report are relative
            to it.
        scan_path: The path argument, relative to ``cwd``.
        all_files: Whether to pass ``--all-files`` (scan every file, not those git tracks).
        exclude: The ``--exclude-files`` pattern.
        prefix: The way from ``cwd`` to the path that was asked for, as the leading part of
            every file name in the report. Empty unless ``cwd`` is the top level of the
            repository that holds a subdirectory.
        git_root: The top level of the repository whose tracked files are scanned, or None
            when the files are not chosen by git.
    """

    cwd: Path
    scan_path: str
    all_files: bool
    exclude: str
    prefix: PurePath = _NO_PREFIX
    git_root: Path | None = None


def _plan_scan(path: Path) -> _ScanPlan:
    """Decide where and how to run detect-secrets over ``path``.

    A file is scanned from its own directory, whatever git tracks. A directory outside a git
    work tree is scanned for all of its files: detect-secrets lists a directory's files with
    ``git ls-files``, which there fails, so it logs a notice, exits 0 and reports no files,
    and that read as a clean scan of a directory it never looked at (#851). Inside a work
    tree it scans the files git tracks (fast, and it skips ignored files), as it always did.

    That list holds paths relative to the top level of the repository, and detect-secrets
    matches them with the paths it builds relative to the directory it runs in. They agree
    only when that directory is the top level, and in a subdirectory not one file matched,
    so a scan of ``sub/`` found nothing and reported no error. A subdirectory is therefore
    scanned from the top level, with its own path as the path to scan.
    """
    if not path.is_dir():
        return _ScanPlan(path.parent, path.name, all_files=False, exclude=_exclude_files_regex())
    git_root = get_git_root(path)
    prefix = _path_below(path, git_root) if git_root is not None else None
    if git_root is None or prefix is None:
        # Outside a work tree, or the way to its top level cannot be named (a symlink out of
        # the tree, or two spellings of one Windows path). Scanning every file beats none.
        return _ScanPlan(path, ".", all_files=True, exclude=_exclude_files_regex())
    if not prefix.parts:
        return _ScanPlan(path, ".", False, _exclude_files_regex(), git_root=git_root)
    return _ScanPlan(
        git_root,
        prefix.as_posix(),
        all_files=False,
        exclude=_exclude_files_regex(len(prefix.parts)),
        prefix=prefix,
        git_root=git_root,
    )


def _path_below(path: Path, root: Path) -> PurePath | None:
    """``path`` relative to ``root`` with symlinks resolved, or None when it is not below."""
    try:
        return path.resolve().relative_to(root.resolve())
    except (OSError, RuntimeError, ValueError):
        return None


def _scannable_tracked_names(plan: _ScanPlan) -> list[str] | None:
    """The files git tracks below the path of ``plan`` that detect-secrets would scan.

    detect-secrets scans the files git tracks, and it reports nothing at all, not even a
    file count, for a directory where git tracks none (a new repository whose files are not
    added yet, or a directory that is entirely ignored). The caller says so: that is not a
    clean scan. None when the scan does not use git's list, or git cannot be asked.
    """
    if plan.git_root is None:
        return None
    try:
        result = subprocess.run(  # nosec B603, B607
            ["git", "ls-files", "-z", "--", plan.prefix.as_posix() if plan.prefix.parts else "."],
            cwd=str(plan.git_root),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="surrogateescape",
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    skipped = re.compile(plan.exclude)
    return [name for name in result.stdout.split("\0") if name and not skipped.search(name)]


# What git always quotes in a name (a double quote, a backslash, a control character), what it
# also quotes with ``core.quotepath`` on (a byte above 0x7f), and bytes that are not UTF-8, which
# Python reads from git's output as lone surrogates.
_ALWAYS_QUOTED = re.compile(r'["\\\x00-\x1f\x7f]')
_QUOTED_BY_QUOTEPATH = re.compile(r"[^\x00-\x7f]")
_NOT_UTF8 = re.compile("[\udc80-\udcff]")


def _git_quotes(name: str, *, quotepath_off: bool) -> bool:
    """Whether ``git ls-files`` prints ``name`` in quotes, which detect-secrets cannot match."""
    if _ALWAYS_QUOTED.search(name):
        return True
    return not quotepath_off and _QUOTED_BY_QUOTEPATH.search(name) is not None


def _is_undecodable(name: str) -> bool:
    """Whether ``name`` holds bytes that are not UTF-8 (they were read as lone surrogates)."""
    return _NOT_UTF8.search(name) is not None


# ``GIT_CONFIG_COUNT`` and its key and value variables arrived in git 2.31; an older git
# ignores them.
_GIT_CONFIG_ENV_SINCE = (2, 31)


def _git_honors_config_env() -> bool:
    """Whether the installed git reads configuration from ``GIT_CONFIG_COUNT``.

    True when that cannot be told: a git that cannot be asked for its version is no reason to
    report a file as skipped that may well be scanned.
    """
    try:
        result = subprocess.run(  # nosec B603, B607
            ["git", "--version"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return True
    found = re.match(r"git version (\d+)\.(\d+)", result.stdout) if result.stdout else None
    return found is None or (int(found[1]), int(found[2])) >= _GIT_CONFIG_ENV_SINCE


def _not_scanned_warning(path: Path, quoted: list[str]) -> str:
    """The warning for tracked files whose names git quotes, which detect-secrets cannot match."""
    shown = ", ".join(repr(name) for name in quoted[:3])
    more = f" and {len(quoted) - 3} more" if len(quoted) > 3 else ""
    return (
        f"Not scanned in {path}: git writes the name of {len(quoted)} tracked file(s) in quotes, "
        f"which detect-secrets cannot match ({shown}{more}). Git quotes a name with a double "
        "quote, a backslash or a control character, and one with a non-ASCII character when it "
        "cannot be told not to (that needs git 2.31 or later and names that are all UTF-8). "
        "Rename the file or scan it with another scanner."
    )


def _check_git_file_list(path: Path, names: list[str] | None) -> tuple[dict[str, str], list[str]]:
    """The environment to run detect-secrets in, and warnings about the files git lists for it.

    detect-secrets matches the names ``git ls-files`` prints with the files it finds, and git
    writes a name it has to escape in quotes, which matches no file: the file was dropped from
    the scan without a word and the run read as clean. Turning ``core.quotepath`` off makes git
    print non-ASCII names as they are. That is not safe when a name holds bytes that are not
    UTF-8, since detect-secrets decodes the list and fails on them, and it does nothing on a git
    older than 2.31, which ignores the variable; the setting stays at its default then. A name
    that git still quotes is reported, never skipped in silence.

    Args:
        path: The path being scanned, for the messages.
        names: What ``_scannable_tracked_names`` found, None when detect-secrets does not use
            git's list.
    """
    env = dict(os.environ)
    if names is None:
        return env, []
    if not names:
        return env, [
            f"Scanned nothing in {path}: in a git repository detect-secrets scans the files "
            "git tracks, and none is tracked there that it does not skip. Run git add on the "
            "files to scan them."
        ]
    quotepath_off = _git_honors_config_env() and not any(_is_undecodable(name) for name in names)
    if quotepath_off:
        env = _with_unquoted_git_paths(env)
    quoted = [name for name in names if _git_quotes(name, quotepath_off=quotepath_off)]
    return env, [_not_scanned_warning(path, quoted)] if quoted else []


def _report_file(name: str, base_path: Path, prefix: PurePath) -> Path:
    """The path of a file named in a report, below ``base_path`` as the caller named it.

    A report names files relative to the directory detect-secrets ran in, so ``prefix``, the
    way from there to ``base_path``, is dropped first. When ``base_path`` is a file the names
    are relative to its parent directory.
    """
    file_path = Path(name)
    if prefix.parts and file_path.parts[: len(prefix.parts)] == prefix.parts:
        file_path = Path(*file_path.parts[len(prefix.parts) :])
    if file_path.is_absolute():
        return file_path
    return (base_path.parent if base_path.is_file() else base_path) / file_path


def _run_detect_secrets(plan: _ScanPlan, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    """Run ``python -m detect_secrets scan`` over the path of ``plan`` with all plugins on.

    "Final boss" mode: every plugin is enabled. Where it runs, whether it scans every file and
    what it skips depend on the path (see ``_plan_scan``).
    """
    args = [sys.executable, "-m", "detect_secrets", "scan"]
    if plan.all_files:
        args.append("--all-files")
    args.extend(
        [
            "--force-use-all-plugins",  # Enable ALL 27+ detectors
            "--exclude-files",
            plan.exclude,
            # A path is not an option, whatever it starts with: a file named
            # ``--exclude-files=^`` would otherwise exclude everything and pass clean.
            "--",
            plan.scan_path,
        ]
    )
    return subprocess.run(  # nosec B603
        args,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,  # 5 minute timeout
        cwd=str(plan.cwd),
        env=env,
    )


def _read_report(stdout: str) -> dict[str, Any] | None:
    """The report detect-secrets printed, or None when the output is not one.

    A report is a JSON object with a ``results`` mapping, which is empty when nothing was
    found. Output of any other shape (text, another kind of JSON value, an object without
    ``results``) cannot be told from a scan that looked at nothing, so it is not a clean run.
    """
    try:
        report = json.loads(stdout)
    except json.JSONDecodeError:
        return None
    if isinstance(report, dict) and isinstance(report.get("results"), dict):
        return report
    return None


class DetectSecretsInstaller:
    """Installer for detect-secrets Python package."""

    def __init__(
        self,
        version: str | None = None,
        progress_callback: Callable[[str], None] | None = None,
    ) -> None:
        """Initialize installer.

        Args:
            version: detect-secrets version to install. Uses pinned version if None.
            progress_callback: Optional callback for progress updates.
        """
        self.version = version or _get_detect_secrets_version()
        self.progress = progress_callback or (lambda x: None)

    def install(self, force: bool = False) -> bool:
        """Install detect-secrets via uv or pip.

        Args:
            force: Reinstall even if already installed.

        Returns:
            True if installation succeeded.

        Raises:
            DetectSecretsInstallError: If installation fails.
        """
        # Check if already installed
        if not force and self._is_installed():
            self.progress(f"detect-secrets v{self.version} already installed")
            return True

        self.progress(f"Installing detect-secrets v{self.version}...")

        try:
            # Try uv first (preferred in uv-managed projects)
            uv_path = shutil.which("uv")
            if uv_path:
                cmd = [
                    uv_path,
                    "pip",
                    "install",
                    "--quiet",
                    f"detect-secrets=={self.version}",
                ]
            else:
                # Fall back to pip
                cmd = [
                    sys.executable,
                    "-m",
                    "pip",
                    "install",
                    "--quiet",
                    f"detect-secrets=={self.version}",
                ]

            result = subprocess.run(  # nosec B603
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=120,
            )

            if result.returncode != 0:
                raise DetectSecretsInstallError(f"Install failed: {result.stderr}")

            # The package changed, so a version probed before this point is stale.
            _installed_versions.pop(sys.executable, None)
            self.progress(f"Installed detect-secrets v{self.version}")
            return True

        except subprocess.TimeoutExpired as e:
            raise DetectSecretsInstallError("Installation timed out") from e
        except Exception as e:
            raise DetectSecretsInstallError(f"Installation failed: {e}") from e

    def _is_installed(self) -> bool:
        """Check if detect-secrets is installed."""
        try:
            return _run_version_probe().returncode == 0
        except Exception:
            return False


class DetectSecretsScanner(ScannerBackend):
    """Yelp's detect-secrets scanner - the "final boss" of secret detection.

    detect-secrets provides enterprise-grade secret detection with:
    - 27+ specialized detectors for various secret types
    - High entropy string detection (Base64 and Hex)
    - Keyword-based detection for common secret variable names
    - Configurable plugins for maximum coverage

    This scanner runs with ALL plugins enabled for maximum detection.

    Example:
        scanner = DetectSecretsScanner(auto_install=True)
        result = scanner.scan([Path(".")])
        for finding in result.findings:
            print(f"{finding.severity}: {finding.description}")
    """

    # All available plugins for "final boss" mode
    ALL_PLUGINS: ClassVar[list[str]] = [
        "ArtifactoryDetector",
        "AWSKeyDetector",
        "AzureStorageKeyDetector",
        "BasicAuthDetector",
        "CloudantDetector",
        "DiscordBotTokenDetector",
        "GitHubTokenDetector",
        "GitLabTokenDetector",
        "Base64HighEntropyString",
        "HexHighEntropyString",
        "IbmCloudIamDetector",
        "IbmCosHmacDetector",
        "JwtTokenDetector",
        "KeywordDetector",
        "MailchimpDetector",
        "NpmDetector",
        "OpenAIDetector",
        "PrivateKeyDetector",
        "PypiTokenDetector",
        "SendGridDetector",
        "SlackDetector",
        "SoftlayerDetector",
        "SquareOAuthDetector",
        "StripeDetector",
        "TelegramBotTokenDetector",
        "TwilioKeyDetector",
    ]

    def __init__(
        self,
        auto_install: bool = True,
        version: str | None = None,
    ) -> None:
        """Initialize the detect-secrets scanner.

        Args:
            auto_install: Automatically install detect-secrets if not found.
            version: Specific version to use. Uses pinned version if None.
        """
        self._auto_install = auto_install
        self._version = version or _get_detect_secrets_version()
        self._installed: bool | None = None

    # detect-secrets has no git-history mode; ``include_git_history`` is
    # intentionally ignored, so never present it as history coverage (#476).
    supports_git_history = False

    @property
    def name(self) -> str:
        """Return scanner identifier."""
        return "detect-secrets"

    @property
    def description(self) -> str:
        """Return scanner description."""
        return "Yelp detect-secrets (27+ detectors, entropy, keywords)"

    def is_installed(self) -> bool:
        """Check if detect-secrets is available."""
        if self._installed is not None:
            return self._installed

        try:
            result = _run_version_probe()
        except Exception:
            self._installed = False
            return False
        self._installed = result.returncode == 0
        if self._installed:
            # The version is known from this probe, so the scan's version check needs no second.
            _remember_version(result.stdout)
        return self._installed

    def get_version(self) -> str | None:
        """Get installed detect-secrets version."""
        try:
            result = _run_version_probe()
        except Exception:
            return None
        # Output format: "detect-secrets 1.5.0"
        return _remember_version(result.stdout) if result.returncode == 0 else None

    def _ensure_installed(self) -> bool:
        """Ensure detect-secrets is installed.

        Returns:
            True if installed or installation succeeded.

        Raises:
            DetectSecretsNotFoundError: If not installed and auto-install disabled/failed.
        """
        if self.is_installed():
            return True

        if not self._auto_install:
            raise DetectSecretsNotFoundError(
                "detect-secrets not found. Install with: pip install detect-secrets "
                "or enable auto_install=True"
            )

        try:
            installer = DetectSecretsInstaller(version=self._version)
            installer.install()
            self._installed = True
            return True
        except DetectSecretsInstallError as e:
            raise DetectSecretsNotFoundError(
                f"detect-secrets not found and auto-install failed: {e}"
            ) from e

    def install(
        self,
        progress_callback: Callable[[str], None] | None = None,
    ) -> Path | None:
        """Install detect-secrets package.

        Args:
            progress_callback: Optional callback for progress updates.

        Returns:
            None on success (detect-secrets is a pip package, not a binary).
            Raises exception on failure.
        """
        installer = DetectSecretsInstaller(
            version=self._version,
            progress_callback=progress_callback,
        )
        installer.install()
        self._installed = True
        return None  # No binary path for pip packages

    def scan(
        self,
        paths: list[Path],
        include_git_history: bool = False,
    ) -> ScanResult:
        """Scan paths for secrets using detect-secrets.

        A directory inside a git work tree, the top level or a subdirectory of it, is scanned
        for the files git tracks (a new file is scanned once it is added); a directory
        outside one is scanned for all of its files. A file is always scanned.

        Args:
            paths: List of files or directories to scan.
            include_git_history: Not supported by detect-secrets (ignored).

        Returns:
            ScanResult containing all findings. Its ``warnings`` say when the installed
            detect-secrets is not the pinned version, so severities may be inaccurate, and
            when git tracks no file to scan in a directory.
        """
        # Note: detect-secrets doesn't support git history scanning
        _ = include_git_history  # intentionally ignored (interface compatibility)
        start_time = time.time()

        try:
            self._ensure_installed()
        except DetectSecretsNotFoundError as e:
            return ScanResult(
                scanner_name=self.name,
                error=str(e),
                duration_ms=int((time.time() - start_time) * 1000),
            )

        # A different detect-secrets than the pinned one still scans: its detector names
        # may differ from those DETECTOR_SEVERITY is keyed on, so say so with the result.
        warnings = _version_warnings()
        all_findings: list[ScanFinding] = []
        total_files = 0

        def failed(error: str) -> ScanResult:
            return ScanResult(
                scanner_name=self.name,
                findings=all_findings,
                error=error,
                duration_ms=int((time.time() - start_time) * 1000),
                warnings=warnings,
            )

        for path in paths:
            if not path.exists():
                continue

            try:
                plan = _plan_scan(path)
                env, listing_warnings = _check_git_file_list(path, _scannable_tracked_names(plan))
                result = _run_detect_secrets(plan, env)
                warnings = [*warnings, *listing_warnings]

                # Belt and braces for #851: if detect-secrets still found no git work tree
                # to list the files from (the check above and its own can disagree), it
                # scanned nothing, which must not pass for a clean run.
                if _NO_GIT_REPOSITORY_NOTICE in result.stderr:
                    return failed(
                        f"detect-secrets scanned nothing in {path}: it could not list "
                        "the files of a git repository"
                    )

                # detect-secrets outputs JSON baseline to stdout
                if result.stdout.strip():
                    baseline = _read_report(result.stdout)
                    if baseline is None:
                        # A report that cannot be read is not a clean one.
                        return failed(
                            f"detect-secrets output error: {(result.stderr or result.stdout)[:200]}"
                        )
                    all_findings.extend(self._parse_baseline(baseline, path, plan.prefix))
                    total_files += len(baseline["results"])
                elif result.returncode == 0:
                    # It always prints a baseline; none at all means nothing was scanned.
                    return failed(f"detect-secrets printed no report for {path}")

                if result.returncode != 0:
                    return failed(
                        result.stderr.strip()
                        or result.stdout.strip()
                        or f"detect-secrets scan failed for {path} (exit code {result.returncode})"
                    )

            except subprocess.TimeoutExpired:
                return failed(f"Scan timed out for {path}")
            except Exception as e:
                return failed(str(e))

        return ScanResult(
            scanner_name=self.name,
            findings=all_findings,
            files_scanned=total_files,
            duration_ms=int((time.time() - start_time) * 1000),
            warnings=warnings,
        )

    def _parse_baseline(
        self, baseline: dict[str, Any], base_path: Path, prefix: PurePath = _NO_PREFIX
    ) -> list[ScanFinding]:
        """Parse detect-secrets baseline into findings.

        Args:
            baseline: The detect-secrets baseline JSON.
            base_path: Base path for resolving relative paths.
            prefix: The leading part of every file name in the report that leads from the
                directory detect-secrets ran in to ``base_path`` (see ``_plan_scan``). It is
                dropped, so the file is shown below ``base_path`` as the caller named it.

        Returns:
            List of ScanFinding objects.
        """
        findings: list[ScanFinding] = []
        for name, secrets in baseline.get("results", {}).items():
            file_path = _report_file(name, base_path, prefix)
            for secret in secrets:
                finding = self._parse_secret(secret, file_path)
                if finding is not None:
                    findings.append(finding)
        return findings

    def _parse_secret(self, secret: dict[str, Any], file_path: Path) -> ScanFinding | None:
        """Parse a single secret entry into a finding.

        Args:
            secret: Secret entry from baseline.
            file_path: Path to the file containing the secret.

        Returns:
            ScanFinding or None if parsing fails.
        """
        try:
            detector_type = secret.get("type", "unknown")
            line_number = secret.get("line_number")

            # Get severity based on detector type
            severity = DETECTOR_SEVERITY.get(detector_type, FindingSeverity.HIGH)

            # Get the hashed secret (detect-secrets doesn't expose raw secrets)
            hashed_secret = secret.get("hashed_secret", "")
            # Use first 8 chars of hash as preview
            preview = f"[hash:{hashed_secret[:8]}...]" if hashed_secret else ""

            # Check if it's been verified as false positive
            is_false_positive = secret.get("is_secret") is False

            return ScanFinding(
                file_path=file_path,
                line_number=line_number,
                rule_id=f"detect-secrets-{detector_type.lower().replace(' ', '-')}",
                rule_description=detector_type,
                description=f"Secret detected by {detector_type}",
                severity=severity if not is_false_positive else FindingSeverity.INFO,
                secret_preview=preview,
                secret_hash=hashed_secret,
                scanner=self.name,
            )
        except Exception:
            return None
