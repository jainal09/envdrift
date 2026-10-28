"""git-secrets scanner integration with auto-installation.

git-secrets is an AWS tool that prevents committing secrets and credentials
into git repositories by scanning commits, commit messages, and --no-ff merges.

This module provides:
- Automatic installation via Homebrew (macOS) or make install (Linux)
- Integration with git hooks for pre-commit scanning
- AWS-specific pattern registration
- Custom pattern support

Key features of git-secrets:
- Pre-commit hook integration
- AWS credentials detection (--register-aws)
- Custom prohibited patterns
- Allowed patterns for false positives
- Secret providers for dynamic patterns

See: https://github.com/awslabs/git-secrets
"""

from __future__ import annotations

import logging
import os
import platform
import re
import shutil
import subprocess  # nosec B404
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING

from envdrift.scanner.base import (
    FindingSeverity,
    ScanFinding,
    ScannerBackend,
    ScanResult,
    exception_message,
)
from envdrift.scanner.patterns import hash_secret, redact_secret
from envdrift.utils.deadline import run_tool

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)

# An AWS access key ID, the credential the native scanner and gitleaks grade CRITICAL. The
# type decides the severity, so a line is an access key ID only if it holds one: the letters
# "asia" alone (a GCP region such as ``asia-northeast1``) do not make it one. The IAM entity
# IDs that ``git secrets --register-aws`` also flags (AIDA, AROA, ...) name a principal and
# open no door, so they stay generic.
_AWS_ACCESS_KEY_ID_RE = re.compile(
    r"(?<![A-Z0-9])(?:A3T[A-Z0-9]|AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"
)

# A line of git-secrets output that envdrift may quote: not blank, and no match. A match,
# ``path:line:content`` (``commit:path:line:...`` in history), holds the secret.
_QUOTABLE_LINE = re.compile(r"^(?!.*:\d+:).*\S")

# The other two CRITICAL types are also earned by the credential, not by a word near it: a
# secret access key is the 40-character value assigned to the AWS secret field itself, and a
# private key is a PEM header or a long base64 value assigned to ``private_key`` itself. A line
# that only names ``aws_secret_access_key_file`` or ``private_key_path``, holds a long value
# under another field (``private_key_id``, a checksum next to the file name), holds neither,
# so it is HIGH, not CRITICAL (see ``_holds_credential``). The key is base64 without padding,
# so a ``=`` before it is the assignment, not part of it. The assignment is ``=``, ``:`` or the
# hash rocket ``=>`` of Puppet, Ruby and PHP: git-secrets' own AWS pattern takes all three.
_AWS_SECRET_ACCESS_KEY_RE = re.compile(
    r"(?:aws_secret(?:_access)?(?:_key)?|secret_access_key)[\"']?\s*(?:=>|[=:])\s*[\"']?"
    r"[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])",
    re.IGNORECASE,
)
_PRIVATE_KEY_HEADER_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY")
_PRIVATE_KEY_VALUE_RE = re.compile(
    r"private_key[\"']?\s*(?:=>|[:=])\s*[\"']?[A-Za-z0-9+/]{64,}", re.IGNORECASE
)

# git-secrets reports a matching line, not a rule, so ``_detect_rule_type`` names the
# credential from the line's text. The grades follow the severity policy of the scanners
# that grade by credential class (see "Severity" in docs/cli/guard.md): an AWS key or a
# private key is CRITICAL and a generic password, token or API key HIGH, as in the native
# scanner. A line that names nothing it can classify stays MEDIUM.
RULE_TYPE_SEVERITY: dict[str, FindingSeverity] = {
    "aws-access-key": FindingSeverity.CRITICAL,
    "aws-secret-key": FindingSeverity.CRITICAL,
    "private-key": FindingSeverity.CRITICAL,
    "password": FindingSeverity.HIGH,
    "token": FindingSeverity.HIGH,
    "api-key": FindingSeverity.HIGH,
    "generic-secret": FindingSeverity.MEDIUM,
}


def _holds_credential(rule_type: str, content: str) -> bool:
    """Whether the line holds the credential its CRITICAL ``rule_type`` is named for.

    ``_detect_rule_type`` names a line by the words in it, which is enough for the generic
    types but not for a key: ``aws_secret_access_key_file = /root/.aws/credentials`` and
    ``private_key_path = /etc/ssl/server.pem`` contain no secret.
    """
    if rule_type == "aws-secret-key":
        return _AWS_SECRET_ACCESS_KEY_RE.search(content) is not None
    if rule_type == "private-key":
        return (
            _PRIVATE_KEY_HEADER_RE.search(content) is not None
            or _PRIVATE_KEY_VALUE_RE.search(content) is not None
        )
    return True


def _scan_error(
    result: subprocess.CompletedProcess[str], found: list[ScanFinding], path: Path
) -> str | None:
    """Why the git-secrets run that scanned ``path`` failed, or None when it did not.

    git-secrets exits 0 when it finds nothing and 1 when it reports matches. It exits with any
    other code when it fails: 2 when grep fails, 128 when git does, 129 for an option it does
    not know. When git cannot read its config, git-secrets loads no patterns, matches nothing
    and exits 0, so only git's ``fatal:`` message on stderr tells. An exit of 1 with no match
    that envdrift can parse leaves the findings unknown as well (#872). A line that could be a
    match (``path:line:content``) is never quoted: it would hold the secret.
    """
    lines = [line for line in result.stderr.splitlines() if _QUOTABLE_LINE.match(line)]
    fatal = [line for line in lines if line.startswith("fatal: ")]
    if fatal or result.returncode not in (0, 1):
        detail = next(iter(fatal + lines), f"exit code {result.returncode}")
        return f"git-secrets could not scan {path}: {detail}"
    if result.returncode == 1 and not found:
        return f"git-secrets reported a match in {path} that envdrift cannot parse"
    return None


class GitSecretsNotFoundError(Exception):
    """git-secrets not found."""

    pass


class GitSecretsInstallError(Exception):
    """Failed to install git-secrets."""

    pass


class GitSecretsError(Exception):
    """git-secrets command failed."""

    pass


def get_venv_bin_dir() -> Path:
    """Get the virtual environment's bin directory.

    Returns:
        Path to the bin directory where binaries should be installed.
    """
    # Check for virtual environment
    venv_path = os.environ.get("VIRTUAL_ENV")
    if venv_path:
        venv = Path(venv_path)
        if platform.system() == "Windows":
            return venv / "Scripts"
        return venv / "bin"

    # Default to user bin directory
    if platform.system() != "Windows":
        user_bin = Path.home() / ".local" / "bin"
        user_bin.mkdir(parents=True, exist_ok=True)
        return user_bin

    raise RuntimeError("Cannot find suitable bin directory for installation")


class GitSecretsInstaller:
    """Installer for git-secrets.

    git-secrets is a shell script, so installation methods vary by platform:
    - macOS: Homebrew (brew install git-secrets)
    - Linux: Clone repo and make install
    - Windows: PowerShell script or manual
    """

    REPO_URL = "https://github.com/awslabs/git-secrets.git"

    def __init__(
        self,
        progress_callback: Callable[[str], None] | None = None,
    ) -> None:
        """Initialize installer.

        Args:
            progress_callback: Optional callback for progress updates.
        """
        self.progress = progress_callback or (lambda x: None)

    def install(self, force: bool = False) -> Path:
        """Install git-secrets.

        Args:
            force: Reinstall even if already installed.

        Returns:
            Path to the installed git-secrets script.

        Raises:
            GitSecretsInstallError: If installation fails.
        """
        # Check if already installed
        existing = shutil.which("git-secrets")
        if existing and not force:
            self.progress("git-secrets already installed")
            return Path(existing)

        system = platform.system()

        if system == "Darwin":
            return self._install_homebrew()
        elif system == "Linux":
            return self._install_from_source()
        else:
            raise GitSecretsInstallError(
                f"Automatic installation not supported on {system}. "
                "Please install git-secrets manually: "
                "https://github.com/awslabs/git-secrets#installing-git-secrets"
            )

    def _install_homebrew(self) -> Path:
        """Install via Homebrew on macOS."""
        self.progress("Installing git-secrets via Homebrew...")

        # Check if Homebrew is available
        if not shutil.which("brew"):
            raise GitSecretsInstallError(
                "Homebrew not found. Please install Homebrew first: https://brew.sh"
            )

        try:
            result = run_tool(
                ["brew", "install", "git-secrets"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=300,
            )

            # Check if installation succeeded
            if result.returncode != 0:
                # Check if already installed
                if "already installed" in result.stderr or "already installed" in result.stdout:
                    self.progress("git-secrets is already installed via Homebrew")
                else:
                    raise GitSecretsInstallError(f"Homebrew installation failed: {result.stderr}")

            # Find the installed binary
            git_secrets_path = shutil.which("git-secrets")
            if git_secrets_path:
                self.progress(f"Installed to {git_secrets_path}")
                return Path(git_secrets_path)

            raise GitSecretsInstallError("git-secrets not found after installation")

        except subprocess.TimeoutExpired as e:
            raise GitSecretsInstallError("Homebrew installation timed out") from e
        except subprocess.SubprocessError as e:
            raise GitSecretsInstallError(f"Homebrew installation failed: {e}") from e

    def _install_from_source(self) -> Path:
        """Install from source on Linux."""
        self.progress("Installing git-secrets from source...")

        # Check if git is available
        if not shutil.which("git"):
            raise GitSecretsInstallError("git not found. Please install git first.")

        # Check if make is available
        if not shutil.which("make"):
            raise GitSecretsInstallError("make not found. Please install make first.")

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            repo_path = tmp_path / "git-secrets"

            try:
                # Clone the repository
                self.progress("Cloning git-secrets repository...")
                run_tool(
                    ["git", "clone", "--depth", "1", self.REPO_URL, str(repo_path)],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=120,
                    check=True,
                )

                # Install to user's local bin
                target_dir = get_venv_bin_dir()
                self.progress(f"Installing to {target_dir}...")

                # Run make install with custom PREFIX
                run_tool(
                    ["make", "install", f"PREFIX={target_dir.parent}"],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=60,
                    cwd=repo_path,
                    check=True,
                )

                git_secrets_path = target_dir / "git-secrets"
                if git_secrets_path.exists():
                    self.progress(f"Installed to {git_secrets_path}")
                    return git_secrets_path

                # Try system-wide check
                system_path = shutil.which("git-secrets")
                if system_path:
                    return Path(system_path)

                raise GitSecretsInstallError("git-secrets not found after installation")

            except subprocess.CalledProcessError as e:
                raise GitSecretsInstallError(f"Installation failed: {e.stderr or e.stdout}") from e
            except subprocess.TimeoutExpired as e:
                raise GitSecretsInstallError("Installation timed out") from e


class GitSecretsScanner(ScannerBackend):
    """git-secrets scanner with automatic installation.

    git-secrets provides:
    - Pre-commit hook integration
    - AWS credentials detection
    - Custom pattern matching
    - Commit message scanning

    Example:
        scanner = GitSecretsScanner(auto_install=True)
        result = scanner.scan([Path(".")])
        for finding in result.findings:
            print(f"{finding.severity}: {finding.description}")
    """

    def __init__(
        self,
        auto_install: bool = True,
        register_aws: bool = True,
    ) -> None:
        """Initialize the git-secrets scanner.

        Args:
            auto_install: Automatically install git-secrets if not found.
            register_aws: Register AWS-specific patterns (--register-aws).
        """
        self._auto_install = auto_install
        self._register_aws = register_aws
        self._binary_path: Path | None = None

    # Scans git history when ``include_git_history`` is set (#476).
    supports_git_history = True

    @property
    def name(self) -> str:
        """Return scanner identifier."""
        return "git-secrets"

    @property
    def description(self) -> str:
        """Return scanner description."""
        return "AWS git-secrets (pre-commit hooks + AWS credential detection)"

    def is_installed(self) -> bool:
        """Check if git-secrets is available."""
        try:
            self._find_binary()
            return True
        except GitSecretsNotFoundError:
            return False

    def get_version(self) -> str | None:
        """Get installed git-secrets version.

        Note: git-secrets doesn't have a --version flag, so we return None.
        """
        # git-secrets doesn't have a version command
        return None

    def _find_binary(self) -> Path:
        """Find the git-secrets binary, installing if necessary.

        Returns:
            Path to the git-secrets binary/script.

        Raises:
            GitSecretsNotFoundError: If binary cannot be found or installed.
        """
        if self._binary_path and self._binary_path.exists():
            return self._binary_path

        # Check system PATH
        system_path = shutil.which("git-secrets")
        if system_path:
            self._binary_path = Path(system_path)
            return self._binary_path

        # Check git subcommand (git secrets)
        try:
            result = run_tool(
                ["git", "secrets", "--list"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=5,
            )
            # Only check returncode - a successful command means git-secrets is installed
            if result.returncode == 0:
                # Mark as available via git subcommand
                # _run_git_secrets will detect the proper invocation method at runtime
                self._binary_path = Path("git-secrets-subcommand")
                return self._binary_path
        except Exception as exc:
            logger.debug(
                "Failed to detect git-secrets via 'git secrets --list': %s",
                exc,
            )

        # Auto-install if enabled
        if self._auto_install:
            try:
                installer = GitSecretsInstaller()
                self._binary_path = installer.install()
                return self._binary_path
            except GitSecretsInstallError as e:
                raise GitSecretsNotFoundError(
                    f"git-secrets not found and auto-install failed: {e}"
                ) from e

        raise GitSecretsNotFoundError(
            "git-secrets not found. Install with: brew install git-secrets"
        )

    def install(
        self,
        progress_callback: Callable[[str], None] | None = None,
    ) -> Path | None:
        """Install git-secrets.

        Args:
            progress_callback: Optional callback for progress updates.

        Returns:
            Path to the installed binary.
        """
        installer = GitSecretsInstaller(progress_callback=progress_callback)
        self._binary_path = installer.install()
        return self._binary_path

    def _run_git_secrets(self, args: list[str], cwd: Path) -> subprocess.CompletedProcess:
        """Run git-secrets command.

        Args:
            args: Arguments to pass to git-secrets.
            cwd: Working directory.

        Returns:
            CompletedProcess object.
        """
        # Try as standalone command first
        git_secrets_path = shutil.which("git-secrets")
        if git_secrets_path:
            return run_tool(
                [git_secrets_path, *args],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=300,
                cwd=cwd,
            )

        # Fall back to git subcommand
        return run_tool(
            ["git", "secrets", *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=300,
            cwd=cwd,
        )

    def scan(
        self,
        paths: list[Path],
        include_git_history: bool = False,
    ) -> ScanResult:
        """Scan paths for secrets using git-secrets.

        Args:
            paths: List of files or directories to scan.
            include_git_history: If True, scan git history (--scan-history).

        Returns:
            ScanResult containing all findings.
        """
        start_time = time.time()

        try:
            self._find_binary()
        except GitSecretsNotFoundError as e:
            return ScanResult(
                scanner_name=self.name,
                error=exception_message(e),
                duration_ms=int((time.time() - start_time) * 1000),
            )

        all_findings: list[ScanFinding] = []
        total_files = 0
        path_errors: list[str] = []

        for path in paths:
            if not path.exists():
                continue

            # Count file for files_scanned metric
            if path.is_file():
                total_files += 1

            # Determine working directory and scan paths
            # Store original file path for proper resolution later
            original_path = path.resolve()
            if path.is_file():
                cwd = path.parent.resolve()
                scan_paths = [path.name]
            else:
                cwd = path.resolve()
                scan_paths = ["."]

            # Check if this is a git repository - find the git root
            git_root = cwd
            git_dir = cwd / ".git"
            if not git_dir.exists():
                # Try to find parent git repo
                current = cwd
                while current.parent != current:
                    if (current / ".git").exists():
                        git_root = current
                        # Update scan_paths to be relative to git root
                        if path.is_file():
                            try:
                                scan_paths = [str(original_path.relative_to(git_root))]
                            except ValueError:
                                # File is outside the git repository, skip it
                                logger.debug(
                                    "File %s is outside git repository %s, skipping",
                                    original_path,
                                    git_root,
                                )
                                continue
                        break
                    current = current.parent
            # Use git_root as cwd for git-secrets commands
            cwd = git_root

            try:
                # First, try to register AWS patterns if in a git repo
                if (cwd / ".git").exists():
                    # Check if git-secrets is installed in this repo
                    list_result = self._run_git_secrets(["--list"], cwd)

                    # Register AWS patterns if enabled
                    # Check for AWS-specific pattern entries in secrets.patterns
                    if self._register_aws:
                        # Look for AWS access key pattern (A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)
                        # or aws_secret_access_key provider which is registered by --register-aws
                        aws_patterns_installed = (
                            "A3T[A-Z0-9]" in list_result.stdout
                            or "aws_secret_access_key" in list_result.stdout
                            or "git secrets --aws-provider" in list_result.stdout
                        )
                        if not aws_patterns_installed:
                            logger.debug(
                                "Registering AWS patterns in git-secrets for repo: %s",
                                cwd,
                            )
                            try:
                                self._run_git_secrets(["--register-aws"], cwd)
                            except Exception as e:
                                logger.debug(
                                    "Failed to register AWS patterns in %s: %s",
                                    cwd,
                                    e,
                                )

                # Run the scan
                if include_git_history:
                    # Scan entire git history
                    result = self._run_git_secrets(["--scan-history"], cwd)
                else:
                    # ``--no-index`` recurses through the requested paths but
                    # excludes Git metadata. ``-r .`` scans ``.git/config``,
                    # where modern git-secrets stores its own literal Bedrock
                    # pattern, producing a false positive (#581). Unlike
                    # ``--untracked``, this keeps ignored user files (such as
                    # ``.env``) in the scanner's scope.
                    args = ["--scan", "--no-index", *scan_paths]
                    result = self._run_git_secrets(args, cwd)

                # Parse output.
                # git-secrets writes its findings (format: path:line_number:content,
                # followed by an "[ERROR] Matched..." trailer) to STDERR, not stdout,
                # and exits 1 when matches are found. Parse stderr to capture
                # them; _parse_output skips the "[ERROR]"/"error:" trailer lines.
                # Defensive fallback: some git-secrets variants/wrappers may emit
                # findings on stdout. Parse it too so findings are never dropped.
                found = self._parse_output(result.stderr, cwd)
                found += self._parse_output(result.stdout, cwd)
                for finding in found:
                    if finding not in all_findings:
                        all_findings.append(finding)
                error = _scan_error(result, found, path)
                if error:
                    path_errors.append(error)

            except subprocess.TimeoutExpired:
                # The paths that failed before this one still count.
                return ScanResult(
                    scanner_name=self.name,
                    findings=all_findings,
                    error="; ".join([*path_errors, f"Scan timed out for {path}"]),
                    duration_ms=int((time.time() - start_time) * 1000),
                )
            except Exception as e:
                # The other paths are still scanned, but this one was not, so
                # the run is incomplete, not clean (#872).
                path_errors.append(f"git-secrets could not scan {path}: {exception_message(e)}")

        return ScanResult(
            scanner_name=self.name,
            findings=all_findings,
            files_scanned=total_files,
            error="; ".join(path_errors) if path_errors else None,
            duration_ms=int((time.time() - start_time) * 1000),
        )

    def _parse_output(self, output: str, base_path: Path) -> list[ScanFinding]:
        """Parse git-secrets output into findings.

        git-secrets output format:
        - Scan output: path:line_number:content
        - History output: commit:path:line_number:content

        Args:
            output: Raw output from git-secrets.
            base_path: Base path for resolving relative paths.

        Returns:
            List of ScanFinding objects.
        """
        findings: list[ScanFinding] = []

        # Pattern for scan output: file.txt:10:SECRET_VALUE
        scan_pattern = re.compile(r"^(.+?):(\d+):(.*)$")

        # Pattern for history output: abc123:file.txt:10:SECRET_VALUE
        history_pattern = re.compile(r"^([a-f0-9]{7,40}):(.+?):(\d+):(.*)$")

        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue

            # Skip error messages
            if line.startswith("[ERROR]") or line.startswith("error:"):
                continue

            finding = None

            # Try history pattern first (more specific)
            history_match = history_pattern.match(line)
            if history_match:
                commit_sha = history_match.group(1)
                file_path_str = history_match.group(2)
                line_number = int(history_match.group(3))
                content = history_match.group(4)

                finding = self._create_finding(
                    file_path_str=file_path_str,
                    line_number=line_number,
                    content=content,
                    base_path=base_path,
                    commit_sha=commit_sha,
                )
            else:
                # Try scan pattern
                scan_match = scan_pattern.match(line)
                if scan_match:
                    file_path_str = scan_match.group(1)
                    line_number = int(scan_match.group(2))
                    content = scan_match.group(3)

                    finding = self._create_finding(
                        file_path_str=file_path_str,
                        line_number=line_number,
                        content=content,
                        base_path=base_path,
                    )

            if finding:
                findings.append(finding)

        return findings

    def _create_finding(
        self,
        file_path_str: str,
        line_number: int,
        content: str,
        base_path: Path,
        commit_sha: str | None = None,
    ) -> ScanFinding:
        """Create a ScanFinding from parsed output.

        Args:
            file_path_str: File path string.
            line_number: Line number in file.
            content: Line content with secret.
            base_path: Base path for resolving relative paths.
            commit_sha: Optional commit SHA for history findings.

        Returns:
            ScanFinding object.
        """
        # Resolve file path
        file_path = Path(file_path_str)
        if not file_path.is_absolute():
            file_path = (base_path / file_path).resolve()

        # Try to extract the secret value
        secret = self._extract_secret(content)
        redacted = redact_secret(secret) if secret else ""
        secret_hash = hash_secret(secret) if secret else ""

        # Determine rule type based on content
        rule_id = self._detect_rule_type(content)
        rule_description = self._get_rule_description(rule_id)

        # Severity based on rule type. A CRITICAL type needs the credential itself on the line:
        # a line that only names a key (``private_key_path = ...``) is HIGH at most.
        severity = RULE_TYPE_SEVERITY.get(rule_id, FindingSeverity.MEDIUM)
        if severity is FindingSeverity.CRITICAL and not _holds_credential(rule_id, content):
            severity = FindingSeverity.HIGH

        return ScanFinding(
            file_path=file_path,
            line_number=line_number,
            rule_id=f"git-secrets-{rule_id}",
            rule_description=rule_description,
            description=f"Secret detected by git-secrets: {rule_description}",
            severity=severity,
            secret_preview=redacted,
            secret_hash=secret_hash,
            commit_sha=commit_sha,
            scanner=self.name,
        )

    def _extract_secret(self, content: str) -> str:
        """Extract the secret value from line content.

        Args:
            content: Line content containing the secret.

        Returns:
            Extracted secret or the full content if extraction fails.
        """
        # Common patterns for secret assignments
        patterns = [
            # AWS Access Key ID (20 chars, starts with AKIA or ASIA)
            r"(AKIA[A-Z0-9]{16})",
            r"(ASIA[A-Z0-9]{16})",
            # AWS Secret Access Key (40 chars, base64-like, adjacent to known keys)
            r"(?:aws_secret_access_key|secret_access_key|AWS_SECRET)\s*(?:=>|[=:])\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?",
            # KEY=VALUE, KEY => VALUE or KEY: VALUE
            r'(?:=>|=)\s*["\']?([^"\'\s]+)["\']?',
            r':\s*["\']?([^"\'\s]+)["\']?',
        ]

        for pattern in patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(1)

        # Return content if no pattern matches (first 50 chars)
        return content[:50] if len(content) > 50 else content

    def _detect_rule_type(self, content: str) -> str:
        """Detect the type of secret based on content.

        Args:
            content: Line content.

        Returns:
            Rule type identifier.
        """
        content_lower = content.lower()

        if _AWS_ACCESS_KEY_ID_RE.search(content):
            return "aws-access-key"
        if "aws_secret" in content_lower or "secret_access_key" in content_lower:
            return "aws-secret-key"
        if _PRIVATE_KEY_HEADER_RE.search(content):
            return "private-key"
        if "password" in content_lower or "passwd" in content_lower:
            return "password"
        if "token" in content_lower:
            return "token"
        if "api_key" in content_lower or "apikey" in content_lower:
            return "api-key"
        if "private_key" in content_lower:
            return "private-key"

        return "generic-secret"

    def _get_rule_description(self, rule_id: str) -> str:
        """
        Return a human-readable description for the specified rule identifier.

        Parameters:
            rule_id (str): Rule identifier to describe.

        Returns:
            description (str): Human-readable rule description, or "Secret Pattern Match" if the identifier is unknown.
        """
        descriptions = {  # nosec B105 - rule ID descriptions, not actual secrets
            "aws-access-key": "AWS Access Key ID",
            "aws-secret-key": "AWS Secret Access Key",
            "password": "Password or Credential",  # nosec B105 - not a real password
            "token": "Authentication Token",  # nosec B105 - not a real token
            "api-key": "API Key",
            "private-key": "Private Key",
            "generic-secret": "Potential Secret",
        }
        return descriptions.get(rule_id, "Secret Pattern Match")

    def install_hooks(self, repo_path: Path) -> bool:
        """Install git-secrets hooks in a repository.

        This sets up pre-commit and commit-msg hooks to prevent
        accidentally committing secrets.

        Args:
            repo_path: Path to the git repository.

        Returns:
            True if hooks were installed successfully.
        """
        if not (repo_path / ".git").exists():
            return False

        try:
            self._find_binary()
            result = self._run_git_secrets(["--install"], repo_path)
            return result.returncode == 0
        except Exception:
            return False

    def add_pattern(self, pattern: str, repo_path: Path, allowed: bool = False) -> bool:
        """Add a custom pattern to git-secrets.

        Args:
            pattern: Regex pattern to add.
            repo_path: Path to the git repository.
            allowed: If True, add as allowed pattern (for false positives).

        Returns:
            True if pattern was added successfully.
        """
        try:
            self._find_binary()
            args = ["--add"]
            if allowed:
                args.append("--allowed")
            args.append(pattern)

            result = self._run_git_secrets(args, repo_path)
            return result.returncode == 0
        except Exception:
            return False

    def list_patterns(self, repo_path: Path) -> dict[str, list[str]]:
        """List configured patterns in a repository.

        Args:
            repo_path: Path to the git repository.

        Returns:
            Dictionary with 'patterns', 'allowed', and 'providers' lists.
        """
        result_dict: dict[str, list[str]] = {
            "patterns": [],
            "allowed": [],
            "providers": [],
        }

        try:
            self._find_binary()
            result = self._run_git_secrets(["--list"], repo_path)

            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    line = line.strip()
                    if line.startswith("secrets.patterns"):
                        # Extract pattern value
                        parts = line.split("=", 1)
                        if len(parts) > 1:
                            result_dict["patterns"].append(parts[1].strip())
                    elif line.startswith("secrets.allowed"):
                        parts = line.split("=", 1)
                        if len(parts) > 1:
                            result_dict["allowed"].append(parts[1].strip())
                    elif line.startswith("secrets.providers"):
                        parts = line.split("=", 1)
                        if len(parts) > 1:
                            result_dict["providers"].append(parts[1].strip())

        except Exception:
            pass

        return result_dict
