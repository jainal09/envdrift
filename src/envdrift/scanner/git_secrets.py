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
)
from envdrift.scanner.patterns import hash_secret, redact_secret

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)


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
            result = subprocess.run(  # nosec B603, B607
                ["brew", "install", "git-secrets"],
                capture_output=True,
                text=True,
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
                subprocess.run(  # nosec B603, B607
                    ["git", "clone", "--depth", "1", self.REPO_URL, str(repo_path)],
                    capture_output=True,
                    text=True,
                    timeout=120,
                    check=True,
                )

                # Install to user's local bin
                target_dir = get_venv_bin_dir()
                self.progress(f"Installing to {target_dir}...")

                # Run make install with custom PREFIX
                subprocess.run(  # nosec B603, B607
                    ["make", "install", f"PREFIX={target_dir.parent}"],
                    capture_output=True,
                    text=True,
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
            result = subprocess.run(  # nosec B603, B607
                ["git", "secrets", "--list"],
                capture_output=True,
                text=True,
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
            return subprocess.run(  # nosec B603
                [git_secrets_path, *args],
                capture_output=True,
                text=True,
                timeout=300,
                cwd=cwd,
            )

        # Fall back to git subcommand
        return subprocess.run(  # nosec B603, B607
            ["git", "secrets", *args],
            capture_output=True,
            text=True,
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
                error=str(e),
                duration_ms=int((time.time() - start_time) * 1000),
            )

        all_findings: list[ScanFinding] = []
        total_files = 0

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
                    # Scan specific files or directory
                    args = ["--scan", "-r"] + scan_paths
                    result = self._run_git_secrets(args, cwd)

                # Parse output
                # git-secrets outputs format: path:line_number:content
                if result.returncode != 0 and result.stdout:
                    findings = self._parse_output(result.stdout, cwd)
                    all_findings.extend(findings)

                # Also check stderr for findings
                if result.stderr:
                    # Filter out actual errors vs finding output
                    stderr_findings = self._parse_output(result.stderr, cwd)
                    for finding in stderr_findings:
                        if finding not in all_findings:
                            all_findings.append(finding)

            except subprocess.TimeoutExpired:
                return ScanResult(
                    scanner_name=self.name,
                    findings=all_findings,
                    error=f"Scan timed out for {path}",
                    duration_ms=int((time.time() - start_time) * 1000),
                )
            except Exception as e:
                # Non-fatal errors, log and continue with other paths
                logger.debug("Error scanning %s: %s", path, e)
                continue

        return ScanResult(
            scanner_name=self.name,
            findings=all_findings,
            files_scanned=total_files,
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

        # Severity based on rule type
        severity = FindingSeverity.HIGH if "aws" in rule_id else FindingSeverity.MEDIUM

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
            r"(?:aws_secret_access_key|secret_access_key|AWS_SECRET)\s*[=:]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?",
            # KEY=VALUE or KEY: VALUE
            r'=\s*["\']?([^"\'\s]+)["\']?',
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

        if "akia" in content_lower or "asia" in content_lower:
            return "aws-access-key"
        if "aws_secret" in content_lower or "secret_access_key" in content_lower:
            return "aws-secret-key"
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
