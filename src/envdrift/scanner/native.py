"""Native scanner - zero external dependencies.

This scanner provides built-in secret detection capabilities without requiring
any external tools. It checks for:

1. Unencrypted .env files (missing dotenvx/SOPS encryption markers)
2. Common secret patterns (API keys, tokens, passwords)
3. High-entropy strings (optional, for detecting random secrets)
"""

from __future__ import annotations

import fnmatch
import time
from pathlib import Path

from envdrift.scanner.base import (
    FindingSeverity,
    ScanFinding,
    ScannerBackend,
    ScanResult,
)
from envdrift.scanner.patterns import (
    ALL_PATTERNS,
    calculate_entropy,
    hash_secret,
    redact_secret,
)

# Encryption markers for dotenvx
DOTENVX_MARKERS = (
    # Check for actual encrypted values, not just the public key header
    # DOTENV_PUBLIC_KEY header means file CAN be encrypted, not that values ARE encrypted
    "encrypted:",
)

# Encryption markers for SOPS
SOPS_MARKERS = (
    "sops:",
    "sops_",
    "ENC[AES256_GCM,",
)

# Default patterns to ignore - comprehensive list for all major languages and tools
DEFAULT_IGNORE_PATTERNS = (
    # Env file examples/templates
    ".env.example",
    ".env.sample",
    ".env.template",
    ".env.test",
    ".env.local",
    # Documentation and text files
    "*.md",
    "*.txt",
    "*.rst",
    "*.adoc",
    # Lock and checksum files
    "*.lock",
    "*.sum",
    "*-lock.json",
    "*.lock.json",
    # Minified files (high entropy but not secrets)
    "*.min.js",
    "*.min.css",
    "*.bundle.js",
    "*.chunk.js",
    # Python
    "__pycache__/**",
    "*.pyc",
    "*.pyo",
    "*.pyd",
    ".Python",
    ".venv/**",
    "venv/**",
    "env/**",
    "ENV/**",
    ".tox/**",
    ".nox/**",
    ".pytest_cache/**",
    ".mypy_cache/**",
    ".ruff_cache/**",
    ".hypothesis/**",
    "*.egg-info/**",
    "*.egg",
    "dist/**",
    "build/**",
    "*.whl",
    ".coverage",
    "htmlcov/**",
    ".cache/**",
    # Node.js / JavaScript / TypeScript
    "node_modules/**",
    ".npm/**",
    ".yarn/**",
    ".pnp.*",
    "*.log",
    "npm-debug.log*",
    "yarn-debug.log*",
    "yarn-error.log*",
    "lerna-debug.log*",
    ".pnpm-debug.log*",
    ".next/**",
    "out/**",
    ".nuxt/**",
    ".cache/**",
    ".parcel-cache/**",
    ".svelte-kit/**",
    "dist/**",
    "build/**",
    "coverage/**",
    ".turbo/**",
    # Java / Maven / Gradle
    "target/**",
    "*.class",
    "*.jar",
    "*.war",
    "*.ear",
    ".gradle/**",
    "build/**",
    ".mvn/**",
    # .NET / C#
    "bin/**",
    "obj/**",
    "*.dll",
    "*.exe",
    "*.pdb",
    "packages/**",
    ".vs/**",
    "*.user",
    "*.suo",
    # Go
    "vendor/**",
    "*.exe",
    "*.test",
    "*.out",
    # Rust
    "target/**",
    "Cargo.lock",
    # Ruby
    ".bundle/**",
    "vendor/bundle/**",
    "*.gem",
    # PHP
    "vendor/**",
    "composer.lock",
    # Version control
    ".git/**",
    ".svn/**",
    ".hg/**",
    ".bzr/**",
    # IDEs and editors
    ".idea/**",
    ".vscode/**",
    ".vs/**",
    "*.swp",
    "*.swo",
    "*~",
    ".project",
    ".classpath",
    ".settings/**",
    "*.sublime-*",
    # OS files
    ".DS_Store",
    "Thumbs.db",
    "desktop.ini",
    # Docker
    ".docker/**",
    # Terraform
    ".terraform/**",
    "*.tfstate",
    "*.tfstate.*",
    # Large binary and media files
    "*.zip",
    "*.tar",
    "*.tar.gz",
    "*.rar",
    "*.7z",
    "*.iso",
    "*.dmg",
    "*.pkg",
    "*.jpg",
    "*.jpeg",
    "*.png",
    "*.gif",
    "*.bmp",
    "*.ico",
    "*.svg",
    "*.mp3",
    "*.mp4",
    "*.avi",
    "*.mov",
    "*.pdf",
    "*.woff",
    "*.woff2",
    "*.ttf",
    "*.eot",
    # Logs
    "*.log",
    "logs/**",
    # Temporary files
    "tmp/**",
    "temp/**",
    "*.tmp",
    "*.temp",
    "*.bak",
    "*.backup",
    # Configuration files (contain "secret" keyword but no real secrets)
    "envdrift.toml",
    "pyproject.toml",
    "mkdocs.yml",
    "mkdocs.yaml",
)


class NativeScanner(ScannerBackend):
    """Built-in scanner with zero external dependencies.

    This scanner provides basic secret detection without requiring any external
    tools to be installed. It's always available and serves as the foundation
    for the guard command.

    Features:
    - Detects unencrypted .env files
    - Matches common secret patterns (AWS keys, GitHub tokens, etc.)
    - Optional entropy-based detection for random secrets
    - Configurable ignore patterns

    Example:
        scanner = NativeScanner()
        result = scanner.scan([Path(".")])
        for finding in result.findings:
            print(f"{finding.severity}: {finding.description}")
    """

    def __init__(
        self,
        check_entropy: bool = False,
        entropy_threshold: float = 4.5,
        ignore_patterns: list[str] | None = None,
        additional_ignore_patterns: list[str] | None = None,
        allowed_clear_files: list[str] | None = None,
        skip_clear_files: bool = False,
    ) -> None:
        """Initialize the native scanner.

        Args:
            check_entropy: Enable entropy-based secret detection.
            entropy_threshold: Minimum entropy to flag as potential secret.
            ignore_patterns: Patterns to ignore (replaces defaults if provided).
            additional_ignore_patterns: Additional patterns to ignore (added to defaults).
            allowed_clear_files: Files that are intentionally unencrypted (from partial_encryption config).
            skip_clear_files: Skip .clear files from scanning entirely.
        """
        self._check_entropy = check_entropy
        self._entropy_threshold = entropy_threshold
        self._allowed_clear_files = set(allowed_clear_files or [])
        self._skip_clear_files = skip_clear_files

        if ignore_patterns is not None:
            self._ignore_patterns = tuple(ignore_patterns)
        else:
            self._ignore_patterns = DEFAULT_IGNORE_PATTERNS

        if additional_ignore_patterns:
            self._ignore_patterns = self._ignore_patterns + tuple(additional_ignore_patterns)

    @property
    def name(self) -> str:
        """Return scanner identifier."""
        return "native"

    @property
    def description(self) -> str:
        """Return scanner description."""
        return "Built-in scanner (encryption markers + secret patterns)"

    def is_installed(self) -> bool:
        """Check if scanner is available (always True for native)."""
        return True

    def scan(
        self,
        paths: list[Path],
        include_git_history: bool = False,
    ) -> ScanResult:
        """Scan paths for secrets and policy violations.

        Args:
            paths: List of files or directories to scan.
            include_git_history: Ignored for native scanner (no git support).

        Returns:
            ScanResult containing all findings.
        """
        start_time = time.time()
        findings: list[ScanFinding] = []
        files_scanned = 0

        for path in paths:
            if not path.exists():
                continue

            files_to_scan = [path] if path.is_file() else self._collect_files(path)

            for file_path in files_to_scan:
                if self._should_ignore(file_path, path):
                    continue

                files_scanned += 1
                file_findings = self._scan_file(file_path)
                findings.extend(file_findings)

        duration_ms = int((time.time() - start_time) * 1000)

        return ScanResult(
            scanner_name=self.name,
            findings=findings,
            files_scanned=files_scanned,
            duration_ms=duration_ms,
        )

    def _collect_files(self, directory: Path) -> list[Path]:
        """Collect files using hybrid approach: git ls-files + untracked .env files.

        This is much faster than rglob because:
        1. git ls-files reads from git's index (no filesystem traversal)
        2. Untracked .env files are found via git, respecting .gitignore

        Args:
            directory: Directory to scan.

        Returns:
            List of file paths.
        """
        import subprocess  # nosec B404

        files: set[Path] = set()
        directory = directory.resolve()

        # Method 1: Get tracked files from git (fast - reads index)
        try:
            result = subprocess.run(  # nosec B603, B607
                ["git", "ls-files"],
                capture_output=True,
                text=True,
                cwd=directory,
                timeout=30,
            )
            if result.returncode != 0:
                # Not a git repo or git error - use fallback
                return self._collect_files_fallback(directory)

            for rel_path in result.stdout.splitlines():
                if rel_path:
                    files.add(directory / rel_path)

        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            # git not available - fall back to os.walk
            return self._collect_files_fallback(directory)

        # Method 2: Get untracked .env* files (respects .gitignore)
        # These are files developers might forget to encrypt before committing
        try:
            result = subprocess.run(  # nosec B603, B607
                ["git", "ls-files", "--others", "--exclude-standard"],
                capture_output=True,
                text=True,
                cwd=directory,
                timeout=30,
            )
            if result.returncode == 0:
                for rel_path in result.stdout.splitlines():
                    if rel_path:
                        file_name = Path(rel_path).name
                        # Only include .env* files from untracked
                        if file_name == ".env" or file_name.startswith(".env."):
                            files.add(directory / rel_path)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        return list(files)

    def _collect_files_fallback(self, directory: Path) -> list[Path]:
        """Fallback file collection using os.walk with early directory pruning.

        Used when git is not available or directory is not a git repository.

        Args:
            directory: Directory to scan.

        Returns:
            List of file paths.
        """
        import os

        files = []
        skip_dirs = {
            "node_modules",
            ".git",
            ".venv",
            "venv",
            "__pycache__",
            ".next",
            "dist",
            "build",
            ".tox",
            ".nox",
            "coverage",
            ".gradle",
            "target",
            "vendor",
            ".idea",
            ".vscode",
            ".terraform",
            "bin",
            "obj",
            ".cache",
            ".pytest_cache",
            ".mypy_cache",
            ".ruff_cache",
            "htmlcov",
            ".svn",
            ".hg",
        }

        try:
            for root, dirs, filenames in os.walk(directory):
                # Prune directories in-place to skip them entirely
                dirs[:] = [d for d in dirs if d not in skip_dirs]

                for filename in filenames:
                    files.append(Path(root) / filename)
        except PermissionError:
            pass

        return files

    def _should_ignore(self, file_path: Path, base_path: Path) -> bool:
        """Check if a file should be ignored based on patterns.

        Args:
            file_path: Path to the file.
            base_path: Base path for relative matching.

        Returns:
            True if the file should be ignored.
        """
        # Get relative path for matching
        try:
            relative_path = file_path.relative_to(base_path)
        except ValueError:
            relative_path = file_path

        path_str = str(relative_path)
        name = file_path.name

        for pattern in self._ignore_patterns:
            # Match against full relative path
            if fnmatch.fnmatch(path_str, pattern):
                return True
            # Match against filename only
            if fnmatch.fnmatch(name, pattern):
                return True
            # Match against path parts
            if any(fnmatch.fnmatch(part, pattern) for part in relative_path.parts):
                return True

        return False

    def _scan_file(self, file_path: Path) -> list[ScanFinding]:
        """Scan a single file for secrets.

        Args:
            file_path: Path to the file to scan.

        Returns:
            List of findings from this file.
        """
        findings: list[ScanFinding] = []

        # Skip .clear files entirely if skip_clear_files is enabled
        is_clear_file = self._is_clear_file(file_path)
        if is_clear_file and self._skip_clear_files:
            return findings

        # Try to read file content
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, UnicodeDecodeError):
            return findings

        # Skip empty files
        if not content.strip():
            return findings

        # Skip binary files (heuristic: check for null bytes)
        if "\x00" in content[:8192]:
            return findings

        # Check 1: Is this an unencrypted .env file?
        is_env_file = self._is_env_file(file_path)
        is_encrypted = self._is_encrypted(content)
        # Note: is_clear_file already calculated at line 476 for early return

        # Check if file is an allowed clear file (from partial_encryption config)
        is_allowed_clear = self._is_allowed_clear_file(file_path)

        # .clear files are semantically meant to be unencrypted, so don't flag them
        if is_env_file and not is_encrypted and not is_allowed_clear and not is_clear_file:
            findings.append(
                ScanFinding(
                    file_path=file_path,
                    rule_id="unencrypted-env-file",
                    rule_description="Unencrypted Environment File",
                    description=(
                        f"Environment file '{file_path.name}' is not encrypted. "
                        f"Run 'envdrift encrypt {file_path}' before committing."
                    ),
                    severity=FindingSeverity.HIGH,
                    scanner=self.name,
                )
            )

        # Check 2: Scan for secret patterns
        # Skip pattern scanning for encrypted files to avoid false positives
        if not is_encrypted:
            findings.extend(self._scan_patterns(file_path, content))

        # Check 3: High-entropy strings
        # Run for env files or if check_entropy is enabled globally
        if is_env_file or self._check_entropy:
            findings.extend(self._scan_entropy(file_path, content))

        return findings

    def _is_env_file(self, path: Path) -> bool:
        """Check if a file is an environment file.

        Args:
            path: Path to check.

        Returns:
            True if this is a .env file.
        """
        name = path.name
        return name == ".env" or name.startswith(".env.")

    def _is_clear_file(self, path: Path) -> bool:
        """Check if a file is a .clear file (partial encryption non-sensitive file).

        .clear files typically contain non-sensitive configuration values that may be
        intentionally left unencrypted. They are exempt from the "unencrypted-env-file"
        check but are still subject to entropy and pattern scanning unless clear files
        are explicitly skipped elsewhere (for example via a skip_clear_files setting).

        Args:
            path: Path to check.

        Returns:
            True if this is a .clear file.
        """
        name = path.name
        return name.endswith(".clear")

    def _is_allowed_clear_file(self, path: Path) -> bool:
        """Check if a file is an allowed clear file from partial_encryption config.

        These files are intentionally unencrypted (contain non-sensitive variables).

        Args:
            path: Path to check.

        Returns:
            True if this file is configured as a clear_file in partial_encryption.
        """
        if not self._allowed_clear_files:
            return False

        # Check against filename and path with strict matching
        name = path.name
        path_str = str(path)

        for allowed in self._allowed_clear_files:
            allowed_path = Path(allowed)
            # If allowed is just a filename, match by filename only
            if allowed_path.name == allowed and name == allowed:
                return True
            # Match by path suffix (e.g., "config/.env.clear" matches "/path/to/config/.env.clear")
            if path_str.endswith(f"/{allowed}") or path_str == allowed:
                return True
        return False

    def _is_encrypted(self, content: str) -> bool:
        """Check if file content has encryption markers.

        Args:
            content: File content to check.

        Returns:
            True if encryption markers are present.
        """
        # Check dotenvx markers
        for marker in DOTENVX_MARKERS:
            if marker in content:
                return True

        # Check SOPS markers
        for marker in SOPS_MARKERS:
            if marker in content:
                return True

        return False

    def _scan_patterns(self, file_path: Path, content: str) -> list[ScanFinding]:
        """Scan content for secret patterns.

        Args:
            file_path: Path to the file being scanned.
            content: File content to scan.

        Returns:
            List of pattern-matched findings.
        """
        findings: list[ScanFinding] = []
        lines = content.splitlines()

        for line_num, line in enumerate(lines, start=1):
            # Skip empty lines and comments
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Skip lines with encrypted values (dotenvx or SOPS)
            # This handles partially encrypted files or mixed content
            if "encrypted:" in line or "ENC[" in line:
                continue

            for pattern in ALL_PATTERNS:
                match = pattern.pattern.search(line)
                if match:
                    # Extract the secret (first group or full match)
                    secret = match.group(1) if match.groups() else match.group(0)

                    # For generic-secret pattern, apply entropy filter to reduce false positives
                    # Real secrets have high entropy (randomness), code variables don't
                    if pattern.id == "generic-secret":
                        entropy = calculate_entropy(secret)
                        # Entropy threshold 4.0 filters out most variable names/code patterns
                        # Real API keys, tokens, passwords typically have entropy > 4.0
                        if entropy < 4.0:
                            continue
                        # Skip variable references - these point to secrets, not the secrets themselves
                        # Universal patterns: ${VAR}, $(cmd), $VAR, %VAR%, {{var}}, {var}, \${var}
                        if secret.startswith(("${", "$(", "$", "%", "{{", "{", "\\${")):
                            continue
                        # Skip code patterns - method/property access (real secrets don't have dots)
                        # e.g., "config.Password", "handler.ReadToken()", "obj?.Property"
                        if "." in secret or "?" in secret:
                            continue

                    # Calculate column number
                    col_num = match.start() + 1

                    findings.append(
                        ScanFinding(
                            file_path=file_path,
                            line_number=line_num,
                            column_number=col_num,
                            rule_id=pattern.id,
                            rule_description=pattern.description,
                            description=f"Potential {pattern.description} detected",
                            severity=pattern.severity,
                            secret_preview=redact_secret(secret),
                            secret_hash=hash_secret(secret),
                            scanner=self.name,
                        )
                    )

        return findings

    def _scan_entropy(self, file_path: Path, content: str) -> list[ScanFinding]:
        """Scan content for high-entropy strings.

        Args:
            file_path: Path to the file being scanned.
            content: File content to scan.

        Returns:
            List of entropy-based findings.
        """
        import re

        findings: list[ScanFinding] = []
        lines = content.splitlines()

        # Pattern for assignment-like statements
        assignment_pattern = re.compile(r"[A-Z_][A-Z0-9_]*\s*[=:]\s*[\"']?([^\"'\s=]{16,})[\"']?")

        for line_num, line in enumerate(lines, start=1):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            for match in assignment_pattern.finditer(line):
                value = match.group(1)

                # Skip if it looks like a URL or path
                if value.startswith(("http://", "https://", "/", "./")):
                    continue

                # Skip if it's all lowercase or all uppercase letters only
                if value.isalpha() and (value.islower() or value.isupper()):
                    continue

                # Skip template/format strings (high entropy but not secrets)
                # e.g., "{Timestamp:G}|{Message}|{AT_DataSource}|..."
                if self._is_template_string(value):
                    continue

                entropy = calculate_entropy(value)

                if entropy >= self._entropy_threshold:
                    findings.append(
                        ScanFinding(
                            file_path=file_path,
                            line_number=line_num,
                            rule_id="high-entropy-string",
                            rule_description="High Entropy String",
                            description=(
                                f"High-entropy string detected (entropy: {entropy:.2f}). "
                                f"This may be a secret."
                            ),
                            severity=FindingSeverity.MEDIUM,
                            secret_preview=redact_secret(value),
                            secret_hash=hash_secret(value),
                            entropy=entropy,
                            scanner=self.name,
                        )
                    )

        return findings

    def _is_template_string(self, value: str) -> bool:
        """Check if a value looks like a template/format string.

        Template strings have high entropy due to varied characters but aren't secrets.
        Examples:
        - "{Timestamp:G}|{Message}|{AT_DataSource}"
        - "{{user.name}} - {{user.email}}"
        - "%Y-%m-%d %H:%M:%S"

        Args:
            value: The string value to check.

        Returns:
            True if this looks like a template string.
        """
        # Count template-like patterns
        template_indicators = 0

        # Check for common template delimiters
        if "{" in value and "}" in value:
            # Count pairs of braces - templates have multiple
            open_braces = value.count("{")
            close_braces = value.count("}")
            if open_braces >= 2 and close_braces >= 2:
                template_indicators += 2

        # Check for format specifiers like :G, :d, :s, :1
        if ":" in value and any(c in value for c in "GgDdSsFfXxNn"):
            template_indicators += 1

        # Check for pipe-separated format strings (common in logging)
        if value.count("|") >= 3:
            template_indicators += 1

        # Check for common template variable names
        template_keywords = [
            "Timestamp",
            "Message",
            "Exception",
            "NewLine",
            "Level",
            "Logger",
            "Thread",
            "Source",
            "Event",
            "Date",
            "Time",
        ]
        if any(kw in value for kw in template_keywords):
            template_indicators += 1

        return template_indicators >= 2
