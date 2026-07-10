"""Native scanner - zero external dependencies.

This scanner provides built-in secret detection capabilities without requiring
any external tools. It checks for:

1. Unencrypted .env files (missing dotenvx/SOPS encryption markers)
2. Common secret patterns (API keys, tokens, passwords)
3. High-entropy strings (optional, for detecting random secrets)
"""

from __future__ import annotations

import codecs
import fnmatch
import math
import re
import time
from pathlib import Path, PurePosixPath

from envdrift.core.encryption import is_dotenvx_public_key_var

# Structure-aware line/content classification helpers live in a sibling module to
# keep this file within the single-file LOC budget. They are re-exported from here
# because ``engine.py`` and the scanner tests import them from
# ``envdrift.scanner.native``.
from envdrift.scanner._native_filters import (
    _EC_PUBKEY_RE,
    _content_has_sops_markers,
    _content_is_encrypted,
    _is_encrypted_value_line,
    _looks_like_code_member_access,
)
from envdrift.scanner.base import (
    FindingSeverity,
    ScanFinding,
    ScannerBackend,
    ScanResult,
)
from envdrift.scanner.patterns import (
    ALL_PATTERNS,
    SecretPattern,
    calculate_entropy,
    hash_secret,
    redact_secret,
)
from envdrift.utils.git import is_file_tracked

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
#
# NOTE (#477): only example/template env files are excluded here. Real-secret
# env names (.env.local, .env.test) and config/lock files (pyproject.toml,
# *.lock, ...) are deliberately NOT in this list: they routinely carry live
# credentials, so they must be scanned. The engine suppresses only the *noisy*
# keyword/entropy rules in config/lock files (see
# ScanEngine.DEFAULT_GLOBAL_IGNORE_PATHS), never distinctive-prefix detections.
DEFAULT_IGNORE_PATTERNS = (
    # Env file examples/templates (placeholder values by convention)
    ".env.example",
    ".env.sample",
    ".env.template",
    # Documentation and text files
    "*.md",
    "*.txt",
    "*.rst",
    "*.adoc",
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
    # Compiled Go test binaries are named "<pkg>.test" — never dotfiles. The
    # leading [!.] keeps this from swallowing the real-secret ".env.test" (#477).
    "[!.]*.test",
    "*.out",
    # Rust
    "target/**",
    # Ruby
    ".bundle/**",
    "vendor/bundle/**",
    "*.gem",
    # PHP
    "vendor/**",
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
)


# dotenvx's private-key file. Always plaintext by design and meant to be
# gitignored; it must not be treated as an "unencrypted env file" to encrypt.
DOTENVX_KEYS_FILENAME = ".env.keys"

# git pathspecs that match env-file naming shapes at any depth: the leading-dot
# convention (.env, .env.*) and the trailing-suffix convention (<name>.env,
# #477). Passed to `git ls-files` so git itself filters to env files instead of
# enumerating every untracked or ignored path (e.g. a large node_modules) and
# letting Python discard them. A superset of _is_env_file (it also matches e.g.
# ".envrc"), which still does the precise filtering, so correctness is unchanged.
_ENV_FILE_PATHSPECS = (":(glob)**/.env*", ":(glob)**/*.env")


def _is_env_file(rel_path: str) -> bool:
    """Return True if a path's filename matches an env-file naming shape.

    Recognizes the leading-dot convention (``.env``, ``.env.production``) and
    the trailing-suffix convention (``production.env``, ``database.env``) used
    by ``docker --env-file``, direnv and many CI systems (#477).
    """
    file_name = Path(rel_path).name
    # `.env` itself is covered by endswith(".env"); the dotted form (.env.local)
    # by startswith(".env."); trailing-suffix (production.env) by endswith.
    return file_name.startswith(".env.") or file_name.endswith(".env")


# Bytes that legitimately appear in text files: printable/high bytes plus the
# usual whitespace controls (BS HT LF VT FF CR). Anything else (NUL, other
# control bytes) counts as "non-text" when deciding if a file is binary.
_TEXT_BYTES = frozenset(range(0x20, 0x100)) | frozenset({0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D})


def _looks_binary(raw: bytes, *, sample: int = 8192, threshold: float = 0.05) -> bool:
    """Heuristic: is ``raw`` a genuinely-binary blob (vs. text with a stray NUL)?

    git treats a file as binary if it finds a NUL in the first 8 KiB. We instead
    require a *ratio* of non-text bytes, so a lone (or maliciously injected) NUL
    byte in an otherwise-text ``.env`` file does not cause the scanner to discard
    every finding and let a real plaintext secret slip through (#22). Genuine
    binaries — overwhelmingly non-text — are still skipped to avoid noise.

    The threshold is deliberately low (5 %): a legitimate ``.env``/text file has
    virtually no non-text bytes, so a small ratio still absorbs a handful of
    stray NULs while shrinking the window for an attacker who pads a file with
    control bytes specifically to re-trigger the binary skip and hide a secret.
    """
    chunk = raw[:sample]
    if not chunk:
        return False
    nontext = sum(1 for b in chunk if b not in _TEXT_BYTES)
    return nontext / len(chunk) > threshold


# Unicode BOMs mapped to the codec that decodes them, longest BOMs first so the
# UTF-32-LE BOM (\xff\xfe\x00\x00) is not misread as UTF-16-LE (\xff\xfe).
_BOM_CODECS: tuple[tuple[bytes, str], ...] = (
    (codecs.BOM_UTF32_LE, "utf-32"),
    (codecs.BOM_UTF32_BE, "utf-32"),
    (codecs.BOM_UTF16_LE, "utf-16"),
    (codecs.BOM_UTF16_BE, "utf-16"),
    (codecs.BOM_UTF8, "utf-8-sig"),
)


def _sniff_utf16_stride(raw: bytes, *, sample: int = 8192) -> str | None:
    """Detect BOM-less UTF-16 text by its alternating-NUL byte stride.

    ASCII-dominated UTF-16 stores each character as one text byte plus one NUL
    high byte: at odd offsets for little-endian, even offsets for big-endian.
    Require the NUL plane to be almost entirely NULs and the character plane to
    be almost entirely non-NUL, so genuine binaries (NULs spread across both
    planes) and ordinary text (no NULs) never match.
    """
    chunk = raw[:sample]
    if len(chunk) < 8:
        return None
    if len(chunk) % 2:
        chunk = chunk[:-1]
    half = len(chunk) // 2
    even_nuls = chunk[0::2].count(0)
    odd_nuls = chunk[1::2].count(0)
    if odd_nuls / half > 0.7 and even_nuls / half < 0.05:
        return "utf-16-le"
    if even_nuls / half > 0.7 and odd_nuls / half < 0.05:
        return "utf-16-be"
    return None


def _decode_unicode_text(raw: bytes) -> str | None:
    """Decode bytes that are demonstrably Unicode text (BOM or UTF-16 stride).

    UTF-16 is the default "Unicode" output of Windows Notepad and PowerShell's
    ``Out-File``; its ~50% NUL bytes would otherwise trip the binary-ratio
    heuristic and the scanner would silently skip a human-readable env file full
    of plaintext secrets (#477). Returns the decoded text, or ``None`` when the
    bytes carry no BOM / recognizable UTF-16 stride — the caller then falls back
    to the binary check + lenient UTF-8 decode used for ordinary files.
    """
    # A clear BOM or a clean UTF-16 NUL stride POSITIVELY identifies the bytes as
    # text, so decode with errors="replace": a single bad/truncated code unit
    # (a half-written Notepad file, a lone surrogate, or the trailing odd byte
    # the stride sniff deliberately tolerates) must not send us back to
    # _looks_binary — which is True for any ~50%-NUL UTF-16 content — and
    # silently skip a file full of plaintext secrets, the exact pre-#477 gap
    # this decode path exists to close (#505 review).
    for bom, encoding in _BOM_CODECS:
        if raw.startswith(bom):
            return raw.decode(encoding, errors="replace")
    stride_encoding = _sniff_utf16_stride(raw)
    if stride_encoding is not None:
        return raw.decode(stride_encoding, errors="replace")
    return None


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
        check_entropy: bool | None = None,
        entropy_threshold: float = 4.5,
        ignore_patterns: list[str] | None = None,
        additional_ignore_patterns: list[str] | None = None,
        allowed_clear_files: list[str] | None = None,
        skip_clear_files: bool = False,
        mapped_env_files: list[str] | None = None,
    ) -> None:
        """Initialize the native scanner.

        Args:
            check_entropy: Tri-state entropy knob (#478) — ``None`` (unset)
                runs entropy detection on env files only (the default),
                ``True`` extends it to all scanned files, ``False`` disables
                it entirely (env files included).
            entropy_threshold: Minimum entropy to flag as potential secret.
                Coerced to ``float`` here so a wrong-typed value fails at
                construction with a clear error instead of mid-scan (#478).
            ignore_patterns: Patterns to ignore (replaces defaults if provided).
            additional_ignore_patterns: Additional patterns to ignore (added to defaults).
            allowed_clear_files: Files that are intentionally unencrypted (from partial_encryption config).
            skip_clear_files: Skip .clear files from scanning entirely.
            mapped_env_files: Custom env files from vault.sync mappings that must be treated as env files.
        """
        self._check_entropy = check_entropy
        try:
            self._entropy_threshold = float(entropy_threshold)
        except (TypeError, ValueError):
            raise ValueError(
                f"entropy_threshold must be a number, got {entropy_threshold!r}"
            ) from None
        if not math.isfinite(self._entropy_threshold):
            # nan/inf pass float() but break every ``entropy >= threshold``
            # comparison, silently disabling entropy detection (#478 review).
            raise ValueError(f"entropy_threshold must be finite, got {entropy_threshold!r}")
        self._allowed_clear_files = set(allowed_clear_files or [])
        self._skip_clear_files = skip_clear_files
        # Canonicalize mapped env files to absolute paths so they match regardless
        # of which directory is being scanned (relative paths would otherwise be
        # re-rooted per scan dir, letting a mapped file slip past the guard).
        cwd = Path.cwd()
        self._mapped_env_files = {
            (Path(p) if Path(p).is_absolute() else cwd / Path(p)).resolve()
            for p in mapped_env_files or []
        }

        if ignore_patterns is not None:
            self._ignore_patterns = tuple(ignore_patterns)
        else:
            self._ignore_patterns = DEFAULT_IGNORE_PATTERNS

        if additional_ignore_patterns:
            self._ignore_patterns = self._ignore_patterns + tuple(additional_ignore_patterns)

    # The native scanner reads file content only and ignores
    # ``include_git_history``; guard refuses ``--history`` when no active
    # scanner declares history support instead of passing silently (#476).
    supports_git_history = False

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

        # ``-z`` keeps filenames byte-for-byte rather than applying Git's
        # C-style quotepath escaping to non-ASCII or newline-containing paths.
        # Every git invocation below therefore uses NUL-separated output.

        # Method 1: Get tracked files from git (fast - reads index)
        try:
            result = subprocess.run(  # nosec B603, B607
                ["git", "ls-files", "-z"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=directory,
                timeout=30,
            )
            if result.returncode != 0:
                # Not a git repo or git error - use fallback
                return self._collect_files_fallback(directory)

            for rel_path in result.stdout.split("\0"):
                if rel_path:
                    files.add(directory / rel_path)

        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            # git not available - fall back to os.walk
            return self._collect_files_fallback(directory)

        # Method 2: Get untracked .env* files (respects .gitignore)
        # These are files developers might forget to encrypt before committing
        try:
            result = subprocess.run(  # nosec B603, B607
                [
                    "git",
                    "ls-files",
                    "--others",
                    "--exclude-standard",
                    "-z",
                    "--",
                    *_ENV_FILE_PATHSPECS,
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=directory,
                timeout=30,
            )
            if result.returncode == 0:
                for rel_path in result.stdout.split("\0"):
                    if rel_path and _is_env_file(rel_path):
                        files.add(directory / rel_path)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        # Method 3: Get untracked .env* files that ARE gitignored.
        # Partial-encryption secret/combined files are typically gitignored, and a
        # `pull-partial` leaves them as PLAINTEXT on disk. Methods 1-2 miss an
        # untracked + gitignored secret file, so it would slip through the scan and
        # leak. Secret files must always be scanned regardless of git status.
        #
        # Exception: a gitignored .env.keys is the CORRECT state — it is dotenvx's
        # private key file, always plaintext, and meant to stay local-only. Scanning
        # it here would wrongly flag a properly-configured project as having an
        # "unencrypted env file". A *tracked* .env.keys is still caught by Method 1.
        try:
            result = subprocess.run(  # nosec B603, B607
                [
                    "git",
                    "ls-files",
                    "--others",
                    "--ignored",
                    "--exclude-standard",
                    "-z",
                    "--",
                    *_ENV_FILE_PATHSPECS,
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=directory,
                timeout=30,
            )
            if result.returncode == 0:
                for rel_path in result.stdout.split("\0"):
                    if (
                        rel_path
                        and _is_env_file(rel_path)
                        and Path(rel_path).name != DOTENVX_KEYS_FILENAME
                    ):
                        files.add(directory / rel_path)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        # Method 4: Add explicitly configured custom env files from vault.sync.
        # These may not match ".env*" and can otherwise be missed when untracked.
        # Paths are already absolute; only include those under the scan directory.
        directory_resolved = directory.resolve()
        for candidate in self._mapped_env_files:
            try:
                candidate.relative_to(directory_resolved)
            except ValueError:
                continue
            if candidate.exists() and candidate.is_file():
                files.add(candidate)

        # Return deterministically ordered list for stable scan results
        return sorted(files, key=lambda p: str(p))

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
                # Stable traversal order
                dirs.sort()
                filenames.sort()

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
        # Get relative path for matching. Resolve BOTH sides first (#477):
        # _collect_files resolves the scan directory, so collected file paths
        # are absolute physical paths. An unresolved base (a relative ``guard .``
        # argument, or a symlinked path such as macOS /tmp) made ``relative_to``
        # raise, the fallback matched against the absolute path, and every
        # directory-scoped pattern (bin/**, dist/**, vendor/**, ...) silently
        # stopped applying — ``guard`` and ``guard .`` returned different results.
        try:
            relative_path = file_path.resolve().relative_to(base_path.resolve())
        except (ValueError, OSError):
            relative_path = file_path

        path_str = str(relative_path)
        name = file_path.name

        return any(
            self._pattern_matches(pattern, path_str, name, relative_path.parts)
            for pattern in self._ignore_patterns
        )

    @staticmethod
    def _pattern_matches(pattern: str, path_str: str, name: str, parts: tuple[str, ...]) -> bool:
        """Whether one ignore pattern matches a file, path-aware.

        A path-shaped pattern (one containing ``/`` such as ``bin/**``) is matched
        against the full relative path. A basename-shaped pattern (``*.pyc``,
        ``[!.]*.test``) is matched ONLY against the file name or a single path
        part — never the whole path. ``fnmatch``'s ``*`` crosses ``/``, so a
        whole-path match would let ``[!.]*.test`` swallow a nested ``.env.test``:
        the ``[!.]`` anchor only constrains the first character of the entire
        string (the top directory's letter), not the filename's leading dot, so a
        tracked ``apps/web/.env.test`` full of live secrets was silently ignored
        (#505 review).
        """
        if "/" in pattern:
            return fnmatch.fnmatch(path_str, pattern)
        if fnmatch.fnmatch(name, pattern):
            return True
        return any(fnmatch.fnmatch(part, pattern) for part in parts)

    @staticmethod
    def _read_scannable_content(file_path: Path) -> str | None:
        """Read ``file_path`` and return its text content, or ``None`` to skip it.

        Reads raw bytes (so the binary check sees the true content: ``read_text``
        with ``errors="ignore"`` would silently drop the very non-text bytes that
        identify a binary file), decodes demonstrably-Unicode text first, and
        neutralizes stray NULs. Returns ``None`` for an unreadable file, a genuine
        binary blob, or an empty/whitespace-only file.
        """
        try:
            raw = file_path.read_bytes()
        except OSError:
            return None

        # Decode demonstrably-Unicode text before the binary heuristic can see it
        # (#477): a UTF-16 env file is ~50% NUL bytes, which the ratio check would
        # misclassify as a compiled blob and skip wholesale — silently passing a
        # human-readable file full of plaintext secrets. A BOM or a clean 2-byte
        # NUL stride identifies the bytes as text, so decode through the right
        # codec first.
        content = _decode_unicode_text(raw)
        if content is None:
            # Skip genuinely-binary files (compiled blobs etc.) to avoid noise —
            # but a single stray NUL must NOT hide secrets in an otherwise-text
            # file. The old "any NUL in the first 8 KiB -> discard ALL findings"
            # rule let an attacker evade guard by injecting one NUL byte, leaving
            # a real plaintext key undetected with a clean [OK] (#22).
            if _looks_binary(raw):
                return None
            content = raw.decode("utf-8", errors="ignore")

        # Neutralize any stray NULs so they can't break pattern matching downstream.
        content = content.replace("\x00", "")
        if not content.strip():
            return None
        return content

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

        content = self._read_scannable_content(file_path)
        if content is None:
            return findings

        # Private-key file (.env.keys) handling.
        # A dotenvx private key must never be committed; "encrypt it" (the
        # unencrypted-env-file remediation) is nonsensical advice for a key file.
        # A purely local, untracked key file is the expected state (a gitignored one
        # is already dropped during collection), so only flag it once git tracks or
        # stages it (is_file_tracked reads the index, which covers both). Either way
        # it bypasses the env-file/pattern checks below.
        if self._is_private_key_file(file_path):
            if is_file_tracked(file_path):
                findings.append(
                    ScanFinding(
                        file_path=file_path,
                        rule_id="committed-private-key",
                        rule_description="Committed Private Key",
                        description=(
                            f"Private key file '{file_path.name}' is tracked or staged "
                            "in git. Anyone with repository access can decrypt every "
                            "secret it protects. Do NOT encrypt it — remove it from git "
                            f"('git rm --cached {file_path.name}'), rotate the exposed "
                            "key(s), and add '.env.keys' to .gitignore."
                        ),
                        severity=FindingSeverity.CRITICAL,
                        scanner=self.name,
                    )
                )
            return findings

        # Check 1: Is this an unencrypted .env file?
        is_env_file = self._is_env_file(file_path)
        is_encrypted = self._is_encrypted(content)
        # Note: is_clear_file already calculated at line 476 for early return

        # Check if file is an allowed clear file (from partial_encryption config)
        is_allowed_clear = self._is_allowed_clear_file(file_path)

        # .clear files are semantically meant to be unencrypted, so don't flag them
        if is_env_file and not is_encrypted and not is_allowed_clear and not is_clear_file:
            # A partial-encryption ".secret" file is sensitive by definition — a
            # plaintext one is a leak, not a generic "unencrypted env file". Flag it
            # with a dedicated CRITICAL rule whose remediation points at
            # `envdrift push` (the partial flow that encrypts it), not `envdrift encrypt`.
            if self._is_secret_file(file_path):
                rule_id = "unencrypted-secret-file"
                rule_description = "Unencrypted Secret File"
                description = (
                    f"Partial-encryption secret file '{file_path.name}' is plaintext. "
                    "Committing it leaks every secret it holds. Run 'envdrift push' to "
                    "encrypt it before committing."
                )
                severity = FindingSeverity.CRITICAL
            else:
                rule_id = "unencrypted-env-file"
                rule_description = "Unencrypted Environment File"
                description = (
                    f"Environment file '{file_path.name}' is not encrypted. "
                    f"Run 'envdrift encrypt {file_path}' before committing."
                )
                severity = FindingSeverity.HIGH
            findings.append(
                ScanFinding(
                    file_path=file_path,
                    rule_id=rule_id,
                    rule_description=rule_description,
                    description=description,
                    severity=severity,
                    scanner=self.name,
                )
            )

        # Check 2: Scan for secret patterns.
        # Run per-line so combined partial-encryption files (dotenvx-encrypted secret
        # lines interleaved with cleartext config) still get their cleartext portion
        # scanned — a whole-file skip on any "encrypted:" marker would hide it; the
        # per-line skip in _scan_patterns ignores the encrypted values.
        # SOPS files are the exception: they are wholly encrypted with no cleartext
        # partial model, and their metadata lines (sops_*, macs, fingerprints) yield
        # only false positives, so keep skipping them entirely.
        if not self._has_sops_markers(content):
            findings.extend(self._scan_patterns(file_path, content))

        # Check 3: High-entropy strings (tri-state knob, #478):
        # - True: entropy detection on every scanned file
        # - None (unset): entropy detection on env files only (the default)
        # - False: entropy detection disabled everywhere, env files included
        if self._check_entropy is True or (self._check_entropy is None and is_env_file):
            findings.extend(self._scan_entropy(file_path, content))

        return findings

    def _is_env_file(self, path: Path) -> bool:
        """Check if a file is an environment file.

        Matches the same naming shapes as the module-level :func:`_is_env_file`
        (leading-dot ``.env``/``.env.*`` and trailing ``<name>.env``, #477) plus
        explicitly mapped custom env files from vault.sync config.

        Args:
            path: Path to check.

        Returns:
            True if this is an env file.
        """
        return _is_env_file(path.name) or self._is_mapped_env_file(path)

    def _is_mapped_env_file(self, path: Path) -> bool:
        if not self._mapped_env_files:
            return False

        # _mapped_env_files are canonical absolute paths; compare on the same form.
        candidate = path if path.is_absolute() else Path.cwd() / path
        try:
            resolved = candidate.resolve()
        except OSError:
            return False
        return resolved in self._mapped_env_files

    def _is_private_key_file(self, path: Path) -> bool:
        """Check if a file is dotenvx's private-key file (``.env.keys``).

        Args:
            path: Path to check.

        Returns:
            True if this is a ``.env.keys`` private-key file.
        """
        return path.name == DOTENVX_KEYS_FILENAME

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

    def _is_secret_file(self, path: Path) -> bool:
        """Check if a file is a partial-encryption ``.secret`` file.

        These hold the sensitive half of a partial-encryption environment and are
        meant to be dotenvx-encrypted before commit. A plaintext one is a leak, so
        it gets the dedicated CRITICAL ``unencrypted-secret-file`` rule rather than
        the generic ``unencrypted-env-file``.

        Args:
            path: Path to check.

        Returns:
            True if this is a ``.secret`` file.
        """
        return path.name.endswith(".secret")

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

        # Check against filename and path with strict matching. Normalize to
        # POSIX separators on both sides so a path-qualified clear_file (e.g.
        # "config/.env.public") matches on Windows, where ``str(Path)`` yields
        # backslashes (``config\.env.public``) that the literal "/" check misses.
        name = path.name
        path_str = path.as_posix()

        for allowed in self._allowed_clear_files:
            allowed_posix = Path(allowed).as_posix()
            allowed_name = PurePosixPath(allowed_posix).name
            # If allowed is just a filename, match by filename only
            if allowed_name == allowed_posix and name == allowed_posix:
                return True
            # Match by path suffix (e.g., "config/.env.clear" matches "/path/to/config/.env.clear")
            if path_str.endswith(f"/{allowed_posix}") or path_str == allowed_posix:
                return True
        return False

    def _is_encrypted(self, content: str) -> bool:
        """Check if file content has encryption markers.

        Args:
            content: File content to check.

        Returns:
            True if encryption markers are present.
        """
        # Structure-aware (#348): the dotenvx ``encrypted:`` marker must appear in
        # value position on an assignment line (not in a comment or arbitrary text),
        # and SOPS needs its canonical envelope/top-level metadata key — a bare
        # substring match falsely suppressed the unencrypted-env-file policy.
        return _content_is_encrypted(content)

    def _has_sops_markers(self, content: str) -> bool:
        """Return True if content has SOPS encryption markers.

        SOPS files are wholly encrypted with no cleartext/partial model, so pattern
        scanning their metadata (sops_*, macs, fingerprints) only yields false
        positives. Used to skip pattern scanning for them while still scanning
        dotenvx combined files line-by-line.
        """
        return _content_has_sops_markers(content)

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

        # File-scope keyword gate (#355): a keyword-gated pattern only fires when
        # one of its context keywords appears anywhere in the file. Computed once
        # for the whole file (not per line). A pattern flagged require_keyword but
        # configured with no keywords is treated as always-gated (fail-safe: it
        # never fires without context) rather than silently disabling the gate.
        content_lower = content.lower()
        gated_out_patterns = {
            pattern.id
            for pattern in ALL_PATTERNS
            if pattern.require_keyword
            and not any(kw.lower() in content_lower for kw in pattern.keywords)
        }

        def _build_finding(
            pattern: SecretPattern, secret: str, line_num: int, col_num: int
        ) -> ScanFinding:
            return ScanFinding(
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

        for line_num, line in enumerate(lines, start=1):
            # Skip empty lines and comments
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Skip already-encrypted values (dotenvx or SOPS) — handles combined /
            # mixed-content files.
            if _is_encrypted_value_line(line):
                continue

            # Skip dotenvx's public-key artifact. The public key is public by
            # definition (not a secret) but looks like a high-entropy assignment;
            # this mirrors how the partial-encryption combine step excludes it from
            # secret-var counts (see partial_encryption._is_secret_var_line).
            if is_dotenvx_public_key_var(stripped.split("=", 1)[0].strip()):
                continue

            for pattern in ALL_PATTERNS:
                # Multiline patterns (e.g. gcp-service-account JSON) are scanned
                # against the whole file in a separate pass below (#354).
                if pattern.multiline:
                    continue

                # File-scope keyword gate (#355): suppress broad-regex matches
                # unless the file mentions the provider context somewhere (gate
                # set precomputed once above). Distinctive-prefix patterns (AKIA…,
                # sq0atp-…) aren't require_keyword, so a genuine key with no
                # sibling provider context is still reported.
                if pattern.id in gated_out_patterns:
                    continue

                # finditer (not search): a single line may hold multiple
                # independent secrets for the same pattern (e.g. two AWS access
                # keys, or two api_key= assignments). search() would report only
                # the first and silently drop the rest (#348). This mirrors the
                # multiline finditer pass below. The aws pattern's trailing
                # boundary is a zero-width lookahead (see patterns.py), so a
                # single delimiter between two adjacent keys is left available as
                # the leading boundary of the next match — both keys are found.
                for match in pattern.pattern.finditer(line):
                    # Extract the secret (first group or full match)
                    secret = match.group(1) if match.groups() else match.group(0)

                    # Drop dotenvx EC public keys by value shape (#370): public,
                    # not a secret. This IS reachable: the generic-api-key pattern
                    # (api[_-]?key … ([a-zA-Z0-9_-]{20,})) excludes the quote char
                    # from its capture group, so `API_KEY="<66-hex pubkey>"`
                    # captures the *bare* pubkey as `secret`, and that pattern has
                    # no entropy filter (only generic-secret does). Without this
                    # drop the bare pubkey is reported as a generic-api-key FP under
                    # an unexpected (non-DOTENV_PUBLIC_KEY) var name; the var-name
                    # skip above and the hash-based ScanEngine._filter_public_keys
                    # don't cover that case. Covered by
                    # TestKeywordGate.test_ec_pubkey_dropped_by_value_shape_under_api_key_var.
                    if _EC_PUBKEY_RE.match(secret):
                        continue

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
                        # Skip values that look like code member access — a chain
                        # of word-like identifiers joined by '.'/'?.'/'->' (with
                        # optional call parens), e.g. "config.Password",
                        # "handler.ReadToken()", "obj?.Property". Do NOT skip every
                        # value that merely contains a '.' or '?': a high-entropy
                        # dotted password such as "Xk9.mQ2vLp8wRt4nZs6yBdFh" is a
                        # real secret and must be reported (it already cleared the
                        # entropy gate above) (#413).
                        if _looks_like_code_member_access(secret):
                            continue

                    # Calculate column number
                    col_num = match.start() + 1

                    findings.append(_build_finding(pattern, secret, line_num, col_num))

        # Full-content pass for multiline patterns (#354). These match across
        # newlines (re.DOTALL is baked into the compiled regex), so they cannot be
        # found in the per-line loop above. The keyword gate is intentionally not
        # applied here: the multiline patterns carry their own strong anchors
        # (e.g. "type":"service_account").
        for pattern in ALL_PATTERNS:
            if not pattern.multiline:
                continue
            # finditer (not search): a file may hold multiple service-account
            # JSON blocks; search() would report only the first.
            for match in pattern.pattern.finditer(content):
                secret = match.group(1) if match.groups() else match.group(0)
                line_num = content.count("\n", 0, match.start()) + 1
                col_num = match.start() - content.rfind("\n", 0, match.start())
                findings.append(_build_finding(pattern, secret, line_num, col_num))

        return findings

    def _scan_entropy(self, file_path: Path, content: str) -> list[ScanFinding]:
        """Scan content for high-entropy strings.

        Args:
            file_path: Path to the file being scanned.
            content: File content to scan.

        Returns:
            List of entropy-based findings.
        """
        findings: list[ScanFinding] = []
        lines = content.splitlines()

        # Pattern for assignment-like statements. The LHS allows lower/upper/mixed
        # case (#369) so lowercase or camelCase var names — api_key=, apiKey:,
        # secretToken = — are not missed. Downstream filters (URL/path skip,
        # alpha-only skip, template-string skip, entropy threshold) contain the
        # added surface to genuine high-entropy assignments.
        assignment_pattern = re.compile(
            r"[A-Za-z_][A-Za-z0-9_]*\s*[=:]\s*[\"']?([^\"'\s=]{16,})[\"']?"
        )

        for line_num, line in enumerate(lines, start=1):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            # Skip already-encrypted values and the public-key artifact. Encrypted
            # blobs are high-entropy by nature but not leaked secrets, so flagging
            # them would flood combined partial-encryption files with noise.
            if _is_encrypted_value_line(line):
                continue
            if is_dotenvx_public_key_var(stripped.split("=", 1)[0].strip()):
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
