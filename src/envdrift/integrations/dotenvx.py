"""dotenvx CLI wrapper with local binary installation.

This module wraps the dotenvx binary for encryption/decryption of .env files.
Key features:
- Installs dotenvx binary inside .venv/bin/ (NOT system-wide)
- Pins version from constants.json for reproducibility
- Cross-platform support (Windows, macOS, Linux)
- Automatic line ending normalization for cross-platform compatibility
- No Node.js dependency required
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import stat
import subprocess  # nosec B404
import sys
import tempfile
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import ClassVar


def _load_constants() -> dict:
    """
    Load and return the parsed contents of the package's constants.json.

    The file is resolved relative to this module (../constants.json).

    Returns:
        dict: Parsed JSON object from constants.json.
    """
    constants_path = Path(__file__).parent.parent / "constants.json"
    with open(constants_path) as f:
        return json.load(f)


def _get_dotenvx_version() -> str:
    """
    Return the pinned dotenvx version from the package constants.

    Returns:
        version (str): The pinned dotenvx version string (for example, "1.2.3").
    """
    return _load_constants()["dotenvx_version"]


def _get_download_url_templates() -> dict[str, str]:
    """
    Return the download URL templates loaded from constants.json.

    Returns:
        download_urls (dict[str, str]): Mapping from platform/architecture identifiers to URL templates that include a version placeholder.
    """
    return _load_constants()["download_urls"]


# Load version from constants.json
DOTENVX_VERSION = _get_dotenvx_version()

# Download URLs by platform - loaded from constants.json and mapped to tuples
_URL_TEMPLATES = _get_download_url_templates()
DOWNLOAD_URLS = {
    ("Darwin", "x86_64"): _URL_TEMPLATES["darwin_amd64"],
    ("Darwin", "arm64"): _URL_TEMPLATES["darwin_arm64"],
    ("Linux", "x86_64"): _URL_TEMPLATES["linux_amd64"],
    ("Linux", "aarch64"): _URL_TEMPLATES["linux_arm64"],
    ("Windows", "AMD64"): _URL_TEMPLATES["windows_amd64"],
    ("Windows", "x86_64"): _URL_TEMPLATES["windows_amd64"],
}

_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


class DotenvxNotFoundError(Exception):
    """dotenvx binary not found."""

    pass


class DotenvxError(Exception):
    """dotenvx command failed."""

    pass


class DotenvxInstallError(Exception):
    """Failed to install dotenvx."""

    pass


class DotenvxFilenameError(Exception):
    """Filename not compatible with dotenvx due to known bugs."""

    pass


# Known problematic filename patterns for dotenvx on Windows
# See: https://github.com/dotenvx/dotenvx/issues/724
PROBLEMATIC_FILENAME_PATTERNS = [
    # .env.local causes "Input string must contain hex characters" on Windows
    # because dotenvx tries to parse "LOCAL" as a hex string
    r"^\.env\.local$",
]


def get_platform_info() -> tuple[str, str]:
    """
    Return the current platform name and a normalized architecture identifier.

    The returned architecture value normalizes common variants (for example, AMD64 -> `x86_64` on non-Windows systems; `arm64` vs `aarch64` differs between Darwin and other OSes).

    Returns:
        tuple: `(system, machine)` where `system` is the platform name (e.g., "Darwin", "Linux", "Windows") and `machine` is the normalized architecture (e.g., "x86_64", "arm64", "aarch64", "AMD64").
    """
    system = platform.system()
    machine = platform.machine()

    # Normalize some architecture names
    if machine == "x86_64":
        pass  # Keep as is
    elif machine in ("AMD64", "amd64"):
        machine = "AMD64" if system == "Windows" else "x86_64"
    elif machine in ("arm64", "aarch64"):
        machine = "arm64" if system == "Darwin" else "aarch64"

    return system, machine


def get_venv_bin_dir() -> Path:
    """
    Determine the filesystem path to the current virtual environment's executable directory.

    Searches these locations in order: the VIRTUAL_ENV environment variable, candidate venv directories found on sys.path (including uv tool and pipx installs), a .venv directory in the current working directory, and finally falls back to user bin directories (~/.local/bin on Linux/macOS or %APPDATA%\\Python\\Scripts on Windows). Returns the venv's "bin" subdirectory on POSIX systems or "Scripts" on Windows.

    Returns:
        Path: Path to the virtual environment's bin directory (or Scripts on Windows).

    Raises:
        RuntimeError: If no virtual environment directory can be located.
    """
    # Check for virtual environment
    venv_path = os.environ.get("VIRTUAL_ENV")
    if venv_path:
        venv = Path(venv_path)
        if platform.system() == "Windows":
            return venv / "Scripts"
        return venv / "bin"

    # Try to find venv relative to the package
    # This handles cases where VIRTUAL_ENV isn't set
    for path in sys.path:
        p = Path(path)
        # Check for standard venv directories
        if ".venv" in p.parts or "venv" in p.parts:
            # Walk up to find the venv root
            while p.name not in (".venv", "venv") and p.parent != p:
                p = p.parent
            if p.name in (".venv", "venv"):
                if platform.system() == "Windows":
                    return p / "Scripts"
                return p / "bin"
        # Check for uv tool install (e.g., ~/.local/share/uv/tools/envdrift/)
        # or pipx install (e.g., ~/.local/pipx/venvs/envdrift/)
        is_uv_tool = "uv" in p.parts and "tools" in p.parts
        is_pipx = "pipx" in p.parts and "venvs" in p.parts
        if is_uv_tool or is_pipx:
            # Walk up to find the tool's venv root
            # Linux: lib/pythonX.Y/site-packages (3 levels up)
            # Windows: Lib/site-packages (2 levels up)
            while p.name != "site-packages" and p.parent != p:
                p = p.parent
            if p.name == "site-packages":
                # Check parent structure to determine levels
                if platform.system() == "Windows":
                    # Windows: site-packages -> Lib -> tool_venv
                    tool_venv = p.parent.parent
                    bin_dir = tool_venv / "Scripts"
                else:
                    # Linux: site-packages -> pythonX.Y -> lib -> tool_venv
                    tool_venv = p.parent.parent.parent
                    bin_dir = tool_venv / "bin"
                # Validate path exists before returning
                if bin_dir.parent.exists():
                    return bin_dir

    # Default to creating in current directory's .venv
    cwd_venv = Path.cwd() / ".venv"
    if cwd_venv.exists():
        if platform.system() == "Windows":
            return cwd_venv / "Scripts"
        return cwd_venv / "bin"

    # Fallback for plain pip install (system or --user)
    # Use user-writable bin directory
    if platform.system() == "Windows":
        # Windows user scripts: %APPDATA%\Python\Scripts
        appdata = os.environ.get("APPDATA")
        if appdata:
            user_scripts = Path(appdata) / "Python" / "Scripts"
            user_scripts.mkdir(parents=True, exist_ok=True)
            return user_scripts
    else:
        # Linux/macOS: ~/.local/bin (standard user bin directory)
        user_bin = Path.home() / ".local" / "bin"
        user_bin.mkdir(parents=True, exist_ok=True)
        return user_bin

    # Only reachable on Windows when APPDATA is not set
    raise RuntimeError(
        "Cannot find virtual environment or user bin directory. "
        "On Windows, ensure the APPDATA environment variable is set, "
        "or activate a virtual environment with: python -m venv .venv"
    )


def get_dotenvx_path() -> Path:
    """
    Return the expected filesystem path of the dotenvx executable within the project's virtual environment.

    Returns:
        Path to the dotenvx binary inside the virtual environment's bin (or Scripts on Windows).
    """
    bin_dir = get_venv_bin_dir()
    binary_name = "dotenvx.exe" if platform.system() == "Windows" else "dotenvx"
    return bin_dir / binary_name


class DotenvxInstaller:
    """Install dotenvx binary to the virtual environment."""

    def __init__(
        self,
        version: str = DOTENVX_VERSION,
        progress_callback: Callable[[str], None] | None = None,
    ):
        """Initialize installer.

        Args:
            version: dotenvx version to install
            progress_callback: Optional callback for progress updates
        """
        self.version = version
        self.progress = progress_callback or (lambda x: None)

    def get_download_url(self) -> str:
        """
        Determine the platform-specific download URL for the configured dotenvx version.

        Returns:
            download_url (str): The concrete URL for the current system and architecture with the target version substituted.

        Raises:
            DotenvxInstallError: If the current platform/architecture is not supported.
        """
        system, machine = get_platform_info()
        key = (system, machine)

        if key not in DOWNLOAD_URLS:
            raise DotenvxInstallError(
                f"Unsupported platform: {system} {machine}. "
                f"Supported: {', '.join(f'{s}/{m}' for s, m in DOWNLOAD_URLS)}"
            )

        # Replace version in URL
        url = DOWNLOAD_URLS[key]
        if "{version}" in url:
            return url.format(version=self.version)
        return url.replace(DOTENVX_VERSION, self.version)

    def download_and_extract(self, target_path: Path) -> None:
        """
        Download the packaged dotenvx release for the current platform and place the extracted binary at the given target path.

        The function creates the target directory if necessary, extracts the platform-specific archive, copies the included dotenvx binary to target_path (overwriting if present), and sets executable permissions on non-Windows systems.

        Parameters:
            target_path (Path): Destination path for the dotenvx executable.

        Raises:
            DotenvxInstallError: If the download, extraction, or locating/copying of the binary fails.
        """
        url = self.get_download_url()
        self.progress(f"Downloading dotenvx v{self.version}...")

        # Create temp directory
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            archive_name = url.split("/")[-1]
            archive_path = tmp_path / archive_name

            # Download
            try:
                urllib.request.urlretrieve(url, archive_path)  # nosec B310
            except Exception as e:
                raise DotenvxInstallError(f"Download failed: {e}") from e

            self.progress("Extracting...")

            # Extract based on archive type
            if archive_name.endswith(".tar.gz"):
                self._extract_tar_gz(archive_path, tmp_path)
            elif archive_name.endswith(".zip"):
                self._extract_zip(archive_path, tmp_path)
            else:
                raise DotenvxInstallError(f"Unknown archive format: {archive_name}")

            # Find the binary
            binary_name = "dotenvx.exe" if platform.system() == "Windows" else "dotenvx"
            extracted_binary = None

            for f in tmp_path.rglob(binary_name):
                if f.is_file():
                    extracted_binary = f
                    break

            if not extracted_binary:
                raise DotenvxInstallError(f"Binary '{binary_name}' not found in archive")

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
        """
        Extracts all files from a gzip-compressed tar archive into the given target directory.

        Parameters:
            archive_path (Path): Path to the .tar.gz archive to extract.
            target_dir (Path): Destination directory where the archive contents will be extracted.
        """
        import tarfile

        with tarfile.open(archive_path, "r:gz") as tar:
            # Filter to prevent path traversal attacks (CVE-2007-4559)
            for member in tar.getmembers():
                member_path = target_dir / member.name
                # Resolve to absolute and ensure it's within target_dir
                if not member_path.resolve().is_relative_to(target_dir.resolve()):
                    raise DotenvxInstallError(f"Unsafe path in archive: {member.name}")
            try:
                tar.extractall(target_dir, filter="data")  # nosec B202
            except TypeError:
                # Python <3.12 doesn't support the filter argument.
                tar.extractall(target_dir)  # nosec B202

    def _extract_zip(self, archive_path: Path, target_dir: Path) -> None:
        """
        Extract the contents of a ZIP archive into the given target directory.

        Parameters:
            archive_path (Path): Path to the ZIP archive to extract.
            target_dir (Path): Directory where archive contents will be extracted.
        """
        import zipfile

        with zipfile.ZipFile(archive_path, "r") as zip_ref:
            # Filter to prevent path traversal attacks
            for name in zip_ref.namelist():
                member_path = target_dir / name
                # Resolve to absolute and ensure it's within target_dir
                if not member_path.resolve().is_relative_to(target_dir.resolve()):
                    raise DotenvxInstallError(f"Unsafe path in archive: {name}")
            zip_ref.extractall(target_dir)  # nosec B202

    def install(self, force: bool = False) -> Path:
        """
        Install the pinned dotenvx binary into the virtual environment.

        If the target binary already exists and `force` is False, verifies the installed version and skips reinstallation when it matches the requested version; otherwise downloads and installs the requested version.

        Parameters:
            force (bool): Reinstall even if a binary already exists.

        Returns:
            Path: Path to the installed dotenvx binary.

        Raises:
            DotenvxInstallError: If installation fails.
        """
        target_path = get_dotenvx_path()

        if target_path.exists() and not force:
            # Verify version
            try:
                result = subprocess.run(  # nosec B603
                    [str(target_path), "--version"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if self.version in result.stdout:
                    self.progress(f"dotenvx v{self.version} already installed")
                    return target_path
            except Exception as e:  # nosec B110
                # Version check failed, will reinstall
                import logging

                logging.debug(f"Version check failed: {e}")

        self.download_and_extract(target_path)
        return target_path

    @staticmethod
    def ensure_installed(version: str = DOTENVX_VERSION) -> Path:
        """
        Ensure the dotenvx binary of the given version is installed into the virtual environment.

        Parameters:
            version (str): Target dotenvx version to install.

        Returns:
            Path: Path to the installed dotenvx binary
        """
        installer = DotenvxInstaller(version=version)
        return installer.install()


class DotenvxWrapper:
    """Wrapper around dotenvx CLI.

    This wrapper:
    - Optionally installs dotenvx if not found (auto_install defaults to False)
    - Uses the binary from .venv/bin/ (not system-wide)
    - Provides Python-friendly interface to dotenvx commands
    """

    def __init__(self, auto_install: bool = False, version: str = DOTENVX_VERSION):
        """
        Create a DotenvxWrapper that provides methods to run and manage the dotenvx CLI within a virtual environment.

        Parameters:
            auto_install (bool): If True, attempt to install dotenvx into the project's virtual environment when it cannot be found.
            version (str): Pinned dotenvx version to use for lookups and installations.
        """
        self.auto_install = auto_install
        self.version = version
        self._binary_path: Path | None = None

    def _find_binary(self) -> Path:
        """
        Locate and return the filesystem path to the dotenvx executable, caching the result.

        Searches the virtual environment, then the system PATH, and attempts to auto-install the binary when configured to do so.

        Returns:
            Path: Filesystem path to the found dotenvx executable.

        Raises:
            DotenvxNotFoundError: If the executable cannot be found and auto-installation is not enabled or fails.
        """
        if self._binary_path and self._binary_path.exists():
            return self._binary_path

        # Check in venv first
        try:
            venv_path = get_dotenvx_path()
            if venv_path.exists():
                self._binary_path = venv_path
                return venv_path
        except RuntimeError:
            pass

        # Check system PATH
        system_path = shutil.which("dotenvx")
        if system_path:
            self._binary_path = Path(system_path)
            return self._binary_path

        # Auto-install if enabled
        if self.auto_install:
            try:
                installer = DotenvxInstaller(version=self.version)
                self._binary_path = installer.install()
                return self._binary_path
            except DotenvxInstallError as e:
                raise DotenvxNotFoundError(f"dotenvx not found and auto-install failed: {e}") from e

        raise DotenvxNotFoundError("dotenvx not found. Install with: envdrift install-dotenvx")

    @property
    def binary_path(self) -> Path:
        """
        Resolve and return the path to the dotenvx executable.

        Returns:
            path (Path): The resolved filesystem path to the dotenvx binary.
        """
        return self._find_binary()

    def is_installed(self) -> bool:
        """
        Determine whether the dotenvx binary is available (will attempt installation when auto_install is enabled).

        Returns:
            `true` if the dotenvx binary was found or successfully installed, `false` otherwise.
        """
        try:
            self._find_binary()
            return True
        except DotenvxNotFoundError:
            return False

    def get_version(self) -> str:
        """
        Get the installed dotenvx CLI version.

        Returns:
            str: The version string reported by the dotenvx binary (trimmed).
        """
        result = self._run(["--version"])
        return result.stdout.strip()

    def _run(
        self,
        args: list[str],
        check: bool = True,
        capture_output: bool = True,
        env: dict[str, str] | None = None,
        cwd: Path | str | None = None,
    ) -> subprocess.CompletedProcess:
        """
        Execute the dotenvx CLI with the provided arguments.

        Parameters:
            args (list[str]): Arguments to pass to the dotenvx executable (excluding the binary path).
            check (bool): If True, raise DotenvxError when the process exits with a non-zero status.
            capture_output (bool): If True, capture stdout and stderr and include them on the returned CompletedProcess.
            env (dict[str, str] | None): Optional environment mapping to use for the subprocess; defaults to the current environment.
            cwd (Path | str | None): Optional working directory for the subprocess.

        Returns:
            subprocess.CompletedProcess: The finished process result, including returncode, stdout, and stderr.

        Raises:
            DotenvxError: If the command times out or (when `check` is True) exits with a non-zero status.
            DotenvxNotFoundError: If the dotenvx executable cannot be found.
        """
        binary = self._find_binary()
        cmd = [str(binary)] + args

        try:
            result = subprocess.run(  # nosec B603
                cmd,
                capture_output=capture_output,
                text=True,
                timeout=120,
                env=env,
                cwd=str(cwd) if cwd else None,
            )

            if check and result.returncode != 0:
                stderr = (result.stderr or "").strip()
                if stderr:
                    stderr = _ANSI_ESCAPE_RE.sub("", stderr).strip()
                    if not stderr:
                        stderr = "no error output"
                else:
                    stderr = "no error output"
                raise DotenvxError(f"dotenvx command failed (exit {result.returncode}): {stderr}")

            return result
        except subprocess.TimeoutExpired as e:
            raise DotenvxError("dotenvx command timed out") from e
        except FileNotFoundError as e:
            raise DotenvxNotFoundError(f"dotenvx binary not found: {e}") from e

    # Error patterns that indicate encryption failure even with exit code 0
    ENCRYPT_ERROR_PATTERNS: ClassVar[list[str]] = [
        "does not match the existing public key",
        "MISSING_DOTENV_KEY",
        "private key not found",
        "decryption failed",
        "Input string must contain hex characters",  # Windows hex parsing error
    ]

    # Regex to strip ANSI escape codes from output
    ANSI_ESCAPE_PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"\x1b\[[0-9;]*m")

    @classmethod
    def _clean_output(cls, text: str) -> str:
        """Strip ANSI escape codes and normalize Unicode characters for clean output."""
        # Strip ANSI escape codes
        text = cls.ANSI_ESCAPE_PATTERN.sub("", text)
        # Replace Unicode ellipsis with ASCII equivalent (avoids encoding issues on Windows)
        text = text.replace("…", "...")
        # Also handle the mojibake version (UTF-8 ellipsis decoded as Windows-1252)
        text = text.replace("â€¦", "...")
        return text

    @staticmethod
    def _normalize_line_endings(file_path: Path) -> bool:
        """
        Normalize line endings in a file to Unix-style (LF) for cross-platform compatibility.

        dotenvx has known issues on Windows when files contain CRLF line endings or
        certain characters that get misinterpreted. This method normalizes the file
        to use Unix line endings (LF) which works consistently across all platforms.

        Parameters:
            file_path (Path): Path to the file to normalize.

        Returns:
            bool: True if the file was modified, False if already normalized.
        """
        try:
            # Read as binary to detect actual line endings
            content = file_path.read_bytes()

            # Check if normalization is needed (contains CRLF)
            if b"\r\n" not in content and b"\r" not in content:
                return False  # Already normalized

            # Normalize: CRLF -> LF, then any remaining CR -> LF
            normalized = content.replace(b"\r\n", b"\n").replace(b"\r", b"\n")

            # Write back
            file_path.write_bytes(normalized)
            return True
        except OSError:
            # If normalization fails, proceed anyway - dotenvx might still work
            return False

    @staticmethod
    def _validate_filename(file_path: Path) -> None:
        """
        Validate that the filename is compatible with dotenvx.

        dotenvx has known bugs on Windows where certain filenames cause errors.
        For example, `.env.local` causes "Input string must contain hex characters"
        because dotenvx tries to parse the suffix "LOCAL" as a hex string.

        Parameters:
            file_path (Path): Path to the file to validate.

        Raises:
            DotenvxFilenameError: If the filename matches a known problematic pattern.
        """
        filename = file_path.name.lower()
        for pattern in PROBLEMATIC_FILENAME_PATTERNS:
            if re.match(pattern, filename, re.IGNORECASE):
                raise DotenvxFilenameError(
                    f"Cannot encrypt/decrypt '{file_path.name}': "
                    f"dotenvx has a known bug on Windows where this filename causes "
                    f"'Input string must contain hex characters in even length' error. "
                    f"Workaround: Rename the file (e.g., '.env.localenv' or '.env.dev') "
                    f"before encryption. See: https://github.com/dotenvx/dotenvx/issues/724"
                )

    # Regex pattern for dotenvx public key header blocks
    DOTENVX_HEADER_BLOCK_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"#/---+\[DOTENV_PUBLIC_KEY\]---+/\n"
        r"#/[^\n]+/\n"
        r"#/[^\n]+/\n"
        r"#/---+/\n"
        r'DOTENV_PUBLIC_KEY_(\w+)="[^"]+"\n\n'
        r"# \.env\.(\w+)\n",
        re.MULTILINE,
    )

    @classmethod
    def _clean_mismatched_headers(cls, file_path: Path) -> bool:
        """
        Remove dotenvx header blocks that don't match the current filename.

        When a file is renamed (e.g., .env.local -> .env.localenv), dotenvx
        prepends a new header block without removing the old one, causing
        duplicate headers. This method removes any header blocks where the
        environment suffix doesn't match the current filename.

        Parameters:
            file_path (Path): Path to the env file to clean.

        Returns:
            bool: True if any headers were removed, False otherwise.
        """
        try:
            content = file_path.read_text(encoding="utf-8")
        except OSError:
            return False

        # Extract expected environment from filename (e.g., .env.localenv -> localenv)
        filename = file_path.name
        if filename.startswith(".env."):
            expected_env = filename[5:].lower()  # Remove ".env." prefix
        elif filename == ".env":
            expected_env = ""
        else:
            return False  # Not a .env file

        # Find all header blocks and check for mismatches
        modified = False
        new_content = content

        for match in cls.DOTENVX_HEADER_BLOCK_PATTERN.finditer(content):
            key_env = match.group(1).lower()  # Environment from DOTENV_PUBLIC_KEY_XXX
            comment_env = match.group(2).lower()  # Environment from # .env.xxx comment

            # If the key/comment environment doesn't match the filename, remove this block
            if key_env != expected_env or comment_env != expected_env:
                new_content = new_content.replace(match.group(0), "")
                modified = True

        if modified:
            # Clean up any resulting double newlines
            while "\n\n\n" in new_content:
                new_content = new_content.replace("\n\n\n", "\n\n")
            new_content = new_content.lstrip("\n")
            file_path.write_text(new_content, encoding="utf-8")

        return modified

    def encrypt(
        self,
        env_file: Path | str,
        env_keys_file: Path | str | None = None,
        env: dict[str, str] | None = None,
        cwd: Path | str | None = None,
    ) -> None:
        """
        Encrypt the specified .env file in place.

        Automatically normalizes line endings to Unix-style (LF) before encryption
        to ensure cross-platform compatibility with dotenvx.

        Parameters:
            env_file (Path | str): Path to the .env file to encrypt.
            env_keys_file (Path | str | None): Optional path to the .env.keys file to use.
            env (dict[str, str] | None): Optional environment variables for the subprocess.
            cwd (Path | str | None): Optional working directory for the subprocess.

        Raises:
            DotenvxFilenameError: If the filename is not compatible with dotenvx.
            DotenvxError: If the file does not exist or the encryption command fails.
        """
        env_file = Path(env_file)
        if not env_file.exists():
            raise DotenvxError(f"File not found: {env_file}")

        # Validate filename for known dotenvx bugs (Windows-specific)
        if platform.system() == "Windows":
            self._validate_filename(env_file)

        # Normalize line endings for cross-platform compatibility
        # dotenvx on Windows can fail with "Input string must contain hex characters"
        # when files have CRLF line endings
        self._normalize_line_endings(env_file)

        # Clean up mismatched headers from renamed files
        # When a file is renamed (e.g., .env.local -> .env.localenv), dotenvx
        # prepends a new header without removing the old one, causing duplicates
        self._clean_mismatched_headers(env_file)

        args = ["encrypt", "-f", str(env_file)]
        if env_keys_file:
            args.extend(["-fk", str(env_keys_file)])

        # Run with check=False to handle exit code 0 errors ourselves
        result = self._run(args, env=env, cwd=cwd, check=False)

        # Check for error patterns in output (dotenvx sometimes returns 0 on errors)
        combined_output = (result.stdout or "") + (result.stderr or "")
        # Clean output for readable error messages
        clean_output = self._clean_output(combined_output).strip()
        for pattern in self.ENCRYPT_ERROR_PATTERNS:
            if pattern.lower() in combined_output.lower():
                raise DotenvxError(f"dotenvx encryption failed: {clean_output}")

        # Also check if return code was non-zero
        if result.returncode != 0:
            clean_stderr = self._clean_output(result.stderr or "").strip()
            raise DotenvxError(f"dotenvx command failed (exit {result.returncode}): {clean_stderr}")

    def decrypt(
        self,
        env_file: Path | str,
        env_keys_file: Path | str | None = None,
        env: dict[str, str] | None = None,
        cwd: Path | str | None = None,
    ) -> None:
        """
        Decrypt the specified dotenv file in place.

        Automatically normalizes line endings to Unix-style (LF) before decryption
        to ensure cross-platform compatibility with dotenvx.

        Parameters:
            env_file (Path | str): Path to the .env file to decrypt.
            env_keys_file (Path | str | None): Optional path to a .env.keys file to use for decryption.
            env (dict[str, str] | None): Optional environment variables to supply to the subprocess.
            cwd (Path | str | None): Optional working directory for the subprocess.

        Raises:
            DotenvxFilenameError: If the filename is not compatible with dotenvx.
            DotenvxError: If env_file does not exist or the decryption command fails.
            DotenvxNotFoundError: If the dotenvx binary cannot be located when running the command.
        """
        env_file = Path(env_file)
        if not env_file.exists():
            raise DotenvxError(f"File not found: {env_file}")

        # Validate filename for known dotenvx bugs (Windows-specific)
        if platform.system() == "Windows":
            self._validate_filename(env_file)

        # Normalize line endings for cross-platform compatibility
        self._normalize_line_endings(env_file)

        args = ["decrypt", "-f", str(env_file)]
        if env_keys_file:
            args.extend(["-fk", str(env_keys_file)])

        self._run(args, env=env, cwd=cwd)

    def run(self, env_file: Path | str, command: list[str]) -> subprocess.CompletedProcess:
        """
        Run the given command with environment variables loaded from the specified env file.

        The command is executed via the installed dotenvx CLI and will not raise on non-zero exit; inspect the returned CompletedProcess to determine success.

        Parameters:
            env_file (Path | str): Path to the dotenv file whose variables should be loaded.
            command (list[str]): The command and its arguments to execute (e.g. ["python", "script.py"]).

        Returns:
            subprocess.CompletedProcess: The completed process result containing return code, stdout, and stderr.
        """
        env_file = Path(env_file)
        return self._run(["run", "-f", str(env_file), "--"] + command, check=False)

    def get(self, env_file: Path | str, key: str) -> str | None:
        """
        Retrieve the value for `key` from the given env file.

        Parameters:
            env_file (Path | str): Path to the env file to read.
            key (str): Name of the variable to retrieve.

        Returns:
            str | None: Trimmed value of the variable if present, `None` if the key is not present or the command fails.
        """
        env_file = Path(env_file)
        result = self._run(["get", "-f", str(env_file), key], check=False)

        if result.returncode != 0:
            return None

        return result.stdout.strip()

    def set(self, env_file: Path | str, key: str, value: str) -> None:
        """
        Set a key to the given value in the specified dotenv file.

        Parameters:
            env_file (Path | str): Path to the .env file to modify.
            key (str): The environment variable name to set.
            value (str): The value to assign to `key`.
        """
        env_file = Path(env_file)
        self._run(["set", "-f", str(env_file), key, value])

    @staticmethod
    def install_instructions() -> str:
        """
        Provide multi-option installation instructions for obtaining the dotenvx CLI.

        Returns:
            str: Multi-line installation instructions containing installation options
                 for different scenarios. The pinned version is interpolated into
                 the instructions.
        """
        return f"""
dotenvx is not installed.

Option 1 - Install to ~/.local/bin (recommended):
  curl -sfS "https://dotenvx.sh?directory=$HOME/.local/bin" | sh -s -- --version={DOTENVX_VERSION}
  (Make sure ~/.local/bin is in your PATH)

Option 2 - Install to current directory:
  curl -sfS "https://dotenvx.sh?directory=." | sh -s -- --version={DOTENVX_VERSION}

Option 3 - System-wide install (requires sudo):
  curl -sfS https://dotenvx.sh | sudo sh -s -- --version={DOTENVX_VERSION}

After installing, run your envdrift command again.
"""
