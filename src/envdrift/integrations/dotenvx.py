"""dotenvx CLI wrapper with local binary installation.

This module wraps the dotenvx binary for encryption/decryption of .env files.
Key features:
- Installs dotenvx binary inside .venv/bin/ (NOT system-wide)
- Pins version from constants.json for reproducibility
- Cross-platform support (Windows, macOS, Linux)
- No Node.js dependency required
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import stat
import subprocess  # nosec B404
import sys
import tempfile
import urllib.request
from collections.abc import Callable
from pathlib import Path


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


class DotenvxNotFoundError(Exception):
    """dotenvx binary not found."""

    pass


class DotenvxError(Exception):
    """dotenvx command failed."""

    pass


class DotenvxInstallError(Exception):
    """Failed to install dotenvx."""

    pass


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

    Searches these locations in order: the VIRTUAL_ENV environment variable, candidate venv directories found on sys.path, and a .venv directory in the current working directory. Returns the venv's "bin" subdirectory on POSIX systems or "Scripts" on Windows.

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
        if ".venv" in p.parts or "venv" in p.parts:
            # Walk up to find the venv root
            while p.name not in (".venv", "venv") and p.parent != p:
                p = p.parent
            if p.name in (".venv", "venv"):
                if platform.system() == "Windows":
                    return p / "Scripts"
                return p / "bin"

    # Default to creating in current directory's .venv
    cwd_venv = Path.cwd() / ".venv"
    if cwd_venv.exists():
        if platform.system() == "Windows":
            return cwd_venv / "Scripts"
        return cwd_venv / "bin"

    raise RuntimeError(
        "Cannot find virtual environment. "
        "Please activate a virtual environment or create one with: python -m venv .venv"
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
            tar.extractall(target_dir, filter="data")  # nosec B202

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
    - Automatically installs dotenvx if not found
    - Uses the binary from .venv/bin/ (not system-wide)
    - Provides Python-friendly interface to dotenvx commands
    """

    def __init__(self, auto_install: bool = True, version: str = DOTENVX_VERSION):
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
    ) -> subprocess.CompletedProcess:
        """
        Execute the dotenvx CLI with the provided arguments and return the completed process.

        Parameters:
            args (list[str]): Arguments to pass to the dotenvx executable (excluding the binary path).
            check (bool): If True, raise DotenvxError when the process exits with a non-zero status.
            capture_output (bool): If True, capture and return stdout and stderr on the CompletedProcess.

        Returns:
            subprocess.CompletedProcess: The result of the executed command, including return code, stdout, and stderr.

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
            )

            if check and result.returncode != 0:
                raise DotenvxError(
                    f"dotenvx command failed (exit {result.returncode}): {result.stderr}"
                )

            return result
        except subprocess.TimeoutExpired as e:
            raise DotenvxError("dotenvx command timed out") from e
        except FileNotFoundError as e:
            raise DotenvxNotFoundError(f"dotenvx binary not found: {e}") from e

    def encrypt(self, env_file: Path | str) -> None:
        """
        Encrypt the specified .env file in place.

        Parameters:
            env_file (Path | str): Path to the .env file to encrypt.

        Raises:
            DotenvxError: If the file does not exist or the encryption command fails.
        """
        env_file = Path(env_file)
        if not env_file.exists():
            raise DotenvxError(f"File not found: {env_file}")

        self._run(["encrypt", "-f", str(env_file)])

    def decrypt(self, env_file: Path | str) -> None:
        """
        Decrypt the specified dotenv file in place.

        Parameters:
            env_file (Path | str): Path to the .env file to decrypt.

        Raises:
            DotenvxError: If the file does not exist or the decryption command fails.
        """
        env_file = Path(env_file)
        if not env_file.exists():
            raise DotenvxError(f"File not found: {env_file}")

        self._run(["decrypt", "-f", str(env_file)])

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
            str: Multi-line installation instructions containing three options:
                 1) Auto-install into the project's virtual environment (recommended),
                 2) Manual install via DotenvxInstaller.ensure_installed(),
                 3) System install via the official install script. The pinned version
                 is interpolated into the instructions.
        """
        return f"""
dotenvx is not installed.

Option 1 - Auto-install (recommended):
  The next envdrift command will automatically install dotenvx v{DOTENVX_VERSION}
  to your virtual environment.

Option 2 - Manual install:
  python -c "from envdrift.integrations.dotenvx import DotenvxInstaller; DotenvxInstaller.ensure_installed()"

Option 3 - System install:
  curl -sfS https://dotenvx.sh | sh -s -- --version={DOTENVX_VERSION}

Note: envdrift prefers using a local binary in .venv/bin/ for reproducibility.
"""
