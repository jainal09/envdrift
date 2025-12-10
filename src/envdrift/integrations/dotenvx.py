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
import subprocess
import sys
import tempfile
import urllib.request
from collections.abc import Callable
from pathlib import Path


def _load_constants() -> dict:
    """Load constants from constants.json file."""
    constants_path = Path(__file__).parent.parent / "constants.json"
    with open(constants_path) as f:
        return json.load(f)


def _get_dotenvx_version() -> str:
    """Get the pinned dotenvx version from constants."""
    return _load_constants()["dotenvx_version"]


def _get_download_url_templates() -> dict[str, str]:
    """Get download URL templates from constants."""
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
    """Get current platform and architecture.

    Returns:
        Tuple of (system, machine) e.g., ("Darwin", "arm64")
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
    """Get the bin directory of the current virtual environment.

    Returns:
        Path to .venv/bin/ (or .venv/Scripts/ on Windows)

    Raises:
        RuntimeError: If not running in a virtual environment
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
    """Get the path where dotenvx binary should be installed.

    Returns:
        Path to the dotenvx binary
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
        """Get the download URL for the current platform.

        Returns:
            URL to download dotenvx binary

        Raises:
            DotenvxInstallError: If platform is not supported
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
        """Download and extract dotenvx binary.

        Args:
            target_path: Where to place the binary

        Raises:
            DotenvxInstallError: If download or extraction fails
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
                urllib.request.urlretrieve(url, archive_path)
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
                raise DotenvxInstallError(
                    f"Binary '{binary_name}' not found in archive"
                )

            # Ensure target directory exists
            target_path.parent.mkdir(parents=True, exist_ok=True)

            # Copy to target
            shutil.copy2(extracted_binary, target_path)

            # Make executable (Unix)
            if platform.system() != "Windows":
                target_path.chmod(target_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

            self.progress(f"Installed to {target_path}")

    def _extract_tar_gz(self, archive_path: Path, target_dir: Path) -> None:
        """Extract a tar.gz archive."""
        import tarfile

        with tarfile.open(archive_path, "r:gz") as tar:
            tar.extractall(target_dir)

    def _extract_zip(self, archive_path: Path, target_dir: Path) -> None:
        """Extract a zip archive."""
        import zipfile

        with zipfile.ZipFile(archive_path, "r") as zip_ref:
            zip_ref.extractall(target_dir)

    def install(self, force: bool = False) -> Path:
        """Install dotenvx binary to virtual environment.

        Args:
            force: Force reinstall even if already installed

        Returns:
            Path to the installed binary

        Raises:
            DotenvxInstallError: If installation fails
        """
        target_path = get_dotenvx_path()

        if target_path.exists() and not force:
            # Verify version
            try:
                result = subprocess.run(
                    [str(target_path), "--version"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if self.version in result.stdout:
                    self.progress(f"dotenvx v{self.version} already installed")
                    return target_path
            except Exception:
                pass  # Will reinstall

        self.download_and_extract(target_path)
        return target_path

    @staticmethod
    def ensure_installed(version: str = DOTENVX_VERSION) -> Path:
        """Static method to ensure dotenvx is installed.

        Args:
            version: Version to install

        Returns:
            Path to dotenvx binary
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
        """Initialize dotenvx wrapper.

        Args:
            auto_install: Automatically install dotenvx if not found
            version: Version to use/install
        """
        self.auto_install = auto_install
        self.version = version
        self._binary_path: Path | None = None

    def _find_binary(self) -> Path:
        """Find dotenvx binary.

        Returns:
            Path to dotenvx binary

        Raises:
            DotenvxNotFoundError: If not found and auto_install is False
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
                raise DotenvxNotFoundError(
                    f"dotenvx not found and auto-install failed: {e}"
                ) from e

        raise DotenvxNotFoundError(
            "dotenvx not found. Install with: envdrift install-dotenvx"
        )

    @property
    def binary_path(self) -> Path:
        """Get path to dotenvx binary."""
        return self._find_binary()

    def is_installed(self) -> bool:
        """Check if dotenvx is installed."""
        try:
            self._find_binary()
            return True
        except DotenvxNotFoundError:
            return False

    def get_version(self) -> str:
        """Get installed dotenvx version.

        Returns:
            Version string
        """
        result = self._run(["--version"])
        return result.stdout.strip()

    def _run(
        self,
        args: list[str],
        check: bool = True,
        capture_output: bool = True,
    ) -> subprocess.CompletedProcess:
        """Run dotenvx command.

        Args:
            args: Command arguments
            check: Raise on non-zero exit
            capture_output: Capture stdout/stderr

        Returns:
            CompletedProcess result

        Raises:
            DotenvxError: If command fails and check=True
        """
        binary = self._find_binary()
        cmd = [str(binary)] + args

        try:
            result = subprocess.run(
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
        """Encrypt an env file in place.

        Args:
            env_file: Path to .env file

        Raises:
            DotenvxError: If encryption fails
        """
        env_file = Path(env_file)
        if not env_file.exists():
            raise DotenvxError(f"File not found: {env_file}")

        self._run(["encrypt", "-f", str(env_file)])

    def decrypt(self, env_file: Path | str) -> None:
        """Decrypt an env file in place.

        Args:
            env_file: Path to .env file

        Raises:
            DotenvxError: If decryption fails
        """
        env_file = Path(env_file)
        if not env_file.exists():
            raise DotenvxError(f"File not found: {env_file}")

        self._run(["decrypt", "-f", str(env_file)])

    def run(self, env_file: Path | str, command: list[str]) -> subprocess.CompletedProcess:
        """Run a command with env file loaded.

        Args:
            env_file: Path to .env file
            command: Command to run

        Returns:
            CompletedProcess result
        """
        env_file = Path(env_file)
        return self._run(["run", "-f", str(env_file), "--"] + command, check=False)

    def get(self, env_file: Path | str, key: str) -> str | None:
        """Get a single value from env file.

        Args:
            env_file: Path to .env file
            key: Variable name

        Returns:
            Value or None if not found
        """
        env_file = Path(env_file)
        result = self._run(["get", "-f", str(env_file), key], check=False)

        if result.returncode != 0:
            return None

        return result.stdout.strip()

    def set(self, env_file: Path | str, key: str, value: str) -> None:
        """Set a value in env file.

        Args:
            env_file: Path to .env file
            key: Variable name
            value: Value to set
        """
        env_file = Path(env_file)
        self._run(["set", "-f", str(env_file), key, value])

    @staticmethod
    def install_instructions() -> str:
        """Return installation instructions."""
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
