"""Dotenvx encryption backend implementation."""

from __future__ import annotations

import re
from pathlib import Path
from threading import Lock
from typing import ClassVar

from envdrift.encryption.base import (
    EncryptionBackend,
    EncryptionBackendError,
    EncryptionNotFoundError,
    EncryptionResult,
    EncryptionStatus,
)


class DotenvxEncryptionBackend(EncryptionBackend):
    """Encryption backend using dotenvx CLI.

    dotenvx is a tool for encrypting .env files with a public/private key pair.
    It stores encrypted values with the prefix "encrypted:" and adds file headers.
    """

    # Patterns that indicate encrypted values (dotenvx format)
    ENCRYPTED_PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"^encrypted:")

    # Header patterns that indicate the file has been encrypted by dotenvx
    ENCRYPTED_FILE_MARKERS: ClassVar[list[str]] = [
        "#/---BEGIN DOTENV ENCRYPTED---/",
        "DOTENV_PUBLIC_KEY",
    ]

    def __init__(self, auto_install: bool = False):
        """
        Initialize the dotenvx encryption backend.

        Parameters:
            auto_install (bool): If True, attempt to auto-install dotenvx if not found.
        """
        self._auto_install = auto_install
        self._wrapper = None
        self._wrapper_lock = Lock()

    @property
    def name(self) -> str:
        """Return backend name."""
        return "dotenvx"

    @property
    def encrypted_value_prefix(self) -> str:
        """Return the prefix used to identify encrypted values."""
        return "encrypted:"

    def _get_wrapper(self):
        """Lazily initialize the DotenvxWrapper."""
        if self._wrapper is None:
            with self._wrapper_lock:
                if self._wrapper is None:
                    from envdrift.integrations.dotenvx import DotenvxWrapper

                    self._wrapper = DotenvxWrapper(auto_install=self._auto_install)
        return self._wrapper

    def is_installed(self) -> bool:
        """Check if dotenvx is installed."""
        from envdrift.integrations.dotenvx import DotenvxError, DotenvxNotFoundError

        try:
            return self._get_wrapper().is_installed()
        except (DotenvxNotFoundError, DotenvxError, OSError, RuntimeError):
            return False

    def get_version(self) -> str | None:
        """Get the installed dotenvx version."""
        from envdrift.integrations.dotenvx import DotenvxError, DotenvxNotFoundError

        try:
            if not self.is_installed():
                return None
            return self._get_wrapper().get_version()
        except (DotenvxNotFoundError, DotenvxError, OSError, RuntimeError):
            return None

    def encrypt(
        self,
        env_file: Path | str,
        keys_file: Path | str | None = None,
        **kwargs,
    ) -> EncryptionResult:
        """
        Encrypt a .env file using dotenvx.

        Parameters:
            env_file (Path | str): Path to the .env file to encrypt.
            keys_file (Path | str | None): Optional path to .env.keys file.
            **kwargs: Additional options:
                - env (dict): Environment variables to pass to subprocess.
                - cwd (Path | str): Working directory for subprocess.

        Returns:
            EncryptionResult: Result of the encryption operation.
        """
        env_file = Path(env_file)

        if not env_file.exists():
            return EncryptionResult(
                success=False,
                message=f"File not found: {env_file}",
                file_path=env_file,
            )

        if not self.is_installed():
            raise EncryptionNotFoundError(
                f"dotenvx is not installed.\n{self.install_instructions()}"
            )

        from envdrift.integrations.dotenvx import DotenvxError

        try:
            wrapper = self._get_wrapper()
            wrapper.encrypt(
                env_file=env_file,
                env_keys_file=keys_file,
                env=kwargs.get("env"),
                cwd=kwargs.get("cwd"),
            )
            return EncryptionResult(
                success=True,
                message=f"Encrypted {env_file}",
                file_path=env_file,
            )
        except DotenvxError as e:
            raise EncryptionBackendError(f"dotenvx encryption failed: {e}") from e

    def decrypt(
        self,
        env_file: Path | str,
        keys_file: Path | str | None = None,
        **kwargs,
    ) -> EncryptionResult:
        """
        Decrypt a .env file using dotenvx.

        Parameters:
            env_file (Path | str): Path to the .env file to decrypt.
            keys_file (Path | str | None): Optional path to .env.keys file.
            **kwargs: Additional options:
                - env (dict): Environment variables to pass to subprocess.
                - cwd (Path | str): Working directory for subprocess.

        Returns:
            EncryptionResult: Result of the decryption operation.
        """
        env_file = Path(env_file)

        if not env_file.exists():
            return EncryptionResult(
                success=False,
                message=f"File not found: {env_file}",
                file_path=env_file,
            )

        if not self.is_installed():
            raise EncryptionNotFoundError(
                f"dotenvx is not installed.\n{self.install_instructions()}"
            )

        from envdrift.integrations.dotenvx import DotenvxError

        try:
            wrapper = self._get_wrapper()
            wrapper.decrypt(
                env_file=env_file,
                env_keys_file=keys_file,
                env=kwargs.get("env"),
                cwd=kwargs.get("cwd"),
            )
            return EncryptionResult(
                success=True,
                message=f"Decrypted {env_file}",
                file_path=env_file,
            )
        except DotenvxError as e:
            raise EncryptionBackendError(f"dotenvx decryption failed: {e}") from e

    def detect_encryption_status(self, value: str) -> EncryptionStatus:
        """
        Detect the encryption status of a value.

        Parameters:
            value (str): The unquoted value string to classify.

        Returns:
            EncryptionStatus: EMPTY if value is empty, ENCRYPTED if it starts
                              with "encrypted:", PLAINTEXT otherwise.
        """
        if not value:
            return EncryptionStatus.EMPTY

        if self.ENCRYPTED_PATTERN.match(value):
            return EncryptionStatus.ENCRYPTED

        return EncryptionStatus.PLAINTEXT

    def has_encrypted_header(self, content: str) -> bool:
        """
        Check if file content contains dotenvx encryption markers.

        Parameters:
            content (str): Raw file content to inspect.

        Returns:
            bool: True if dotenvx encryption markers are present.
        """
        for marker in self.ENCRYPTED_FILE_MARKERS:
            if marker in content:
                return True
        return False

    def install_instructions(self) -> str:
        """Return installation instructions for dotenvx."""
        from envdrift.integrations.dotenvx import DOTENVX_VERSION

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
