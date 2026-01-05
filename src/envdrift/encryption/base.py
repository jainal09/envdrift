"""Abstract base class for encryption backends."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class EncryptionBackendError(Exception):
    """Base exception for encryption backend operations."""

    pass


class EncryptionNotFoundError(EncryptionBackendError):
    """Encryption tool binary not found."""

    pass


class EncryptionStatus(Enum):
    """Encryption status of an environment variable value."""

    ENCRYPTED = "encrypted"
    PLAINTEXT = "plaintext"
    EMPTY = "empty"


@dataclass
class EncryptionResult:
    """Result of an encryption/decryption operation."""

    success: bool
    message: str
    file_path: Path | None = None


class EncryptionBackend(ABC):
    """Abstract interface for encryption backends.

    Implementations must provide:
    - encrypt: Encrypt a file
    - decrypt: Decrypt a file
    - is_installed: Check if the encryption tool is available
    - detect_encryption_status: Detect if a value is encrypted by this backend
    - has_encrypted_header: Check if file content has encryption markers

    Implementations should be safe for concurrent use; protect any shared lazy
    initialization of backend state with locks.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """
        Human-readable name of the encryption backend.

        Returns:
            str: Backend name (e.g., "dotenvx", "sops").
        """
        ...

    @property
    @abstractmethod
    def encrypted_value_prefix(self) -> str | None:
        """
        Prefix used to identify encrypted values in .env files.

        Returns:
            str | None: The prefix (e.g., "encrypted:" for dotenvx, "ENC[" for SOPS),
                        or None if the backend doesn't use value prefixes.
        """
        ...

    @abstractmethod
    def is_installed(self) -> bool:
        """
        Determine whether the encryption tool binary is available.

        Returns:
            bool: True if the tool is installed and available, False otherwise.
        """
        ...

    @abstractmethod
    def get_version(self) -> str | None:
        """
        Get the installed version of the encryption tool.

        Returns:
            str | None: Version string if available, None if not installed.
        """
        ...

    @abstractmethod
    def encrypt(
        self,
        env_file: Path | str,
        keys_file: Path | str | None = None,
        **kwargs,
    ) -> EncryptionResult:
        """
        Encrypt a .env file.

        Parameters:
            env_file (Path | str): Path to the .env file to encrypt.
            keys_file (Path | str | None): Optional path to keys file.
            **kwargs: Backend-specific options.

        Returns:
            EncryptionResult: Result containing success status and message.

        Raises:
            EncryptionBackendError: If encryption fails.
            EncryptionNotFoundError: If the encryption tool is not installed.
        """
        ...

    @abstractmethod
    def decrypt(
        self,
        env_file: Path | str,
        keys_file: Path | str | None = None,
        **kwargs,
    ) -> EncryptionResult:
        """
        Decrypt a .env file.

        Parameters:
            env_file (Path | str): Path to the .env file to decrypt.
            keys_file (Path | str | None): Optional path to keys file.
            **kwargs: Backend-specific options.

        Returns:
            EncryptionResult: Result containing success status and message.

        Raises:
            EncryptionBackendError: If decryption fails.
            EncryptionNotFoundError: If the encryption tool is not installed.
        """
        ...

    @abstractmethod
    def detect_encryption_status(self, value: str) -> EncryptionStatus:
        """
        Detect the encryption status of a single value.

        Parameters:
            value (str): The unquoted value string to classify.

        Returns:
            EncryptionStatus: EMPTY if value is empty, ENCRYPTED if it matches
                              this backend's encrypted pattern, PLAINTEXT otherwise.
        """
        ...

    @abstractmethod
    def has_encrypted_header(self, content: str) -> bool:
        """
        Determine whether file content contains this backend's encryption markers.

        Parameters:
            content (str): Raw file content to inspect.

        Returns:
            bool: True if encryption markers are present, False otherwise.
        """
        ...

    def is_file_encrypted(self, path: Path) -> bool:
        """
        Determine whether a file contains encryption markers.

        Parameters:
            path (Path): Filesystem path to the file to inspect.

        Returns:
            bool: True if the file contains encryption markers, False otherwise.
        """
        if not path.exists():
            return False

        content = path.read_text(encoding="utf-8")
        return self.has_encrypted_header(content)

    def is_value_encrypted(self, value: str) -> bool:
        """
        Check if a value is encrypted by this backend.

        Parameters:
            value (str): The value to check.

        Returns:
            bool: True if the value is encrypted, False otherwise.
        """
        return self.detect_encryption_status(value) == EncryptionStatus.ENCRYPTED

    @abstractmethod
    def install_instructions(self) -> str:
        """
        Provide installation instructions for the encryption tool.

        Returns:
            str: Human-readable installation instructions.
        """
        ...

    def ensure_installed(self) -> None:
        """
        Ensure the encryption tool is installed, raising if not.

        Raises:
            EncryptionNotFoundError: If the tool is not installed.
        """
        if not self.is_installed():
            raise EncryptionNotFoundError(
                f"{self.name} is not installed.\n{self.install_instructions()}"
            )
