"""Abstract base class for vault clients."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


class VaultError(Exception):
    """Base exception for vault operations."""

    pass


class AuthenticationError(VaultError):
    """Authentication to vault failed."""

    pass


class SecretNotFoundError(VaultError):
    """Secret not found in vault."""

    pass


@dataclass
class SecretValue:
    """Value retrieved from vault."""

    name: str
    value: str
    version: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        """Return masked representation."""
        return f"SecretValue(name={self.name}, value=****)"


class VaultClient(ABC):
    """Abstract interface for vault backends.

    Implementations must provide:
    - get_secret: Retrieve a secret by name
    - list_secrets: List available secret names
    - is_authenticated: Check authentication status
    - authenticate: Perform authentication
    """

    @abstractmethod
    def get_secret(self, name: str) -> SecretValue:
        """Retrieve a secret by name.

        Args:
            name: The name/path of the secret

        Returns:
            SecretValue with the secret data

        Raises:
            SecretNotFoundError: If the secret doesn't exist
            AuthenticationError: If not authenticated
            VaultError: For other vault errors
        """
        ...

    @abstractmethod
    def list_secrets(self, prefix: str = "") -> list[str]:
        """List available secret names.

        Args:
            prefix: Optional prefix to filter secrets

        Returns:
            List of secret names

        Raises:
            AuthenticationError: If not authenticated
            VaultError: For other vault errors
        """
        ...

    @abstractmethod
    def is_authenticated(self) -> bool:
        """Check if client is authenticated.

        Returns:
            True if authenticated, False otherwise
        """
        ...

    @abstractmethod
    def authenticate(self) -> None:
        """Authenticate to the vault.

        Raises:
            AuthenticationError: If authentication fails
        """
        ...

    def get_secret_value(self, name: str) -> str:
        """Convenience method to get just the secret value.

        Args:
            name: The name/path of the secret

        Returns:
            The secret value as a string
        """
        return self.get_secret(name).value

    def ensure_authenticated(self) -> None:
        """Ensure client is authenticated, authenticating if needed.

        Raises:
            AuthenticationError: If authentication fails
        """
        if not self.is_authenticated():
            self.authenticate()
