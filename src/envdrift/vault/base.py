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
        """
        Produce a string representation of the SecretValue with the secret value masked.

        Returns:
            str: A string in the form "SecretValue(name=<name>, value=****)" where the actual secret value is redacted.
        """
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
        """
        Retrieve the secret identified by `name` from the vault.

        Parameters:
            name (str): Secret name or path within the vault.

        Returns:
            SecretValue: The secret object containing the secret's value and metadata.

        Raises:
            SecretNotFoundError: If the secret does not exist.
            AuthenticationError: If the client is not authenticated.
            VaultError: For other vault-related errors.
        """
        ...

    @abstractmethod
    def list_secrets(self, prefix: str = "") -> list[str]:
        """
        List secret names available in the vault, optionally filtered by a prefix.

        Parameters:
            prefix (str): Optional prefix to filter returned secret names.

        Returns:
            list[str]: Secret names that match the prefix (or all secret names if prefix is empty).

        Raises:
            AuthenticationError: If the client is not authenticated.
            VaultError: For other vault-related errors.
        """
        ...

    @abstractmethod
    def is_authenticated(self) -> bool:
        """
        Determine whether the client is currently authenticated.

        Returns:
            True if the client is authenticated, False otherwise.
        """
        ...

    @abstractmethod
    def authenticate(self) -> None:
        """
        Authenticate the client with the vault.

        Raises:
            AuthenticationError: If authentication fails.
        """
        ...

    def get_secret_value(self, name: str) -> str:
        """
        Retrieve the value string of a secret identified by name.

        Parameters:
                name (str): The secret's name or path.

        Returns:
                The secret's value string.
        """
        return self.get_secret(name).value

    def ensure_authenticated(self) -> None:
        """
        Authenticate the client if it is not already authenticated.

        Raises:
            AuthenticationError: If authentication fails.
        """
        if not self.is_authenticated():
            self.authenticate()
