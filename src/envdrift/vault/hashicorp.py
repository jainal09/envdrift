"""HashiCorp Vault client implementation."""

from __future__ import annotations

import os

from envdrift.vault.base import (
    AuthenticationError,
    SecretNotFoundError,
    SecretValue,
    VaultClient,
    VaultError,
)

try:
    import hvac
    from hvac.exceptions import Forbidden, InvalidPath, Unauthorized

    HVAC_AVAILABLE = True
except ImportError:
    HVAC_AVAILABLE = False
    hvac = None
    InvalidPath = Exception
    Forbidden = Exception
    Unauthorized = Exception


class HashiCorpVaultClient(VaultClient):
    """HashiCorp Vault implementation.

    Supports KV v2 secrets engine (the default in modern Vault).

    Authentication methods supported:
    - Token (via token parameter or VAULT_TOKEN env var)
    """

    def __init__(
        self,
        url: str,
        token: str | None = None,
        mount_point: str = "secret",
    ):
        """
        Create a HashiCorp Vault client configured to use the KV v2 secrets engine.

        Parameters:
            url (str): Vault server URL (e.g., "https://vault.example.com:8200").
            token (str | None): Authentication token; if omitted, the VAULT_TOKEN environment variable is used.
            mount_point (str): KV secrets engine mount point (default "secret").
        """
        if not HVAC_AVAILABLE:
            raise ImportError("hvac not installed. Install with: pip install envdrift[hashicorp]")

        self.url = url
        self.token = token or os.environ.get("VAULT_TOKEN")
        self.mount_point = mount_point
        self._client: hvac.Client | None = None

    def authenticate(self) -> None:
        """
        Authenticate the client against HashiCorp Vault using the configured token.

        This initializes and verifies the underlying hvac client and stores it on the instance
        when authentication succeeds.

        Raises:
                AuthenticationError: If no token was provided, the token is invalid, expired, or Vault
                        rejects authentication (including Unauthorized or Forbidden responses).
                VaultError: For other connection or unexpected errors communicating with Vault.
        """
        if not self.token:
            raise AuthenticationError(
                "No Vault token provided. Set VAULT_TOKEN or pass token parameter."
            )

        try:
            self._client = hvac.Client(url=self.url, token=self.token)

            if not self._client.is_authenticated():
                raise AuthenticationError("Vault token is invalid or expired")
        except (Unauthorized, Forbidden) as e:
            raise AuthenticationError(f"Vault authentication failed: {e}") from e
        except Exception as e:
            raise VaultError(f"Vault connection error: {e}") from e

    def is_authenticated(self) -> bool:
        """
        Return whether the stored hvac client is currently authenticated.

        Returns:
            bool: `True` if an internal hvac client exists and reports it is authenticated, `False` otherwise.
        """
        if self._client is None:
            return False
        try:
            return self._client.is_authenticated()
        except Exception:
            return False

    def get_secret(self, name: str) -> SecretValue:
        """
        Retrieve a secret from Vault at the given path relative to the client's mount point.

        If the stored secret data contains only a single key named "value", that value is returned; otherwise the entire secret data dict is JSON-encoded and returned as the value. The returned SecretValue includes the secret's version and metadata (created_time, deletion_time, destroyed, custom_metadata).

        Parameters:
            name: Secret path relative to the configured mount point.

        Returns:
            A SecretValue containing the secret's value, version, and metadata.

        Raises:
            SecretNotFoundError: If the secret path does not exist.
            AuthenticationError: If access to the secret is denied or the client is unauthenticated.
            VaultError: For other Vault-related errors.
        """
        self.ensure_authenticated()

        try:
            response = self._client.secrets.kv.v2.read_secret_version(
                path=name,
                mount_point=self.mount_point,
            )

            data = response.get("data", {})
            secret_data = data.get("data", {})
            metadata = data.get("metadata", {})

            # If there's a single "value" key, return that
            # Otherwise return the JSON string of all data
            if "value" in secret_data and len(secret_data) == 1:
                value = secret_data["value"]
            else:
                import json

                value = json.dumps(secret_data)

            return SecretValue(
                name=name,
                value=value,
                version=str(metadata.get("version", "")),
                metadata={
                    "created_time": metadata.get("created_time"),
                    "deletion_time": metadata.get("deletion_time"),
                    "destroyed": metadata.get("destroyed", False),
                    "custom_metadata": metadata.get("custom_metadata", {}),
                },
            )
        except InvalidPath as e:
            raise SecretNotFoundError(f"Secret '{name}' not found in Vault") from e
        except (Unauthorized, Forbidden) as e:
            raise AuthenticationError(f"Access denied to secret '{name}': {e}") from e
        except Exception as e:
            raise VaultError(f"Vault error: {e}") from e

    def list_secrets(self, prefix: str = "") -> list[str]:
        """List secret paths in HashiCorp Vault.

        Args:
            prefix: Path prefix to list under

        Returns:
            List of secret paths
        """
        self.ensure_authenticated()

        try:
            response = self._client.secrets.kv.v2.list_secrets(
                path=prefix,
                mount_point=self.mount_point,
            )

            keys = response.get("data", {}).get("keys", [])
            return sorted(keys)
        except InvalidPath:
            # Path doesn't exist, return empty list
            return []
        except (Unauthorized, Forbidden) as e:
            raise AuthenticationError(f"Access denied to list secrets: {e}") from e
        except Exception as e:
            raise VaultError(f"Vault error: {e}") from e

    def create_or_update_secret(self, name: str, data: dict) -> SecretValue:
        """
        Create or update a secret at the given Vault path.

        Parameters:
            name (str): Secret path in the KV v2 engine.
            data (dict): Dictionary of key-value pairs to store for the secret.

        Returns:
            SecretValue: The stored secret representation containing the secret `name`, a string `value` (JSON-encoded when multiple keys), the secret `version`, and metadata including `created_time`.

        Raises:
            AuthenticationError: If the client is not authorized to write the secret.
            VaultError: For other Vault-related errors.
        """
        self.ensure_authenticated()

        try:
            response = self._client.secrets.kv.v2.create_or_update_secret(
                path=name,
                secret=data,
                mount_point=self.mount_point,
            )

            metadata = response.get("data", {})

            # Use same value extraction logic as get_secret for consistency
            import json

            value = data["value"] if ("value" in data and len(data) == 1) else json.dumps(data)

            return SecretValue(
                name=name,
                value=value,
                version=str(metadata.get("version", "")),
                metadata={
                    "created_time": metadata.get("created_time"),
                },
            )
        except (Unauthorized, Forbidden) as e:
            raise AuthenticationError(f"Access denied to write secret: {e}") from e
        except Exception as e:
            raise VaultError(f"Vault error: {e}") from e

    def set_secret(self, name: str, value: str) -> SecretValue:
        """
        Set a string secret at the given path.

        Parameters:
            name (str): Secret path in Vault.
            value (str): Secret string to store.

        Returns:
            SecretValue: The created or updated secret, including its stored value and metadata.
        """
        return self.create_or_update_secret(name, {"value": value})
