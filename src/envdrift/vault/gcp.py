"""GCP Secret Manager client implementation."""

from __future__ import annotations

import contextlib
from typing import Any

from envdrift.vault.base import (
    AuthenticationError,
    SecretNotFoundError,
    SecretValue,
    VaultClient,
    VaultError,
)

try:
    from google.api_core import exceptions as _google_exceptions
    from google.auth.exceptions import DefaultCredentialsError
    from google.cloud import secretmanager as _secretmanager

    GCP_AVAILABLE = True
except ImportError:
    GCP_AVAILABLE = False
    _secretmanager = None
    _google_exceptions = None
    DefaultCredentialsError = Exception  # type: ignore[misc, assignment]


def _get_gcp_modules() -> tuple[Any, Any]:
    """Get GCP modules, raising ImportError if not available."""
    if not GCP_AVAILABLE or _secretmanager is None or _google_exceptions is None:
        raise ImportError(
            "GCP Secret Manager support requires additional dependencies. "
            "Install with: pip install envdrift[gcp]"
        )
    return _secretmanager, _google_exceptions


class GCPSecretManagerClient(VaultClient):
    """GCP Secret Manager implementation.

    Uses Application Default Credentials which support:
    - GOOGLE_APPLICATION_CREDENTIALS env var
    - gcloud auth application-default login
    - Workload Identity / service account bindings
    """

    def __init__(self, project_id: str):
        """
        Create a GCP Secret Manager client bound to the provided project ID.

        Parameters:
            project_id (str): GCP project ID (e.g., "my-gcp-project").

        Raises:
            ImportError: If the GCP SDK is not installed (install with `pip install envdrift[gcp]`).
        """
        _get_gcp_modules()  # Verify GCP SDK is available
        self.project_id = project_id
        self._client: Any = None

    def _project_path(self) -> str:
        return f"projects/{self.project_id}"

    def _secret_id(self, name: str) -> str:
        if name.startswith("projects/"):
            parts = name.split("/")
            if "secrets" in parts:
                idx = parts.index("secrets")
                if idx + 1 < len(parts):
                    return parts[idx + 1]
        return name

    def _secret_path(self, name: str) -> str:
        return f"{self._project_path()}/secrets/{self._secret_id(name)}"

    def _version_path(self, name: str, version: str = "latest") -> str:
        if name.startswith("projects/") and "/versions/" in name:
            return name
        if name.startswith("projects/") and "/secrets/" in name:
            return f"{name}/versions/{version}"
        return f"{self._secret_path(name)}/versions/{version}"

    def authenticate(self) -> None:
        """
        Authenticate to GCP Secret Manager and initialize the client.

        Raises AuthenticationError for credential issues and VaultError for API failures.
        """
        secretmanager, google_exceptions = _get_gcp_modules()
        try:
            self._client = secretmanager.SecretManagerServiceClient()
            secrets_iter = self._client.list_secrets(
                request={"parent": self._project_path(), "page_size": 1}
            )
            next(iter(secrets_iter), None)
        except DefaultCredentialsError as e:
            self._client = None
            raise AuthenticationError(f"GCP authentication failed: {e}") from e
        except (
            google_exceptions.PermissionDenied,
            google_exceptions.Unauthenticated,
        ) as e:
            self._client = None
            raise AuthenticationError(f"GCP authentication failed: {e}") from e
        except google_exceptions.GoogleAPICallError as e:
            self._client = None
            raise VaultError(f"GCP Secret Manager error: {e}") from e

    def is_authenticated(self) -> bool:
        return self._client is not None

    def get_secret(self, name: str) -> SecretValue:
        """
        Retrieve a secret from GCP Secret Manager.

        Parameters:
            name (str): Secret name or full resource path.

        Returns:
            SecretValue: Contains the secret's name, value, version, and metadata.
        """
        self.ensure_authenticated()
        _, google_exceptions = _get_gcp_modules()

        try:
            version_path = self._version_path(name)
            response = self._client.access_secret_version(request={"name": version_path})
            payload = response.payload.data if response.payload else b""
            try:
                value = payload.decode("utf-8")
            except UnicodeDecodeError:
                import base64

                value = base64.b64encode(payload).decode("ascii")
            version = response.name.split("/")[-1] if response.name else None
            return SecretValue(
                name=self._secret_id(name),
                value=value,
                version=version,
                metadata={"name": response.name},
            )
        except google_exceptions.NotFound as e:
            raise SecretNotFoundError(f"Secret '{name}' not found") from e
        except (
            google_exceptions.PermissionDenied,
            google_exceptions.Unauthenticated,
        ) as e:
            raise AuthenticationError(f"Access denied to secret '{name}': {e}") from e
        except google_exceptions.GoogleAPICallError as e:
            raise VaultError(f"GCP Secret Manager error: {e}") from e

    def list_secrets(self, prefix: str = "") -> list[str]:
        """
        List secret names in the project, optionally filtered by a prefix.

        Parameters:
            prefix (str): Optional prefix to filter secret names.
        """
        self.ensure_authenticated()
        _, google_exceptions = _get_gcp_modules()

        try:
            secrets = []
            for secret in self._client.list_secrets(request={"parent": self._project_path()}):
                secret_id = secret.name.split("/")[-1] if secret.name else ""
                if secret_id and (not prefix or secret_id.startswith(prefix)):
                    secrets.append(secret_id)
            return sorted(secrets)
        except (
            google_exceptions.PermissionDenied,
            google_exceptions.Unauthenticated,
        ) as e:
            raise AuthenticationError(f"Access denied to list secrets: {e}") from e
        except google_exceptions.GoogleAPICallError as e:
            raise VaultError(f"GCP Secret Manager error: {e}") from e

    def set_secret(self, name: str, value: str) -> SecretValue:
        """
        Create or update a secret in GCP Secret Manager.

        Returns:
            SecretValue containing the stored secret's name, value, version, and metadata.
        """
        self.ensure_authenticated()
        _, google_exceptions = _get_gcp_modules()

        secret_id = self._secret_id(name)
        secret_path = self._secret_path(name)

        try:
            with contextlib.suppress(google_exceptions.AlreadyExists):
                self._client.create_secret(
                    request={
                        "parent": self._project_path(),
                        "secret_id": secret_id,
                        "secret": {"replication": {"automatic": {}}},
                    }
                )

            version = self._client.add_secret_version(
                request={
                    "parent": secret_path,
                    "payload": {"data": value.encode("utf-8")},
                }
            )
            version_id = version.name.split("/")[-1] if version.name else None
            return SecretValue(
                name=secret_id,
                value=value,
                version=version_id,
                metadata={"name": version.name},
            )
        except (
            google_exceptions.PermissionDenied,
            google_exceptions.Unauthenticated,
        ) as e:
            raise AuthenticationError(f"Access denied to write secret '{name}': {e}") from e
        except google_exceptions.GoogleAPICallError as e:
            raise VaultError(f"GCP Secret Manager error: {e}") from e
