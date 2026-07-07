"""GCP Secret Manager client implementation."""

from __future__ import annotations

import contextlib
import re
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
    from google.auth.exceptions import (
        DefaultCredentialsError,
        GoogleAuthError,
        RefreshError,
    )
    from google.cloud import secretmanager as _secretmanager

    GCP_AVAILABLE = True
except ImportError:
    GCP_AVAILABLE = False
    _secretmanager = None
    _google_exceptions = None
    DefaultCredentialsError = Exception  # type: ignore[misc, assignment]
    GoogleAuthError = Exception  # type: ignore[misc, assignment]
    RefreshError = Exception  # type: ignore[misc, assignment]


def _get_gcp_modules() -> tuple[Any, Any]:
    """Get GCP modules, raising ImportError if not available."""
    if not GCP_AVAILABLE or _secretmanager is None or _google_exceptions is None:
        raise ImportError(
            "GCP Secret Manager support requires additional dependencies. "
            "Install with: pip install envdrift[gcp]"
        )
    return _secretmanager, _google_exceptions


def _map_gcp_error(
    e: Exception,
    google_exceptions: Any,
    *,
    denied_msg: str,
    not_found_msg: str | None = None,
) -> Exception:
    """Translate a GCP SDK exception into a domain error.

    Shared by get/list/set so each delegates instead of repeating the
    not-found/permission/API/auth catch ladder:

    - ``NotFound`` -> ``SecretNotFoundError`` (only when ``not_found_msg`` given).
    - ``PermissionDenied`` / ``Unauthenticated`` (authz/expired-token) and
      ``RefreshError`` (mid-session refresh failure) -> ``AuthenticationError``.
    - ``GoogleAPICallError`` and any other ``GoogleAuthError`` (e.g. transport
      ``TransportError``) -> ``VaultError``.

    ``RefreshError`` is a ``GoogleAuthError`` subclass, so it is checked first.
    """
    if not_found_msg is not None and isinstance(e, google_exceptions.NotFound):
        return SecretNotFoundError(not_found_msg)
    if isinstance(
        e, (google_exceptions.PermissionDenied, google_exceptions.Unauthenticated, RefreshError)
    ):
        return AuthenticationError(denied_msg)
    return VaultError(f"GCP Secret Manager error: {e}")


# Canonical GCP Secret Manager resource name: projects/<P>/secrets/<S> optionally
# followed by /versions/<V>. Each segment is non-empty and slash-free. A bare
# secret name (no `projects/` prefix) is handled separately and resolves under the
# bound project. Declaring the shape once here keeps validation in a single place.
_QUALIFIED_NAME_RE = re.compile(r"^projects/(?P<project>[^/]+)/secrets/[^/]+(?:/versions/[^/]+)?$")


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

    def _validate_project(self, name: str) -> None:
        """Reject resource names that are malformed or target a different project.

        A bare secret name (no ``projects/`` prefix) is left to resolve under the
        bound project. A fully-qualified name must match the canonical shape
        ``projects/<P>/secrets/<S>`` optionally followed by ``/versions/<V>``, and
        ``<P>`` must match the project this backend is bound to. This prevents a
        caller-supplied name from being silently rewritten into a synthetic path
        (e.g. ``projects/<P>`` or ``projects/<P>/other/<S>``) or from crossing the
        configured project boundary.
        """
        if not name.startswith("projects/"):
            return
        match = _QUALIFIED_NAME_RE.match(name)
        if match is None:
            raise VaultError(f"Malformed GCP secret resource name: {name!r}")
        requested_project = match.group("project")
        if requested_project != self.project_id:
            raise VaultError(
                f"Secret resource name targets project {requested_project!r}, "
                f"but this backend is bound to project {self.project_id!r}. "
                f"Cross-project access is not allowed."
            )

    def _secret_id(self, name: str) -> str:
        self._validate_project(name)
        if name.startswith("projects/"):
            parts = name.split("/")
            if "secrets" in parts:
                idx = parts.index("secrets")
                if idx + 1 < len(parts):
                    return parts[idx + 1]
        return name

    def _secret_path(self, name: str) -> str:
        self._validate_project(name)
        return f"{self._project_path()}/secrets/{self._secret_id(name)}"

    def _version_path(self, name: str, version: str = "latest") -> str:
        self._validate_project(name)
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
        except google_exceptions.PermissionDenied:
            # The credential authenticated successfully but lacks
            # `secretmanager.secrets.list`. A least-privilege service account that
            # only holds `secretmanager.versions.access` (enough for get_secret,
            # which is all sync needs) hits this on the list probe. Treat it as
            # authenticated-but-cannot-list: keep the client. If a specific secret
            # genuinely can't be read, get_secret() surfaces a clear error later.
            pass
        except (
            DefaultCredentialsError,
            google_exceptions.GoogleAPICallError,
            GoogleAuthError,
        ) as e:
            # Any other failure invalidates the half-initialized client. Map it
            # via the shared helper: DefaultCredentialsError (no usable ADC) is a
            # genuine auth failure, so treat it like the access-denied family.
            self._client = None
            if isinstance(e, DefaultCredentialsError):
                raise AuthenticationError(f"GCP authentication failed: {e}") from e
            raise _map_gcp_error(
                e, google_exceptions, denied_msg=f"GCP authentication failed: {e}"
            ) from e

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
            metadata: dict[str, Any] = {"name": response.name}
            try:
                value = payload.decode("utf-8")
            except UnicodeDecodeError:
                import base64

                value = base64.b64encode(payload).decode("ascii")
                # Mark the transformation: the value is no longer the stored
                # bytes. dotenvx key flows reject base64-marked payloads instead
                # of installing them as key material (#480).
                metadata["encoding"] = "base64"
            version = response.name.split("/")[-1] if response.name else None
            return SecretValue(
                name=self._secret_id(name),
                value=value,
                version=version,
                metadata=metadata,
            )
        except (google_exceptions.GoogleAPICallError, GoogleAuthError) as e:
            raise _map_gcp_error(
                e,
                google_exceptions,
                denied_msg=f"Access denied to secret '{name}': {e}",
                not_found_msg=f"Secret '{name}' not found",
            ) from e

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
        except (google_exceptions.GoogleAPICallError, GoogleAuthError) as e:
            raise _map_gcp_error(
                e, google_exceptions, denied_msg=f"Access denied to list secrets: {e}"
            ) from e

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
        except (google_exceptions.GoogleAPICallError, GoogleAuthError) as e:
            raise _map_gcp_error(
                e, google_exceptions, denied_msg=f"Access denied to write secret '{name}': {e}"
            ) from e
