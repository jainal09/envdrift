"""Tests for envdrift.vault.gcp module - GCP Secret Manager client."""

from __future__ import annotations

import base64
import importlib
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from envdrift.vault.base import AuthenticationError, SecretNotFoundError, VaultError


class DummyGcpError(Exception):
    """Base error for fake GCP exceptions."""


class DummyGoogleAPICallError(DummyGcpError):
    """Fake GoogleAPICallError.

    The real ``google.api_core.exceptions.GoogleAPICallError`` is the generic
    base of the concrete status errors below (PermissionDenied, Unauthenticated,
    NotFound, AlreadyExists all subclass it via ClientError). Mirroring that MRO
    here is load-bearing: ``authenticate()`` relies on the *specific* clauses
    (PermissionDenied -> accept, Unauthenticated -> reject) preceding the generic
    ``except GoogleAPICallError`` clause. If these fakes were flat siblings, a
    reordering regression (generic clause first) would still pass the tests while
    re-breaking #359 in the real SDK. See test_authenticate_except_clause_ordering.
    """


class DummyPermissionDeniedError(DummyGoogleAPICallError):
    """Fake PermissionDenied (a GoogleAPICallError subclass, as in the real SDK)."""


class DummyUnauthenticatedError(DummyGoogleAPICallError):
    """Fake Unauthenticated (a GoogleAPICallError subclass, as in the real SDK)."""


class DummyNotFoundError(DummyGoogleAPICallError):
    """Fake NotFound (a GoogleAPICallError subclass, as in the real SDK)."""


class DummyAlreadyExistsError(DummyGoogleAPICallError):
    """Fake AlreadyExists (a GoogleAPICallError subclass, as in the real SDK)."""


class DummyGoogleAuthError(Exception):
    """Fake ``google.auth.exceptions.GoogleAuthError`` (the auth-layer base).

    The real SDK makes ``DefaultCredentialsError``, ``RefreshError`` and
    ``TransportError`` all subclass ``GoogleAuthError`` (and crucially NONE of them
    subclass ``GoogleAPICallError``). Mirroring that here is load-bearing: it lets
    the tests exercise the production split where ``RefreshError`` -> auth failure
    and other ``GoogleAuthError`` (e.g. ``TransportError``) -> ``VaultError``.
    """


class DummyDefaultCredentialsError(DummyGoogleAuthError):
    """Fake DefaultCredentialsError (a GoogleAuthError subclass, as in the real SDK)."""


class DummyRefreshError(DummyGoogleAuthError):
    """Fake RefreshError (a GoogleAuthError subclass; e.g. invalid_grant)."""


class DummyTransportError(DummyGoogleAuthError):
    """Fake TransportError (a GoogleAuthError subclass; DNS/TLS/connectivity)."""


@pytest.fixture
def mock_gcp():
    """Mock GCP SDK modules."""
    exceptions_mod = SimpleNamespace(
        GoogleAPICallError=DummyGoogleAPICallError,
        PermissionDenied=DummyPermissionDeniedError,
        Unauthenticated=DummyUnauthenticatedError,
        NotFound=DummyNotFoundError,
        AlreadyExists=DummyAlreadyExistsError,
    )
    api_core_mod = SimpleNamespace(exceptions=exceptions_mod)

    auth_exceptions_mod = SimpleNamespace(
        GoogleAuthError=DummyGoogleAuthError,
        DefaultCredentialsError=DummyDefaultCredentialsError,
        RefreshError=DummyRefreshError,
        TransportError=DummyTransportError,
    )
    auth_mod = SimpleNamespace(exceptions=auth_exceptions_mod)

    secretmanager_mod = SimpleNamespace(SecretManagerServiceClient=MagicMock())
    cloud_mod = SimpleNamespace(secretmanager=secretmanager_mod)

    google_mod = SimpleNamespace(
        api_core=api_core_mod,
        auth=auth_mod,
        cloud=cloud_mod,
    )

    import envdrift.vault.gcp as gcp_module

    try:
        with patch.dict(
            sys.modules,
            {
                "google": google_mod,
                "google.api_core": api_core_mod,
                "google.api_core.exceptions": exceptions_mod,
                "google.auth": auth_mod,
                "google.auth.exceptions": auth_exceptions_mod,
                "google.cloud": cloud_mod,
                "google.cloud.secretmanager": secretmanager_mod,
            },
        ):
            importlib.reload(gcp_module)
            yield gcp_module
    finally:
        # patch.dict has restored sys.modules by now; reload once more so the
        # module re-binds the REAL GCP SDK (or its genuine unavailable state)
        # instead of leaving the stubs poisoning later tests in-process (#497) —
        # test_vault_gcp_paths.py runs right after this file in the unit lane.
        importlib.reload(gcp_module)


class TestGCPSecretManagerClient:
    """Tests for GCPSecretManagerClient."""

    def test_init_sets_project_id(self, mock_gcp):
        """Test client initializes with project ID."""
        client = mock_gcp.GCPSecretManagerClient(project_id="my-project")
        assert client.project_id == "my-project"

    def test_is_authenticated_false_initially(self, mock_gcp):
        """Test is_authenticated returns False before authentication."""
        client = mock_gcp.GCPSecretManagerClient(project_id="my-project")
        assert client.is_authenticated() is False

    def test_authenticate_success(self, mock_gcp):
        """Test successful authentication."""
        mock_client = MagicMock()
        mock_client.list_secrets.return_value = iter([])
        mock_gcp._secretmanager.SecretManagerServiceClient.return_value = mock_client

        client = mock_gcp.GCPSecretManagerClient(project_id="my-project")
        client.authenticate()

        assert client.is_authenticated() is True
        assert client._client is mock_client

    def test_get_secret(self, mock_gcp):
        """Test retrieving a secret."""
        mock_client = MagicMock()
        mock_client.list_secrets.return_value = iter([])
        mock_client.access_secret_version.return_value = SimpleNamespace(
            name="projects/my-project/secrets/my-secret/versions/3",
            payload=SimpleNamespace(data=b"secret-value"),
        )
        mock_gcp._secretmanager.SecretManagerServiceClient.return_value = mock_client

        client = mock_gcp.GCPSecretManagerClient(project_id="my-project")
        client.authenticate()

        secret = client.get_secret("my-secret")
        assert secret.name == "my-secret"
        assert secret.value == "secret-value"
        assert secret.version == "3"

    def test_list_secrets_with_prefix(self, mock_gcp):
        """Test listing secrets with prefix filter."""
        mock_client = MagicMock()
        mock_client.list_secrets.side_effect = [
            iter([]),
            iter(
                [
                    SimpleNamespace(name="projects/my-project/secrets/app-secret1"),
                    SimpleNamespace(name="projects/my-project/secrets/app-secret2"),
                    SimpleNamespace(name="projects/my-project/secrets/other-secret"),
                ]
            ),
        ]
        mock_gcp._secretmanager.SecretManagerServiceClient.return_value = mock_client

        client = mock_gcp.GCPSecretManagerClient(project_id="my-project")
        client.authenticate()

        secrets = client.list_secrets(prefix="app-")
        assert "app-secret1" in secrets
        assert "app-secret2" in secrets
        assert "other-secret" not in secrets

    def test_set_secret(self, mock_gcp):
        """Test setting a secret."""
        mock_client = MagicMock()
        mock_client.list_secrets.return_value = iter([])
        mock_client.add_secret_version.return_value = SimpleNamespace(
            name="projects/my-project/secrets/my-secret/versions/5"
        )
        mock_gcp._secretmanager.SecretManagerServiceClient.return_value = mock_client

        client = mock_gcp.GCPSecretManagerClient(project_id="my-project")
        client.authenticate()

        result = client.set_secret("my-secret", "value")
        assert result.name == "my-secret"
        assert result.value == "value"
        assert result.version == "5"

    def test_secret_helpers(self, mock_gcp):
        """Test helper path methods (same-project fully-qualified names allowed)."""
        client = mock_gcp.GCPSecretManagerClient(project_id="my-project")

        assert client._secret_id("plain-secret") == "plain-secret"
        assert client._secret_id("projects/my-project/secrets/secret-1") == "secret-1"
        assert client._secret_id("projects/my-project/secrets/secret-2/versions/9") == "secret-2"
        # A fully-qualified name that isn't the canonical projects/<P>/secrets/<S>[/versions/<V>]
        # shape is now hard-failed rather than silently passed through (see #393 / CodeRabbit).
        with pytest.raises(VaultError, match="Malformed"):
            client._secret_id("projects/my-project/other/secret-3")

        assert client._version_path("projects/my-project/secrets/secret-4/versions/7") == (
            "projects/my-project/secrets/secret-4/versions/7"
        )
        assert client._version_path("projects/my-project/secrets/secret-5", version="8") == (
            "projects/my-project/secrets/secret-5/versions/8"
        )
        assert client._version_path("secret-6") == (
            "projects/my-project/secrets/secret-6/versions/latest"
        )

    def test_authenticate_default_credentials_error(self, mock_gcp):
        """DefaultCredentialsError should map to AuthenticationError."""
        mock_gcp._secretmanager.SecretManagerServiceClient.side_effect = (
            mock_gcp.DefaultCredentialsError("no creds")
        )

        client = mock_gcp.GCPSecretManagerClient(project_id="my-project")
        with pytest.raises(AuthenticationError):
            client.authenticate()

        assert client.is_authenticated() is False

    def test_authenticate_permission_denied_on_list_probe_accepted(self, mock_gcp):
        """PermissionDenied on the list probe means the credential authenticated but
        lacks ``secretmanager.secrets.list``.

        A least-privilege service account holding only
        ``secretmanager.versions.access`` (enough for get_secret, which is all sync
        needs) hits this. authenticate() must NOT raise and must retain the client so
        get_secret can still surface a clear error per-secret later (see #359, GCP half).
        """
        mock_client = MagicMock()
        mock_client.list_secrets.side_effect = mock_gcp._google_exceptions.PermissionDenied(
            "permission 'secretmanager.secrets.list' denied"
        )
        mock_gcp._secretmanager.SecretManagerServiceClient.return_value = mock_client

        client = mock_gcp.GCPSecretManagerClient(project_id="my-project")
        client.authenticate()

        assert client.is_authenticated() is True
        assert client._client is mock_client

    def test_authenticate_unauthenticated_still_fails(self, mock_gcp):
        """Unauthenticated is a genuine credential failure and must still raise.

        Unlike PermissionDenied (authenticated, missing list permission), an
        Unauthenticated error means the credential itself is invalid/expired, so
        authenticate() must map it to AuthenticationError and drop the client.
        """
        mock_client = MagicMock()
        mock_client.list_secrets.side_effect = mock_gcp._google_exceptions.Unauthenticated(
            "invalid credentials"
        )
        mock_gcp._secretmanager.SecretManagerServiceClient.return_value = mock_client

        client = mock_gcp.GCPSecretManagerClient(project_id="my-project")
        with pytest.raises(AuthenticationError):
            client.authenticate()

        assert client.is_authenticated() is False

    def test_authenticate_google_api_error(self, mock_gcp):
        """GoogleAPICallError should map to VaultError."""
        mock_client = MagicMock()
        mock_client.list_secrets.side_effect = mock_gcp._google_exceptions.GoogleAPICallError(
            "boom"
        )
        mock_gcp._secretmanager.SecretManagerServiceClient.return_value = mock_client

        client = mock_gcp.GCPSecretManagerClient(project_id="my-project")
        with pytest.raises(VaultError):
            client.authenticate()

        assert client.is_authenticated() is False

    def test_authenticate_except_clause_ordering(self, mock_gcp):
        """The specific PermissionDenied/Unauthenticated clauses must precede the
        generic GoogleAPICallError clause in authenticate().

        Both PermissionDenied and Unauthenticated subclass GoogleAPICallError (in
        the real SDK and now in these fakes), so a generic-first ordering would
        swallow BOTH of them as VaultError. This test pins the outcomes that only
        hold under the production specific-before-generic order:

        - PermissionDenied (subclass of GoogleAPICallError) -> ACCEPTED (no raise,
          client retained), per the #359 least-privilege fix.
        - Unauthenticated (subclass of GoogleAPICallError) -> AuthenticationError,
          NOT VaultError.

        If someone moves ``except GoogleAPICallError`` ahead of the specific
        clauses, PermissionDenied stops being accepted (caught as VaultError) and
        Unauthenticated is mis-categorized as VaultError — both assertions below
        fail, catching the regression.
        """
        exc = mock_gcp._google_exceptions
        # Sanity: the fakes mirror the real MRO (specific errors ARE GoogleAPICallError).
        assert issubclass(exc.PermissionDenied, exc.GoogleAPICallError)
        assert issubclass(exc.Unauthenticated, exc.GoogleAPICallError)

        # PermissionDenied is accepted even though it is a GoogleAPICallError subclass.
        mock_client = MagicMock()
        mock_client.list_secrets.side_effect = exc.PermissionDenied("list denied")
        mock_gcp._secretmanager.SecretManagerServiceClient.return_value = mock_client
        client = mock_gcp.GCPSecretManagerClient(project_id="my-project")
        client.authenticate()
        assert client.is_authenticated() is True
        assert client._client is mock_client

        # Unauthenticated maps to AuthenticationError (not VaultError) and drops the client.
        mock_client_2 = MagicMock()
        mock_client_2.list_secrets.side_effect = exc.Unauthenticated("invalid creds")
        mock_gcp._secretmanager.SecretManagerServiceClient.return_value = mock_client_2
        client_2 = mock_gcp.GCPSecretManagerClient(project_id="my-project")
        with pytest.raises(AuthenticationError):
            client_2.authenticate()
        assert client_2.is_authenticated() is False

    def test_authenticate_refresh_error_maps_to_authentication_error(self, mock_gcp):
        """Regression #413: a token-refresh failure (RefreshError, e.g. invalid_grant)
        during authenticate() is an *auth* problem and must map to AuthenticationError.

        RefreshError is a GoogleAuthError (NOT a GoogleAPICallError), so it previously
        escaped every except clause and propagated as a raw SDK exception.
        """
        mock_client = MagicMock()
        mock_client.list_secrets.side_effect = mock_gcp.RefreshError("invalid_grant")
        mock_gcp._secretmanager.SecretManagerServiceClient.return_value = mock_client

        client = mock_gcp.GCPSecretManagerClient(project_id="my-project")
        with pytest.raises(AuthenticationError):
            client.authenticate()

        assert client.is_authenticated() is False

    def test_authenticate_transport_error_maps_to_vault_error(self, mock_gcp):
        """Regression #413: a transport-layer GoogleAuthError (TransportError:
        DNS/TLS/connectivity) during authenticate() is wrapped as VaultError, not
        leaked raw. It is a GoogleAuthError but NOT a GoogleAPICallError, so it
        previously escaped all handlers.
        """
        mock_client = MagicMock()
        mock_client.list_secrets.side_effect = mock_gcp.GoogleAuthError("network unreachable")
        mock_gcp._secretmanager.SecretManagerServiceClient.return_value = mock_client

        client = mock_gcp.GCPSecretManagerClient(project_id="my-project")
        with pytest.raises(VaultError) as exc_info:
            client.authenticate()

        # Must be a domain VaultError, not the raw auth-layer exception.
        assert not isinstance(exc_info.value, mock_gcp.GoogleAuthError)
        assert client.is_authenticated() is False

    @staticmethod
    def _authenticated_client_with_op_error(mock_gcp, *, op: str, error: Exception):
        """Build an authenticated client whose post-auth ``op`` call raises ``error``.

        Authentication consumes the first ``list_secrets`` (an empty iterator); the
        injected error is wired onto the operation under test so the four
        auth-layer-failure regressions (#413) share one setup instead of copying
        the build/authenticate boilerplate.
        """
        mock_client = MagicMock()
        if op == "list_secrets":
            # list_secrets is called twice: once by authenticate(), once under test.
            mock_client.list_secrets.side_effect = [iter([]), error]
        else:
            mock_client.list_secrets.return_value = iter([])
            getattr(mock_client, op).side_effect = error
        mock_gcp._secretmanager.SecretManagerServiceClient.return_value = mock_client
        client = mock_gcp.GCPSecretManagerClient(project_id="my-project")
        client.authenticate()
        return client

    def test_get_secret_refresh_error_maps_to_authentication_error(self, mock_gcp):
        """Regression #413: a RefreshError during get_secret() maps to AuthenticationError."""
        client = self._authenticated_client_with_op_error(
            mock_gcp, op="access_secret_version", error=mock_gcp.RefreshError("invalid_grant")
        )
        with pytest.raises(AuthenticationError):
            client.get_secret("secret-name")

    @pytest.mark.parametrize(
        ("op", "call"),
        [
            ("access_secret_version", lambda c: c.get_secret("secret-name")),
            ("list_secrets", lambda c: c.list_secrets()),
            ("add_secret_version", lambda c: c.set_secret("write-error", "value")),
        ],
    )
    def test_transport_error_maps_to_vault_error(self, mock_gcp, op, call):
        """Regression #413: a transport GoogleAuthError during any operation is wrapped
        as a domain VaultError rather than leaked as a raw auth-layer SDK exception.
        """
        client = self._authenticated_client_with_op_error(
            mock_gcp, op=op, error=mock_gcp.GoogleAuthError("network down")
        )
        with pytest.raises(VaultError) as exc_info:
            call(client)
        assert not isinstance(exc_info.value, mock_gcp.GoogleAuthError)

    def test_get_secret_binary_payload(self, mock_gcp):
        """Binary payload should be base64-encoded."""
        payload = b"\xff\xff"
        mock_client = MagicMock()
        mock_client.list_secrets.return_value = iter([])
        mock_client.access_secret_version.return_value = SimpleNamespace(
            name="projects/my-project/secrets/bin/versions/1",
            payload=SimpleNamespace(data=payload),
        )
        mock_gcp._secretmanager.SecretManagerServiceClient.return_value = mock_client

        client = mock_gcp.GCPSecretManagerClient(project_id="my-project")
        client.authenticate()

        secret = client.get_secret("bin")
        assert secret.value == base64.b64encode(payload).decode("ascii")
        assert secret.version == "1"

    def test_get_secret_not_found(self, mock_gcp):
        """NotFound should map to SecretNotFoundError."""
        mock_client = MagicMock()
        mock_client.list_secrets.return_value = iter([])
        mock_client.access_secret_version.side_effect = mock_gcp._google_exceptions.NotFound(
            "missing"
        )
        mock_gcp._secretmanager.SecretManagerServiceClient.return_value = mock_client

        client = mock_gcp.GCPSecretManagerClient(project_id="my-project")
        client.authenticate()

        with pytest.raises(SecretNotFoundError):
            client.get_secret("missing-secret")

    def test_get_secret_permission_denied(self, mock_gcp):
        """PermissionDenied should map to AuthenticationError."""
        mock_client = MagicMock()
        mock_client.list_secrets.return_value = iter([])
        mock_client.access_secret_version.side_effect = (
            mock_gcp._google_exceptions.PermissionDenied("denied")
        )
        mock_gcp._secretmanager.SecretManagerServiceClient.return_value = mock_client

        client = mock_gcp.GCPSecretManagerClient(project_id="my-project")
        client.authenticate()

        with pytest.raises(AuthenticationError):
            client.get_secret("secret-name")

    def test_get_secret_google_api_error(self, mock_gcp):
        """GoogleAPICallError should map to VaultError."""
        mock_client = MagicMock()
        mock_client.list_secrets.return_value = iter([])
        mock_client.access_secret_version.side_effect = (
            mock_gcp._google_exceptions.GoogleAPICallError("boom")
        )
        mock_gcp._secretmanager.SecretManagerServiceClient.return_value = mock_client

        client = mock_gcp.GCPSecretManagerClient(project_id="my-project")
        client.authenticate()

        with pytest.raises(VaultError):
            client.get_secret("secret-name")

    def test_list_secrets_permission_denied(self, mock_gcp):
        """PermissionDenied should map to AuthenticationError."""
        mock_client = MagicMock()
        mock_client.list_secrets.side_effect = [
            iter([]),
            mock_gcp._google_exceptions.PermissionDenied("denied"),
        ]
        mock_gcp._secretmanager.SecretManagerServiceClient.return_value = mock_client

        client = mock_gcp.GCPSecretManagerClient(project_id="my-project")
        client.authenticate()

        with pytest.raises(AuthenticationError):
            client.list_secrets()

    def test_list_secrets_google_api_error(self, mock_gcp):
        """GoogleAPICallError should map to VaultError."""
        mock_client = MagicMock()
        mock_client.list_secrets.side_effect = [
            iter([]),
            mock_gcp._google_exceptions.GoogleAPICallError("boom"),
        ]
        mock_gcp._secretmanager.SecretManagerServiceClient.return_value = mock_client

        client = mock_gcp.GCPSecretManagerClient(project_id="my-project")
        client.authenticate()

        with pytest.raises(VaultError):
            client.list_secrets()

    def test_set_secret_permission_denied(self, mock_gcp):
        """PermissionDenied should map to AuthenticationError."""
        mock_client = MagicMock()
        mock_client.list_secrets.return_value = iter([])
        mock_client.add_secret_version.side_effect = mock_gcp._google_exceptions.PermissionDenied(
            "denied"
        )
        mock_gcp._secretmanager.SecretManagerServiceClient.return_value = mock_client

        client = mock_gcp.GCPSecretManagerClient(project_id="my-project")
        client.authenticate()

        with pytest.raises(AuthenticationError):
            client.set_secret("write-denied", "value")

    def test_set_secret_google_api_error(self, mock_gcp):
        """GoogleAPICallError should map to VaultError."""
        mock_client = MagicMock()
        mock_client.list_secrets.return_value = iter([])
        mock_client.add_secret_version.side_effect = mock_gcp._google_exceptions.GoogleAPICallError(
            "boom"
        )
        mock_gcp._secretmanager.SecretManagerServiceClient.return_value = mock_client

        client = mock_gcp.GCPSecretManagerClient(project_id="my-project")
        client.authenticate()

        with pytest.raises(VaultError):
            client.set_secret("write-error", "value")

    def test_set_secret_existing_secret(self, mock_gcp):
        """AlreadyExists should be suppressed when creating secrets."""
        mock_client = MagicMock()
        mock_client.list_secrets.return_value = iter([])
        mock_client.create_secret.side_effect = mock_gcp._google_exceptions.AlreadyExists("exists")
        mock_client.add_secret_version.return_value = SimpleNamespace(
            name="projects/my-project/secrets/my-secret/versions/9"
        )
        mock_gcp._secretmanager.SecretManagerServiceClient.return_value = mock_client

        client = mock_gcp.GCPSecretManagerClient(project_id="my-project")
        client.authenticate()

        result = client.set_secret("my-secret", "value")
        assert result.version == "9"
