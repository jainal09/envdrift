"""Tests for envdrift.vault.azure module - Azure Key Vault client."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from envdrift.vault.base import AuthenticationError, SecretNotFoundError, VaultError


class FakeAzureError(Exception):
    """Stand-in for ``azure.core.exceptions.AzureError`` (the SDK error base).

    The real MRO is ``HttpResponseError -> AzureError`` and
    ``ServiceRequestError -> AzureError`` (the latter is a transport failure and is
    NOT a ``HttpResponseError``). Modeling that here lets the tests prove a
    transport ``ServiceRequestError`` is wrapped as a domain ``VaultError`` while
    still reaching the dedicated ``AzureError`` catch-all clause.
    """


class FakeHttpResponseError(FakeAzureError):
    """Stand-in for ``azure.core.exceptions.HttpResponseError``.

    Carries a ``status_code`` like the real SDK exception so the production
    ``status_code == 403`` accept branch can be exercised. Subclasses
    ``FakeAzureError`` to mirror the real ``HttpResponseError -> AzureError`` MRO.
    """

    def __init__(self, message: str = "", status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class FakeServiceRequestError(FakeAzureError):
    """Stand-in for ``azure.core.exceptions.ServiceRequestError`` (transport).

    Critically it subclasses ``FakeAzureError`` but NOT ``FakeHttpResponseError``,
    mirroring the real SDK: a DNS/TLS/connectivity failure that the production
    ``except HttpResponseError`` clause does NOT catch, so it must fall through to
    the dedicated ``except AzureError`` catch-all and be wrapped as a VaultError.
    """


class FakeClientAuthenticationError(FakeHttpResponseError):
    """Stand-in for ``azure.core.exceptions.ClientAuthenticationError``.

    Critically, this **subclasses** :class:`FakeHttpResponseError`, mirroring the
    real SDK MRO (``ClientAuthenticationError -> HttpResponseError -> AzureError``).
    Without this inheritance the production except-clause *ordering* (catch
    ``ClientAuthenticationError`` before ``HttpResponseError``) is never exercised,
    and a reordering/collapse regression would slip through. Defaults to a 401
    ``status_code``, consistent with a real credential failure.
    """

    def __init__(self, message: str = "", status_code: int | None = 401):
        super().__init__(message, status_code=status_code)


class FakeResourceNotFoundError(FakeHttpResponseError):
    """Stand-in for ``azure.core.exceptions.ResourceNotFoundError`` (a 404)."""

    def __init__(self, message: str = "", status_code: int | None = 404):
        super().__init__(message, status_code=status_code)


class TestAzureKeyVaultClient:
    """Tests for AzureKeyVaultClient."""

    @pytest.fixture
    def mock_azure(self):
        """Mock Azure SDK."""
        import importlib

        import envdrift.vault.azure as azure_module

        try:
            with patch.dict(
                "sys.modules",
                {
                    "azure": MagicMock(),
                    "azure.core": MagicMock(),
                    "azure.core.exceptions": MagicMock(),
                    "azure.identity": MagicMock(),
                    "azure.keyvault": MagicMock(),
                    "azure.keyvault.secrets": MagicMock(),
                },
            ):
                importlib.reload(azure_module)
                yield azure_module
        finally:
            # patch.dict has restored sys.modules by now; reload once more so the
            # module re-binds the REAL Azure SDK (or its genuine unavailable state)
            # instead of leaving MagicMocks poisoning later tests in-process (#497).
            importlib.reload(azure_module)

    @contextmanager
    def _patched_client(
        self,
        mock_azure: Any,
        secret_client: MagicMock,
        *,
        credential: MagicMock | None = None,
        faithful_exceptions: bool = False,
    ) -> Iterator[Any]:
        """Build an ``AzureKeyVaultClient`` wired to ``secret_client``.

        Patches ``_DefaultAzureCredential`` / ``_SecretClient`` so ``authenticate()``
        uses the supplied mock secret client. When ``faithful_exceptions`` is set,
        the module's ``HttpResponseError`` / ``ClientAuthenticationError`` /
        ``ResourceNotFoundError`` are swapped for the faithful fakes above (whose
        MRO mirrors the real Azure SDK), so the production except-clause ordering is
        actually exercised.
        """
        cred = credential if credential is not None else MagicMock()
        with (
            patch.object(mock_azure, "_DefaultAzureCredential", return_value=cred),
            patch.object(mock_azure, "_SecretClient", return_value=secret_client),
        ):
            if faithful_exceptions:
                mock_azure.AzureError = FakeAzureError
                mock_azure.HttpResponseError = FakeHttpResponseError
                mock_azure.ClientAuthenticationError = FakeClientAuthenticationError
                mock_azure.ResourceNotFoundError = FakeResourceNotFoundError
            client = mock_azure.AzureKeyVaultClient(vault_url="https://test.vault.azure.net")
            yield client

    def test_init_sets_vault_url(self, mock_azure):
        """Test client initializes with vault URL."""
        client = mock_azure.AzureKeyVaultClient(vault_url="https://myvault.vault.azure.net")
        assert client.vault_url == "https://myvault.vault.azure.net"

    def test_is_authenticated_false_initially(self, mock_azure):
        """Test is_authenticated returns False before authentication."""
        client = mock_azure.AzureKeyVaultClient(vault_url="https://test.vault.azure.net")
        assert client.is_authenticated() is False

    def test_authenticate_success(self, mock_azure):
        """Test successful authentication."""
        mock_secret_client = MagicMock()
        mock_secret_client.list_properties_of_secrets.return_value = iter([])

        with self._patched_client(mock_azure, mock_secret_client) as client:
            client.authenticate()

            assert client.is_authenticated() is True
            assert client._client is not None

    def test_get_secret(self, mock_azure):
        """Test retrieving a secret."""
        mock_secret_client = MagicMock()
        mock_secret_client.list_properties_of_secrets.return_value = iter([])

        # Create mock secret response
        mock_props = MagicMock()
        mock_props.version = "v1"
        mock_props.enabled = True
        mock_props.created_on = "2024-01-01"
        mock_props.updated_on = "2024-01-02"
        mock_props.content_type = "text/plain"

        mock_secret = MagicMock()
        mock_secret.value = "secret-value"
        mock_secret.properties = mock_props
        mock_secret_client.get_secret.return_value = mock_secret

        with self._patched_client(mock_azure, mock_secret_client) as client:
            client.authenticate()

            secret = client.get_secret("my-secret")

            assert secret.name == "my-secret"
            assert secret.value == "secret-value"
            assert secret.version == "v1"

    def test_list_secrets(self, mock_azure):
        """Test listing secrets."""
        mock_secret_client = MagicMock()

        # Create mock secret properties for list
        mock_prop1 = MagicMock()
        mock_prop1.name = "secret1"
        mock_prop2 = MagicMock()
        mock_prop2.name = "secret2"

        mock_secret_client.list_properties_of_secrets.return_value = iter([mock_prop1, mock_prop2])

        with self._patched_client(mock_azure, mock_secret_client) as client:
            client.authenticate()

            # Reset the mock for list call in test
            mock_secret_client.list_properties_of_secrets.return_value = iter(
                [mock_prop1, mock_prop2]
            )

            secrets = client.list_secrets()
            assert "secret1" in secrets
            assert "secret2" in secrets

    def test_list_secrets_with_prefix(self, mock_azure):
        """Test listing secrets with prefix filter."""
        mock_secret_client = MagicMock()

        mock_prop1 = MagicMock()
        mock_prop1.name = "app-secret1"
        mock_prop2 = MagicMock()
        mock_prop2.name = "app-secret2"
        mock_prop3 = MagicMock()
        mock_prop3.name = "other-secret"

        mock_secret_client.list_properties_of_secrets.return_value = iter(
            [mock_prop1, mock_prop2, mock_prop3]
        )

        with self._patched_client(mock_azure, mock_secret_client) as client:
            client.authenticate()

            mock_secret_client.list_properties_of_secrets.return_value = iter(
                [mock_prop1, mock_prop2, mock_prop3]
            )

            secrets = client.list_secrets(prefix="app-")
            assert "app-secret1" in secrets
            assert "app-secret2" in secrets
            assert "other-secret" not in secrets

    def test_set_secret(self, mock_azure):
        """Test setting a secret."""
        mock_secret_client = MagicMock()
        mock_secret_client.list_properties_of_secrets.return_value = iter([])

        mock_props = MagicMock()
        mock_props.version = "v1"
        mock_props.enabled = True

        mock_secret = MagicMock()
        mock_secret.value = "new-value"
        mock_secret.properties = mock_props
        mock_secret_client.set_secret.return_value = mock_secret

        with self._patched_client(mock_azure, mock_secret_client) as client:
            client.authenticate()

            result = client.set_secret("new-secret", "new-value")

            assert result.name == "new-secret"
            assert result.value == "new-value"

    def test_init_raises_without_sdk(self, mock_azure):
        """Init should raise ImportError when Azure SDK is unavailable."""
        mock_azure.AZURE_AVAILABLE = False

        with pytest.raises(ImportError):
            mock_azure.AzureKeyVaultClient(vault_url="https://test.vault.azure.net")

    def test_authenticate_client_auth_error(self, mock_azure):
        """Authentication errors should raise AuthenticationError."""
        mock_secret_client = MagicMock()
        mock_secret_client.list_properties_of_secrets.side_effect = FakeClientAuthenticationError(
            "bad creds"
        )

        with self._patched_client(
            mock_azure, mock_secret_client, faithful_exceptions=True
        ) as client:
            with pytest.raises(AuthenticationError):
                client.authenticate()

    def test_authenticate_http_error(self, mock_azure):
        """HTTP errors should raise VaultError."""
        mock_secret_client = MagicMock()
        mock_secret_client.list_properties_of_secrets.side_effect = FakeHttpResponseError("boom")

        with self._patched_client(
            mock_azure, mock_secret_client, faithful_exceptions=True
        ) as client:
            with pytest.raises(VaultError):
                client.authenticate()

    def test_authenticate_list_forbidden_accepts_least_privilege_identity(self, mock_azure):
        """A 403/Forbidden on the list probe must NOT fail authentication (#359).

        The list probe is not a least-privilege check: an identity granted only
        Get/Set on secrets (no List) authenticates fine but is forbidden to
        enumerate secrets. authenticate() must keep the client and report
        is_authenticated() == True so get_secret/set_secret can proceed.
        """
        mock_credential = MagicMock()
        mock_secret_client = MagicMock()
        mock_secret_client.list_properties_of_secrets.side_effect = FakeHttpResponseError(
            "Forbidden", status_code=403
        )

        with self._patched_client(
            mock_azure,
            mock_secret_client,
            credential=mock_credential,
            faithful_exceptions=True,
        ) as client:
            # Must NOT raise: 403 on list means authenticated-but-cannot-list.
            client.authenticate()

            assert client.is_authenticated() is True
            assert client._client is not None
            assert client._credential is not None

    def test_authenticate_list_client_auth_error_before_http_error_clause(self, mock_azure):
        """ClientAuthenticationError (IS-A HttpResponseError, 401) must map to AuthenticationError.

        This proves the production except-clause *ordering* is load-bearing.
        ``FakeClientAuthenticationError`` subclasses ``FakeHttpResponseError`` (as
        the real SDK does) and carries ``status_code == 401`` — i.e. it is NOT a
        403, so it must NOT take the 403-accept path, and because it is *also* an
        ``HttpResponseError`` it would be mis-caught by a misordered/collapsed
        handler. authenticate() must catch it via the earlier
        ``except ClientAuthenticationError`` clause and raise AuthenticationError
        (not VaultError, not silently accept), leaving the client unauthenticated.

        If the production ``except`` clauses were reordered to put
        ``HttpResponseError`` first (or collapsed into one handler with a
        ``status_code`` check), this 401 would be reported as a generic VaultError
        and this test would fail.
        """
        mock_credential = MagicMock()
        mock_secret_client = MagicMock()
        err = FakeClientAuthenticationError("invalid credential", status_code=401)
        # Sanity: the fake faithfully mirrors the real SDK MRO and is a non-403.
        assert isinstance(err, FakeHttpResponseError)
        assert err.status_code == 401
        mock_secret_client.list_properties_of_secrets.side_effect = err

        with self._patched_client(
            mock_azure,
            mock_secret_client,
            credential=mock_credential,
            faithful_exceptions=True,
        ) as client:
            with pytest.raises(AuthenticationError):
                client.authenticate()

            assert client.is_authenticated() is False
            assert client._client is None
            assert client._credential is None

    def test_authenticate_list_client_auth_error_still_fails(self, mock_azure):
        """A genuine ClientAuthenticationError on the probe still rejects the bad credential (#359).

        Counterpart to the 403 case: a real authentication failure must keep
        raising AuthenticationError and leave the client unauthenticated.
        """
        mock_credential = MagicMock()
        mock_secret_client = MagicMock()
        mock_secret_client.list_properties_of_secrets.side_effect = FakeClientAuthenticationError(
            "bad creds"
        )

        with self._patched_client(
            mock_azure,
            mock_secret_client,
            credential=mock_credential,
            faithful_exceptions=True,
        ) as client:
            with pytest.raises(AuthenticationError):
                client.authenticate()

            assert client.is_authenticated() is False
            assert client._client is None
            assert client._credential is None

    def test_authenticate_list_non_403_http_error_still_raises_vault_error(self, mock_azure):
        """A non-403 HTTP error on the list probe is still a real failure (VaultError).

        Only 403/Forbidden is treated as authenticated-but-cannot-list; other HTTP
        errors (e.g. 500) remain genuine Key Vault failures.
        """
        mock_credential = MagicMock()
        mock_secret_client = MagicMock()
        mock_secret_client.list_properties_of_secrets.side_effect = FakeHttpResponseError(
            "Server Error", status_code=500
        )

        with self._patched_client(
            mock_azure,
            mock_secret_client,
            credential=mock_credential,
            faithful_exceptions=True,
        ) as client:
            with pytest.raises(VaultError):
                client.authenticate()

            assert client.is_authenticated() is False
            assert client._client is None
            assert client._credential is None

    def test_authenticate_transport_error_maps_to_vault_error(self, mock_azure):
        """Regression #413: a transport ServiceRequestError during authenticate()
        (an AzureError that is NOT an HttpResponseError, e.g. DNS/TLS failure) must
        be wrapped as a domain VaultError, not escape as the raw SDK exception, and
        the half-initialized client/credential must be discarded.
        """
        mock_credential = MagicMock()
        mock_secret_client = MagicMock()
        mock_secret_client.list_properties_of_secrets.side_effect = FakeServiceRequestError(
            "DNS failure"
        )

        with self._patched_client(
            mock_azure,
            mock_secret_client,
            credential=mock_credential,
            faithful_exceptions=True,
        ) as client:
            with pytest.raises(VaultError):
                client.authenticate()

            assert client.is_authenticated() is False
            assert client._client is None
            assert client._credential is None

    def test_is_authenticated_false_after_failed_auth_error(self, mock_azure):
        """After authenticate() fails on the probe, is_authenticated() must be False.

        Regression for #304: self._client was assigned before the verification
        probe, so a failed probe left _client non-None and is_authenticated()
        wrongly returned True.
        """
        mock_secret_client = MagicMock()
        mock_secret_client.list_properties_of_secrets.side_effect = FakeClientAuthenticationError(
            "bad creds"
        )

        with self._patched_client(
            mock_azure, mock_secret_client, faithful_exceptions=True
        ) as client:
            with pytest.raises(AuthenticationError):
                client.authenticate()

            assert client.is_authenticated() is False
            assert client._client is None
            assert client._credential is None

    def test_is_authenticated_false_after_failed_http_error(self, mock_azure):
        """A failed probe raising HttpResponseError also leaves the client unauthenticated."""
        mock_secret_client = MagicMock()
        mock_secret_client.list_properties_of_secrets.side_effect = FakeHttpResponseError("boom")

        with self._patched_client(
            mock_azure, mock_secret_client, faithful_exceptions=True
        ) as client:
            with pytest.raises(VaultError):
                client.authenticate()

            assert client.is_authenticated() is False
            assert client._client is None
            assert client._credential is None

    def test_get_secret_not_found_raises(self, mock_azure):
        """Missing secrets should raise SecretNotFoundError."""
        mock_secret_client = MagicMock()
        mock_secret_client.list_properties_of_secrets.return_value = iter([])
        mock_secret_client.get_secret.side_effect = FakeResourceNotFoundError("missing")

        with self._patched_client(
            mock_azure, mock_secret_client, faithful_exceptions=True
        ) as client:
            client.authenticate()

            with pytest.raises(SecretNotFoundError):
                client.get_secret("missing-secret")

    def test_list_secrets_http_error(self, mock_azure):
        """List failures should raise VaultError."""
        mock_secret_client = MagicMock()
        mock_secret_client.list_properties_of_secrets.return_value = iter([])

        with self._patched_client(
            mock_azure, mock_secret_client, faithful_exceptions=True
        ) as client:
            client.authenticate()

            mock_secret_client.list_properties_of_secrets.side_effect = FakeHttpResponseError(
                "boom"
            )

            with pytest.raises(VaultError):
                client.list_secrets()

    def test_get_secret_http_error_raises_vault_error(self, mock_azure):
        """A non-not-found HTTP error during get_secret should raise VaultError."""
        mock_secret_client = MagicMock()
        mock_secret_client.list_properties_of_secrets.return_value = iter([])
        mock_secret_client.get_secret.side_effect = FakeHttpResponseError("boom")

        with self._patched_client(
            mock_azure, mock_secret_client, faithful_exceptions=True
        ) as client:
            client.authenticate()

            with pytest.raises(VaultError):
                client.get_secret("some-secret")

    def test_set_secret_http_error_raises_vault_error(self, mock_azure):
        """A HTTP error during set_secret should raise VaultError."""
        mock_secret_client = MagicMock()
        mock_secret_client.list_properties_of_secrets.return_value = iter([])
        mock_secret_client.set_secret.side_effect = FakeHttpResponseError("boom")

        with self._patched_client(
            mock_azure, mock_secret_client, faithful_exceptions=True
        ) as client:
            client.authenticate()

            with pytest.raises(VaultError):
                client.set_secret("some-secret", "value")

    def test_get_secret_client_auth_error_maps_to_authentication_error(self, mock_azure):
        """Regression #413 (low): a mid-session credential expiry (401) during
        get_secret() must map to AuthenticationError, not a generic VaultError.

        ClientAuthenticationError subclasses HttpResponseError, so the dedicated
        ``except ClientAuthenticationError`` clause must precede ``except
        HttpResponseError`` (ordering matters). Callers special-casing
        AuthenticationError (e.g. to prompt re-login) rely on this distinction.
        """
        mock_secret_client = MagicMock()
        mock_secret_client.list_properties_of_secrets.return_value = iter([])
        mock_secret_client.get_secret.side_effect = FakeClientAuthenticationError(
            "token expired", status_code=401
        )

        with self._patched_client(
            mock_azure, mock_secret_client, faithful_exceptions=True
        ) as client:
            client.authenticate()

            with pytest.raises(AuthenticationError):
                client.get_secret("some-secret")

    def test_list_secrets_client_auth_error_maps_to_authentication_error(self, mock_azure):
        """Regression #413 (low): mid-session 401 during list_secrets() maps to
        AuthenticationError (ClientAuthenticationError before HttpResponseError)."""
        mock_secret_client = MagicMock()
        mock_secret_client.list_properties_of_secrets.return_value = iter([])

        with self._patched_client(
            mock_azure, mock_secret_client, faithful_exceptions=True
        ) as client:
            client.authenticate()

            mock_secret_client.list_properties_of_secrets.side_effect = (
                FakeClientAuthenticationError("token expired", status_code=401)
            )

            with pytest.raises(AuthenticationError):
                client.list_secrets()

    def test_set_secret_client_auth_error_maps_to_authentication_error(self, mock_azure):
        """Regression #413 (low): mid-session 401 during set_secret() maps to
        AuthenticationError (ClientAuthenticationError before HttpResponseError)."""
        mock_secret_client = MagicMock()
        mock_secret_client.list_properties_of_secrets.return_value = iter([])
        mock_secret_client.set_secret.side_effect = FakeClientAuthenticationError(
            "token expired", status_code=401
        )

        with self._patched_client(
            mock_azure, mock_secret_client, faithful_exceptions=True
        ) as client:
            client.authenticate()

            with pytest.raises(AuthenticationError):
                client.set_secret("some-secret", "value")

    def test_get_secret_transport_error_maps_to_vault_error(self, mock_azure):
        """Regression #413 (high): a transport ServiceRequestError (AzureError but
        NOT HttpResponseError: DNS/TLS/connectivity) during get_secret() must be
        wrapped as a domain VaultError, not escape raw to the CLI."""
        mock_secret_client = MagicMock()
        mock_secret_client.list_properties_of_secrets.return_value = iter([])
        mock_secret_client.get_secret.side_effect = FakeServiceRequestError("DNS failure")

        with self._patched_client(
            mock_azure, mock_secret_client, faithful_exceptions=True
        ) as client:
            client.authenticate()

            with pytest.raises(VaultError) as exc_info:
                client.get_secret("some-secret")
        # Wrapped, not leaked as the raw transport exception.
        assert not isinstance(exc_info.value, FakeServiceRequestError)

    def test_list_secrets_transport_error_maps_to_vault_error(self, mock_azure):
        """Regression #413 (high): a transport ServiceRequestError during
        list_secrets() is wrapped as a domain VaultError."""
        mock_secret_client = MagicMock()
        mock_secret_client.list_properties_of_secrets.return_value = iter([])

        with self._patched_client(
            mock_azure, mock_secret_client, faithful_exceptions=True
        ) as client:
            client.authenticate()

            mock_secret_client.list_properties_of_secrets.side_effect = FakeServiceRequestError(
                "connection reset"
            )

            with pytest.raises(VaultError) as exc_info:
                client.list_secrets()
        assert not isinstance(exc_info.value, FakeServiceRequestError)

    def test_set_secret_transport_error_maps_to_vault_error(self, mock_azure):
        """Regression #413 (high): a transport ServiceRequestError during
        set_secret() is wrapped as a domain VaultError."""
        mock_secret_client = MagicMock()
        mock_secret_client.list_properties_of_secrets.return_value = iter([])
        mock_secret_client.set_secret.side_effect = FakeServiceRequestError("TLS handshake failed")

        with self._patched_client(
            mock_azure, mock_secret_client, faithful_exceptions=True
        ) as client:
            client.authenticate()

            with pytest.raises(VaultError) as exc_info:
                client.set_secret("some-secret", "value")
        assert not isinstance(exc_info.value, FakeServiceRequestError)
