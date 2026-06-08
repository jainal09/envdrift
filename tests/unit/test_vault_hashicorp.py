"""Tests for envdrift.vault.hashicorp module - HashiCorp Vault client.

These tests check the module behavior without requiring actual hvac library,
by testing the code paths and exception handling.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from envdrift.vault.base import AuthenticationError, SecretNotFoundError, VaultError


@pytest.fixture(autouse=True, scope="module")
def mock_hvac_module():
    """Provide a stub hvac module so tests don't require the real dependency."""
    hvac_exceptions = SimpleNamespace(
        Forbidden=type("Forbidden", (Exception,), {}),
        InvalidPath=type("InvalidPath", (Exception,), {}),
        Unauthorized=type("Unauthorized", (Exception,), {}),
    )
    hvac_module = SimpleNamespace(
        exceptions=hvac_exceptions,
        Client=MagicMock(),
    )

    with patch.dict(
        "sys.modules",
        {"hvac": hvac_module, "hvac.exceptions": hvac_exceptions},
    ):
        import importlib

        import envdrift.vault.hashicorp as hashicorp_module

        importlib.reload(hashicorp_module)
        yield hashicorp_module


class TestHashiCorpVaultImport:
    """Test module import behavior."""

    def test_hvac_available_flag_exists(self):
        """Test HVAC_AVAILABLE flag exists in module."""
        from envdrift.vault import hashicorp

        assert hasattr(hashicorp, "HVAC_AVAILABLE")

    def test_hashicorp_vault_client_exists(self):
        """Test HashiCorpVaultClient class exists."""
        from envdrift.vault import hashicorp

        assert hasattr(hashicorp, "HashiCorpVaultClient")


class TestHashiCorpVaultClientWithMock:
    """Test HashiCorpVaultClient with mocked hvac."""

    def test_init_url_and_token(self):
        """Test client stores url and token."""
        from envdrift.vault.hashicorp import HashiCorpVaultClient

        client = HashiCorpVaultClient(url="http://localhost:8200", token="my-token")

        assert client.url == "http://localhost:8200"
        assert client.token == "my-token"

    def test_init_default_mount_point(self):
        """Test default mount point is 'secret'."""
        from envdrift.vault.hashicorp import HashiCorpVaultClient

        client = HashiCorpVaultClient(url="http://localhost:8200", token="my-token")

        assert client.mount_point == "secret"

    def test_init_custom_mount_point(self):
        """Test custom mount point."""
        from envdrift.vault.hashicorp import HashiCorpVaultClient

        client = HashiCorpVaultClient(
            url="http://localhost:8200", token="my-token", mount_point="kv"
        )

        assert client.mount_point == "kv"

    def test_init_token_from_env(self, monkeypatch: pytest.MonkeyPatch):
        """Test token from environment."""
        monkeypatch.setenv("VAULT_TOKEN", "env-token")

        from envdrift.vault.hashicorp import HashiCorpVaultClient

        client = HashiCorpVaultClient(url="http://localhost:8200")
        assert client.token == "env-token"

    def test_token_only_resolved_from_param_or_vault_token_env(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        """Token is resolved only from the ``token`` param or VAULT_TOKEN env.

        Regression guard for #328: a token supplied anywhere else (e.g. a
        ``[vault.hashicorp] token`` TOML key, which the client never receives) is
        NOT honored — with no param and no VAULT_TOKEN, the client has no token and
        authenticate() must fail fast with AuthenticationError.
        """
        monkeypatch.delenv("VAULT_TOKEN", raising=False)

        from envdrift.vault.hashicorp import HashiCorpVaultClient

        client = HashiCorpVaultClient(url="http://localhost:8200")
        assert client.token is None

        with pytest.raises(AuthenticationError, match="No Vault token provided"):
            client.authenticate()

    @patch("envdrift.vault.hashicorp._hvac")
    def test_authenticate_uses_token_only_no_other_auth_methods(self, mock_hvac_module):
        """Authentication is token-only: no AppRole/OIDC/Kubernetes login is invoked.

        Regression guard for #327: docs must not over-promise auth methods that the
        code does not implement. Rather than coupling to exact docstring wording, this
        asserts the actual behavior — the only auth signal sent to hvac is the token
        passed to ``Client(...)``, and none of the non-token ``auth.*`` login methods
        are ever called.
        """
        mock_client = MagicMock()
        mock_client.is_authenticated.return_value = True
        mock_hvac_module.Client.return_value = mock_client

        from envdrift.vault.hashicorp import HashiCorpVaultClient

        client = HashiCorpVaultClient(url="http://localhost:8200", token="valid-token")
        client.authenticate()

        # The token is the sole credential handed to hvac.
        assert mock_hvac_module.Client.call_args.kwargs["token"] == "valid-token"
        # No non-token auth backend (AppRole/OIDC/Kubernetes/...) is exercised.
        assert not mock_client.auth.approle.login.called
        assert not mock_client.auth.oidc.login.called
        assert not mock_client.auth.kubernetes.login.called

    def test_authenticate_without_token_does_not_attempt_other_auth(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        """With no token configured, authenticate() fails fast with AuthenticationError.

        Regression guard for #327/#328: the client does not silently fall back to any
        other hvac auth method when a token is absent — it raises immediately. This is
        the behavioral contract behind the "token-only" documentation.
        """
        monkeypatch.delenv("VAULT_TOKEN", raising=False)

        from envdrift.vault.hashicorp import HashiCorpVaultClient

        client = HashiCorpVaultClient(url="http://localhost:8200")
        assert client.token is None

        with pytest.raises(AuthenticationError):
            client.authenticate()

        # No hvac client was even constructed: nothing other than the token path runs.
        assert client._client is None

    def test_is_authenticated_false_initially(self):
        """Test is_authenticated returns False before authenticate."""
        from envdrift.vault.hashicorp import HashiCorpVaultClient

        client = HashiCorpVaultClient(url="http://localhost:8200", token="my-token")

        assert client.is_authenticated() is False
        assert client._client is None

    def test_authenticate_no_token_raises(self, monkeypatch: pytest.MonkeyPatch):
        """Test authenticate raises without token."""
        monkeypatch.delenv("VAULT_TOKEN", raising=False)

        from envdrift.vault.hashicorp import HashiCorpVaultClient

        client = HashiCorpVaultClient(url="http://localhost:8200", token=None)

        with pytest.raises(AuthenticationError) as exc_info:
            client.authenticate()

        assert "token" in str(exc_info.value).lower()

    @patch("envdrift.vault.hashicorp._hvac")
    def test_authenticate_success(self, mock_hvac_module):
        """Test successful authentication."""
        mock_client = MagicMock()
        mock_client.is_authenticated.return_value = True
        mock_hvac_module.Client.return_value = mock_client

        from envdrift.vault.hashicorp import HashiCorpVaultClient

        client = HashiCorpVaultClient(url="http://localhost:8200", token="valid-token")
        client.authenticate()

        assert client._client is mock_client
        assert client.is_authenticated() is True

    @patch("envdrift.vault.hashicorp._hvac")
    def test_authenticate_invalid_token_raises_authentication_error(self, mock_hvac_module):
        """An invalid/expired token (is_authenticated() -> False) must raise
        AuthenticationError, not a re-wrapped VaultError.

        Regression test for #305: the broad ``except Exception`` previously caught
        the just-raised AuthenticationError and re-wrapped it as VaultError. The
        AuthenticationError must propagate so callers can match on it specifically.
        """
        mock_client = MagicMock()
        mock_client.is_authenticated.return_value = False
        mock_hvac_module.Client.return_value = mock_client

        from envdrift.vault.hashicorp import HashiCorpVaultClient

        client = HashiCorpVaultClient(url="http://localhost:8200", token="invalid-token")

        with pytest.raises(AuthenticationError, match="invalid or expired") as exc_info:
            client.authenticate()

        # It must be exactly AuthenticationError, not the broader VaultError wrapper.
        assert type(exc_info.value) is AuthenticationError
        assert "connection error" not in str(exc_info.value)
        # The half-initialized client must be cleared so the unauthenticated-state
        # invariant holds after a failed authenticate() (mirrors gcp/azure).
        assert client._client is None

    @patch("envdrift.vault.hashicorp._hvac")
    def test_authenticate_unauthorized_raises_authentication_error(self, mock_hvac_module):
        """An Unauthorized response from hvac surfaces as AuthenticationError."""
        from envdrift.vault.hashicorp import HashiCorpVaultClient, Unauthorized

        mock_hvac_module.Client.side_effect = Unauthorized("nope")

        client = HashiCorpVaultClient(url="http://localhost:8200", token="valid-token")

        with pytest.raises(AuthenticationError, match="authentication failed"):
            client.authenticate()

    @patch("envdrift.vault.hashicorp._hvac")
    def test_authenticate_connection_error_wraps_as_vault_error(self, mock_hvac_module):
        """An unexpected (non-auth) error during connect is wrapped as VaultError."""
        from envdrift.vault.hashicorp import HashiCorpVaultClient

        mock_hvac_module.Client.side_effect = RuntimeError("connection refused")

        client = HashiCorpVaultClient(url="http://localhost:8200", token="valid-token")

        with pytest.raises(VaultError, match="connection error") as exc_info:
            client.authenticate()
        # Not misclassified as an auth failure.
        assert type(exc_info.value) is VaultError

    @patch("envdrift.vault.hashicorp._hvac")
    def test_is_authenticated_false_when_client_check_raises(self, mock_hvac_module):
        """is_authenticated() swallows hvac errors and reports False, not an exception."""
        from envdrift.vault.hashicorp import HashiCorpVaultClient

        mock_client = MagicMock()
        mock_client.is_authenticated.return_value = True
        mock_hvac_module.Client.return_value = mock_client

        client = HashiCorpVaultClient(url="http://localhost:8200", token="valid-token")
        client.authenticate()

        # A transient failure when probing the live client must not propagate.
        mock_client.is_authenticated.side_effect = RuntimeError("network down")
        assert client.is_authenticated() is False

    @patch("envdrift.vault.hashicorp._hvac")
    def test_get_secret_unexpected_error_wraps_as_vault_error(self, mock_hvac_module):
        """A non-auth, non-not-found error during get_secret is wrapped as VaultError."""
        from envdrift.vault.hashicorp import HashiCorpVaultClient

        mock_client = MagicMock()
        mock_client.is_authenticated.return_value = True
        mock_client.secrets.kv.v2.read_secret_version.side_effect = RuntimeError("boom")
        mock_hvac_module.Client.return_value = mock_client

        client = HashiCorpVaultClient(url="http://localhost:8200", token="valid-token")
        client.authenticate()

        with pytest.raises(VaultError, match="Vault error"):
            client.get_secret("whatever")

    @patch("envdrift.vault.hashicorp._hvac")
    def test_list_secrets_unauthorized_raises_authentication_error(self, mock_hvac_module):
        """Unauthorized while listing surfaces as AuthenticationError."""
        from envdrift.vault.hashicorp import HashiCorpVaultClient, Unauthorized

        mock_client = MagicMock()
        mock_client.is_authenticated.return_value = True
        mock_client.secrets.kv.v2.list_secrets.side_effect = Unauthorized("nope")
        mock_hvac_module.Client.return_value = mock_client

        client = HashiCorpVaultClient(url="http://localhost:8200", token="valid-token")
        client.authenticate()

        with pytest.raises(AuthenticationError, match="Access denied"):
            client.list_secrets()

    @patch("envdrift.vault.hashicorp._hvac")
    def test_list_secrets_unexpected_error_wraps_as_vault_error(self, mock_hvac_module):
        """A non-auth, non-InvalidPath error while listing is wrapped as VaultError."""
        from envdrift.vault.hashicorp import HashiCorpVaultClient

        mock_client = MagicMock()
        mock_client.is_authenticated.return_value = True
        mock_client.secrets.kv.v2.list_secrets.side_effect = RuntimeError("boom")
        mock_hvac_module.Client.return_value = mock_client

        client = HashiCorpVaultClient(url="http://localhost:8200", token="valid-token")
        client.authenticate()

        with pytest.raises(VaultError, match="Vault error"):
            client.list_secrets()

    @patch("envdrift.vault.hashicorp._hvac")
    def test_create_or_update_secret_unexpected_error_wraps_as_vault_error(self, mock_hvac_module):
        """A non-auth error while writing is wrapped as VaultError."""
        from envdrift.vault.hashicorp import HashiCorpVaultClient

        mock_client = MagicMock()
        mock_client.is_authenticated.return_value = True
        mock_client.secrets.kv.v2.create_or_update_secret.side_effect = RuntimeError("boom")
        mock_hvac_module.Client.return_value = mock_client

        client = HashiCorpVaultClient(url="http://localhost:8200", token="valid-token")
        client.authenticate()

        with pytest.raises(VaultError, match="Vault error"):
            client.create_or_update_secret("secret", {"value": "x"})

    @patch("envdrift.vault.hashicorp._hvac")
    def test_get_secret_with_single_value(self, mock_hvac_module):
        """Test get_secret returns single value correctly."""
        mock_client = MagicMock()
        mock_client.is_authenticated.return_value = True
        mock_client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"value": "my-secret-value"}, "metadata": {"version": 1}}
        }
        mock_hvac_module.Client.return_value = mock_client

        from envdrift.vault.hashicorp import HashiCorpVaultClient

        client = HashiCorpVaultClient(url="http://localhost:8200", token="valid-token")
        client.authenticate()

        secret = client.get_secret("my-secret")

        assert secret.name == "my-secret"
        assert secret.value == "my-secret-value"

    @patch("envdrift.vault.hashicorp._hvac")
    @pytest.mark.parametrize(
        ("stored_value", "expected"),
        [
            (42, "42"),
            (True, "true"),
            (3.5, "3.5"),
            ({"nested": "dict"}, '{"nested": "dict"}'),
            ([1, 2, 3], "[1, 2, 3]"),
        ],
    )
    def test_get_secret_single_non_string_value_is_coerced_to_str(
        self, mock_hvac_module, stored_value, expected
    ):
        """Regression #413: a KV entry whose single ``value`` is a non-string
        (int/bool/float/dict/list) must still yield a ``str`` SecretValue.value.

        Vault KV stores arbitrary JSON, so ``secret_data["value"]`` can be a
        non-string. The single-``value`` fast path previously assigned it verbatim
        (no ``json.dumps``), so SecretValue.value was a non-str. The sync engine and
        vault-pull then crash downstream when they treat the value as text. The
        multi-key path already JSON-encodes; the single-value path must too.
        """
        mock_client = MagicMock()
        mock_client.is_authenticated.return_value = True
        mock_client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"value": stored_value}, "metadata": {"version": 1}}
        }
        mock_hvac_module.Client.return_value = mock_client

        from envdrift.vault.hashicorp import HashiCorpVaultClient

        client = HashiCorpVaultClient(url="http://localhost:8200", token="valid-token")
        client.authenticate()

        secret = client.get_secret("my-secret")

        assert isinstance(secret.value, str)
        assert secret.value == expected

    @patch("envdrift.vault.hashicorp._hvac")
    def test_get_secret_with_multiple_values(self, mock_hvac_module):
        """Test get_secret returns JSON for multiple values."""
        mock_client = MagicMock()
        mock_client.is_authenticated.return_value = True
        mock_client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"key1": "value1", "key2": "value2"}, "metadata": {"version": 2}}
        }
        mock_hvac_module.Client.return_value = mock_client

        from envdrift.vault.hashicorp import HashiCorpVaultClient

        client = HashiCorpVaultClient(url="http://localhost:8200", token="valid-token")
        client.authenticate()

        secret = client.get_secret("json-secret")

        assert secret.name == "json-secret"
        assert "key1" in secret.value
        assert "value1" in secret.value

    @patch("envdrift.vault.hashicorp._hvac")
    def test_get_secret_not_found_raises(self, mock_hvac_module):
        """Test get_secret raises SecretNotFoundError for missing secret.

        This test verifies that when hvac raises InvalidPath (secret doesn't exist),
        the client properly converts it to SecretNotFoundError.
        """
        # Import the actual InvalidPath from the module (which may be Exception if hvac not installed)
        from envdrift.vault.hashicorp import InvalidPath

        mock_client = MagicMock()
        mock_client.is_authenticated.return_value = True
        # Raise InvalidPath which is what hvac raises when secret doesn't exist
        mock_client.secrets.kv.v2.read_secret_version.side_effect = InvalidPath("not found")
        mock_hvac_module.Client.return_value = mock_client

        from envdrift.vault.hashicorp import HashiCorpVaultClient

        client = HashiCorpVaultClient(url="http://localhost:8200", token="valid-token")
        client.authenticate()

        with pytest.raises(SecretNotFoundError):
            client.get_secret("nonexistent")

    @patch("envdrift.vault.hashicorp._hvac")
    def test_list_secrets(self, mock_hvac_module):
        """Test list_secrets returns list of secret names."""
        mock_client = MagicMock()
        mock_client.is_authenticated.return_value = True
        mock_client.secrets.kv.v2.list_secrets.return_value = {
            "data": {"keys": ["secret1", "secret2", "folder/"]}
        }
        mock_hvac_module.Client.return_value = mock_client

        from envdrift.vault.hashicorp import HashiCorpVaultClient

        client = HashiCorpVaultClient(url="http://localhost:8200", token="valid-token")
        client.authenticate()

        secrets = client.list_secrets()

        assert len(secrets) == 3
        assert "secret1" in secrets
        assert "secret2" in secrets
        assert "folder/" in secrets

    @patch("envdrift.vault.hashicorp._hvac")
    def test_list_secrets_with_prefix(self, mock_hvac_module):
        """Test list_secrets with prefix parameter."""
        mock_client = MagicMock()
        mock_client.is_authenticated.return_value = True
        mock_client.secrets.kv.v2.list_secrets.return_value = {
            "data": {"keys": ["db-pass", "db-user"]}
        }
        mock_hvac_module.Client.return_value = mock_client

        from envdrift.vault.hashicorp import HashiCorpVaultClient

        client = HashiCorpVaultClient(url="http://localhost:8200", token="valid-token")
        client.authenticate()

        secrets = client.list_secrets(prefix="myapp/")

        mock_client.secrets.kv.v2.list_secrets.assert_called_once()
        assert "db-pass" in secrets

    @patch("envdrift.vault.hashicorp._hvac")
    def test_list_secrets_invalid_path_returns_empty(self, mock_hvac_module):
        """
        Verify that list_secrets() returns an empty list when the KV backend raises InvalidPath for the requested prefix.

        Ensures missing paths are treated as no-results instead of propagating an error.
        """
        from envdrift.vault.hashicorp import HashiCorpVaultClient, InvalidPath

        mock_client = MagicMock()
        mock_client.is_authenticated.return_value = True
        mock_client.secrets.kv.v2.list_secrets.side_effect = InvalidPath("missing")
        mock_hvac_module.Client.return_value = mock_client

        client = HashiCorpVaultClient(url="http://localhost:8200", token="valid-token")
        client.authenticate()

        assert client.list_secrets(prefix="missing/") == []

    @patch("envdrift.vault.hashicorp._hvac")
    def test_get_secret_unauthorized_raises(self, mock_hvac_module):
        """Unauthorized errors should raise AuthenticationError."""
        from envdrift.vault.hashicorp import HashiCorpVaultClient, Unauthorized

        mock_client = MagicMock()
        mock_client.is_authenticated.return_value = True
        mock_client.secrets.kv.v2.read_secret_version.side_effect = Unauthorized("nope")
        mock_hvac_module.Client.return_value = mock_client

        client = HashiCorpVaultClient(url="http://localhost:8200", token="valid-token")
        client.authenticate()

        with pytest.raises(AuthenticationError):
            client.get_secret("restricted")

    @patch("envdrift.vault.hashicorp._hvac")
    def test_create_or_update_secret_forbidden_raises(self, mock_hvac_module):
        """Forbidden errors should raise AuthenticationError."""
        from envdrift.vault.hashicorp import Forbidden, HashiCorpVaultClient

        mock_client = MagicMock()
        mock_client.is_authenticated.return_value = True
        mock_client.secrets.kv.v2.create_or_update_secret.side_effect = Forbidden("nope")
        mock_hvac_module.Client.return_value = mock_client

        client = HashiCorpVaultClient(url="http://localhost:8200", token="valid-token")
        client.authenticate()

        with pytest.raises(AuthenticationError):
            client.create_or_update_secret("secret", {"value": "x"})

    @patch("envdrift.vault.hashicorp._hvac")
    def test_create_or_update_secret(self, mock_hvac_module):
        """Test create_or_update_secret calls hvac client."""
        mock_client = MagicMock()
        mock_client.is_authenticated.return_value = True
        mock_hvac_module.Client.return_value = mock_client

        from envdrift.vault.hashicorp import HashiCorpVaultClient

        client = HashiCorpVaultClient(url="http://localhost:8200", token="valid-token")
        client.authenticate()

        client.create_or_update_secret("new-secret", {"value": "new-value"})

        mock_client.secrets.kv.v2.create_or_update_secret.assert_called_once()

    @patch("envdrift.vault.hashicorp._hvac")
    def test_create_or_update_secret_with_dict(self, mock_hvac_module):
        """Test create_or_update_secret accepts dict value."""
        mock_client = MagicMock()
        mock_client.is_authenticated.return_value = True
        mock_hvac_module.Client.return_value = mock_client

        from envdrift.vault.hashicorp import HashiCorpVaultClient

        client = HashiCorpVaultClient(url="http://localhost:8200", token="valid-token")
        client.authenticate()

        client.create_or_update_secret("json-secret", {"key": "value"})

        call_args = mock_client.secrets.kv.v2.create_or_update_secret.call_args
        assert call_args[1]["secret"] == {"key": "value"}

    @patch("envdrift.vault.hashicorp._hvac")
    def test_create_or_update_secret_single_non_string_value_returns_str(self, mock_hvac_module):
        """Regression #413: writing a non-string single ``value`` returns a ``str``.

        ``SecretValue.value`` must always be a str (the sync engine/vault-pull treat
        it as text), so the write path coerces a non-string single value to JSON,
        mirroring the read path. The secret stored in Vault keeps its raw type.
        """
        mock_client = MagicMock()
        mock_client.is_authenticated.return_value = True
        mock_client.secrets.kv.v2.create_or_update_secret.return_value = {
            "data": {"version": 1, "created_time": "now"}
        }
        mock_hvac_module.Client.return_value = mock_client

        from envdrift.vault.hashicorp import HashiCorpVaultClient

        client = HashiCorpVaultClient(url="http://localhost:8200", token="valid-token")
        client.authenticate()

        result = client.create_or_update_secret("num-secret", {"value": 123})

        # Returned value is a JSON-coerced str; the payload written to Vault is raw.
        assert isinstance(result.value, str)
        assert result.value == "123"
        call_args = mock_client.secrets.kv.v2.create_or_update_secret.call_args
        assert call_args[1]["secret"] == {"value": 123}

    @patch("envdrift.vault.hashicorp._hvac")
    def test_set_secret_delegates_to_create_or_update(self, mock_hvac_module):
        """Test set_secret is an alias."""
        mock_client = MagicMock()
        mock_client.is_authenticated.return_value = True
        mock_hvac_module.Client.return_value = mock_client

        from envdrift.vault.hashicorp import HashiCorpVaultClient

        client = HashiCorpVaultClient(url="http://localhost:8200", token="valid-token")
        client.authenticate()

        client.set_secret("test-secret", "test-value")

        mock_client.secrets.kv.v2.create_or_update_secret.assert_called()


class TestEnsureAuthenticated:
    """Test ensure_authenticated behavior."""

    @patch("envdrift.vault.hashicorp._hvac")
    def test_ensure_authenticated_raises_when_not_authenticated(self, mock_hvac_module):
        """Test ensure_authenticated raises AuthenticationError."""
        mock_client = MagicMock()
        mock_client.is_authenticated.return_value = False
        mock_hvac_module.Client.return_value = mock_client

        from envdrift.vault.hashicorp import HashiCorpVaultClient

        client = HashiCorpVaultClient(url="http://localhost:8200", token="my-token")
        # Don't set _client - it should try to authenticate and fail

        with pytest.raises((AuthenticationError, VaultError)):
            client.ensure_authenticated()
