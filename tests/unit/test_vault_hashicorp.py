"""Tests for envdrift.vault.hashicorp module - HashiCorp Vault client.

These tests check the module behavior without requiring actual hvac library,
by testing the code paths and exception handling.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from envdrift.vault.base import (
    AuthenticationError,
    SecretNotFoundError,
    VaultError,
)


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

    @patch("envdrift.vault.hashicorp.hvac")
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

    @patch("envdrift.vault.hashicorp.hvac")
    def test_authenticate_invalid_token_raises(self, mock_hvac_module):
        """Test authentication with invalid token raises."""
        mock_client = MagicMock()
        mock_client.is_authenticated.return_value = False
        mock_hvac_module.Client.return_value = mock_client

        from envdrift.vault.hashicorp import HashiCorpVaultClient

        client = HashiCorpVaultClient(url="http://localhost:8200", token="invalid-token")

        with pytest.raises((AuthenticationError, VaultError)):
            client.authenticate()

    @patch("envdrift.vault.hashicorp.hvac")
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

    @patch("envdrift.vault.hashicorp.hvac")
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

    @patch("envdrift.vault.hashicorp.hvac")
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

    @patch("envdrift.vault.hashicorp.hvac")
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

    @patch("envdrift.vault.hashicorp.hvac")
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

    @patch("envdrift.vault.hashicorp.hvac")
    def test_create_or_update_secret(self, mock_hvac_module):
        """Test create_or_update_secret calls hvac client."""
        mock_client = MagicMock()
        mock_client.is_authenticated.return_value = True
        mock_hvac_module.Client.return_value = mock_client

        from envdrift.vault.hashicorp import HashiCorpVaultClient

        client = HashiCorpVaultClient(url="http://localhost:8200", token="valid-token")
        client.authenticate()

        client.create_or_update_secret("new-secret", "new-value")

        mock_client.secrets.kv.v2.create_or_update_secret.assert_called_once()

    @patch("envdrift.vault.hashicorp.hvac")
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

    @patch("envdrift.vault.hashicorp.hvac")
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

    @patch("envdrift.vault.hashicorp.hvac")
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
