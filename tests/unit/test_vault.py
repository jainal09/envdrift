"""Tests for envdrift.vault module - base classes and factory."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from envdrift.vault import VaultProvider, get_vault_client
from envdrift.vault.base import (
    AuthenticationError,
    SecretNotFoundError,
    SecretValue,
    VaultClient,
    VaultError,
)


class TestVaultExceptions:
    """Test vault exception hierarchy."""

    def test_vault_error_is_exception(self):
        """Test VaultError inherits from Exception."""
        err = VaultError("test error")
        assert isinstance(err, Exception)
        assert str(err) == "test error"

    def test_authentication_error_is_vault_error(self):
        """Test AuthenticationError inherits from VaultError."""
        err = AuthenticationError("auth failed")
        assert isinstance(err, VaultError)
        assert isinstance(err, Exception)

    def test_secret_not_found_error_is_vault_error(self):
        """Test SecretNotFoundError inherits from VaultError."""
        err = SecretNotFoundError("secret missing")
        assert isinstance(err, VaultError)


class TestSecretValue:
    """Tests for SecretValue dataclass."""

    def test_basic_secret_value(self):
        """Test creating basic SecretValue."""
        secret = SecretValue(name="API_KEY", value="secret123")
        assert secret.name == "API_KEY"
        assert secret.value == "secret123"
        assert secret.version is None
        assert secret.metadata == {}

    def test_secret_value_with_version(self):
        """Test SecretValue with version."""
        secret = SecretValue(name="DB_PASSWORD", value="pass", version="v1")
        assert secret.version == "v1"

    def test_secret_value_with_metadata(self):
        """Test SecretValue with metadata."""
        meta = {"created": "2024-01-01", "owner": "admin"}
        secret = SecretValue(name="CONFIG", value="data", metadata=meta)
        assert secret.metadata == meta

    def test_str_masks_value(self):
        """Test __str__ masks the secret value."""
        secret = SecretValue(name="SECRET", value="super-sensitive-data")
        string_repr = str(secret)
        assert "SECRET" in string_repr
        assert "super-sensitive-data" not in string_repr
        assert "****" in string_repr


class TestVaultProvider:
    """Tests for VaultProvider enum."""

    def test_azure_provider(self):
        """Test Azure provider value."""
        assert VaultProvider.AZURE.value == "azure"

    def test_aws_provider(self):
        """Test AWS provider value."""
        assert VaultProvider.AWS.value == "aws"

    def test_hashicorp_provider(self):
        """Test HashiCorp provider value."""
        assert VaultProvider.HASHICORP.value == "hashicorp"

    def test_from_string(self):
        """Test creating provider from string."""
        assert VaultProvider("azure") == VaultProvider.AZURE
        assert VaultProvider("aws") == VaultProvider.AWS
        assert VaultProvider("hashicorp") == VaultProvider.HASHICORP

    def test_invalid_provider_raises(self):
        """Test invalid provider string raises ValueError."""
        with pytest.raises(ValueError):
            VaultProvider("invalid")


class TestGetVaultClient:
    """Tests for get_vault_client factory function."""

    def test_azure_requires_vault_url(self):
        """Test Azure provider requires vault_url config."""
        # The azure module isn't imported until get_vault_client is called
        # so we need to mock the import
        mock_azure_module = MagicMock()

        with patch.dict("sys.modules", {"envdrift.vault.azure": mock_azure_module}):
            with pytest.raises(ValueError) as exc_info:
                get_vault_client("azure")
            assert "vault_url" in str(exc_info.value)

    def test_azure_client_creation(self):
        """Test Azure client is created with vault_url."""
        mock_client = MagicMock()
        mock_azure_module = MagicMock()
        mock_azure_module.AzureKeyVaultClient.return_value = mock_client

        with patch.dict("sys.modules", {"envdrift.vault.azure": mock_azure_module}):
            client = get_vault_client(VaultProvider.AZURE, vault_url="https://myvault.vault.azure.net")
            assert client is not None

    def test_aws_default_region(self):
        """Test AWS client uses default region."""
        mock_aws_module = MagicMock()

        with patch.dict("sys.modules", {"envdrift.vault.aws": mock_aws_module}):
            get_vault_client("aws")
            mock_aws_module.AWSSecretsManagerClient.assert_called_once()

    def test_hashicorp_requires_url(self):
        """Test HashiCorp provider requires url config."""
        mock_hashi_module = MagicMock()

        with patch.dict("sys.modules", {"envdrift.vault.hashicorp": mock_hashi_module}):
            with pytest.raises(ValueError) as exc_info:
                get_vault_client("hashicorp")
            assert "url" in str(exc_info.value)

    def test_hashicorp_client_creation(self):
        """Test HashiCorp client is created with url and token."""
        mock_client = MagicMock()
        mock_hashi_module = MagicMock()
        mock_hashi_module.HashiCorpVaultClient.return_value = mock_client

        with patch.dict("sys.modules", {"envdrift.vault.hashicorp": mock_hashi_module}):
            client = get_vault_client(
                "hashicorp",
                url="http://localhost:8200",
                token="mytoken"
            )
            assert client is not None

    def test_unsupported_provider_raises(self):
        """Test unsupported provider raises ValueError."""
        with pytest.raises(ValueError):
            get_vault_client("unsupported_provider")

    def test_provider_as_string(self):
        """Test provider can be passed as string."""
        mock_aws_module = MagicMock()

        with patch.dict("sys.modules", {"envdrift.vault.aws": mock_aws_module}):
            # Should convert "aws" string to VaultProvider.AWS
            client = get_vault_client("aws", region="us-west-2")
            assert client is not None


class ConcreteVaultClient(VaultClient):
    """Concrete implementation for testing VaultClient base class."""

    def __init__(self):
        self._authenticated = False
        self._secrets = {}

    def get_secret(self, name: str) -> SecretValue:
        if not self._authenticated:
            raise AuthenticationError("Not authenticated")
        if name not in self._secrets:
            raise SecretNotFoundError(f"Secret {name} not found")
        return SecretValue(name=name, value=self._secrets[name])

    def list_secrets(self, prefix: str = "") -> list[str]:
        if not self._authenticated:
            raise AuthenticationError("Not authenticated")
        return [k for k in self._secrets if k.startswith(prefix)]

    def is_authenticated(self) -> bool:
        return self._authenticated

    def authenticate(self) -> None:
        self._authenticated = True


class TestVaultClientBase:
    """Tests for VaultClient base class methods."""

    def test_get_secret_value_convenience_method(self):
        """Test get_secret_value returns just the value string."""
        client = ConcreteVaultClient()
        client._authenticated = True
        client._secrets["MY_SECRET"] = "my-value"

        value = client.get_secret_value("MY_SECRET")
        assert value == "my-value"

    def test_ensure_authenticated_when_not_authenticated(self):
        """Test ensure_authenticated calls authenticate when needed."""
        client = ConcreteVaultClient()
        assert not client.is_authenticated()

        client.ensure_authenticated()
        assert client.is_authenticated()

    def test_ensure_authenticated_when_already_authenticated(self):
        """Test ensure_authenticated does nothing when already authenticated."""
        client = ConcreteVaultClient()
        client._authenticated = True

        # Should not raise or change state
        client.ensure_authenticated()
        assert client.is_authenticated()

    def test_get_secret_when_not_authenticated(self):
        """Test get_secret raises when not authenticated."""
        client = ConcreteVaultClient()

        with pytest.raises(AuthenticationError):
            client.get_secret("SOME_SECRET")

    def test_list_secrets_when_not_authenticated(self):
        """Test list_secrets raises when not authenticated."""
        client = ConcreteVaultClient()

        with pytest.raises(AuthenticationError):
            client.list_secrets()

    def test_list_secrets_with_prefix(self):
        """Test list_secrets filters by prefix."""
        client = ConcreteVaultClient()
        client._authenticated = True
        client._secrets = {
            "APP_KEY": "val1",
            "APP_SECRET": "val2",
            "DB_PASSWORD": "val3",
        }

        result = client.list_secrets(prefix="APP_")
        assert "APP_KEY" in result
        assert "APP_SECRET" in result
        assert "DB_PASSWORD" not in result
