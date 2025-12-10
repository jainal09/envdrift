"""Tests for envdrift.vault.azure module - Azure Key Vault client."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


class TestAzureKeyVaultClient:
    """Tests for AzureKeyVaultClient."""

    @pytest.fixture
    def mock_azure(self):
        """Mock Azure SDK."""
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
            import importlib

            import envdrift.vault.azure as azure_module

            importlib.reload(azure_module)
            yield azure_module

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
        mock_credential = MagicMock()
        mock_secret_client = MagicMock()
        mock_secret_client.list_properties_of_secrets.return_value = iter([])

        with (
            patch.object(mock_azure, "DefaultAzureCredential", return_value=mock_credential),
            patch.object(mock_azure, "SecretClient", return_value=mock_secret_client),
        ):
            client = mock_azure.AzureKeyVaultClient(vault_url="https://test.vault.azure.net")
            client.authenticate()

            assert client.is_authenticated() is True
            assert client._client is not None

    def test_get_secret(self, mock_azure):
        """Test retrieving a secret."""
        mock_credential = MagicMock()
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

        with (
            patch.object(mock_azure, "DefaultAzureCredential", return_value=mock_credential),
            patch.object(mock_azure, "SecretClient", return_value=mock_secret_client),
        ):
            client = mock_azure.AzureKeyVaultClient(vault_url="https://test.vault.azure.net")
            client.authenticate()

            secret = client.get_secret("my-secret")

            assert secret.name == "my-secret"
            assert secret.value == "secret-value"
            assert secret.version == "v1"

    def test_list_secrets(self, mock_azure):
        """Test listing secrets."""
        mock_credential = MagicMock()
        mock_secret_client = MagicMock()

        # Create mock secret properties for list
        mock_prop1 = MagicMock()
        mock_prop1.name = "secret1"
        mock_prop2 = MagicMock()
        mock_prop2.name = "secret2"

        mock_secret_client.list_properties_of_secrets.return_value = iter([mock_prop1, mock_prop2])

        with (
            patch.object(mock_azure, "DefaultAzureCredential", return_value=mock_credential),
            patch.object(mock_azure, "SecretClient", return_value=mock_secret_client),
        ):
            client = mock_azure.AzureKeyVaultClient(vault_url="https://test.vault.azure.net")
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
        mock_credential = MagicMock()
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

        with (
            patch.object(mock_azure, "DefaultAzureCredential", return_value=mock_credential),
            patch.object(mock_azure, "SecretClient", return_value=mock_secret_client),
        ):
            client = mock_azure.AzureKeyVaultClient(vault_url="https://test.vault.azure.net")
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
        mock_credential = MagicMock()
        mock_secret_client = MagicMock()
        mock_secret_client.list_properties_of_secrets.return_value = iter([])

        mock_props = MagicMock()
        mock_props.version = "v1"
        mock_props.enabled = True

        mock_secret = MagicMock()
        mock_secret.value = "new-value"
        mock_secret.properties = mock_props
        mock_secret_client.set_secret.return_value = mock_secret

        with (
            patch.object(mock_azure, "DefaultAzureCredential", return_value=mock_credential),
            patch.object(mock_azure, "SecretClient", return_value=mock_secret_client),
        ):
            client = mock_azure.AzureKeyVaultClient(vault_url="https://test.vault.azure.net")
            client.authenticate()

            result = client.set_secret("new-secret", "new-value")

            assert result.name == "new-secret"
            assert result.value == "new-value"
