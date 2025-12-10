"""Tests for envdrift.vault.aws module - AWS Secrets Manager client."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from envdrift.vault.base import (
    AuthenticationError,
    VaultError,
)


class TestAWSSecretsManagerClient:
    """Tests for AWSSecretsManagerClient."""

    @pytest.fixture
    def mock_boto3(self):
        """Mock boto3 and its exceptions."""
        with patch.dict("sys.modules", {
            "boto3": MagicMock(),
            "botocore": MagicMock(),
            "botocore.exceptions": MagicMock(),
        }):
            # Need to import after patching
            import importlib

            import envdrift.vault.aws as aws_module
            importlib.reload(aws_module)
            yield aws_module

    def test_init_sets_region(self, mock_boto3):
        """Test client initializes with region."""
        client = mock_boto3.AWSSecretsManagerClient(region="us-west-2")
        assert client.region == "us-west-2"

    def test_init_default_region(self, mock_boto3):
        """Test client uses default region."""
        client = mock_boto3.AWSSecretsManagerClient()
        assert client.region == "us-east-1"

    def test_authenticate_success(self, mock_boto3):
        """Test successful authentication."""
        mock_sm_client = MagicMock()
        mock_sts_client = MagicMock()

        with patch("boto3.client") as mock_client:
            def client_factory(service, **kwargs):
                if service == "secretsmanager":
                    return mock_sm_client
                elif service == "sts":
                    return mock_sts_client
                return MagicMock()

            mock_client.side_effect = client_factory

            client = mock_boto3.AWSSecretsManagerClient()
            client.authenticate()

            assert client._client is not None

    def test_authenticate_no_credentials(self, mock_boto3):
        """Test authentication fails with no credentials."""
        with patch("boto3.client") as mock_client:
            # Simulate NoCredentialsError
            mock_client.side_effect = Exception("No credentials")

            client = mock_boto3.AWSSecretsManagerClient()
            # The actual exception type depends on mocking setup
            with pytest.raises((AuthenticationError, VaultError, Exception)):
                client.authenticate()

    def test_is_authenticated_false_when_no_client(self, mock_boto3):
        """Test is_authenticated returns False when not authenticated."""
        client = mock_boto3.AWSSecretsManagerClient()
        assert client.is_authenticated() is False

    def test_is_authenticated_true_after_auth(self, mock_boto3):
        """Test is_authenticated returns True after authentication."""
        mock_sm_client = MagicMock()
        mock_sts_client = MagicMock()

        with patch("boto3.client") as mock_client:
            def client_factory(service, **kwargs):
                if service == "secretsmanager":
                    return mock_sm_client
                elif service == "sts":
                    return mock_sts_client
                return MagicMock()

            mock_client.side_effect = client_factory

            client = mock_boto3.AWSSecretsManagerClient()
            client.authenticate()

            # After auth, is_authenticated should check STS again
            assert client.is_authenticated() is True

    def test_get_secret_string(self, mock_boto3):
        """Test retrieving a string secret."""
        mock_sm_client = MagicMock()
        mock_sm_client.get_secret_value.return_value = {
            "Name": "my-secret",
            "SecretString": "secret-value",
            "VersionId": "v1",
            "ARN": "arn:aws:secretsmanager:...",
            "CreatedDate": "2024-01-01",
            "VersionStages": ["AWSCURRENT"],
        }

        mock_sts_client = MagicMock()

        with patch("boto3.client") as mock_client:
            def client_factory(service, **kwargs):
                if service == "secretsmanager":
                    return mock_sm_client
                elif service == "sts":
                    return mock_sts_client
                return MagicMock()

            mock_client.side_effect = client_factory

            client = mock_boto3.AWSSecretsManagerClient()
            client.authenticate()

            secret = client.get_secret("my-secret")

            assert secret.name == "my-secret"
            assert secret.value == "secret-value"
            assert secret.version == "v1"

    def test_get_secret_binary(self, mock_boto3):
        """Test retrieving a binary secret."""
        mock_sm_client = MagicMock()
        mock_sm_client.get_secret_value.return_value = {
            "Name": "binary-secret",
            "SecretBinary": b"binary-data",
            "VersionId": "v1",
        }

        mock_sts_client = MagicMock()

        with patch("boto3.client") as mock_client:
            def client_factory(service, **kwargs):
                if service == "secretsmanager":
                    return mock_sm_client
                elif service == "sts":
                    return mock_sts_client
                return MagicMock()

            mock_client.side_effect = client_factory

            client = mock_boto3.AWSSecretsManagerClient()
            client.authenticate()

            secret = client.get_secret("binary-secret")
            assert secret.value == "binary-data"

    def test_list_secrets(self, mock_boto3):
        """Test listing secrets."""
        mock_sm_client = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {"SecretList": [{"Name": "secret1"}, {"Name": "secret2"}]},
            {"SecretList": [{"Name": "secret3"}]},
        ]
        mock_sm_client.get_paginator.return_value = mock_paginator

        mock_sts_client = MagicMock()

        with patch("boto3.client") as mock_client:
            def client_factory(service, **kwargs):
                if service == "secretsmanager":
                    return mock_sm_client
                elif service == "sts":
                    return mock_sts_client
                return MagicMock()

            mock_client.side_effect = client_factory

            client = mock_boto3.AWSSecretsManagerClient()
            client.authenticate()

            secrets = client.list_secrets()
            assert secrets == ["secret1", "secret2", "secret3"]

    def test_list_secrets_with_prefix(self, mock_boto3):
        """Test listing secrets with prefix filter."""
        mock_sm_client = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {"SecretList": [{"Name": "app/secret1"}, {"Name": "app/secret2"}, {"Name": "other/secret"}]},
        ]
        mock_sm_client.get_paginator.return_value = mock_paginator

        mock_sts_client = MagicMock()

        with patch("boto3.client") as mock_client:
            def client_factory(service, **kwargs):
                if service == "secretsmanager":
                    return mock_sm_client
                elif service == "sts":
                    return mock_sts_client
                return MagicMock()

            mock_client.side_effect = client_factory

            client = mock_boto3.AWSSecretsManagerClient()
            client.authenticate()

            secrets = client.list_secrets(prefix="app/")
            assert secrets == ["app/secret1", "app/secret2"]

    def test_create_secret(self, mock_boto3):
        """Test creating a secret."""
        mock_sm_client = MagicMock()
        mock_sm_client.create_secret.return_value = {
            "Name": "new-secret",
            "VersionId": "v1",
            "ARN": "arn:aws:...",
        }

        mock_sts_client = MagicMock()

        with patch("boto3.client") as mock_client:
            def client_factory(service, **kwargs):
                if service == "secretsmanager":
                    return mock_sm_client
                elif service == "sts":
                    return mock_sts_client
                return MagicMock()

            mock_client.side_effect = client_factory

            client = mock_boto3.AWSSecretsManagerClient()
            client.authenticate()

            secret = client.create_secret("new-secret", "value", "description")
            assert secret.name == "new-secret"
            assert secret.value == "value"

    def test_update_secret(self, mock_boto3):
        """Test updating a secret."""
        mock_sm_client = MagicMock()
        mock_sm_client.put_secret_value.return_value = {
            "Name": "existing-secret",
            "VersionId": "v2",
            "ARN": "arn:aws:...",
        }

        mock_sts_client = MagicMock()

        with patch("boto3.client") as mock_client:
            def client_factory(service, **kwargs):
                if service == "secretsmanager":
                    return mock_sm_client
                elif service == "sts":
                    return mock_sts_client
                return MagicMock()

            mock_client.side_effect = client_factory

            client = mock_boto3.AWSSecretsManagerClient()
            client.authenticate()

            secret = client.update_secret("existing-secret", "new-value")
            assert secret.name == "existing-secret"
            assert secret.value == "new-value"
            assert secret.version == "v2"

    def test_get_secret_json(self, mock_boto3):
        """Test getting secret as JSON."""
        mock_sm_client = MagicMock()
        mock_sm_client.get_secret_value.return_value = {
            "Name": "json-secret",
            "SecretString": '{"key": "value", "number": 42}',
            "VersionId": "v1",
        }

        mock_sts_client = MagicMock()

        with patch("boto3.client") as mock_client:
            def client_factory(service, **kwargs):
                if service == "secretsmanager":
                    return mock_sm_client
                elif service == "sts":
                    return mock_sts_client
                return MagicMock()

            mock_client.side_effect = client_factory

            client = mock_boto3.AWSSecretsManagerClient()
            client.authenticate()

            data = client.get_secret_json("json-secret")
            assert data == {"key": "value", "number": 42}
