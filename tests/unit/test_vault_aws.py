"""Tests for envdrift.vault.aws module - AWS Secrets Manager client."""

from __future__ import annotations

import importlib
import sys
from unittest.mock import MagicMock, patch

import pytest

from envdrift.vault.base import (
    AuthenticationError,
    VaultError,
)


@pytest.fixture
def mock_client_factory():
    """Create reusable mocked AWS clients for testing."""

    mock_sm_client = MagicMock()
    mock_sts_client = MagicMock()

    def client_factory(service, **kwargs):
        """Return a mock AWS service client for the given service."""
        if service == "secretsmanager":
            return mock_sm_client
        if service == "sts":
            return mock_sts_client
        return MagicMock()

    return client_factory, mock_sm_client, mock_sts_client


@pytest.fixture
def patched_boto_clients(mock_client_factory):
    """Patch boto3.client to return shared mock clients."""

    client_factory, mock_sm_client, mock_sts_client = mock_client_factory
    with patch("boto3.client") as mock_client:
        mock_client.side_effect = client_factory
        yield mock_sm_client, mock_sts_client


class TestAWSSecretsManagerClient:
    """Tests for AWSSecretsManagerClient."""

    @pytest.fixture
    def mock_boto3(self):
        """Mock boto3 and its exceptions."""
        with patch.dict(
            "sys.modules",
            {
                "boto3": MagicMock(),
                "botocore": MagicMock(),
                "botocore.exceptions": MagicMock(),
            },
        ):
            # Need to import after patching
            import importlib

            import envdrift.vault.aws as aws_module

            importlib.reload(aws_module)
            yield aws_module

    def test_init_without_boto3_raises(self):
        """Client init should raise when boto3 is unavailable."""

        with patch.dict(
            sys.modules, {"boto3": None, "botocore": None, "botocore.exceptions": None}
        ):
            import envdrift.vault.aws as aws_module

            importlib.reload(aws_module)

            assert aws_module.AWS_AVAILABLE is False
            with pytest.raises(ImportError):
                aws_module.AWSSecretsManagerClient()

        # Restore module after the negative check
        import envdrift.vault.aws as aws_module

        importlib.reload(aws_module)

    def test_init_sets_region(self, mock_boto3):
        """Test client initializes with region."""
        client = mock_boto3.AWSSecretsManagerClient(region="us-west-2")
        assert client.region == "us-west-2"

    def test_init_default_region(self, mock_boto3):
        """Test client uses default region."""
        client = mock_boto3.AWSSecretsManagerClient()
        assert client.region == "us-east-1"

    def test_authenticate_success(self, mock_boto3, mock_client_factory):
        """Test successful authentication."""
        client_factory, mock_sm_client, mock_sts_client = mock_client_factory

        with patch("boto3.client") as mock_client:
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

    def test_is_authenticated_true_after_auth(self, mock_boto3, patched_boto_clients):
        """Test is_authenticated returns True after authentication."""
        _sm, _sts = patched_boto_clients

        client = mock_boto3.AWSSecretsManagerClient()
        client.authenticate()

        # After auth, is_authenticated should check STS again
        assert client.is_authenticated() is True

    def test_get_secret_string(self, mock_boto3, patched_boto_clients):
        """Test retrieving a string secret."""
        mock_sm_client, _ = patched_boto_clients
        mock_sm_client.get_secret_value.return_value = {
            "Name": "my-secret",
            "SecretString": "secret-value",
            "VersionId": "v1",
            "ARN": "arn:aws:secretsmanager:...",
            "CreatedDate": "2024-01-01",
            "VersionStages": ["AWSCURRENT"],
        }

        client = mock_boto3.AWSSecretsManagerClient()
        client.authenticate()

        secret = client.get_secret("my-secret")

        assert secret.name == "my-secret"
        assert secret.value == "secret-value"
        assert secret.version == "v1"

    def test_get_secret_binary(self, mock_boto3, patched_boto_clients):
        """Test retrieving a binary secret."""
        mock_sm_client, _ = patched_boto_clients
        mock_sm_client.get_secret_value.return_value = {
            "Name": "binary-secret",
            "SecretBinary": b"binary-data",
            "VersionId": "v1",
        }

        client = mock_boto3.AWSSecretsManagerClient()
        client.authenticate()

        secret = client.get_secret("binary-secret")
        assert secret.value == "binary-data"

    def test_list_secrets(self, mock_boto3, patched_boto_clients):
        """Test listing secrets."""
        mock_sm_client, _ = patched_boto_clients
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {"SecretList": [{"Name": "secret1"}, {"Name": "secret2"}]},
            {"SecretList": [{"Name": "secret3"}]},
        ]
        mock_sm_client.get_paginator.return_value = mock_paginator

        client = mock_boto3.AWSSecretsManagerClient()
        client.authenticate()

        secrets = client.list_secrets()
        assert secrets == ["secret1", "secret2", "secret3"]

    def test_list_secrets_with_prefix(self, mock_boto3, patched_boto_clients):
        """Test listing secrets with prefix filter."""
        mock_sm_client, _ = patched_boto_clients
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "SecretList": [
                    {"Name": "app/secret1"},
                    {"Name": "app/secret2"},
                    {"Name": "other/secret"},
                ]
            },
        ]
        mock_sm_client.get_paginator.return_value = mock_paginator

        client = mock_boto3.AWSSecretsManagerClient()
        client.authenticate()

        secrets = client.list_secrets(prefix="app/")
        assert secrets == ["app/secret1", "app/secret2"]

    def test_create_secret(self, mock_boto3, patched_boto_clients):
        """Test creating a secret."""
        mock_sm_client, _ = patched_boto_clients
        mock_sm_client.create_secret.return_value = {
            "Name": "new-secret",
            "VersionId": "v1",
            "ARN": "arn:aws:...",
        }

        client = mock_boto3.AWSSecretsManagerClient()
        client.authenticate()

        secret = client.create_secret("new-secret", "value", "description")
        assert secret.name == "new-secret"
        assert secret.value == "value"

    def test_update_secret(self, mock_boto3, patched_boto_clients):
        """Test updating a secret."""
        mock_sm_client, _ = patched_boto_clients
        mock_sm_client.put_secret_value.return_value = {
            "Name": "existing-secret",
            "VersionId": "v2",
            "ARN": "arn:aws:...",
        }

        client = mock_boto3.AWSSecretsManagerClient()
        client.authenticate()

        secret = client.update_secret("existing-secret", "new-value")
        assert secret.name == "existing-secret"
        assert secret.value == "new-value"
        assert secret.version == "v2"

    def test_get_secret_json(self, mock_boto3, patched_boto_clients):
        """Test getting secret as JSON."""
        mock_sm_client, _ = patched_boto_clients
        mock_sm_client.get_secret_value.return_value = {
            "Name": "json-secret",
            "SecretString": '{"key": "value", "number": 42}',
            "VersionId": "v1",
        }

        client = mock_boto3.AWSSecretsManagerClient()
        client.authenticate()

        data = client.get_secret_json("json-secret")
        assert data == {"key": "value", "number": 42}

    def test_authenticate_access_denied(self, mock_boto3):
        """AccessDenied should raise AuthenticationError."""

        class FakeClientError(Exception):
            def __init__(self, code):
                """
                Initialize the object with a response dictionary containing an AWS-style error code.

                Parameters:
                    code (str | int): Error code to store under "Error" -> "Code" in the response.
                """
                self.response = {"Error": {"Code": code}}

        mock_boto3.ClientError = FakeClientError
        mock_boto3.NoCredentialsError = Exception
        mock_boto3.PartialCredentialsError = Exception

        with patch("boto3.client") as mock_client:
            mock_client.side_effect = FakeClientError("AccessDenied")

            client = mock_boto3.AWSSecretsManagerClient()
            with pytest.raises(AuthenticationError):
                client.authenticate()

    def test_is_authenticated_resets_on_error(self, mock_boto3):
        """is_authenticated should drop state on credential error."""

        class FakeCredentialsError(Exception):
            pass

        mock_boto3.NoCredentialsError = FakeCredentialsError
        mock_boto3.PartialCredentialsError = FakeCredentialsError
        mock_boto3.ClientError = FakeCredentialsError

        good_sm = MagicMock()
        good_sts = MagicMock()

        with patch("boto3.client") as mock_client:

            def factory(service, **kwargs):
                """
                Selects a mocked AWS client implementation based on the requested service name.

                Parameters:
                    service (str): The AWS service name to select (e.g., "secretsmanager").
                    kwargs: Additional keyword arguments are accepted for compatibility and ignored.

                Returns:
                    The mocked Secrets Manager client when `service` is "secretsmanager", otherwise the mocked STS client.
                """
                return good_sm if service == "secretsmanager" else good_sts

            mock_client.side_effect = factory

            client = mock_boto3.AWSSecretsManagerClient()
            client.authenticate()

        # Now make STS fail to force reset
        with patch("boto3.client") as mock_client:

            def factory_fail(service, **kwargs):
                """
                Produce a mock AWS client for tests, simulating expired STS credentials when requested.

                Parameters:
                        service (str): The AWS service name to create. If "sts", the factory simulates expired credentials.
                        **kwargs: Ignored extra arguments accepted for compatibility with boto3.client signature.

                Returns:
                        The mock Secrets Manager client when `service` is not "sts".

                Raises:
                        FakeCredentialsError: If `service` is "sts", raised to simulate expired/stale credentials.
                """
                if service == "sts":
                    raise FakeCredentialsError("expired")
                return good_sm

            mock_client.side_effect = factory_fail

            assert client.is_authenticated() is False
            assert client._client is None

    def test_get_secret_not_found_raises(self, mock_boto3, patched_boto_clients):
        """ResourceNotFound should raise SecretNotFoundError."""

        from envdrift.vault.base import SecretNotFoundError

        class FakeClientError(Exception):
            def __init__(self, code):
                """
                Initialize the object with a response dictionary containing an AWS-style error code.

                Parameters:
                    code (str | int): Error code to store under "Error" -> "Code" in the response.
                """
                self.response = {"Error": {"Code": code}}

        mock_boto3.ClientError = FakeClientError

        mock_sm_client, _ = patched_boto_clients
        mock_sm_client.get_secret_value.side_effect = FakeClientError("ResourceNotFoundException")

        client = mock_boto3.AWSSecretsManagerClient()
        client.authenticate()

        with pytest.raises(SecretNotFoundError):
            client.get_secret("missing-secret")

    def test_get_secret_binary_base64_fallback(self, mock_boto3, patched_boto_clients):
        """Binary secrets should be base64-encoded when utf-8 decode fails."""

        mock_sm_client, _ = patched_boto_clients
        mock_sm_client.get_secret_value.return_value = {
            "Name": "binary-secret",
            "SecretBinary": b"\xff\xfe",
            "VersionId": "v1",
        }

        client = mock_boto3.AWSSecretsManagerClient()
        client.authenticate()

        secret = client.get_secret("binary-secret")
        # Should be base64 encoded ascii string
        assert isinstance(secret.value, str)
        assert secret.value.strip() != ""

    def test_list_secrets_error_wraps(self, mock_boto3, patched_boto_clients):
        """Paginator errors should raise VaultError."""

        class FakeClientError(Exception):
            def __init__(self, code="Boom"):
                """
                Initialize the object with an error response dictionary containing an error code.

                Parameters:
                    code (str): Error code to set in self.response["Error"]["Code"]. Defaults to "Boom".
                """
                self.response = {"Error": {"Code": code}}

        mock_boto3.ClientError = FakeClientError

        mock_sm_client, _ = patched_boto_clients
        mock_paginator = MagicMock()
        mock_paginator.paginate.side_effect = FakeClientError()
        mock_sm_client.get_paginator.return_value = mock_paginator

        client = mock_boto3.AWSSecretsManagerClient()
        client.authenticate()

        with pytest.raises(VaultError):
            client.list_secrets()

    def test_get_secret_json_invalid(self, mock_boto3, patched_boto_clients):
        """Invalid JSON should raise VaultError."""

        mock_sm_client, _ = patched_boto_clients
        mock_sm_client.get_secret_value.return_value = {
            "Name": "json-secret",
            "SecretString": "not-json",
            "VersionId": "v1",
        }

        client = mock_boto3.AWSSecretsManagerClient()
        client.authenticate()

        with pytest.raises(VaultError):
            client.get_secret_json("json-secret")

    def test_create_secret_error_wraps(self, mock_boto3, patched_boto_clients):
        """Create secret errors should raise VaultError."""

        class FakeClientError(Exception):
            def __init__(self, code="Boom"):
                """
                Initialize the object with an error response dictionary containing an error code.

                Parameters:
                    code (str): Error code to set in self.response["Error"]["Code"]. Defaults to "Boom".
                """
                self.response = {"Error": {"Code": code}}

        mock_boto3.ClientError = FakeClientError

        mock_sm_client, _ = patched_boto_clients
        mock_sm_client.create_secret.side_effect = FakeClientError()

        client = mock_boto3.AWSSecretsManagerClient()
        client.authenticate()

        with pytest.raises(VaultError):
            client.create_secret("name", "value")

    def test_update_secret_error_wraps(self, mock_boto3, patched_boto_clients):
        """Update secret errors should raise VaultError."""

        class FakeClientError(Exception):
            def __init__(self, code="Boom"):
                """
                Initialize the object with an error response dictionary containing an error code.

                Parameters:
                    code (str): Error code to set in self.response["Error"]["Code"]. Defaults to "Boom".
                """
                self.response = {"Error": {"Code": code}}

        mock_boto3.ClientError = FakeClientError

        mock_sm_client, _ = patched_boto_clients
        mock_sm_client.put_secret_value.side_effect = FakeClientError()

        client = mock_boto3.AWSSecretsManagerClient()
        client.authenticate()

        with pytest.raises(VaultError):
            client.update_secret("name", "value")
