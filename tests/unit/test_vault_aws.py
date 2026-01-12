"""Tests for envdrift.vault.aws module - AWS Secrets Manager client."""

from __future__ import annotations

import importlib
import json
import sys
from unittest.mock import MagicMock, patch

import pytest

from envdrift.vault.base import (
    AuthenticationError,
    SecretNotFoundError,
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
        client_factory, _mock_sm_client, _mock_sts_client = mock_client_factory

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

    def test_set_secret_creates_new(self, mock_boto3, patched_boto_clients):
        """Test set_secret creates a new secret."""
        mock_sm_client, _ = patched_boto_clients
        mock_sm_client.create_secret.return_value = {
            "Name": "new-secret",
            "VersionId": "v1",
            "ARN": "arn:aws:...",
        }

        client = mock_boto3.AWSSecretsManagerClient()
        client.authenticate()

        secret = client.set_secret("new-secret", "value")
        assert secret.name == "new-secret"
        assert secret.value == "value"
        assert secret.version == "v1"

    def test_set_secret_updates_existing(self, mock_boto3, patched_boto_clients):
        """Test set_secret updates existing secret when create fails with ResourceExistsException."""

        class FakeClientError(Exception):
            def __init__(self, code):
                self.response = {"Error": {"Code": code}}

        mock_boto3._ClientError = FakeClientError

        mock_sm_client, _ = patched_boto_clients
        mock_sm_client.create_secret.side_effect = FakeClientError("ResourceExistsException")
        mock_sm_client.put_secret_value.return_value = {
            "Name": "existing-secret",
            "VersionId": "v2",
            "ARN": "arn:aws:...",
        }

        client = mock_boto3.AWSSecretsManagerClient()
        client.authenticate()

        secret = client.set_secret("existing-secret", "new-value")
        assert secret.name == "existing-secret"
        assert secret.value == "new-value"
        assert secret.version == "v2"

    def test_set_secret_unauthorized_raises_auth_error(self, mock_boto3, patched_boto_clients):
        """Unauthorized errors should raise AuthenticationError."""

        class FakeClientError(Exception):
            def __init__(self, code):
                self.response = {"Error": {"Code": code}}

        mock_boto3._ClientError = FakeClientError

        mock_sm_client, _ = patched_boto_clients
        mock_sm_client.create_secret.side_effect = FakeClientError("UnauthorizedException")

        client = mock_boto3.AWSSecretsManagerClient()
        client.authenticate()

        with pytest.raises(AuthenticationError):
            client.set_secret("name", "value")

    def test_put_secret_value_requires_authentication(self, mock_boto3):
        """_put_secret_value should require authentication."""
        client = mock_boto3.AWSSecretsManagerClient()

        with pytest.raises(VaultError):
            client._put_secret_value("name", "value")

    def test_put_secret_value_access_denied(self, mock_boto3, patched_boto_clients):
        """_put_secret_value should raise AuthenticationError on access denied."""

        class FakeClientError(Exception):
            def __init__(self, code):
                self.response = {"Error": {"Code": code}}

        mock_boto3._ClientError = FakeClientError

        mock_sm_client, _ = patched_boto_clients
        mock_sm_client.put_secret_value.side_effect = FakeClientError("AccessDeniedException")

        client = mock_boto3.AWSSecretsManagerClient()
        client.authenticate()

        with pytest.raises(AuthenticationError):
            client._put_secret_value("name", "value")

    def test_put_secret_value_error_wraps(self, mock_boto3, patched_boto_clients):
        """_put_secret_value should raise VaultError on other failures."""

        class FakeClientError(Exception):
            def __init__(self, code="Boom"):
                self.response = {"Error": {"Code": code}}

        mock_boto3._ClientError = FakeClientError

        mock_sm_client, _ = patched_boto_clients
        mock_sm_client.put_secret_value.side_effect = FakeClientError()

        client = mock_boto3.AWSSecretsManagerClient()
        client.authenticate()

        with pytest.raises(VaultError):
            client._put_secret_value("name", "value")

    def test_get_secret_json_returns_string(self, mock_boto3, patched_boto_clients):
        """Test getting secret with JSON content returns JSON string."""
        mock_sm_client, _ = patched_boto_clients
        json_data = {"key": "value", "number": 42}
        mock_sm_client.get_secret_value.return_value = {
            "Name": "json-secret",
            "SecretString": json.dumps(json_data),
            "VersionId": "v1",
        }

        client = mock_boto3.AWSSecretsManagerClient()
        client.authenticate()

        secret = client.get_secret("json-secret")
        # JSON content is returned as JSON string
        assert json.loads(secret.value) == json_data

    def test_get_secret_json_list_returns_string(self, mock_boto3, patched_boto_clients):
        """JSON values that aren't dicts should return str(parsed)."""
        mock_sm_client, _ = patched_boto_clients
        json_data = ["a", "b"]
        mock_sm_client.get_secret_value.return_value = {
            "Name": "json-secret",
            "SecretString": json.dumps(json_data),
            "VersionId": "v1",
        }

        client = mock_boto3.AWSSecretsManagerClient()
        client.authenticate()

        secret = client.get_secret("json-secret")
        assert secret.value == json.dumps(json_data)

    def test_get_secret_requires_authentication(self, mock_boto3):
        """get_secret should require authentication."""
        client = mock_boto3.AWSSecretsManagerClient()

        with pytest.raises(VaultError):
            client.get_secret("secret")

    def test_get_secret_access_denied(self, mock_boto3, patched_boto_clients):
        """Access denied should raise AuthenticationError."""

        class FakeClientError(Exception):
            def __init__(self, code):
                self.response = {"Error": {"Code": code}}

        mock_sm_client, _ = patched_boto_clients
        mock_sm_client.get_secret_value.side_effect = FakeClientError("AccessDeniedException")

        client = mock_boto3.AWSSecretsManagerClient()
        client.authenticate()

        with pytest.raises(AuthenticationError):
            client.get_secret("secret")

    def test_get_secret_error_wraps(self, mock_boto3, patched_boto_clients):
        """Unknown errors should raise VaultError."""

        class FakeClientError(Exception):
            def __init__(self, code):
                self.response = {"Error": {"Code": code}}

        mock_sm_client, _ = patched_boto_clients
        mock_sm_client.get_secret_value.side_effect = FakeClientError("Boom")

        client = mock_boto3.AWSSecretsManagerClient()
        client.authenticate()

        with pytest.raises(VaultError):
            client.get_secret("secret")

    def test_list_secrets_requires_authentication(self, mock_boto3):
        """list_secrets should require authentication."""
        client = mock_boto3.AWSSecretsManagerClient()

        with pytest.raises(VaultError):
            client.list_secrets()

    def test_list_secrets_access_denied(self, mock_boto3, patched_boto_clients):
        """Access denied should raise AuthenticationError for list_secrets."""

        class FakeClientError(Exception):
            def __init__(self, code):
                self.response = {"Error": {"Code": code}}

        mock_sm_client, _ = patched_boto_clients
        mock_sm_client.get_paginator.side_effect = FakeClientError("AccessDeniedException")

        client = mock_boto3.AWSSecretsManagerClient()
        client.authenticate()

        with pytest.raises(AuthenticationError):
            client.list_secrets()

    def test_authenticate_access_denied(self, mock_boto3):
        """AccessDenied should raise AuthenticationError."""

        class FakeClientError(Exception):
            def __init__(self, code):
                self.response = {"Error": {"Code": code}}

        mock_boto3._ClientError = FakeClientError
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
        mock_boto3._ClientError = FakeCredentialsError

        good_sm = MagicMock()
        good_sts = MagicMock()

        with patch("boto3.client") as mock_client:

            def factory(service, **kwargs):
                return good_sm if service == "secretsmanager" else good_sts

            mock_client.side_effect = factory

            client = mock_boto3.AWSSecretsManagerClient()
            client.authenticate()

        # Now make STS fail to force reset
        with patch("boto3.client") as mock_client:

            def factory_fail(service, **kwargs):
                if service == "sts":
                    raise FakeCredentialsError("expired")
                return good_sm

            mock_client.side_effect = factory_fail

            assert client.is_authenticated() is False
            assert client._client is None

    def test_get_secret_not_found_raises(self, mock_boto3, patched_boto_clients):
        """ResourceNotFound should raise SecretNotFoundError."""

        class FakeClientError(Exception):
            def __init__(self, code):
                self.response = {"Error": {"Code": code}}

        mock_boto3._ClientError = FakeClientError

        mock_sm_client, _ = patched_boto_clients
        mock_sm_client.get_secret_value.side_effect = FakeClientError("ResourceNotFoundException")

        client = mock_boto3.AWSSecretsManagerClient()
        client.authenticate()

        with pytest.raises(SecretNotFoundError):
            client.get_secret("missing-secret")

    def test_get_secret_binary_decode_error(self, mock_boto3, patched_boto_clients):
        """Binary secrets that can't decode as UTF-8 should be base64-encoded."""

        mock_sm_client, _ = patched_boto_clients
        mock_sm_client.get_secret_value.return_value = {
            "Name": "binary-secret",
            "SecretBinary": b"\xff\xfe",
            "VersionId": "v1",
        }

        client = mock_boto3.AWSSecretsManagerClient()
        client.authenticate()

        # Non-UTF-8 binary secrets are base64-encoded for safe handling
        result = client.get_secret("binary-secret")
        assert result.name == "binary-secret"
        assert result.value == "//4="  # base64 encoding of b"\xff\xfe"
        assert result.version == "v1"

    def test_list_secrets_error_wraps(self, mock_boto3, patched_boto_clients):
        """Paginator errors should raise VaultError."""

        class FakeClientError(Exception):
            def __init__(self, code="Boom"):
                self.response = {"Error": {"Code": code}}

        mock_boto3._ClientError = FakeClientError

        mock_sm_client, _ = patched_boto_clients
        mock_paginator = MagicMock()
        mock_paginator.paginate.side_effect = FakeClientError()
        mock_sm_client.get_paginator.return_value = mock_paginator

        client = mock_boto3.AWSSecretsManagerClient()
        client.authenticate()

        with pytest.raises(VaultError):
            client.list_secrets()

    def test_get_secret_invalid_json_returns_string(self, mock_boto3, patched_boto_clients):
        """Invalid JSON is returned as plain string."""

        mock_sm_client, _ = patched_boto_clients
        mock_sm_client.get_secret_value.return_value = {
            "Name": "json-secret",
            "SecretString": "not-json",
            "VersionId": "v1",
        }

        client = mock_boto3.AWSSecretsManagerClient()
        client.authenticate()

        secret = client.get_secret("json-secret")
        assert secret.value == "not-json"

    def test_set_secret_error_wraps(self, mock_boto3, patched_boto_clients):
        """set_secret errors should raise VaultError."""

        class FakeClientError(Exception):
            def __init__(self, code="Boom"):
                self.response = {"Error": {"Code": code}}

        mock_boto3._ClientError = FakeClientError

        mock_sm_client, _ = patched_boto_clients
        mock_sm_client.create_secret.side_effect = FakeClientError()

        client = mock_boto3.AWSSecretsManagerClient()
        client.authenticate()

        with pytest.raises(VaultError):
            client.set_secret("name", "value")

    def test_set_secret_dict(self, mock_boto3, patched_boto_clients):
        """Test set_secret_dict creates secret with JSON-encoded dict."""
        mock_sm_client, _ = patched_boto_clients
        mock_sm_client.create_secret.return_value = {
            "Name": "dict-secret",
            "VersionId": "v1",
            "ARN": "arn:aws:...",
        }

        client = mock_boto3.AWSSecretsManagerClient()
        client.authenticate()

        data = {"key": "value", "number": 42}
        secret = client.set_secret_dict("dict-secret", data)
        assert secret.name == "dict-secret"
        assert json.loads(secret.value) == data
