"""Tests for envdrift.vault.gcp module - GCP Secret Manager client."""

from __future__ import annotations

import importlib
import sys
import types
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest


class DummyGcpError(Exception):
    """Base error for fake GCP exceptions."""


class DummyGoogleAPICallError(DummyGcpError):
    """Fake GoogleAPICallError."""


class DummyPermissionDeniedError(DummyGcpError):
    """Fake PermissionDenied."""


class DummyUnauthenticatedError(DummyGcpError):
    """Fake Unauthenticated."""


class DummyNotFoundError(DummyGcpError):
    """Fake NotFound."""


class DummyAlreadyExistsError(DummyGcpError):
    """Fake AlreadyExists."""


class DummyDefaultCredentialsError(Exception):
    """Fake DefaultCredentialsError."""


@pytest.fixture
def mock_gcp():
    """Mock GCP SDK modules."""
    exceptions_mod = types.ModuleType("google.api_core.exceptions")
    exceptions_mod.GoogleAPICallError = DummyGoogleAPICallError
    exceptions_mod.PermissionDenied = DummyPermissionDeniedError
    exceptions_mod.Unauthenticated = DummyUnauthenticatedError
    exceptions_mod.NotFound = DummyNotFoundError
    exceptions_mod.AlreadyExists = DummyAlreadyExistsError

    api_core_mod = types.ModuleType("google.api_core")
    api_core_mod.exceptions = exceptions_mod

    auth_exceptions_mod = types.ModuleType("google.auth.exceptions")
    auth_exceptions_mod.DefaultCredentialsError = DummyDefaultCredentialsError

    auth_mod = types.ModuleType("google.auth")
    auth_mod.exceptions = auth_exceptions_mod

    secretmanager_mod = types.ModuleType("google.cloud.secretmanager")
    secretmanager_mod.SecretManagerServiceClient = MagicMock()

    cloud_mod = types.ModuleType("google.cloud")
    cloud_mod.secretmanager = secretmanager_mod

    google_mod = types.ModuleType("google")
    google_mod.api_core = api_core_mod
    google_mod.auth = auth_mod
    google_mod.cloud = cloud_mod

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
        import envdrift.vault.gcp as gcp_module

        importlib.reload(gcp_module)
        yield gcp_module


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
        mock_gcp.secretmanager.SecretManagerServiceClient.return_value = mock_client

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
        mock_gcp.secretmanager.SecretManagerServiceClient.return_value = mock_client

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
        mock_gcp.secretmanager.SecretManagerServiceClient.return_value = mock_client

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
        mock_gcp.secretmanager.SecretManagerServiceClient.return_value = mock_client

        client = mock_gcp.GCPSecretManagerClient(project_id="my-project")
        client.authenticate()

        result = client.set_secret("my-secret", "value")
        assert result.name == "my-secret"
        assert result.value == "value"
        assert result.version == "5"
