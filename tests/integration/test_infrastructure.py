"""Smoke tests to verify integration test infrastructure is working.

These tests verify that the Docker containers (LocalStack, Vault, Lowkey Vault)
are accessible and functioning correctly.
"""

from __future__ import annotations

import pytest


@pytest.mark.integration
@pytest.mark.aws
class TestLocalStackInfrastructure:
    """Verify LocalStack (AWS Secrets Manager) is working."""

    def test_localstack_accessible(self, localstack_endpoint: str) -> None:
        """Verify LocalStack endpoint is accessible."""
        assert localstack_endpoint == "http://localhost:4566"

    def test_localstack_secretsmanager_works(self, aws_secrets_client) -> None:
        """Verify we can create and retrieve secrets from LocalStack."""
        secret_name = "test/infrastructure/smoke-test"
        secret_value = "smoke-test-value"

        # Create a secret
        aws_secrets_client.create_secret(
            Name=secret_name,
            SecretString=secret_value,
        )

        # Retrieve and verify
        response = aws_secrets_client.get_secret_value(SecretId=secret_name)
        assert response["SecretString"] == secret_value

        # Cleanup
        aws_secrets_client.delete_secret(
            SecretId=secret_name,
            ForceDeleteWithoutRecovery=True,
        )


@pytest.mark.integration
@pytest.mark.vault
class TestVaultInfrastructure:
    """Verify HashiCorp Vault is working."""

    def test_vault_accessible(self, vault_endpoint: str) -> None:
        """Verify Vault endpoint is accessible."""
        assert vault_endpoint == "http://localhost:8200"

    def test_vault_kv_works(self, vault_client) -> None:
        """Verify we can write and read secrets from Vault KV v2."""
        path = "infrastructure/smoke-test"
        secret_data = {"key": "smoke-test-value"}

        # Write secret
        vault_client.secrets.kv.v2.create_or_update_secret(
            path=path,
            secret=secret_data,
        )

        # Read and verify
        response = vault_client.secrets.kv.v2.read_secret_version(path=path)
        assert response["data"]["data"] == secret_data

        # Cleanup
        vault_client.secrets.kv.v2.delete_metadata_and_all_versions(path=path)


@pytest.mark.integration
@pytest.mark.azure
class TestLowkeyVaultInfrastructure:
    """Verify Lowkey Vault (Azure Key Vault emulator) is working."""

    def test_lowkey_vault_accessible(self, lowkey_vault_endpoint: str) -> None:
        """Verify Lowkey Vault endpoint is accessible."""
        assert lowkey_vault_endpoint == "https://localhost:8443"

    def test_lowkey_vault_ping(self, lowkey_vault_endpoint: str) -> None:
        """Verify Lowkey Vault responds to ping."""
        import ssl
        import urllib.request

        # Create an unverified SSL context (Lowkey Vault uses self-signed certs)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # Ping the vault
        url = f"{lowkey_vault_endpoint}/ping"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, context=ctx, timeout=5) as response:
            assert response.status == 200
