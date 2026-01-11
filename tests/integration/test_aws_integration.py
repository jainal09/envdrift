"""AWS Secrets Manager integration tests using LocalStack.

These tests require LocalStack to be running:
    make test-integration-up

Tests cover:
- Direct client operations (get, set, list secrets)
- CLI `envdrift pull` with AWS vault
- CLI `envdrift vault-push` to AWS
- Error handling for missing secrets
- Region override functionality
"""

from __future__ import annotations

import contextlib
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Generator

# Check if boto3 is available
import importlib.util

BOTO3_AVAILABLE = importlib.util.find_spec("boto3") is not None

# Mark all tests in this module as requiring AWS (LocalStack)
pytestmark = [
    pytest.mark.integration,
    pytest.mark.aws,
    pytest.mark.skipif(
        not BOTO3_AVAILABLE, reason="boto3 not installed - install with: pip install envdrift[aws]"
    ),
]


# --- Fixtures for AWS Tests ---


@pytest.fixture
def populated_secrets(aws_secrets_client) -> Generator[dict[str, str], None, None]:
    """Pre-populate LocalStack with test secrets and clean up after."""
    secrets = {
        "envdrift-test/single-key": "ec1234567890abcdef",
        "envdrift-test/service-a-key": "key-for-service-a-abc123",
        "envdrift-test/service-b-key": "key-for-service-b-xyz789",
        "envdrift-test/multi-env-key": "DOTENV_PRIVATE_KEY_PRODUCTION=prod123",
    }

    created_arns = []
    for name, value in secrets.items():
        try:
            response = aws_secrets_client.create_secret(Name=name, SecretString=value)
            created_arns.append(response["ARN"])
        except aws_secrets_client.exceptions.ResourceExistsException:
            # Secret already exists, update it
            aws_secrets_client.put_secret_value(SecretId=name, SecretString=value)

    yield secrets

    # Cleanup: force delete secrets
    for name in secrets:
        with contextlib.suppress(Exception):
            aws_secrets_client.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True)


@pytest.fixture
def aws_client_configured(localstack_endpoint: str, monkeypatch):
    """Return a configured AWSSecretsManagerClient for LocalStack."""
    # Set environment for the client (monkeypatch auto-restores after test)
    monkeypatch.setenv("AWS_ENDPOINT_URL", localstack_endpoint)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")

    from envdrift.vault.aws import AWSSecretsManagerClient

    client = AWSSecretsManagerClient(region="us-east-1")
    client.authenticate()
    return client


# --- Category A: Direct Client Tests ---


class TestAWSClientDirect:
    """Test AWSSecretsManagerClient directly against LocalStack."""

    def test_get_secret_single(
        self, aws_client_configured, populated_secrets: dict[str, str]
    ) -> None:
        """Test retrieving a single secret."""
        secret = aws_client_configured.get_secret("envdrift-test/single-key")

        assert secret.name == "envdrift-test/single-key"
        assert secret.value == "ec1234567890abcdef"
        assert secret.version is not None
        assert "arn" in secret.metadata

    def test_get_secret_not_found(self, aws_client_configured) -> None:
        """Test graceful handling of missing secrets."""
        from envdrift.vault.base import SecretNotFoundError

        with pytest.raises(SecretNotFoundError) as exc_info:
            aws_client_configured.get_secret("nonexistent/secret/path")

        assert "not found" in str(exc_info.value).lower()

    def test_set_secret_create(self, aws_client_configured, aws_secrets_client) -> None:
        """Test creating a new secret via set_secret."""
        secret_name = "envdrift-test/new-secret-create"
        secret_value = "brand-new-secret-value"

        try:
            result = aws_client_configured.set_secret(secret_name, secret_value)

            assert result.name == secret_name
            assert result.value == secret_value
            assert result.version is not None

            # Verify via direct boto3 client
            response = aws_secrets_client.get_secret_value(SecretId=secret_name)
            assert response["SecretString"] == secret_value
        finally:
            # Cleanup
            with contextlib.suppress(Exception):
                aws_secrets_client.delete_secret(
                    SecretId=secret_name, ForceDeleteWithoutRecovery=True
                )

    def test_set_secret_update(
        self, aws_client_configured, populated_secrets: dict[str, str]
    ) -> None:
        """Test updating an existing secret via set_secret."""
        secret_name = "envdrift-test/single-key"
        new_value = "updated-secret-value-999"

        result = aws_client_configured.set_secret(secret_name, new_value)

        assert result.name == secret_name
        assert result.value == new_value

        # Verify the update persisted
        retrieved = aws_client_configured.get_secret(secret_name)
        assert retrieved.value == new_value

    def test_list_secrets(self, aws_client_configured, populated_secrets: dict[str, str]) -> None:
        """Test listing secrets with prefix filter."""
        all_secrets = aws_client_configured.list_secrets(prefix="envdrift-test/")

        # Should find all our test secrets
        assert len(all_secrets) >= 4
        assert "envdrift-test/single-key" in all_secrets
        assert "envdrift-test/service-a-key" in all_secrets

    def test_list_secrets_with_prefix(
        self, aws_client_configured, populated_secrets: dict[str, str]
    ) -> None:
        """Test listing secrets with specific prefix."""
        service_secrets = aws_client_configured.list_secrets(prefix="envdrift-test/service-")

        assert len(service_secrets) == 2
        assert "envdrift-test/service-a-key" in service_secrets
        assert "envdrift-test/service-b-key" in service_secrets


# --- Category A: CLI Sync/Pull Tests ---


class TestAWSSyncCommand:
    """Test envdrift CLI sync/pull commands with AWS vault."""

    @pytest.fixture
    def env_project(
        self, work_dir: Path, aws_test_env: dict[str, str], populated_secrets: dict[str, str]
    ) -> Path:
        """Create a project directory with envdrift.toml config."""
        # Create envdrift.toml
        config_content = """\
[encryption]
backend = "dotenvx"

[encryption.dotenvx]
auto_install = true

[vault]
provider = "aws"
region = "us-east-1"

[vault.sync]
env_keys_filename = ".env.keys"

[[vault.sync.mappings]]
secret_name = "envdrift-test/single-key"
folder_path = "."
environment = "production"
"""
        (work_dir / "envdrift.toml").write_text(config_content)

        # Create a minimal encrypted .env file (simulated)
        env_content = """\
#/-------------------[DOTENV][Load]--------------------/#
#/         public-key encryption for .env files        /#
#/  https://github.com/dotenvx/dotenvx-pro?encrypted   /#
#/--------------------------------------------------/#
DOTENV_PUBLIC_KEY_PRODUCTION="034a5e..."
# encrypted values below
DATABASE_URL="encrypted:abc123..."
"""
        (work_dir / ".env.production").write_text(env_content)

        return work_dir

    def test_pull_single_secret(
        self,
        env_project: Path,
        aws_test_env: dict[str, str],
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """Test pulling a single secret from AWS to .env.keys."""
        env = aws_test_env.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            [*envdrift_cmd, "pull"],
            cwd=env_project,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )

        # Check command succeeded
        assert result.returncode == 0, f"stdout: {result.stdout}\nstderr: {result.stderr}"

        # Verify .env.keys was created with the secret value
        env_keys = env_project / ".env.keys"
        assert env_keys.exists(), ".env.keys should be created"

        keys_content = env_keys.read_text()
        assert "DOTENV_PRIVATE_KEY_PRODUCTION" in keys_content
        assert "ec1234567890abcdef" in keys_content

    def test_pull_multiple_secrets(
        self,
        work_dir: Path,
        aws_test_env: dict[str, str],
        integration_pythonpath: str,
        populated_secrets: dict[str, str],
        envdrift_cmd: list[str],
    ) -> None:
        """Test pulling multiple secrets in parallel."""
        # Create config with multiple mappings
        config_content = """\
[encryption]
backend = "dotenvx"

[encryption.dotenvx]
auto_install = true

[vault]
provider = "aws"
region = "us-east-1"

[vault.sync]
max_workers = 2

[[vault.sync.mappings]]
secret_name = "envdrift-test/service-a-key"
folder_path = "service-a"
environment = "production"

[[vault.sync.mappings]]
secret_name = "envdrift-test/service-b-key"
folder_path = "service-b"
environment = "production"
"""
        (work_dir / "envdrift.toml").write_text(config_content)

        # Create service directories with encrypted env files
        for service in ["service-a", "service-b"]:
            service_dir = work_dir / service
            service_dir.mkdir()
            (service_dir / ".env.production").write_text(
                'DOTENV_PUBLIC_KEY_PRODUCTION="key"\nSECRET="encrypted:..."\n'
            )

        env = aws_test_env.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            [*envdrift_cmd, "pull"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )

        assert result.returncode == 0, f"stdout: {result.stdout}\nstderr: {result.stderr}"

        # Verify both .env.keys files were created
        assert (work_dir / "service-a" / ".env.keys").exists()
        assert (work_dir / "service-b" / ".env.keys").exists()

        # Verify correct keys in each
        keys_a = (work_dir / "service-a" / ".env.keys").read_text()
        assert "key-for-service-a" in keys_a

        keys_b = (work_dir / "service-b" / ".env.keys").read_text()
        assert "key-for-service-b" in keys_b


# --- Category A: CLI Vault-Push Tests ---


class TestAWSVaultPushCommand:
    """Test envdrift vault-push command with AWS."""

    def test_vault_push_from_env_keys(
        self,
        work_dir: Path,
        aws_test_env: dict[str, str],
        aws_secrets_client,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """Test pushing a key from .env.keys to AWS vault."""
        secret_name = "envdrift-test/pushed-from-file"

        # Create config
        config_content = f"""\
[encryption]
backend = "dotenvx"

[encryption.dotenvx]
auto_install = true

[vault]
provider = "aws"
region = "us-east-1"

[vault.sync]

[[vault.sync.mappings]]
secret_name = "{secret_name}"
folder_path = "."
environment = "staging"
"""
        (work_dir / "envdrift.toml").write_text(config_content)

        # Create .env.keys with the key to push
        key_value = "staging-private-key-abc123xyz"
        env_keys_content = f"DOTENV_PRIVATE_KEY_STAGING={key_value}\n"
        (work_dir / ".env.keys").write_text(env_keys_content)

        # Create encrypted env file
        (work_dir / ".env.staging").write_text(
            'DOTENV_PUBLIC_KEY_STAGING="pub"\nSECRET="encrypted:..."\n'
        )

        env = aws_test_env.copy()
        env["PYTHONPATH"] = integration_pythonpath

        try:
            result = subprocess.run(
                [*envdrift_cmd, "vault-push", "--all", "--skip-encrypt"],
                cwd=work_dir,
                env=env,
                capture_output=True,
                text=True,
                timeout=60,
            )

            assert result.returncode == 0, f"stdout: {result.stdout}\nstderr: {result.stderr}"

            # Verify secret was pushed to LocalStack
            # vault-push stores the full .env.keys content, not just the value
            response = aws_secrets_client.get_secret_value(SecretId=secret_name)
            assert key_value in response["SecretString"]
        finally:
            # Cleanup
            with contextlib.suppress(Exception):
                aws_secrets_client.delete_secret(
                    SecretId=secret_name, ForceDeleteWithoutRecovery=True
                )

    def test_vault_push_direct_value(
        self,
        work_dir: Path,
        aws_test_env: dict[str, str],
        aws_secrets_client,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """Test pushing a direct key-value to AWS vault."""
        secret_name = "envdrift-test/direct-push"
        secret_value = "DOTENV_PRIVATE_KEY_DIRECT=direct-value-123"

        env = aws_test_env.copy()
        env["PYTHONPATH"] = integration_pythonpath

        try:
            result = subprocess.run(
                [
                    *envdrift_cmd,
                    "vault-push",
                    "--direct",
                    secret_name,
                    secret_value,
                    "--provider",
                    "aws",
                    "--region",
                    "us-east-1",
                ],
                cwd=work_dir,
                env=env,
                capture_output=True,
                text=True,
                timeout=60,
            )

            assert result.returncode == 0, f"stdout: {result.stdout}\nstderr: {result.stderr}"

            # Verify secret was pushed
            response = aws_secrets_client.get_secret_value(SecretId=secret_name)
            assert response["SecretString"] == secret_value
        finally:
            # Cleanup
            with contextlib.suppress(Exception):
                aws_secrets_client.delete_secret(
                    SecretId=secret_name, ForceDeleteWithoutRecovery=True
                )


# --- Category A: Error Handling Tests ---


class TestAWSErrorHandling:
    """Test error handling for AWS operations."""

    def test_sync_secret_not_found_graceful(
        self,
        work_dir: Path,
        aws_test_env: dict[str, str],
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """Test that sync handles missing secrets gracefully."""
        config_content = """\
[encryption]
backend = "dotenvx"

[encryption.dotenvx]
auto_install = true

[vault]
provider = "aws"
region = "us-east-1"

[[vault.sync.mappings]]
secret_name = "nonexistent/secret/that/does/not/exist"
folder_path = "."
environment = "production"
"""
        (work_dir / "envdrift.toml").write_text(config_content)
        (work_dir / ".env.production").write_text('SECRET="encrypted:..."\n')

        env = aws_test_env.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            [*envdrift_cmd, "pull"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )

        # The command should either:
        # 1. Exit with non-zero and include a meaningful error message, OR
        # 2. Log the missing secret error but continue gracefully
        combined_output = (result.stdout + result.stderr).lower()
        has_not_found_message = (
            "not found" in combined_output or "does not exist" in combined_output
        )

        # Verify the error was reported (not silently swallowed)
        assert has_not_found_message or result.returncode != 0, (
            f"Expected 'not found' message or non-zero exit code.\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )


# --- Category A: Region Handling Tests ---


class TestAWSRegionHandling:
    """Test AWS region configuration and override."""

    def test_region_from_config(
        self,
        aws_client_configured,
        populated_secrets: dict[str, str],
    ) -> None:
        """Test that region is correctly read from config."""
        # The aws_client_configured uses us-east-1
        assert aws_client_configured.region == "us-east-1"

        # Should be able to retrieve secrets
        secret = aws_client_configured.get_secret("envdrift-test/single-key")
        assert secret.value == "ec1234567890abcdef"

    @pytest.mark.skip(reason="LocalStack region handling is flaky in CI")
    def test_client_with_different_region(
        self, localstack_endpoint: str, populated_secrets: dict[str, str], monkeypatch
    ) -> None:
        """Test creating client with different region."""
        monkeypatch.setenv("AWS_ENDPOINT_URL", localstack_endpoint)
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")

        from envdrift.vault.aws import AWSSecretsManagerClient

        # LocalStack accepts any region
        client = AWSSecretsManagerClient(region="eu-west-1")
        client.authenticate()

        assert client.region == "eu-west-1"
        # Should still work with LocalStack
        secret = client.get_secret("envdrift-test/single-key")
        assert secret.value == "ec1234567890abcdef"
