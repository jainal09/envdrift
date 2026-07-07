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

    def test_client_with_different_region(
        self, localstack_endpoint: str, populated_secrets: dict[str, str], monkeypatch
    ) -> None:
        """A client pinned to another region sees only that region's secrets.

        Secrets Manager namespaces secrets per region (LocalStack mirrors real
        AWS), so the old version of this test — create in us-east-1, read from
        eu-west-1 — could never pass and sat behind an unconditional skip
        labelled "flaky in CI" (#497). The deterministic contract: a secret
        created in eu-west-1 is readable by an eu-west-1 client, while the
        us-east-1 fixture secrets are NOT visible from eu-west-1.
        """
        boto3 = pytest.importorskip("boto3")
        monkeypatch.setenv("AWS_ENDPOINT_URL", localstack_endpoint)
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")

        from envdrift.vault.aws import AWSSecretsManagerClient
        from envdrift.vault.base import SecretNotFoundError

        secret_name = "envdrift-test/eu-west-1-region-key"
        eu_boto_client = boto3.client(
            "secretsmanager",
            endpoint_url=localstack_endpoint,
            region_name="eu-west-1",
            aws_access_key_id="test",
            aws_secret_access_key="test",
        )
        try:
            try:
                eu_boto_client.create_secret(Name=secret_name, SecretString="eu-west-1-value")
            except eu_boto_client.exceptions.ResourceExistsException:
                eu_boto_client.put_secret_value(
                    SecretId=secret_name, SecretString="eu-west-1-value"
                )

            client = AWSSecretsManagerClient(region="eu-west-1")
            client.authenticate()
            assert client.region == "eu-west-1"

            # The eu-west-1 secret is readable through the envdrift client.
            secret = client.get_secret(secret_name)
            assert secret.value == "eu-west-1-value"

            # Region isolation: the us-east-1 fixture secret is not visible here.
            with pytest.raises(SecretNotFoundError):
                client.get_secret("envdrift-test/single-key")
        finally:
            with contextlib.suppress(Exception):
                eu_boto_client.delete_secret(SecretId=secret_name, ForceDeleteWithoutRecovery=True)


# ---------------------------------------------------------------------------
# Additional real-backend coverage (package: test_aws_integration.py)
#
# Every test below drives a REAL backend: the LocalStack AWS Secrets Manager
# container on :4566, the real envdrift CLI as a subprocess, the real dotenvx
# binary, and/or the SyncEngine driven directly against a live boto3 client.
# Secret names are prefixed with the test name so concurrent/repeat runs never
# collide, and every created secret is force-deleted in a finally block.
# ---------------------------------------------------------------------------


def _force_delete(aws_secrets_client, name: str) -> None:
    """Force-delete a secret, ignoring any error (cleanup helper)."""
    with contextlib.suppress(Exception):
        aws_secrets_client.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True)


def _create_secret(aws_secrets_client, **kwargs):
    """Create a secret, force-deleting any leftover of the same name first.

    Makes every create rerun-safe: a secret left behind by a previously crashed
    run (or a shared LocalStack instance) would otherwise raise
    ``ResourceExistsException`` before the test's own ``finally`` cleanup runs.
    """
    _force_delete(aws_secrets_client, kwargs["Name"])
    return aws_secrets_client.create_secret(**kwargs)


def _dotenvx_available() -> bool:
    """Return True when the real dotenvx binary is on PATH."""
    import shutil

    return shutil.which("dotenvx") is not None


def _make_encrypted_project(folder: Path, environment: str) -> str:
    """Create a real dotenvx-encrypted .env.<environment> file in *folder*.

    Runs the real dotenvx binary to encrypt a plaintext file, then reads the
    generated DOTENV_PRIVATE_KEY_<ENV> value out of the produced .env.keys and
    removes the .env.keys (so tests start from a key-less state). Returns the
    private key value (bare, no prefix).
    """
    import shutil

    dotenvx = shutil.which("dotenvx")
    assert dotenvx is not None, "dotenvx must be installed for this helper"

    env_file = folder / f".env.{environment}"
    env_file.write_text("FOO=bar\nBAZ=qux\n")

    result = subprocess.run(
        [dotenvx, "encrypt", "-f", str(env_file)],
        cwd=str(folder),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"dotenvx encrypt failed: {result.stderr}"

    keys_file = folder / ".env.keys"
    key_name = f"DOTENV_PRIVATE_KEY_{environment.upper()}"
    from envdrift.sync.operations import EnvKeysFile

    key_value = EnvKeysFile(keys_file).read_key(key_name)
    assert key_value, f"{key_name} not found in generated .env.keys"

    # Remove the generated keys file so the test exercises a fresh pull/sync.
    keys_file.unlink()
    return key_value


# --- Category B: CLI vault-push / vault-pull against LocalStack (P0) ---


class TestAWSVaultPushPullCLIRealBackend:
    """End-to-end CLI vault-push / vault-pull flows against LocalStack."""

    def test_vault_push_single_service_stores_key_value_in_vault(
        self,
        work_dir: Path,
        aws_test_env: dict[str, str],
        aws_secrets_client,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """HP-16: single-service vault-push stores DOTENV_PRIVATE_KEY_<ENV>=<value>."""
        secret_name = "envdrift-test/push-single-store"
        (work_dir / ".env.keys").write_text("DOTENV_PRIVATE_KEY_STAGING=staging-key-xyz\n")

        env = aws_test_env.copy()
        env["PYTHONPATH"] = integration_pythonpath

        try:
            result = subprocess.run(
                [
                    *envdrift_cmd,
                    "vault-push",
                    str(work_dir),
                    secret_name,
                    "--env",
                    "staging",
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

            stored = aws_secrets_client.get_secret_value(SecretId=secret_name)
            assert stored["SecretString"] == "DOTENV_PRIVATE_KEY_STAGING=staging-key-xyz"
        finally:
            _force_delete(aws_secrets_client, secret_name)

    def test_vault_push_all_skips_existing_then_force_overwrites(
        self,
        work_dir: Path,
        aws_test_env: dict[str, str],
        aws_secrets_client,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """HP-17 + EC-17 + DOC-force: --all skips existing, --force overwrites."""
        secret_name = "envdrift-test/push-all-force"
        old_value = "DOTENV_PRIVATE_KEY_STAGING=OLDKEY-original"

        # Pre-create the secret with an OLD value so the first --all run skips it.
        _create_secret(aws_secrets_client, Name=secret_name, SecretString=old_value)
        old_version = aws_secrets_client.get_secret_value(SecretId=secret_name)["VersionId"]

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
        # The new local key value, different from what is in the vault.
        (work_dir / ".env.keys").write_text("DOTENV_PRIVATE_KEY_STAGING=NEWKEY-from-local\n")
        (work_dir / ".env.staging").write_text(
            'DOTENV_PUBLIC_KEY_STAGING="pub"\nSECRET="encrypted:abc"\n'
        )

        env = aws_test_env.copy()
        env["PYTHONPATH"] = integration_pythonpath

        try:
            # First run: secret already exists -> skipped, value unchanged.
            first = subprocess.run(
                [*envdrift_cmd, "vault-push", "--all", "--skip-encrypt"],
                cwd=work_dir,
                env=env,
                capture_output=True,
                text=True,
                timeout=60,
            )
            assert first.returncode == 0, f"stdout: {first.stdout}\nstderr: {first.stderr}"
            first_out = (first.stdout + first.stderr).lower()
            assert "skip" in first_out or "already exists" in first_out, first.stdout

            after_first = aws_secrets_client.get_secret_value(SecretId=secret_name)
            assert after_first["SecretString"] == old_value
            assert "NEWKEY" not in after_first["SecretString"]

            # Second run: --force overwrites with the new local value.
            second = subprocess.run(
                [*envdrift_cmd, "vault-push", "--all", "--skip-encrypt", "--force"],
                cwd=work_dir,
                env=env,
                capture_output=True,
                text=True,
                timeout=60,
            )
            assert second.returncode == 0, f"stdout: {second.stdout}\nstderr: {second.stderr}"
            assert "pushed" in (second.stdout + second.stderr).lower(), second.stdout

            after_second = aws_secrets_client.get_secret_value(SecretId=secret_name)
            assert after_second["SecretString"] == "DOTENV_PRIVATE_KEY_STAGING=NEWKEY-from-local"
            assert after_second["VersionId"] != old_version
        finally:
            _force_delete(aws_secrets_client, secret_name)

    def test_push_all_empty_env_keys_filename_falls_back_to_dot_env_keys(
        self,
        work_dir: Path,
        aws_test_env: dict[str, str],
        aws_secrets_client,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """#318: env_keys_filename = "" must resolve to .env.keys, not the folder dir.

        With an empty ``env_keys_filename`` the key-read path previously collapsed to
        ``mapping.folder_path / ""`` (the folder itself), so ``EnvKeysFile`` read a
        directory and surfaced a misleading ``Is a directory`` error instead of
        pushing. The fallback must use ``.env.keys``.
        """
        secret_name = "envdrift-test/empty-keys-filename"
        # Ensure the secret does not exist so the push path (not skip) is taken.
        _force_delete(aws_secrets_client, secret_name)

        (work_dir / "envdrift.toml").write_text(
            '[encryption]\nbackend = "dotenvx"\n'
            '[vault]\nprovider = "aws"\nregion = "us-east-1"\n'
            '[vault.sync]\nenv_keys_filename = ""\n'  # <-- the bug trigger
            "[[vault.sync.mappings]]\n"
            f'secret_name = "{secret_name}"\nfolder_path = "."\nenvironment = "staging"\n'
        )
        (work_dir / ".env.keys").write_text("DOTENV_PRIVATE_KEY_STAGING=NEWKEY-from-local\n")

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
            out = (result.stdout + result.stderr).lower()
            assert "is a directory" not in out, out
            assert ".env.keys not found" not in out, out
            assert result.returncode == 0, out
            stored = aws_secrets_client.get_secret_value(SecretId=secret_name)["SecretString"]
            assert stored == "DOTENV_PRIVATE_KEY_STAGING=NEWKEY-from-local"
        finally:
            _force_delete(aws_secrets_client, secret_name)

    def test_push_all_skipped_existing_does_not_mutate_local_files(
        self,
        work_dir: Path,
        aws_test_env: dict[str, str],
        aws_secrets_client,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """#347: a skipped --all push (secret exists, no --force) must not mutate disk.

        Run WITHOUT ``--skip-encrypt`` so the encrypt-then-skip path is exercised:
        previously a plaintext env file was encrypted (and ``.env.keys`` generated)
        BEFORE the existence/skip check, mutating the working tree even though the
        push was ultimately a no-op. After the fix the skip check runs first, so a
        plaintext file stays plaintext and no ``.env.keys`` appears.
        """
        if not _dotenvx_available():
            pytest.skip("dotenvx binary required")

        secret_name = "envdrift-test/push-all-idempotent"
        # Pre-create the secret so the push is skipped (no --force).
        _create_secret(
            aws_secrets_client,
            Name=secret_name,
            SecretString="DOTENV_PRIVATE_KEY_PRODUCTION=preexisting",
        )

        (work_dir / "envdrift.toml").write_text(
            '[encryption]\nbackend = "dotenvx"\n'
            '[vault]\nprovider = "aws"\nregion = "us-east-1"\n'
            "[vault.sync]\n"
            "[[vault.sync.mappings]]\n"
            f'secret_name = "{secret_name}"\nfolder_path = "."\nenvironment = "production"\n'
        )
        # A *plaintext* env file: on the buggy path it would be encrypted before
        # the skip check, mutating the file and creating .env.keys.
        env_file = work_dir / ".env.production"
        env_file.write_text("FOO=bar\nBAZ=qux\n")
        env_before = env_file.read_bytes()
        keys_path = work_dir / ".env.keys"
        assert not keys_path.exists()

        env = aws_test_env.copy()
        env["PYTHONPATH"] = integration_pythonpath
        try:
            result = subprocess.run(
                [*envdrift_cmd, "vault-push", "--all"],  # NO --skip-encrypt, NO --force
                cwd=work_dir,
                env=env,
                capture_output=True,
                text=True,
                timeout=90,
            )
            out = (result.stdout + result.stderr).lower()
            assert result.returncode == 0, out
            assert "skip" in out or "already exists" in out, out
            # The file must NOT have been encrypted, and no .env.keys generated.
            assert env_file.read_bytes() == env_before, (
                "skipped push encrypted/mutated .env.production (#347)"
            )
            assert "encrypting" not in out, out
            assert not keys_path.exists(), "skipped push generated .env.keys (#347)"
        finally:
            _force_delete(aws_secrets_client, secret_name)

    def test_ephemeral_pull_uses_environment_key_name_not_folder_name(
        self,
        work_dir: Path,
        aws_test_env: dict[str, str],
        aws_secrets_client,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """#325: ephemeral pull derives the key name from the environment.

        Load-bearing construction mirroring the unit test: the mapping's
        ``folder_path`` is a DISTINCT path value from the directory the engine
        ultimately operates on, but the two ``.resolve()`` to the same dir. Here
        the configured ``folder_path`` is a **symlink** (``svc-link``) pointing
        at the real encrypted project dir (``svc-a``); the symlink's basename
        (``svc-link``) differs from both the real folder name (``svc-a``) and the
        environment (``production``). The injected ephemeral key name must be
        ``DOTENV_PRIVATE_KEY_PRODUCTION`` (env-derived) — never
        ``DOTENV_PRIVATE_KEY_SVC-LINK`` / ``DOTENV_PRIVATE_KEY_SVC-A``
        (folder-derived) — so the real dotenvx file decrypts. The fix keys the
        ephemeral map by the *resolved* folder path, so the symlinked /
        relative-vs-absolute mismatch the pre-fix raw ``==`` lookup could not
        bridge now matches.
        """
        if not _dotenvx_available():
            pytest.skip("dotenvx binary required")

        secret_name = "envdrift-test/ephemeral-folder-mismatch"
        # Real encrypted project lives in 'svc-a' (folder name != env).
        svc = work_dir / "svc-a"
        svc.mkdir()
        priv = _make_encrypted_project(svc, "production")  # encrypts svc-a/.env.production

        # Config points at a DISTINCT path (symlink) resolving to the same dir.
        svc_link = work_dir / "svc-link"
        svc_link.symlink_to(svc, target_is_directory=True)
        # Sanity: distinct raw path, same resolved directory (the #325 trigger).
        assert svc_link != svc
        assert svc_link.resolve() == svc.resolve()

        _create_secret(
            aws_secrets_client,
            Name=secret_name,
            SecretString=f"DOTENV_PRIVATE_KEY_PRODUCTION={priv}",
        )

        (work_dir / "envdrift.toml").write_text(
            '[encryption]\nbackend = "dotenvx"\n'
            '[vault]\nprovider = "aws"\nregion = "us-east-1"\n'
            "[vault.sync]\nephemeral_keys = true\n"
            "[[vault.sync.mappings]]\n"
            f'secret_name = "{secret_name}"\nfolder_path = "svc-link"\nenvironment = "production"\n'
        )

        env = aws_test_env.copy()
        env["PYTHONPATH"] = integration_pythonpath
        try:
            result = subprocess.run(
                [*envdrift_cmd, "pull", "--config", "envdrift.toml"],
                cwd=work_dir,
                env=env,
                capture_output=True,
                text=True,
                timeout=90,
            )
            out = result.stdout + result.stderr
            assert result.returncode == 0, out
            assert "DOTENV_PRIVATE_KEY_SVC-LINK" not in out, (
                "folder-derived key name injected instead of env-derived (#325)"
            )
            assert "DOTENV_PRIVATE_KEY_SVC-A" not in out, (
                "folder-derived key name injected instead of env-derived (#325)"
            )
            # Decryption succeeded -> plaintext present; ephemeral -> no .env.keys.
            decrypted = (svc / ".env.production").read_text()
            assert "FOO=bar" in decrypted, decrypted
            assert not (svc / ".env.keys").exists()
        finally:
            _force_delete(aws_secrets_client, secret_name)

    def test_pull_strips_dotenv_private_key_prefix_end_to_end(
        self,
        work_dir: Path,
        aws_test_env: dict[str, str],
        aws_secrets_client,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """HP-10: vault-pull writes a single, non-doubled DOTENV_PRIVATE_KEY prefix."""
        secret_name = "envdrift-test/pull-strip-prefix"
        # Stored with the full KEY=value form (as vault-push would store it).
        _create_secret(
            aws_secrets_client,
            Name=secret_name,
            SecretString="DOTENV_PRIVATE_KEY_PRODUCTION=ec-prefixed-1234",
        )

        env = aws_test_env.copy()
        env["PYTHONPATH"] = integration_pythonpath

        try:
            result = subprocess.run(
                [
                    *envdrift_cmd,
                    "vault-pull",
                    str(work_dir),
                    secret_name,
                    "--env",
                    "production",
                    "--no-decrypt",
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

            keys_content = (work_dir / ".env.keys").read_text()
            assert "DOTENV_PRIVATE_KEY_PRODUCTION=ec-prefixed-1234" in keys_content
            # The prefix must NOT be doubled.
            assert "DOTENV_PRIVATE_KEY_PRODUCTION=DOTENV_PRIVATE_KEY_PRODUCTION" not in keys_content
            assert keys_content.count("DOTENV_PRIVATE_KEY_PRODUCTION=") == 1
        finally:
            _force_delete(aws_secrets_client, secret_name)

    def test_pull_idempotent_second_run_skips_when_key_matches(
        self,
        work_dir: Path,
        aws_test_env: dict[str, str],
        aws_secrets_client,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """HP-02: first sync creates the key, immediate second sync reports SKIPPED."""
        secret_name = "envdrift-test/pull-idempotent"
        _create_secret(
            aws_secrets_client,
            Name=secret_name,
            SecretString="DOTENV_PRIVATE_KEY_PRODUCTION=idem-key-abc",
        )

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
environment = "production"
"""
        (work_dir / "envdrift.toml").write_text(config_content)
        (work_dir / ".env.production").write_text(
            'DOTENV_PUBLIC_KEY_PRODUCTION="pub"\nSECRET="encrypted:abc"\n'
        )

        env = aws_test_env.copy()
        env["PYTHONPATH"] = integration_pythonpath

        try:
            first = subprocess.run(
                [*envdrift_cmd, "sync"],
                cwd=work_dir,
                env=env,
                capture_output=True,
                text=True,
                timeout=60,
            )
            assert first.returncode == 0, f"stdout: {first.stdout}\nstderr: {first.stderr}"
            keys_path = work_dir / ".env.keys"
            assert keys_path.exists()
            first_bytes = keys_path.read_bytes()
            assert b"idem-key-abc" in first_bytes

            second = subprocess.run(
                [*envdrift_cmd, "sync"],
                cwd=work_dir,
                env=env,
                capture_output=True,
                text=True,
                timeout=60,
            )
            assert second.returncode == 0, f"stdout: {second.stdout}\nstderr: {second.stderr}"
            second_out = (second.stdout + second.stderr).lower()
            assert "match" in second_out or "skip" in second_out, second.stdout
            # The file must be byte-identical after the no-op second run.
            assert keys_path.read_bytes() == first_bytes
        finally:
            _force_delete(aws_secrets_client, secret_name)

    def test_vault_pull_env_mismatch_with_stored_key_name_exits_1(
        self,
        work_dir: Path,
        aws_test_env: dict[str, str],
        aws_secrets_client,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """BP-19: pulling --env production a secret stored as STAGING fails fast."""
        secret_name = "envdrift-test/pull-env-mismatch"
        _create_secret(
            aws_secrets_client,
            Name=secret_name,
            SecretString="DOTENV_PRIVATE_KEY_STAGING=staging-secret-val",
        )

        env = aws_test_env.copy()
        env["PYTHONPATH"] = integration_pythonpath

        try:
            result = subprocess.run(
                [
                    *envdrift_cmd,
                    "vault-pull",
                    str(work_dir),
                    secret_name,
                    "--env",
                    "production",
                    "--no-decrypt",
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

            assert result.returncode == 1, (
                f"expected fast-fail exit 1\nstdout: {result.stdout}\nstderr: {result.stderr}"
            )
            combined = result.stdout + result.stderr
            assert "DOTENV_PRIVATE_KEY_STAGING" in combined
            assert "DOTENV_PRIVATE_KEY_PRODUCTION" in combined

            # A fast-failed mismatch must not write .env.keys at all. Assert the
            # file is absent (no pre-run snapshot existed) — this also catches a
            # wrongly-written STAGING key, not just the production key.
            keys_path = work_dir / ".env.keys"
            assert not keys_path.exists(), (
                ".env.keys must not be written on a fast-failed env mismatch; "
                f"found: {keys_path.read_text()}"
            )
        finally:
            _force_delete(aws_secrets_client, secret_name)

    def test_vault_pull_no_decrypt_writes_key_only(
        self,
        work_dir: Path,
        aws_test_env: dict[str, str],
        aws_secrets_client,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """EC-18 + DOC-no-decrypt: --no-decrypt writes only .env.keys, file untouched."""
        if not _dotenvx_available():
            pytest.skip("dotenvx binary not available")

        secret_name = "envdrift-test/pull-no-decrypt"
        # Build a real encrypted .env.production and capture its bytes.
        real_key = _make_encrypted_project(work_dir, "production")
        env_prod = work_dir / ".env.production"
        original_encrypted = env_prod.read_bytes()
        assert b"encrypted:" in original_encrypted

        # The value we actually pull is independent of the real key; we only
        # assert the key is written and the encrypted file stays byte-identical.
        _create_secret(
            aws_secrets_client,
            Name=secret_name,
            SecretString=f"DOTENV_PRIVATE_KEY_PRODUCTION={real_key}",
        )

        env = aws_test_env.copy()
        env["PYTHONPATH"] = integration_pythonpath

        try:
            result = subprocess.run(
                [
                    *envdrift_cmd,
                    "vault-pull",
                    str(work_dir),
                    secret_name,
                    "--env",
                    "production",
                    "--no-decrypt",
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

            keys_content = (work_dir / ".env.keys").read_text()
            assert f"DOTENV_PRIVATE_KEY_PRODUCTION={real_key}" in keys_content

            # The encrypted env file must be byte-for-byte unchanged.
            assert env_prod.read_bytes() == original_encrypted
            assert b"encrypted:" in env_prod.read_bytes()
            assert "decrypt" not in result.stdout.lower() or "no" in result.stdout.lower()
        finally:
            _force_delete(aws_secrets_client, secret_name)

    def test_sync_check_decryption_real_dotenvx_non_destructive(
        self,
        work_dir: Path,
        aws_test_env: dict[str, str],
        aws_secrets_client,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """HP-12: sync --check-decryption verifies with real dotenvx, without mutating.

        The check decrypts a temp-dir COPY (#473); the live encrypted file must
        stay byte-identical (the old in-place decrypt+re-encrypt roundtrip
        churned the ciphertext on every passing run).
        """
        if not _dotenvx_available():
            pytest.skip("dotenvx binary not available")

        secret_name = "envdrift-test/check-decryption"
        # Real encrypted file + the matching real private key.
        real_key = _make_encrypted_project(work_dir, "production")
        env_prod = work_dir / ".env.production"
        assert b"encrypted:" in env_prod.read_bytes()
        original_encrypted_bytes = env_prod.read_bytes()

        _create_secret(
            aws_secrets_client,
            Name=secret_name,
            SecretString=f"DOTENV_PRIVATE_KEY_PRODUCTION={real_key}",
        )

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
environment = "production"
"""
        (work_dir / "envdrift.toml").write_text(config_content)

        env = aws_test_env.copy()
        env["PYTHONPATH"] = integration_pythonpath

        try:
            result = subprocess.run(
                [*envdrift_cmd, "sync", "--check-decryption"],
                cwd=work_dir,
                env=env,
                capture_output=True,
                text=True,
                timeout=120,
            )
            assert result.returncode == 0, f"stdout: {result.stdout}\nstderr: {result.stderr}"

            out = (result.stdout + result.stderr).lower()
            assert "pass" in out, f"expected decryption PASSED\n{result.stdout}"

            # A check must not modify files: byte-identical ciphertext (#473).
            assert env_prod.read_bytes() == original_encrypted_bytes
            # The key was synced locally.
            keys_content = (work_dir / ".env.keys").read_text()
            assert f"DOTENV_PRIVATE_KEY_PRODUCTION={real_key}" in keys_content
        finally:
            _force_delete(aws_secrets_client, secret_name)


# --- Category B: Direct client JSON / binary decoding (P1/P2) ---


class TestAWSClientValueDecoding:
    """get_secret / set_secret value decoding against LocalStack."""

    def test_set_secret_dict_stores_json_string(
        self, aws_client_configured, aws_secrets_client
    ) -> None:
        """HP-09: set_secret_dict serializes a dict to a JSON string and stores it."""
        import json

        name = "envdrift-test/set-secret-dict"
        value_dict = {"username": "admin", "password": "p@ss", "port": "5432"}

        try:
            result = aws_client_configured.set_secret_dict(name, value_dict)

            assert result.name == name
            assert result.value == json.dumps(value_dict)

            raw = aws_secrets_client.get_secret_value(SecretId=name)["SecretString"]
            assert json.loads(raw) == value_dict
        finally:
            _force_delete(aws_secrets_client, name)

    def test_get_secret_parses_json_dict_returns_json_string(
        self, aws_client_configured, aws_secrets_client
    ) -> None:
        """HP-03: a JSON-object secret is parsed and returned as canonical JSON."""
        import json

        name = "envdrift-test/get-secret-json-dict"
        _create_secret(aws_secrets_client, Name=name, SecretString=json.dumps({"a": "1", "b": "2"}))

        try:
            secret = aws_client_configured.get_secret(name)
            assert json.loads(secret.value) == {"a": "1", "b": "2"}
            assert secret.version is not None
            assert secret.metadata.get("arn")
        finally:
            _force_delete(aws_secrets_client, name)

    def test_get_secret_utf8_binary_decodes(
        self, aws_client_configured, aws_secrets_client
    ) -> None:
        """HP-04: SecretBinary holding valid UTF-8 bytes decodes to the original string."""
        name = "envdrift-test/get-secret-utf8-binary"
        raw = "hello-utf8-é".encode()
        _create_secret(aws_secrets_client, Name=name, SecretBinary=raw)

        try:
            secret = aws_client_configured.get_secret(name)
            assert secret.value == "hello-utf8-é"
        finally:
            _force_delete(aws_secrets_client, name)

    def test_get_secret_invalid_json_returns_raw_string(
        self, aws_client_configured, aws_secrets_client
    ) -> None:
        """EC-02: a non-JSON secret value is returned verbatim."""
        name = "envdrift-test/get-secret-invalid-json"
        _create_secret(aws_secrets_client, Name=name, SecretString="not-json: {broken")

        try:
            secret = aws_client_configured.get_secret(name)
            assert secret.value == "not-json: {broken"
        finally:
            _force_delete(aws_secrets_client, name)


# --- Category B: SyncEngine driven directly against LocalStack (P1) ---


class TestAWSSyncEngineRealBackend:
    """Drive the SyncEngine directly against a live LocalStack vault client."""

    @staticmethod
    def _build_engine(work_dir: Path, aws_client_configured, secret_name: str, mode):
        from envdrift.sync.config import ServiceMapping, SyncConfig
        from envdrift.sync.engine import SyncEngine

        config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name=secret_name,
                    folder_path=work_dir,
                    environment="production",
                )
            ]
        )
        return SyncEngine(config=config, vault_client=aws_client_configured, mode=mode)

    def test_force_update_mismatch_creates_backup_via_real_vault(
        self, work_dir: Path, aws_client_configured, aws_secrets_client
    ) -> None:
        """HP-03 (sync): force_update on a mismatch backs up and rewrites .env.keys."""
        from envdrift.sync.engine import SyncMode
        from envdrift.sync.result import SyncAction

        secret_name = "envdrift-test/force-update-backup"
        _create_secret(
            aws_secrets_client,
            Name=secret_name,
            SecretString="DOTENV_PRIVATE_KEY_PRODUCTION=vault-new-value",
        )

        # Local file holds an OLD, different value + an env file so the mapping resolves.
        (work_dir / ".env.production").write_text(
            'DOTENV_PUBLIC_KEY_PRODUCTION="pub"\nSECRET="encrypted:abc"\n'
        )
        keys_path = work_dir / ".env.keys"
        keys_path.write_text("# .env.production\nDOTENV_PRIVATE_KEY_PRODUCTION=local-old-value\n")

        try:
            engine = self._build_engine(
                work_dir,
                aws_client_configured,
                secret_name,
                SyncMode(force_update=True),
            )
            result = engine.sync_all()
            svc = result.services[0]

            assert svc.action == SyncAction.UPDATED
            assert svc.backup_path is not None
            assert svc.backup_path.exists()
            assert "local-old-value" in svc.backup_path.read_text()

            assert "DOTENV_PRIVATE_KEY_PRODUCTION=vault-new-value" in keys_path.read_text()
        finally:
            _force_delete(aws_secrets_client, secret_name)

    def test_ephemeral_mode_fetches_key_from_real_container_vault(
        self, work_dir: Path, aws_client_configured, aws_secrets_client
    ) -> None:
        """HP-05 (sync): ephemeral mode fetches the key without writing .env.keys."""
        from envdrift.sync.config import ServiceMapping, SyncConfig
        from envdrift.sync.engine import SyncEngine, SyncMode
        from envdrift.sync.result import SyncAction

        secret_name = "envdrift-test/ephemeral-key"
        _create_secret(
            aws_secrets_client,
            Name=secret_name,
            SecretString="DOTENV_PRIVATE_KEY_PRODUCTION=eph-real-key",
        )
        (work_dir / ".env.production").write_text(
            'DOTENV_PUBLIC_KEY_PRODUCTION="pub"\nSECRET="encrypted:abc"\n'
        )

        config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name=secret_name,
                    folder_path=work_dir,
                    environment="production",
                )
            ],
            ephemeral_keys=True,
        )
        engine = SyncEngine(config=config, vault_client=aws_client_configured, mode=SyncMode())

        try:
            result = engine.sync_all()
            svc = result.services[0]

            assert svc.action == SyncAction.EPHEMERAL
            # Prefix stripped to the bare value.
            assert svc.vault_key_value == "eph-real-key"
            assert not (work_dir / ".env.keys").exists()
            assert result.ephemeral_count == 1
        finally:
            _force_delete(aws_secrets_client, secret_name)

    def test_verify_ci_key_mismatch_drift_gate_exits_nonzero(
        self, work_dir: Path, aws_client_configured, aws_secrets_client
    ) -> None:
        """BP-14 (sync): verify_only surfaces a local-vs-vault mismatch (CI gate)."""
        from envdrift.sync.engine import SyncMode
        from envdrift.sync.result import SyncAction

        secret_name = "envdrift-test/verify-drift-gate"
        _create_secret(
            aws_secrets_client,
            Name=secret_name,
            SecretString="DOTENV_PRIVATE_KEY_PRODUCTION=vault-value-A",
        )
        (work_dir / ".env.production").write_text(
            'DOTENV_PUBLIC_KEY_PRODUCTION="pub"\nSECRET="encrypted:abc"\n'
        )
        keys_path = work_dir / ".env.keys"
        original_keys = "# .env.production\nDOTENV_PRIVATE_KEY_PRODUCTION=local-value-B\n"
        keys_path.write_text(original_keys)

        try:
            engine = self._build_engine(
                work_dir,
                aws_client_configured,
                secret_name,
                SyncMode(verify_only=True),
            )
            result = engine.sync_all()
            svc = result.services[0]

            assert svc.action == SyncAction.ERROR
            mismatch_msg = f"{svc.message} {svc.error}"
            assert "mismatch" in mismatch_msg.lower() or "differs" in mismatch_msg.lower()
            assert result.has_errors is True

            # verify_only must not mutate the local file.
            assert keys_path.read_text() == original_keys
        finally:
            _force_delete(aws_secrets_client, secret_name)


# --- #480: vault-fetched key material is normalized/validated before install ---


class TestAWSKeyMaterialNormalization:
    """Regression tests for #480 against a live LocalStack Secrets Manager."""

    def test_vault_pull_json_secretstring_extracts_key_field(
        self,
        work_dir: Path,
        aws_test_env: dict[str, str],
        aws_secrets_client,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """#480 item 3: an AWS-console-style JSON key/value SecretString yields
        the bare key, not the JSON document, in .env.keys."""
        import json

        secret_name = "envdrift-test/pull-json-doc-480"
        _create_secret(
            aws_secrets_client,
            Name=secret_name,
            SecretString=json.dumps({"DOTENV_PRIVATE_KEY_PRODUCTION": "json-doc-key-480"}),
        )

        env = aws_test_env.copy()
        env["PYTHONPATH"] = integration_pythonpath

        try:
            result = subprocess.run(
                [
                    *envdrift_cmd,
                    "vault-pull",
                    str(work_dir),
                    secret_name,
                    "--env",
                    "production",
                    "--no-decrypt",
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
            keys_path = work_dir / ".env.keys"
            lines = keys_path.read_text(encoding="utf-8").splitlines()
            assert "DOTENV_PRIVATE_KEY_PRODUCTION=json-doc-key-480" in lines
            # The JSON document itself was never installed.
            assert not any("{" in line for line in lines), lines
        finally:
            _force_delete(aws_secrets_client, secret_name)

    def test_vault_pull_json_secretstring_without_key_field_fails_loudly(
        self,
        work_dir: Path,
        aws_test_env: dict[str, str],
        aws_secrets_client,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """A JSON document with no DOTENV_PRIVATE_KEY field is rejected with a
        clear shape error naming the layout — exit 1, nothing written."""
        import json

        secret_name = "envdrift-test/pull-json-no-key-480"
        _create_secret(
            aws_secrets_client,
            Name=secret_name,
            SecretString=json.dumps({"username": "admin", "password": "p"}),
        )

        env = aws_test_env.copy()
        env["PYTHONPATH"] = integration_pythonpath

        try:
            result = subprocess.run(
                [
                    *envdrift_cmd,
                    "vault-pull",
                    str(work_dir),
                    secret_name,
                    "--env",
                    "production",
                    "--no-decrypt",
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

            assert result.returncode == 1, (
                f"expected exit 1\nstdout: {result.stdout}\nstderr: {result.stderr}"
            )
            combined = " ".join((result.stdout + result.stderr).split())
            assert "JSON" in combined
            assert not (work_dir / ".env.keys").exists()
        finally:
            _force_delete(aws_secrets_client, secret_name)

    def test_vault_pull_secret_binary_rejected_with_clear_error(
        self,
        work_dir: Path,
        aws_test_env: dict[str, str],
        aws_secrets_client,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """#480 item 5: a non-UTF-8 SecretBinary payload must not be silently
        base64-encoded and installed as key material; vault-pull exits 1 with an
        error that names the binary shape."""
        secret_name = "envdrift-test/pull-binary-480"
        _create_secret(
            aws_secrets_client,
            Name=secret_name,
            SecretBinary=b"\xff\xfe\x00binarykey\x99",
        )

        env = aws_test_env.copy()
        env["PYTHONPATH"] = integration_pythonpath

        try:
            result = subprocess.run(
                [
                    *envdrift_cmd,
                    "vault-pull",
                    str(work_dir),
                    secret_name,
                    "--env",
                    "production",
                    "--no-decrypt",
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

            assert result.returncode == 1, (
                f"expected exit 1\nstdout: {result.stdout}\nstderr: {result.stderr}"
            )
            combined = " ".join((result.stdout + result.stderr).split()).lower()
            assert "binary" in combined
            assert not (work_dir / ".env.keys").exists()
        finally:
            _force_delete(aws_secrets_client, secret_name)

    def test_get_secret_binary_sets_base64_marker(
        self, aws_client_configured, aws_secrets_client
    ) -> None:
        """#480 item 5 (client contract): the base64 transformation of a binary
        payload is marked in SecretValue.metadata, never silent."""
        name = "envdrift-test/get-secret-binary-marker-480"
        _create_secret(aws_secrets_client, Name=name, SecretBinary=b"\xff\xfe\x00\x99")

        try:
            secret = aws_client_configured.get_secret(name)
            assert secret.metadata.get("encoding") == "base64"
        finally:
            _force_delete(aws_secrets_client, name)
