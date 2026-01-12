"""Error Handling Integration Tests.

Tests for graceful error handling and recovery scenarios.

Test categories (from spec.md Category G):
- Network timeout handling (vault unreachable)
- Partial sync failures (some secrets fail, others succeed)
- Corrupt .env file parsing
- Corrupt encrypted file detection

Requires: docker-compose -f tests/docker-compose.test.yml up -d
"""

from __future__ import annotations

import contextlib
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    pass

# Mark all tests in this module
pytestmark = [pytest.mark.integration]


class TestNetworkTimeoutVault:
    """Test that vault operations handle network timeouts gracefully."""

    def test_vault_unreachable_timeout(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """Test that operations timeout gracefully when vault is unreachable.

        This test configures envdrift to connect to a non-routable IP address,
        which should trigger a connection timeout rather than hanging indefinitely.
        """
        # Use a non-routable IP that will timeout (TEST-NET-1 per RFC 5737)
        unreachable_host = "http://192.0.2.1:8200"

        config_content = f"""\
[encryption]
backend = "dotenvx"

[encryption.dotenvx]
auto_install = true

[vault]
provider = "hashicorp"
address = "{unreachable_host}"
token = "fake-token"

[[vault.sync.mappings]]
secret_name = "test/secret"
folder_path = "."
environment = "production"
"""
        (work_dir / "envdrift.toml").write_text(config_content)
        (work_dir / ".env.production").write_text('SECRET="encrypted:..."')

        env = {"PYTHONPATH": integration_pythonpath}

        # Run with a timeout - the command should fail gracefully, not hang
        result = subprocess.run(
            [*envdrift_cmd, "pull"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,  # Should fail well before this timeout
        )

        # The command should exit with an error (non-zero)
        assert result.returncode != 0, (
            f"Expected non-zero exit code for unreachable vault.\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

        # Should have some error message about connection/timeout
        combined_output = (result.stdout + result.stderr).lower()
        has_error_message = any(
            msg in combined_output
            for msg in ["error", "timeout", "connect", "failed", "unreachable"]
        )
        assert has_error_message, (
            f"Expected error message about connection failure.\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

    def test_aws_endpoint_unreachable(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """Test AWS client handles unreachable endpoint gracefully."""
        config_content = """\
[encryption]
backend = "dotenvx"

[encryption.dotenvx]
auto_install = true

[vault]
provider = "aws"
region = "us-east-1"

[[vault.sync.mappings]]
secret_name = "test/secret"
folder_path = "."
environment = "production"
"""
        (work_dir / "envdrift.toml").write_text(config_content)
        (work_dir / ".env.production").write_text('SECRET="encrypted:..."')

        # Build environment with unreachable endpoint (port that's not listening)
        # Using localhost with wrong port fails fast (connection refused)
        env = {
            "PYTHONPATH": integration_pythonpath,
            "AWS_ENDPOINT_URL": "http://127.0.0.1:59999",  # Port not listening
            "AWS_ACCESS_KEY_ID": "test",
            "AWS_SECRET_ACCESS_KEY": "test",
            "AWS_DEFAULT_REGION": "us-east-1",
            "AWS_MAX_ATTEMPTS": "1",
            "AWS_RETRY_MODE": "standard",
        }

        result = subprocess.run(
            [*envdrift_cmd, "pull"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should fail with connection error
        assert result.returncode != 0


class TestPartialSyncFailure:
    """Test handling of partial sync failures."""

    @pytest.mark.aws
    def test_some_secrets_fail_others_succeed(
        self,
        work_dir: Path,
        localstack_endpoint: str,
        aws_test_env: dict[str, str],
        aws_secrets_client,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """Test that sync continues for valid secrets when some fail.

        Creates a config with multiple mappings where one points to a
        non-existent secret. Verifies that the valid secrets are still synced.
        """
        # Create one valid secret
        valid_secret_name = "envdrift-test/partial-valid"
        try:
            aws_secrets_client.create_secret(
                Name=valid_secret_name,
                SecretString="valid-key-12345",
            )
        except aws_secrets_client.exceptions.ResourceExistsException:
            aws_secrets_client.put_secret_value(
                SecretId=valid_secret_name,
                SecretString="valid-key-12345",
            )

        config_content = f"""\
[encryption]
backend = "dotenvx"

[encryption.dotenvx]
auto_install = true

[vault]
provider = "aws"
region = "us-east-1"

[[vault.sync.mappings]]
secret_name = "{valid_secret_name}"
folder_path = "service-valid"
environment = "production"

[[vault.sync.mappings]]
secret_name = "nonexistent/secret/that/does/not/exist"
folder_path = "service-invalid"
environment = "production"
"""
        (work_dir / "envdrift.toml").write_text(config_content)

        # Create service directories
        (work_dir / "service-valid").mkdir()
        (work_dir / "service-valid" / ".env.production").write_text(
            'DOTENV_PUBLIC_KEY_PRODUCTION="key"\nSECRET="encrypted:..."'
        )
        (work_dir / "service-invalid").mkdir()
        (work_dir / "service-invalid" / ".env.production").write_text(
            'DOTENV_PUBLIC_KEY_PRODUCTION="key"\nSECRET="encrypted:..."'
        )

        env = aws_test_env.copy()
        env["PYTHONPATH"] = integration_pythonpath

        try:
            result = subprocess.run(
                [*envdrift_cmd, "pull"],
                cwd=work_dir,
                env=env,
                capture_output=True,
                text=True,
                timeout=60,
            )

            # The valid service should have its .env.keys file created
            valid_keys = work_dir / "service-valid" / ".env.keys"
            assert valid_keys.exists(), (
                f"Valid service should have .env.keys created.\n"
                f"stdout: {result.stdout}\nstderr: {result.stderr}"
            )
            assert "valid-key-12345" in valid_keys.read_text()

            # The output should mention the failed secret
            combined_output = (result.stdout + result.stderr).lower()
            has_error_mention = "not found" in combined_output or "error" in combined_output
            assert has_error_mention, "Output should mention the failed secret"

        finally:
            # Cleanup

            with contextlib.suppress(Exception):
                aws_secrets_client.delete_secret(
                    SecretId=valid_secret_name, ForceDeleteWithoutRecovery=True
                )


class TestCorruptEnvFile:
    """Test handling of malformed .env files."""

    def test_malformed_env_file_parsing(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """
        Verify that running `lock --check` does not produce an unhandled exception when the project contains a malformed `.env` file.

        This test writes a malformed `.env` and a minimal `envdrift.toml`, runs the CLI command `lock --check`, and asserts that the command's stderr does not contain a Python traceback.
        """
        # Create various malformed .env files
        malformed_content = """\
# This is a comment
VALID_KEY=valid_value
=missing_key_name
KEY_WITH_NO_VALUE=
KEY WITH SPACES=value
KEY\tWITH\tTABS=value
MULTI=LINE=EQUALS=value
unclosed_quote="value
"""
        (work_dir / ".env").write_text(malformed_content)

        # Create a minimal config
        config_content = """\
[encryption]
backend = "dotenvx"
"""
        (work_dir / "envdrift.toml").write_text(config_content)

        env = {"PYTHONPATH": integration_pythonpath}

        # Run lock --check which will parse the .env file
        result = subprocess.run(
            [*envdrift_cmd, "lock", "--check"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should not crash - may succeed or fail depending on parsing logic,
        # but should not raise an unhandled exception
        assert "Traceback" not in result.stderr, (
            f"Should not have unhandled exception.\nstderr: {result.stderr}"
        )

    def test_binary_content_in_env_file(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """Test handling of binary content in .env files."""
        # Write binary content
        binary_content = b"KEY=value\x00\x01\x02\x03\nBINARY=\xff\xfe\xfd"
        (work_dir / ".env").write_bytes(binary_content)

        config_content = """\
[encryption]
backend = "dotenvx"
"""
        (work_dir / "envdrift.toml").write_text(config_content)

        env = {"PYTHONPATH": integration_pythonpath}

        result = subprocess.run(
            [*envdrift_cmd, "lock", "--check"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should handle gracefully without crashing
        assert "Traceback" not in result.stderr, (
            f"Should not have unhandled exception.\nstderr: {result.stderr}"
        )

    def test_empty_env_file(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """
        Verify that running `envdrift lock --check` on an empty `.env` file completes without unhandled exceptions.

        Writes an empty `.env` and a minimal `envdrift.toml`, runs the CLI under the provided PYTHONPATH, and asserts there is no traceback in stderr.
        """
        (work_dir / ".env").write_text("")

        config_content = """\
[encryption]
backend = "dotenvx"
"""
        (work_dir / "envdrift.toml").write_text(config_content)

        env = {"PYTHONPATH": integration_pythonpath}

        result = subprocess.run(
            [*envdrift_cmd, "lock", "--check"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Empty file should be handled gracefully
        assert "Traceback" not in result.stderr


class TestCorruptEncryptedFile:
    """Test detection and handling of corrupt encrypted files."""

    def test_tampered_ciphertext_detection(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """Test that tampered encrypted content is detected."""
        # Create a file with corrupted encrypted content
        corrupted_content = """\
#/-------------------[DOTENV][Load]--------------------/#
#/         public-key encryption for .env files        /#
#/  https://github.com/dotenvx/dotenvx-pro?encrypted   /#
#/--------------------------------------------------/#
DOTENV_PUBLIC_KEY_PRODUCTION="034a5e..."
# encrypted values below - tampered ciphertext
DATABASE_URL="encrypted:INVALID_BASE64!!@@##CORRUPTED"
API_KEY="encrypted:YWJjZGVm"
"""
        (work_dir / ".env.production").write_text(corrupted_content)

        # Create .env.keys with a key
        (work_dir / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=test-key-12345\n")

        config_content = """\
[encryption]
backend = "dotenvx"
"""
        (work_dir / "envdrift.toml").write_text(config_content)

        env = {"PYTHONPATH": integration_pythonpath}

        # Try to decrypt - should fail gracefully
        result = subprocess.run(
            [*envdrift_cmd, "lock", "--check"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should not crash with an unhandled exception
        assert "Traceback" not in result.stderr

    def test_incomplete_encryption_markers(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """Test handling of files with incomplete encryption markers."""
        # Encrypted marker present but value is not properly formatted
        incomplete_content = """\
DOTENV_PUBLIC_KEY_PRODUCTION="034a5e..."
DATABASE_URL="encrypted:"
API_KEY="encrypted"
SECRET=""
"""
        (work_dir / ".env.production").write_text(incomplete_content)
        (work_dir / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=test-key\n")

        config_content = """\
[encryption]
backend = "dotenvx"
"""
        (work_dir / "envdrift.toml").write_text(config_content)

        env = {"PYTHONPATH": integration_pythonpath}

        result = subprocess.run(
            [*envdrift_cmd, "lock", "--check"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should handle gracefully
        assert "Traceback" not in result.stderr


class TestVaultClientErrorHandling:
    """Test vault client error handling at the library level."""

    def test_aws_client_authentication_failure(self, monkeypatch) -> None:
        """Test AWS client handles authentication failures gracefully."""
        # Set invalid credentials and explicitly unset any LocalStack endpoint
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "invalid")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "invalid")
        monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
        # Unset endpoint URL to force using real AWS (which will fail auth)
        monkeypatch.delenv("AWS_ENDPOINT_URL", raising=False)

        from envdrift.vault.aws import AWS_AVAILABLE

        if not AWS_AVAILABLE:
            pytest.skip("boto3 not installed")

        from envdrift.vault.aws import AWSSecretsManagerClient
        from envdrift.vault.base import AuthenticationError, VaultError

        client = AWSSecretsManagerClient(region="us-east-1")

        # Should raise AuthenticationError or VaultError
        with pytest.raises((AuthenticationError, VaultError)):
            client.authenticate()

    def test_hashicorp_client_invalid_token(self, vault_endpoint: str) -> None:
        """Test HashiCorp client handles invalid token gracefully."""
        from envdrift.vault.hashicorp import HVAC_AVAILABLE

        if not HVAC_AVAILABLE:
            pytest.skip("hvac not installed")

        from envdrift.vault.base import AuthenticationError, VaultError
        from envdrift.vault.hashicorp import HashiCorpVaultClient

        client = HashiCorpVaultClient(
            url=vault_endpoint,
            token="invalid-token-that-does-not-exist",
        )

        # Should raise AuthenticationError or VaultError on authenticate()
        with pytest.raises((AuthenticationError, VaultError)):
            client.authenticate()

    def test_hashicorp_client_secret_not_found(self, vault_endpoint: str, vault_client) -> None:
        """Test HashiCorp client handles missing secrets gracefully."""
        from envdrift.vault.base import SecretNotFoundError
        from envdrift.vault.hashicorp import HashiCorpVaultClient

        client = HashiCorpVaultClient(
            url=vault_endpoint,
            token="test-root-token",
        )
        client.authenticate()

        with pytest.raises(SecretNotFoundError):
            client.get_secret("nonexistent/path/that/does/not/exist")


class TestFilePermissionErrors:
    """Test handling of file permission errors."""

    def test_readonly_env_keys_file(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """Test handling when .env.keys is read-only."""
        import stat

        # Create read-only .env.keys
        env_keys = work_dir / ".env.keys"
        env_keys.write_text("DOTENV_PRIVATE_KEY_PRODUCTION=old-key\n")
        env_keys.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)

        try:
            # Create config that would try to update the file
            config_content = """\
[encryption]
backend = "dotenvx"

[encryption.dotenvx]
auto_install = true

[vault]
provider = "hashicorp"
address = "http://localhost:8200"
token = "test-token"

[[vault.sync.mappings]]
secret_name = "test/secret"
folder_path = "."
environment = "production"
"""
            (work_dir / "envdrift.toml").write_text(config_content)
            (work_dir / ".env.production").write_text('SECRET="encrypted:..."')

            env = {"PYTHONPATH": integration_pythonpath}

            # This would try to write to .env.keys
            # Should handle permission error gracefully
            result = subprocess.run(
                [*envdrift_cmd, "lock", "--check"],
                cwd=work_dir,
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
            )

            # Should not crash with unhandled exception
            assert "Traceback" not in result.stderr, (
                f"Should not have unhandled exception.\nstderr: {result.stderr}"
            )
        finally:
            # Restore write permission for cleanup
            env_keys.chmod(stat.S_IWUSR | stat.S_IRUSR)


class TestMockVaultTimeouts:
    """Test vault timeout handling with mocked clients."""

    def test_sync_engine_handles_vault_timeout(self, work_dir: Path) -> None:
        """Test that SyncEngine handles vault timeouts gracefully."""
        from envdrift.sync.config import ServiceMapping, SyncConfig
        from envdrift.sync.engine import SyncEngine, SyncMode
        from envdrift.sync.result import SyncAction
        from envdrift.vault.base import VaultClient, VaultError

        # Create a mock vault client that times out
        class TimeoutVaultClient(VaultClient):
            def authenticate(self) -> None:
                """
                Authenticate the client so it can perform subsequent vault operations.

                This method establishes or refreshes the client's authentication state; implementations may perform network requests or credential exchanges as needed.
                """
                pass

            def is_authenticated(self) -> bool:
                """
                Indicates whether the client is currently authenticated.

                Returns:
                    `True` if the client is authenticated, `False` otherwise.
                """
                return True

            def get_secret(self, name: str):
                """
                Attempt to retrieve a secret by name but always raise a connection timeout error.

                Parameters:
                    name (str): Identifier of the secret to retrieve.

                Raises:
                    VaultError: Always raised with the message "Connection timed out".
                """
                raise VaultError("Connection timed out")

            def list_secrets(self, prefix: str = "") -> list[str]:
                """
                Return the names of secrets stored under the given prefix.

                Parameters:
                        prefix (str): Path prefix or namespace to filter secrets; empty string lists all top-level secrets.

                Returns:
                        list[str]: A list of secret names found under the specified prefix.

                Raises:
                        VaultError: If the vault operation fails (e.g., connection timeout or authentication failure).
                """
                raise VaultError("Connection timed out")

            def set_secret(self, name: str, value: str):
                """
                Simulates a secret write operation that always fails with a connection timeout.

                Raises:
                    VaultError: always raised with the message "Connection timed out".
                """
                raise VaultError("Connection timed out")

        # Create test directory and files
        (work_dir / ".env.production").write_text('SECRET="encrypted:..."')

        config = SyncConfig(
            env_keys_filename=".env.keys",
            mappings=[
                ServiceMapping(
                    secret_name="test/secret",
                    folder_path=work_dir,
                    environment="production",
                )
            ],
        )

        engine = SyncEngine(
            config=config,
            vault_client=TimeoutVaultClient(),
            mode=SyncMode(),
        )

        result = engine.sync_all()

        assert len(result.services) == 1
        assert result.services[0].action == SyncAction.ERROR
        assert "timed out" in result.services[0].error.lower()
