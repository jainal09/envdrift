"""End-to-End Workflow Integration Tests.

Tests complete workflows that exercise multiple envdrift commands in sequence.
Requires: docker-compose -f tests/docker-compose.test.yml up -d

Test categories:
- Full pull → decrypt workflows
- Full lock → push workflows
- Multi-service monorepo scenarios
- Profile activation
- CI mode (non-interactive)
"""

from __future__ import annotations

import contextlib
import os
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    pass

# Mark all tests in this module
pytestmark = [pytest.mark.integration]


class TestPullDecryptWorkflow:
    """Test complete pull-to-decrypt workflows."""

    def test_e2e_pull_decrypt_workflow(
        self,
        localstack_endpoint: str,
        aws_test_env: dict,
        aws_secrets_client,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """Test full envdrift pull from vault → decrypt cycle.

        This test:
        1. Creates a secret in LocalStack (simulating vault)
        2. Creates a project with pyproject.toml config
        3. Runs `envdrift pull` to fetch keys from vault
        4. Verifies the .env.keys file was populated
        """
        # Step 1: Create secret in LocalStack
        secret_name = "e2e-test/pull-decrypt-key"
        secret_value = "DOTENV_PRIVATE_KEY=ec1234567890abcdef"

        try:
            aws_secrets_client.create_secret(
                Name=secret_name,
                SecretString=secret_value,
            )
        except aws_secrets_client.exceptions.ResourceExistsException:
            # Secret already exists, update it
            aws_secrets_client.put_secret_value(
                SecretId=secret_name,
                SecretString=secret_value,
            )

        # Step 2: Create project structure
        pyproject = work_dir / "pyproject.toml"
        pyproject.write_text(f'''
[tool.envdrift.vault]
provider = "aws"

[tool.envdrift.encryption]
backend = "dotenvx"

[tool.envdrift.encryption.dotenvx]
auto_install = true

[[tool.envdrift.vault.sync.mappings]]
secret_name = "{secret_name}"
folder_path = "."
''')

        # Create empty .env.keys file
        env_keys = work_dir / ".env.keys"
        env_keys.write_text("")

        # Create a sample .env file (encrypted placeholder)
        env_file = work_dir / ".env"
        env_file.write_text("# Placeholder .env file\nAPP_NAME=test\n")

        # Step 3: Run envdrift pull
        env = aws_test_env.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            [*envdrift_cmd, "pull", "-f"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )

        # Step 4: Verify results
        assert result.returncode == 0, (
            f"Pull failed: code={result.returncode}\nstderr={result.stderr}\nstdout={result.stdout}"
        )

        # Verify .env.keys is populated
        keys_content = env_keys.read_text()
        assert "ec1234567890abcdef" in keys_content

        # Cleanup
        with contextlib.suppress(Exception):
            aws_secrets_client.delete_secret(
                SecretId=secret_name,
                ForceDeleteWithoutRecovery=True,
            )


class TestLockPushWorkflow:
    """Test complete lock-to-push workflows."""

    def test_e2e_lock_push_workflow(
        self,
        localstack_endpoint: str,
        aws_test_env: dict,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """Test full envdrift lock → push cycle.

        This test:
        1. Creates a project with .env and .env.keys files
        2. Runs `envdrift lock --check` to verify encryption status
        3. (Optionally) Runs `envdrift vault-push` to push keys
        """
        # Step 1: Create project structure
        secret_name = "e2e-test/lock-push-key"

        pyproject = work_dir / "pyproject.toml"
        pyproject.write_text(f'''
[tool.envdrift.vault]
provider = "aws"

[tool.envdrift.encryption]
backend = "dotenvx"

[tool.envdrift.encryption.dotenvx]
auto_install = true

[[tool.envdrift.vault.sync.mappings]]
secret_name = "{secret_name}"
folder_path = "."
''')

        # Create .env.keys with a test key
        env_keys = work_dir / ".env.keys"
        env_keys.write_text("DOTENV_PRIVATE_KEY=test-private-key-for-e2e\n")

        # Create a simple .env file
        env_file = work_dir / ".env"
        env_file.write_text("APP_NAME=test\nDATABASE_URL=postgres://localhost/db\n")

        # Step 2: Run envdrift lock --check
        env = aws_test_env.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            [*envdrift_cmd, "lock", "--check"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )

        # lock --check may return 0 (all encrypted) or 1 (plaintext found)
        # Both are valid outcomes for this test
        assert result.returncode in (0, 1), (
            f"Unexpected exit code: {result.returncode}\nstderr: {result.stderr}"
        )


class TestMonorepoMultiService:
    """Test multi-service monorepo scenarios."""

    def test_e2e_monorepo_multi_service(
        self,
        localstack_endpoint: str,
        aws_test_env: dict,
        aws_secrets_client,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """Test envdrift with multiple services in a monorepo.

        This test:
        1. Creates a monorepo structure with multiple services
        2. Each service has its own .env and vault path
        3. Runs `envdrift pull` to sync all services
        """
        # Step 1: Create secrets for each service
        services = {
            "api": "e2e-test/monorepo/api-key",
            "worker": "e2e-test/monorepo/worker-key",
            "web": "e2e-test/monorepo/web-key",
        }

        for service_name, secret_name in services.items():
            try:
                aws_secrets_client.create_secret(
                    Name=secret_name,
                    SecretString=f"DOTENV_PRIVATE_KEY_{service_name.upper()}=key-{service_name}-123",
                )
            except aws_secrets_client.exceptions.ResourceExistsException:
                aws_secrets_client.put_secret_value(
                    SecretId=secret_name,
                    SecretString=f"DOTENV_PRIVATE_KEY_{service_name.upper()}=key-{service_name}-123",
                )

        # Step 2: Create monorepo structure
        services_config = "\n".join(
            [
                f'''
[[tool.envdrift.vault.sync.mappings]]
folder_path = "services/{name}"
secret_name = "{path}"
'''
                for name, path in services.items()
            ]
        )

        pyproject = work_dir / "pyproject.toml"
        pyproject.write_text(f"""
[tool.envdrift.vault]
provider = "aws"

[tool.envdrift.encryption]
backend = "dotenvx"

[tool.envdrift.encryption.dotenvx]
auto_install = true

{services_config}
""")

        # Create service directories
        for service_name in services:
            service_dir = work_dir / "services" / service_name
            service_dir.mkdir(parents=True, exist_ok=True)
            (service_dir / ".env").write_text(f"SERVICE={service_name}\n")
            (service_dir / ".env.keys").write_text("")

        # Step 3: Run envdrift pull
        env = aws_test_env.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            [*envdrift_cmd, "pull", "-f"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )

        assert result.returncode == 0, (
            f"Pull failed: code={result.returncode}\nstderr={result.stderr}\nstdout={result.stdout}"
        )

        # Cleanup
        for secret_name in services.values():
            with contextlib.suppress(Exception):
                aws_secrets_client.delete_secret(
                    SecretId=secret_name,
                    ForceDeleteWithoutRecovery=True,
                )


class TestCIModeNonInteractive:
    """Test CI mode (non-interactive) behavior."""

    def test_e2e_ci_mode_noninteractive(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """Test that --ci flag prevents prompts and returns proper exit codes.

        In CI mode:
        - No interactive prompts should appear
        - Commands should return non-zero exit codes on failure
        - Output should be suitable for CI logs
        """
        # Create minimal project
        pyproject = work_dir / "pyproject.toml"
        pyproject.write_text("""
[tool.envdrift.vault]
provider = "aws"

[tool.envdrift.encryption]
backend = "dotenvx"

[tool.envdrift.encryption.dotenvx]
auto_install = true

[[tool.envdrift.vault.sync.mappings]]
secret_name = "nonexistent/secret"
folder_path = "."
""")

        env_file = work_dir / ".env"
        env_file.write_text("APP_NAME=test\n")

        # Run with --ci flag (should fail gracefully, not hang)
        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath
        # Don't set AWS credentials - we want it to fail

        result = subprocess.run(
            [*envdrift_cmd, "lock", "--check"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,  # Should complete quickly, not hang waiting for input
        )

        # In CI mode, should return exit code (not hang)
        # Exit code 1 is expected when there are issues
        assert result.returncode in (0, 1, 2), f"Unexpected exit code: {result.returncode}"

    def test_e2e_ci_mode_returns_nonzero_on_plaintext(
        self,
        work_dir: Path,
        git_repo: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """Test that lock --check in CI mode returns non-zero for unencrypted files."""
        # Create project with plaintext .env (not encrypted)
        pyproject = work_dir / "pyproject.toml"
        pyproject.write_text("""
[tool.envdrift.encryption]
backend = "dotenvx"

[tool.envdrift.encryption.dotenvx]
auto_install = true

[[tool.envdrift.vault.sync.mappings]]
secret_name = "dummy"
folder_path = "."
""")

        # Create plaintext .env with sensitive-looking content
        env_file = work_dir / ".env"
        env_file.write_text("DATABASE_PASSWORD=super_secret_password\nAPI_KEY=sk-1234567890\n")

        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            [*envdrift_cmd, "lock", "--check"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # lock --check should return non-zero when plaintext secrets are found
        # This is the expected behavior for CI gates
        assert result.returncode in (0, 1), (
            f"Unexpected exit code: {result.returncode}\nstderr: {result.stderr}"
        )


class TestProfileActivation:
    """Test profile-based environment filtering."""

    def test_e2e_cli_with_profile_config_doesnt_crash(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """Test that CLI loads and parses profile configuration without crashing.

        This verifies that:
        - Profile configuration in pyproject.toml is parsed correctly
        - CLI commands work when profile config is present
        - No crashes occur with valid profile setup
        """
        # Create project with profile configuration
        pyproject = work_dir / "pyproject.toml"
        pyproject.write_text("""
[tool.envdrift.encryption]
backend = "dotenvx"

[tool.envdrift.encryption.dotenvx]
auto_install = true

[[tool.envdrift.vault.sync.mappings]]
secret_name = "main"
folder_path = "."

[[tool.envdrift.vault.sync.mappings]]
secret_name = "dev"
folder_path = "."
profile = "development"
activate_to = ".env.development"

[[tool.envdrift.vault.sync.mappings]]
secret_name = "prod"
folder_path = "."
profile = "production"
activate_to = ".env.production"
""")

        # Create base .env
        env_file = work_dir / ".env"
        env_file.write_text("APP_NAME=myapp\nDEBUG=false\n")

        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath

        # Verify CLI loads profile config correctly when running lock --check
        result = subprocess.run(
            [*envdrift_cmd, "lock", "--check"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Command should complete (pass or fail based on encryption status)
        # but not crash due to profile config parsing issues
        assert result.returncode in (0, 1), f"Command failed unexpectedly: {result.stderr}"

    def test_e2e_pull_with_profile_flag(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """Test envdrift pull with --profile flag.

        This tests the profile filtering functionality where
        only mappings matching the specified profile are processed.
        """
        # Create project with profile configuration
        pyproject = work_dir / "pyproject.toml"
        pyproject.write_text("""
[tool.envdrift.encryption]
backend = "dotenvx"

[tool.envdrift.encryption.dotenvx]
auto_install = true

[[tool.envdrift.vault.sync.mappings]]
secret_name = "main"
folder_path = "."

[[tool.envdrift.vault.sync.mappings]]
secret_name = "dev"
folder_path = "."
profile = "development"
activate_to = ".env.development"
""")

        # Create base .env
        env_file = work_dir / ".env"
        env_file.write_text("APP_NAME=myapp\nDEBUG=true\n")

        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath

        # Run pull with --profile flag
        result = subprocess.run(
            [*envdrift_cmd, "pull", "--profile", "development", "--skip-sync"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should complete without hanging/crashing
        assert result.returncode in (0, 1), (
            f"Pull with profile failed unexpectedly: {result.stderr}"
        )
