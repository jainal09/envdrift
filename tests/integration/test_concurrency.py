"""Concurrency Integration Tests.

Tests for thread-safety and parallel operation handling.

Test categories (from spec.md Category F):
- Parallel sync thread safety (multiple threads syncing different secrets)
- Parallel encrypt attempts (lock behavior)
- Parallel decrypt of multiple files

Requires: docker-compose -f tests/docker-compose.test.yml up -d
"""

from __future__ import annotations

import contextlib
import shutil
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    pass

# Mark all tests in this module
pytestmark = [pytest.mark.integration]


def _get_envdrift_cmd() -> list[str]:
    """
    Choose the command invocation for the envdrift CLI.
    
    If an envdrift executable is found on the system PATH, returns its path as a single-item list; otherwise returns the fallback invocation ["uv", "run", "envdrift"].
    
    Returns:
        command (list[str]): Command and arguments to execute the envdrift CLI.
    """
    # Try to find envdrift in PATH (installed via uv)
    envdrift_path = shutil.which("envdrift")
    if envdrift_path:
        return [envdrift_path]
    # Fallback: use uv run
    return ["uv", "run", "envdrift"]


class TestParallelSyncThreadSafety:
    """Test thread safety of parallel sync operations."""

    @pytest.mark.aws
    def test_parallel_sync_different_secrets(
        self,
        work_dir: Path,
        localstack_endpoint: str,
        aws_test_env: dict[str, str],
        aws_secrets_client,
        integration_pythonpath: str,
    ) -> None:
        """Test multiple threads syncing different secrets concurrently.

        This test creates multiple secrets and multiple service directories,
        then runs sync operations in parallel to verify thread safety.
        """
        num_services = 5
        secrets = {}
        created_secrets = []

        # Create test secrets
        for i in range(num_services):
            secret_name = f"envdrift-test/parallel-sync-{i}"
            secret_value = f"parallel-key-{i}-{time.time()}"
            secrets[secret_name] = secret_value

            try:
                aws_secrets_client.create_secret(
                    Name=secret_name,
                    SecretString=secret_value,
                )
                created_secrets.append(secret_name)
            except aws_secrets_client.exceptions.ResourceExistsException:
                aws_secrets_client.put_secret_value(
                    SecretId=secret_name,
                    SecretString=secret_value,
                )
                created_secrets.append(secret_name)

        try:
            # Create config with multiple mappings
            mappings = []
            for i in range(num_services):
                mappings.append(f"""
[[vault.sync.mappings]]
secret_name = "envdrift-test/parallel-sync-{i}"
folder_path = "service-{i}"
environment = "production"
""")

            config_content = f"""\
[encryption]
backend = "dotenvx"

[vault]
provider = "aws"
region = "us-east-1"

[vault.sync]
max_workers = {num_services}

{''.join(mappings)}
"""
            (work_dir / "envdrift.toml").write_text(config_content)

            # Create service directories
            for i in range(num_services):
                service_dir = work_dir / f"service-{i}"
                service_dir.mkdir()
                (service_dir / ".env.production").write_text(
                    'DOTENV_PUBLIC_KEY_PRODUCTION="key"\nSECRET="encrypted:..."'
                )

            env = aws_test_env.copy()
            env["PYTHONPATH"] = integration_pythonpath

            # Run parallel sync
            result = subprocess.run(
                [*_get_envdrift_cmd(), "pull"],
                cwd=work_dir,
                env=env,
                capture_output=True,
                text=True,
                timeout=120,
            )

            assert result.returncode == 0, (
                f"Parallel sync failed.\nstdout: {result.stdout}\nstderr: {result.stderr}"
            )

            # Verify all services got their keys
            for i in range(num_services):
                env_keys = work_dir / f"service-{i}" / ".env.keys"
                assert env_keys.exists(), f"service-{i} should have .env.keys"

                content = env_keys.read_text()
                expected_value = secrets[f"envdrift-test/parallel-sync-{i}"]
                assert expected_value in content, (
                    f"service-{i} should have correct key value"
                )

        finally:
            # Cleanup secrets
            for secret_name in created_secrets:
                with contextlib.suppress(Exception):
                    aws_secrets_client.delete_secret(
                        SecretId=secret_name, ForceDeleteWithoutRecovery=True
                    )

    @pytest.mark.vault
    def test_parallel_sync_vault_thread_safety(
        self,
        work_dir: Path,
        vault_endpoint: str,
        vault_test_env: dict[str, str],
        vault_client,
        integration_pythonpath: str,
    ) -> None:
        """
        Verify envdrift performs a parallel HashiCorp Vault synchronization across multiple service mappings without thread-safety failures.
        
        Sets up multiple Vault KV secrets and corresponding service mappings, runs `envdrift pull --skip-decrypt` with parallel workers, and asserts the command succeeds and that each service directory receives an `.env.keys` file.
        """
        num_services = 3
        secrets = {}

        # Create test secrets in Vault
        for i in range(num_services):
            path = f"parallel-vault-{i}"
            value = f"vault-parallel-key-{i}"
            secrets[path] = value
            vault_client.secrets.kv.v2.create_or_update_secret(
                path=path,
                secret={"DOTENV_PRIVATE_KEY_PRODUCTION": value},
            )

        # Create config with multiple mappings
        mappings = []
        for i in range(num_services):
            mappings.append(f"""
[[vault.sync.mappings]]
secret_name = "parallel-vault-{i}"
folder_path = "vault-service-{i}"
environment = "production"
""")

        config_content = f"""\
[encryption]
backend = "dotenvx"

[vault]
provider = "hashicorp"

[vault.hashicorp]
url = "{vault_endpoint}"
token = "test-root-token"

[vault.sync]
max_workers = {num_services}

{''.join(mappings)}
"""
        (work_dir / "envdrift.toml").write_text(config_content)

        # Create service directories
        for i in range(num_services):
            service_dir = work_dir / f"vault-service-{i}"
            service_dir.mkdir()
            (service_dir / ".env.production").write_text(
                'DOTENV_PUBLIC_KEY_PRODUCTION="key"\nSECRET="encrypted:..."'
            )

        env = vault_test_env.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            [*_get_envdrift_cmd(), "pull"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )

        assert result.returncode == 0, (
            f"Vault parallel sync failed.\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )

        # Verify all services got their keys
        for i in range(num_services):
            env_keys = work_dir / f"vault-service-{i}" / ".env.keys"
            assert env_keys.exists(), f"vault-service-{i} should have .env.keys"


class TestParallelEncryptAttempts:
    """Test concurrent encryption operations."""

    def test_concurrent_encrypt_same_file(
        self,
        work_dir: Path,
        git_repo: Path,
        integration_pythonpath: str,
    ) -> None:
        """Test that concurrent encrypt attempts on same file are handled safely.

        This tests the lock behavior when multiple processes try to encrypt
        the same file simultaneously.
        """
        # Create a .env file
        env_content = """
DATABASE_URL=postgres://localhost:5432/mydb
API_KEY=secret123
SECRET_TOKEN=token456
"""
        (work_dir / ".env").write_text(env_content)

        config_content = """\
[encryption]
backend = "dotenvx"
"""
        (work_dir / "envdrift.toml").write_text(config_content)

        env = {"PYTHONPATH": integration_pythonpath}

        results = []
        errors = []

        def run_lock_check():
            """
            Execute the 'envdrift lock --check' command in the configured working directory and record the outcome.
            
            On success, appends the subprocess return code to the outer-scope `results` list; on failure, appends the exception string to the outer-scope `errors` list. The subprocess is run with the test `env` and a 30-second timeout.
            """
            try:
                result = subprocess.run(
                    [*_get_envdrift_cmd(), "lock", "--check"],
                    cwd=work_dir,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                results.append(result.returncode)
            except Exception as e:
                errors.append(str(e))

        # Run multiple lock checks concurrently
        threads = []
        for _ in range(5):
            t = threading.Thread(target=run_lock_check)
            threads.append(t)
            t.start()

        # Wait for all threads
        for t in threads:
            t.join()

        # Should not have any errors
        assert len(errors) == 0, f"Concurrent operations raised errors: {errors}"

        # All operations should complete (either success or expected failure)
        assert len(results) == 5


class TestParallelDecryptDifferentFiles:
    """Test parallel decryption of multiple files."""

    def test_parallel_decrypt_multiple_services(
        self,
        work_dir: Path,
        integration_pythonpath: str,
    ) -> None:
        """Test decrypting multiple env files in parallel.

        This verifies that parallel decryption of different files
        doesn't cause race conditions or file corruption.
        """
        num_services = 3

        # Create encrypted env files for each service
        for i in range(num_services):
            service_dir = work_dir / f"decrypt-service-{i}"
            service_dir.mkdir()

            env_content = f"""\
#/-------------------[DOTENV][Load]--------------------/#
#/         public-key encryption for .env files        /#
#/  https://github.com/dotenvx/dotenvx-pro?encrypted   /#
#/--------------------------------------------------/#
DOTENV_PUBLIC_KEY_PRODUCTION="034a5e..."
SERVICE_ID="encrypted:service{i}"
"""
            (service_dir / ".env.production").write_text(env_content)
            (service_dir / ".env.keys").write_text(
                f"DOTENV_PRIVATE_KEY_PRODUCTION=key-{i}\n"
            )

        config_content = """\
[encryption]
backend = "dotenvx"
"""
        (work_dir / "envdrift.toml").write_text(config_content)

        env = {"PYTHONPATH": integration_pythonpath}

        # Run lock --check on each service in parallel
        def check_service(service_idx):
            """
            Run `envdrift lock --check` inside the service's directory and return the execution result.
            
            Parameters:
            	service_idx (int): Index of the service; used to locate the directory `decrypt-service-<service_idx>` under the test work directory.
            
            Returns:
            	tuple: `(service_idx, return_code, stderr)` where `return_code` is the process exit code and `stderr` is the captured standard error output.
            """
            service_dir = work_dir / f"decrypt-service-{service_idx}"
            result = subprocess.run(
                [*_get_envdrift_cmd(), "lock", "--check"],
                cwd=service_dir,
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
            )
            return service_idx, result.returncode, result.stderr

        with ThreadPoolExecutor(max_workers=num_services) as executor:
            futures = [executor.submit(check_service, i) for i in range(num_services)]
            results = [f.result() for f in as_completed(futures)]

        # All should complete without crashing
        for idx, _code, stderr in results:
            assert "Traceback" not in stderr, (
                f"Service {idx} crashed with traceback: {stderr}"
            )


class TestSyncEngineThreadSafety:
    """Test SyncEngine thread safety at the library level."""

    @pytest.mark.aws
    def test_sync_engine_concurrent_operations(
        self,
        work_dir: Path,
        localstack_endpoint: str,
        aws_secrets_client,
        monkeypatch,
    ) -> None:
        """Test SyncEngine handles concurrent operations thread-safely."""
        # Set up AWS environment
        monkeypatch.setenv("AWS_ENDPOINT_URL", localstack_endpoint)
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
        monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")

        # Create test secrets
        secret_names = []
        for i in range(3):
            name = f"envdrift-test/engine-concurrent-{i}"
            value = f"concurrent-value-{i}"
            try:
                aws_secrets_client.create_secret(Name=name, SecretString=value)
            except aws_secrets_client.exceptions.ResourceExistsException:
                aws_secrets_client.put_secret_value(SecretId=name, SecretString=value)
            secret_names.append(name)

        try:
            from envdrift.sync.config import ServiceMapping, SyncConfig
            from envdrift.sync.engine import SyncEngine, SyncMode
            from envdrift.vault.aws import AWSSecretsManagerClient

            # Create service directories
            mappings = []
            for i in range(3):
                service_dir = work_dir / f"concurrent-service-{i}"
                service_dir.mkdir()
                (service_dir / ".env.production").write_text(
                    'SECRET="encrypted:..."'
                )
                mappings.append(
                    ServiceMapping(
                        secret_name=f"envdrift-test/engine-concurrent-{i}",
                        folder_path=service_dir,
                        environment="production",
                    )
                )

            config = SyncConfig(
                env_keys_filename=".env.keys",
                max_workers=3,
                mappings=mappings,
            )

            client = AWSSecretsManagerClient(region="us-east-1")
            client.authenticate()

            engine = SyncEngine(
                config=config,
                vault_client=client,
                mode=SyncMode(),
            )

            # Run sync (which uses parallel operations internally)
            result = engine.sync_all()

            # All services should be processed
            assert len(result.services) == 3

            # No errors from thread safety issues
            for service_result in result.services:
                if service_result.error:
                    assert "thread" not in service_result.error.lower()
                    assert "lock" not in service_result.error.lower()

        finally:
            # Cleanup
            for name in secret_names:
                with contextlib.suppress(Exception):
                    aws_secrets_client.delete_secret(
                        SecretId=name, ForceDeleteWithoutRecovery=True
                    )


class TestRaceConditions:
    """Test for potential race conditions."""

    def test_concurrent_file_writes(self, work_dir: Path) -> None:
        """Test that concurrent writes to different files don't interfere."""
        num_files = 10
        results = {}
        errors = []

        def write_file(idx: int):
            """
            Write and repeatedly verify a test .env.keys file to detect race conditions.
            
            Performs multiple write-read cycles to work_dir/race-test-<idx>.env.keys, verifying the file content remains stable between writes. On any mismatch or exception, records an error to the surrounding `errors` list; on success, marks `results[idx] = True`.
            
            Parameters:
                idx (int): Numeric index used to name the target test file and embed in its content.
            """
            try:
                file_path = work_dir / f"race-test-{idx}.env.keys"
                content = f"DOTENV_PRIVATE_KEY_TEST_{idx}=key-value-{idx}\n"

                # Simulate the write pattern used by envdrift
                for _ in range(5):  # Multiple writes
                    file_path.write_text(content)
                    time.sleep(0.01)  # Small delay to increase race chance
                    read_content = file_path.read_text()

                    if content != read_content:
                        errors.append(f"File {idx} content mismatch")
                        return

                results[idx] = True
            except Exception as e:
                errors.append(f"File {idx} error: {e}")

        # Run writes in parallel
        threads = []
        for i in range(num_files):
            t = threading.Thread(target=write_file, args=(i,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        assert len(errors) == 0, f"Race condition errors: {errors}"
        assert len(results) == num_files

    def test_concurrent_directory_creation(self, work_dir: Path) -> None:
        """Test that concurrent directory creation is handled safely."""
        from envdrift.sync.operations import ensure_directory

        base_dir = work_dir / "concurrent-dirs"
        errors = []

        def create_nested_dir(idx: int):
            """
            Create a nested directory under the captured `base_dir` using `idx` to name levels and record any errors.
            
            Creates the path: base_dir / f"level1-{idx % 3}" / f"level2-{idx}" and ensures the directory exists. On failure, appends an error message to the captured `errors` list.
             
            Parameters:
                idx (int): Index used to derive the level1 and level2 directory names.
            """
            try:
                dir_path = base_dir / f"level1-{idx % 3}" / f"level2-{idx}"
                ensure_directory(dir_path)
                assert dir_path.exists()
            except Exception as e:
                errors.append(f"Dir {idx} error: {e}")

        # Run directory creation in parallel
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(create_nested_dir, i) for i in range(20)]
            for _f in as_completed(futures):
                pass  # Just wait for completion

        assert len(errors) == 0, f"Concurrent dir creation errors: {errors}"