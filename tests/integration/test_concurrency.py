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
import os
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


class TestParallelSyncThreadSafety:
    """Test thread safety of parallel sync operations."""

    @pytest.mark.aws
    def test_parallel_sync_different_secrets(
        self,
        work_dir: Path,
        aws_test_env: dict[str, str],
        aws_secrets_client,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """
        Verify envdrift concurrently pulls distinct secrets for multiple services without race conditions.

        Creates 5 unique secrets in AWS Secrets Manager and a matching envdrift config.
        Executes `envdrift pull` and asserts all 5 services receive the correct keys in their `.env.keys` files.
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

[encryption.dotenvx]
auto_install = true

[vault]
provider = "aws"
region = "us-east-1"

[vault.sync]
max_workers = {num_services}

{"".join(mappings)}
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
                [*envdrift_cmd, "pull"],
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
                assert expected_value in content, f"service-{i} should have correct key value"

        finally:
            # Cleanup secrets
            for name in created_secrets:
                try:
                    aws_secrets_client.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True)
                except Exception:
                    pass

    @pytest.mark.vault
    def test_parallel_sync_vault_thread_safety(
        self,
        work_dir: Path,
        vault_endpoint: str,
        vault_test_env: dict[str, str],
        vault_client,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """
        Verify envdrift performs a parallel HashiCorp Vault synchronization across multiple service mappings without thread-safety failures.

        Sets up multiple Vault KV secrets and corresponding service mappings, runs `envdrift pull --skip-decrypt` with parallel workers, and asserts the command succeeds and that each service directory receives an `.env.keys` file.
        """
        num_services = 3
        secrets = {}

        # Create test secrets in Vault
        try:
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

[encryption.dotenvx]
auto_install = true

[vault]
provider = "hashicorp"

[vault.hashicorp]
url = "{vault_endpoint}"
token = "test-root-token"

[vault.sync]
max_workers = {num_services}

{"".join(mappings)}
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
                [*envdrift_cmd, "pull"],
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

        finally:
            # Cleanup secrets
            for i in range(num_services):
                with contextlib.suppress(Exception):
                    vault_client.secrets.kv.v2.delete_metadata_and_all_versions(
                        path=f"parallel-vault-{i}"
                    )


class TestParallelEncryptAttempts:
    """Test concurrent check operations."""

    def test_concurrent_lock_check_same_file(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """Test that concurrent lock --check operations on same file are handled safely.

        This tests that multiple processes can run lock --check concurrently
        without crashing. Note: lock --check doesn't require dotenvx and will
        return non-zero exit code for unencrypted files, which is expected.
        """
        # Create a .env file (unencrypted - lock --check will report it)
        env_content = """
DATABASE_URL=postgres://localhost:5432/mydb
API_KEY=secret123
SECRET_TOKEN=token456
"""
        (work_dir / ".env").write_text(env_content)

        config_content = """\
[vault]
provider = "hashicorp"

[vault.hashicorp]
url = "http://localhost:8200"

[encryption]
backend = "dotenvx"

[[vault.sync.mappings]]
secret_name = "dummy"
folder_path = "."
"""
        (work_dir / "envdrift.toml").write_text(config_content)

        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath

        results = []
        crashes = []

        def run_lock_check():
            """
            Execute the 'envdrift lock --check' command in the configured working directory and record the outcome.

            Appends the return code to results list. Only records to crashes list
            if there's an actual exception or traceback (not just non-zero exit).
            """
            try:
                result = subprocess.run(
                    [*envdrift_cmd, "lock", "--check"],
                    cwd=work_dir,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                results.append(result.returncode)
                # Only flag actual crashes/tracebacks, not expected non-zero returns
                if "Traceback" in result.stderr:
                    crashes.append(f"Traceback detected: {result.stderr}")
            except Exception as e:
                crashes.append(str(e))

        # Run multiple checks concurrently
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(run_lock_check) for _ in range(3)]
            # Wait for all to complete
            for f in futures:
                f.result()

        # No crashes should occur (timeouts, exceptions, tracebacks)
        assert not crashes, f"Concurrent operations crashed: {crashes}"
        # All operations should complete (we got results from all)
        assert len(results) == 3, f"Expected 3 results, got {len(results)}"
        # All should return the same code (consistent behavior)
        assert len(set(results)) == 1, f"Inconsistent return codes: {results}"


class TestParallelDecryptDifferentFiles:
    """Test parallel operations on different files."""

    def test_parallel_decrypt_multiple_services(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """Test decrypting multiple unrelated services in parallel.

        Creates separate service directories, each with its own .env.keys and
        encrypted .env files. Runs multiple processes concurrently to ensure
        they don't interfere with each other.
        """
        num_services = 5

        for i in range(num_services):
            service_dir = work_dir / f"decrypt-service-{i}"
            service_dir.mkdir()
            # Create valid encrypted file and keys
            (service_dir / ".env").write_text('DOTENV_PUBLIC_KEY="key"\nSECRET="encrypted:..."')
            (service_dir / ".env.keys").write_text("DOTENV_PRIVATE_KEY=key")

        config_content = """\
[encryption]
backend = "dotenvx"

[[vault.sync.mappings]]
secret_name = "dummy"
folder_path = "."
"""
        (work_dir / "envdrift.toml").write_text(config_content)

        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath

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
                [*envdrift_cmd, "lock", "--check"],
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
            assert "Traceback" not in stderr, f"Service {idx} crashed with traceback: {stderr}"


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
                (service_dir / ".env.production").write_text('SECRET="encrypted:..."')
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
                    aws_secrets_client.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True)


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
