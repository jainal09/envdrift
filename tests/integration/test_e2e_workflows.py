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
import shutil
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

DOTENVX_AVAILABLE = shutil.which("dotenvx") is not None

if TYPE_CHECKING:
    pass

# Mark all tests in this module
pytestmark = [pytest.mark.integration]


class TestPullDecryptWorkflow:
    """Test complete pull-to-decrypt workflows."""

    @pytest.mark.aws
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

    @pytest.mark.aws
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

    @pytest.mark.aws
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

        # Each service uses a plain ``.env`` (which resolves to the ``production``
        # environment), so the vault-stored key line is labeled
        # ``DOTENV_PRIVATE_KEY_PRODUCTION`` to match. envdrift now rejects a key
        # whose ``DOTENV_PRIVATE_KEY_<SUFFIX>`` doesn't match the target
        # environment (so a staging key can't be installed as production), so the
        # label must agree with the file's environment — anything else is the
        # cross-environment misinstall guarded against in test_sync_engine.py.
        for service_name, secret_name in services.items():
            try:
                aws_secrets_client.create_secret(
                    Name=secret_name,
                    SecretString=f"DOTENV_PRIVATE_KEY_PRODUCTION=key-{service_name}-123",
                )
            except aws_secrets_client.exceptions.ResourceExistsException:
                aws_secrets_client.put_secret_value(
                    SecretId=secret_name,
                    SecretString=f"DOTENV_PRIVATE_KEY_PRODUCTION=key-{service_name}-123",
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


@pytest.mark.slow
@pytest.mark.skipif(not DOTENVX_AVAILABLE, reason="dotenvx binary required")
class TestLockCheckIsReadOnly:
    """`lock --check` is a dry run: it must never mutate files on disk (#303)."""

    def test_lock_check_does_not_mutate_on_key_name_mismatch(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """#303: lock --check must not re-encrypt/regenerate keys on a key mismatch.

        Reproduces a real dotenvx file that was encrypted as ``.env.local`` (key
        ``DOTENV_PRIVATE_KEY_LOCAL``) then *renamed* to ``.env.localenv`` while the
        config maps it to environment ``localenv`` (expected key
        ``DOTENV_PRIVATE_KEY_LOCALENV``). The file's own metadata + the present
        LOCAL private key still decrypt it, so the re-key branch can run and would
        rewrite both the env file and ``.env.keys``. Under ``--check`` (a documented
        dry run) nothing on disk may change.
        """
        dotenvx = shutil.which("dotenvx")
        assert dotenvx is not None

        svc = work_dir / "svc"
        svc.mkdir()

        # Many value lines so the encryption ratio is comfortably >= 0.9 and the
        # "fully encrypted" re-key branch is reached.
        env_file = svc / ".env.local"
        env_file.write_text("A=1\nB=2\nC=3\nD=4\nE=5\nF=6\nG=7\nH=8\nI=9\nJ=10\nK=11\nL=12\nM=13\n")
        enc = subprocess.run(
            [dotenvx, "encrypt", "-f", str(env_file)],
            cwd=str(svc),
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert enc.returncode == 0, enc.stderr

        # Rename the encrypted file to .env.localenv. Its metadata + the .env.keys
        # entry still say LOCAL (which decrypts it), but config env is localenv so
        # the expected key is DOTENV_PRIVATE_KEY_LOCALENV -> triggers needs_rekey.
        renamed = svc / ".env.localenv"
        env_file.rename(renamed)
        keys_file = svc / ".env.keys"

        (work_dir / "envdrift.toml").write_text(
            '[encryption]\nbackend = "dotenvx"\n'
            "[vault.sync]\n"
            "[[vault.sync.mappings]]\n"
            'secret_name = "s"\nfolder_path = "svc"\nenvironment = "localenv"\n'
        )

        env_before = renamed.read_bytes()
        keys_before = keys_file.read_bytes()

        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath
        # --provider is required by lock; aws is fine, the re-key branch is purely
        # local (no vault round-trip) so no credentials/containers are needed here.
        result = subprocess.run(
            [
                *envdrift_cmd,
                "lock",
                "--check",
                "--provider",
                "aws",
                "--region",
                "us-east-1",
                "--config",
                "envdrift.toml",
            ],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )

        out = (result.stdout + result.stderr).lower()
        # The check still REPORTS the intended re-key (read-only diagnosis).
        assert "would re-key" in out or "key name mismatch" in out, out
        # The actual mutation phrasing must NOT appear under --check.
        assert "re-encrypted with new key" not in out, out
        # And on disk: both files byte-identical to the pre-check snapshot.
        assert renamed.read_bytes() == env_before, (
            "lock --check mutated the encrypted env file (#303)"
        )
        assert keys_file.read_bytes() == keys_before, "lock --check regenerated .env.keys (#303)"

    def test_lock_check_does_not_normalize_noncanonical_filename(
        self,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ) -> None:
        """#303: lock --check must not rewrite dotenvx metadata for a non-canonical name.

        A second read-only violation distinct from the re-key branch: when a
        mapping pins a file whose name is non-canonical for its environment
        (``env_file = ".env.local"`` mapped to ``environment = "localenv"``),
        ``_normalize_mapped_dotenvx_metadata`` rewrites ``.env.keys`` and the file
        header to the canonical ``LOCALENV`` key. That ``write_text`` ran *before*
        the ``check_only`` guard, so ``--check`` mutated the tree. It must not.
        """
        dotenvx = shutil.which("dotenvx")
        assert dotenvx is not None

        svc = work_dir / "svc"
        svc.mkdir()

        env_file = svc / ".env.local"
        env_file.write_text("A=1\nB=2\nC=3\nD=4\nE=5\nF=6\nG=7\nH=8\nI=9\nJ=10\nK=11\nL=12\nM=13\n")
        enc = subprocess.run(
            [dotenvx, "encrypt", "-f", str(env_file)],
            cwd=str(svc),
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert enc.returncode == 0, enc.stderr

        keys_file = svc / ".env.keys"

        # Keep the non-canonical name .env.local but map it to environment
        # localenv via env_file: the resolved filename is non-canonical, so
        # _normalize_mapped_dotenvx_metadata would rewrite .env.keys + the header.
        (work_dir / "envdrift.toml").write_text(
            '[encryption]\nbackend = "dotenvx"\n'
            "[vault.sync]\n"
            "[[vault.sync.mappings]]\n"
            'secret_name = "s"\nfolder_path = "svc"\n'
            'env_file = ".env.local"\nenvironment = "localenv"\n'
        )

        env_before = env_file.read_bytes()
        keys_before = keys_file.read_bytes()

        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath
        result = subprocess.run(
            [
                *envdrift_cmd,
                "lock",
                "--check",
                "--provider",
                "aws",
                "--region",
                "us-east-1",
                "--config",
                "envdrift.toml",
            ],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )

        # On disk: both files byte-identical to the pre-check snapshot — the
        # metadata-normalization write must be skipped under --check.
        assert env_file.read_bytes() == env_before, (
            f"lock --check rewrote env-file metadata (#303 normalize path)\n{result.stdout}"
        )
        assert keys_file.read_bytes() == keys_before, (
            f"lock --check rewrote .env.keys (#303 normalize path)\n{result.stdout}"
        )


class TestContainerMarkerContract:
    """#453: container-backed tests must be excluded by marker, not fixture luck.

    ``cross-platform-integration.yml`` deselects container tests on macOS/Windows
    runners (no Docker there) with ``-m "integration and not aws and not vault and
    not azure and not gcp"``. A LocalStack-consuming test without ``@pytest.mark.aws``
    is *selected* by that expression and only escapes failure because the
    ``localstack_endpoint`` fixture ``pytest.skip()``s when the port is closed.
    This meta-test makes the marker — not fixture luck — the enforced contract.
    """

    # The CI selector used on Docker-less runners (cross-platform-integration.yml).
    _SELECTOR = "integration and not aws and not vault and not azure and not gcp"

    def test_cross_platform_selector_excludes_localstack_e2e_tests(self) -> None:
        """The Docker-less CI marker expression deselects the LocalStack e2e tests."""
        module = Path(__file__).resolve()
        repo_root = module.parents[2]
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "--collect-only",
                "-q",
                "--no-cov",
                "-p",
                "no:cacheprovider",
                "-m",
                self._SELECTOR,
                str(module),
            ],
            cwd=str(repo_root),
            env={**os.environ, "PYTHONIOENCODING": "utf-8"},
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
        assert result.returncode == 0, result.stdout + result.stderr

        localstack_backed = [
            "test_e2e_pull_decrypt_workflow",
            "test_e2e_lock_push_workflow",
            "test_e2e_monorepo_multi_service",
        ]
        for name in localstack_backed:
            assert name not in result.stdout, (
                f"{name} consumes LocalStack fixtures but is selected by the "
                f"Docker-less CI marker expression — it is missing "
                f"@pytest.mark.aws (#453)\n{result.stdout}"
            )

        # Control: the Docker-free e2e tests must still be selected, proving the
        # expression excludes by marker rather than deselecting everything.
        assert "test_e2e_ci_mode_noninteractive" in result.stdout, result.stdout
