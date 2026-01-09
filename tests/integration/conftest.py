"""Shared fixtures for integration tests.

This module provides session-scoped fixtures for:
- LocalStack (AWS Secrets Manager)
- HashiCorp Vault (dev mode)
- Lowkey Vault (Azure Key Vault emulator)

Fixtures automatically skip tests if Docker containers are not available.
"""

from __future__ import annotations

import contextlib
import os
import socket
import subprocess
import time
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Generator

# Test infrastructure ports
LOCALSTACK_PORT = 4566
VAULT_PORT = 8200
LOWKEY_VAULT_PORT = 8443

# Test tokens/credentials
VAULT_ROOT_TOKEN = "test-root-token"
AWS_TEST_ACCESS_KEY = "test"
AWS_TEST_SECRET_KEY = "test"
AWS_TEST_REGION = "us-east-1"


def _is_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    """Check if a port is open on the given host."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, TimeoutError):
        return False


@pytest.fixture(scope="session")
def envdrift_cmd() -> list[str]:
    """Get the command to run envdrift CLI.

    Returns:
        List of command parts (e.g. ["uv", "run", "envdrift"])
    """
    import shutil

    # Try to find envdrift in PATH (installed via uv)
    envdrift_path = shutil.which("envdrift")
    if envdrift_path:
        return [envdrift_path]
    # Fallback: use uv run
    return ["uv", "run", "envdrift"]


def _wait_for_port(host: str, port: int, timeout: float = 30.0, interval: float = 0.5) -> bool:
    """Wait for a port to become available."""
    start = time.time()
    while time.time() - start < timeout:
        if _is_port_open(host, port):
            return True
        time.sleep(interval)
    return False


def _is_compose_running() -> bool:
    """Check if docker-compose services are running."""
    return (
        _is_port_open("localhost", LOCALSTACK_PORT)
        and _is_port_open("localhost", VAULT_PORT)
        and _is_port_open("localhost", LOWKEY_VAULT_PORT)
    )


# --- Skip markers for container-dependent tests ---


def pytest_configure(config: pytest.Config) -> None:
    """Register custom markers."""
    config.addinivalue_line("markers", "aws: Tests requiring LocalStack (AWS Secrets Manager)")
    config.addinivalue_line("markers", "vault: Tests requiring HashiCorp Vault container")
    config.addinivalue_line("markers", "azure: Tests requiring Lowkey Vault (Azure Key Vault)")
    config.addinivalue_line("markers", "slow: Tests that take >10 seconds")


# --- LocalStack (AWS) Fixtures ---


@pytest.fixture(scope="session")
def localstack_available() -> bool:
    """Check if LocalStack is available."""
    return _is_port_open("localhost", LOCALSTACK_PORT)


@pytest.fixture(scope="session")
def localstack_endpoint(localstack_available: bool) -> Generator[str, None, None]:
    """Provide LocalStack endpoint URL.

    Skips test if LocalStack is not available.
    """
    if not localstack_available:
        pytest.skip(
            "LocalStack not available (run: docker-compose -f tests/docker-compose.test.yml up -d)"
        )

    endpoint = f"http://localhost:{LOCALSTACK_PORT}"

    # Wait for service to be ready
    if not _wait_for_port("localhost", LOCALSTACK_PORT, timeout=30):
        pytest.skip("LocalStack not ready after 30s")

    yield endpoint


@pytest.fixture(scope="session")
def aws_test_env(localstack_endpoint: str) -> Generator[dict[str, str], None, None]:
    """Configure environment for AWS tests with LocalStack."""
    env = os.environ.copy()
    env.update(
        {
            "AWS_ENDPOINT_URL": localstack_endpoint,
            "AWS_ACCESS_KEY_ID": AWS_TEST_ACCESS_KEY,
            "AWS_SECRET_ACCESS_KEY": AWS_TEST_SECRET_KEY,
            "AWS_DEFAULT_REGION": AWS_TEST_REGION,
            # Disable AWS SDK retries for faster test failures
            "AWS_MAX_ATTEMPTS": "1",
        }
    )
    yield env


@pytest.fixture(scope="session")
def aws_secrets_client(localstack_endpoint: str):
    """Provide a boto3 Secrets Manager client for LocalStack."""
    boto3 = pytest.importorskip("boto3")

    client = boto3.client(
        "secretsmanager",
        endpoint_url=localstack_endpoint,
        region_name=AWS_TEST_REGION,
        aws_access_key_id=AWS_TEST_ACCESS_KEY,
        aws_secret_access_key=AWS_TEST_SECRET_KEY,
    )
    return client


# --- HashiCorp Vault Fixtures ---


@pytest.fixture(scope="session")
def vault_available() -> bool:
    """Check if HashiCorp Vault is available."""
    return _is_port_open("localhost", VAULT_PORT)


@pytest.fixture(scope="session")
def vault_endpoint(vault_available: bool) -> Generator[str, None, None]:
    """Provide Vault endpoint URL.

    Skips test if Vault is not available.
    """
    if not vault_available:
        pytest.skip(
            "Vault not available (run: docker-compose -f tests/docker-compose.test.yml up -d)"
        )

    endpoint = f"http://localhost:{VAULT_PORT}"

    # Wait for service to be ready
    if not _wait_for_port("localhost", VAULT_PORT, timeout=30):
        pytest.skip("Vault not ready after 30s")

    yield endpoint


@pytest.fixture(scope="session")
def vault_test_env(vault_endpoint: str) -> Generator[dict[str, str], None, None]:
    """Configure environment for Vault tests."""
    env = os.environ.copy()
    env.update(
        {
            "VAULT_ADDR": vault_endpoint,
            "VAULT_TOKEN": VAULT_ROOT_TOKEN,
        }
    )
    yield env


@pytest.fixture(scope="session")
def vault_client(vault_endpoint: str):
    """Provide an hvac client for Vault."""
    hvac = pytest.importorskip("hvac")

    client = hvac.Client(url=vault_endpoint, token=VAULT_ROOT_TOKEN)

    # Ensure KV v2 is enabled at secret/ path.
    # InvalidRequest is raised if KV v2 is already enabled, which is expected.
    with contextlib.suppress(hvac.exceptions.InvalidRequest):
        client.sys.enable_secrets_engine(
            backend_type="kv",
            path="secret",
            options={"version": "2"},
        )

    return client


# --- Lowkey Vault (Azure) Fixtures ---


@pytest.fixture(scope="session")
def lowkey_vault_available() -> bool:
    """Check if Lowkey Vault is available."""
    return _is_port_open("localhost", LOWKEY_VAULT_PORT)


@pytest.fixture(scope="session")
def lowkey_vault_endpoint(lowkey_vault_available: bool) -> Generator[str, None, None]:
    """Provide Lowkey Vault endpoint URL.

    Skips test if Lowkey Vault is not available.
    """
    if not lowkey_vault_available:
        pytest.skip(
            "Lowkey Vault not available (run: docker-compose -f tests/docker-compose.test.yml up -d)"
        )

    endpoint = f"https://localhost:{LOWKEY_VAULT_PORT}"

    # Wait for service to be ready
    if not _wait_for_port("localhost", LOWKEY_VAULT_PORT, timeout=30):
        pytest.skip("Lowkey Vault not ready after 30s")

    yield endpoint


@pytest.fixture(scope="session")
def azure_test_env(lowkey_vault_endpoint: str) -> Generator[dict[str, str], None, None]:
    """Configure environment for Azure Key Vault tests with Lowkey Vault."""
    env = os.environ.copy()
    env.update(
        {
            # Lowkey Vault uses self-signed certs
            "AZURE_KEYVAULT_URL": lowkey_vault_endpoint,
            "CURL_CA_BUNDLE": "",
            "REQUESTS_CA_BUNDLE": "",
            # For Azure SDK - disable SSL verification
            "AZURE_CLI_DISABLE_CONNECTION_VERIFICATION": "1",
        }
    )
    yield env


# --- Combined Fixtures ---


@pytest.fixture(scope="session")
def docker_services_available() -> bool:
    """Check if all Docker services are available."""
    return _is_compose_running()


@pytest.fixture(scope="session")
def all_services_env(
    aws_test_env: dict[str, str],
    vault_test_env: dict[str, str],
    azure_test_env: dict[str, str],
) -> dict[str, str]:
    """Combined environment with all service configurations."""
    # aws_test_env already contains os.environ; layer service configs on top
    env = aws_test_env.copy()
    env.update(vault_test_env)
    env.update(azure_test_env)
    return env


# --- Test Infrastructure Helpers ---


REPO_ROOT = Path(__file__).resolve().parents[2]
PYTHONPATH = str(REPO_ROOT / "src")


@pytest.fixture(scope="session")
def integration_pythonpath() -> str:
    """Return the PYTHONPATH for running envdrift CLI."""
    return PYTHONPATH


@pytest.fixture
def work_dir(tmp_path: Path) -> Path:
    """Create a temporary working directory for a test."""
    return tmp_path


@pytest.fixture
def git_repo(work_dir: Path) -> Path:
    """Initialize a git repository in the work directory."""
    # Check git availability
    try:
        subprocess.run(["git", "--version"], capture_output=True, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        pytest.skip("git not available")

    subprocess.run(
        ["git", "init"],
        cwd=work_dir,
        capture_output=True,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.email", "test@test.com"],
        cwd=work_dir,
        capture_output=True,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test User"],
        cwd=work_dir,
        capture_output=True,
        check=True,
    )
    return work_dir
