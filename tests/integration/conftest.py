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
import sys
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


@pytest.fixture(autouse=True)
def _deterministic_cli_output(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make envdrift CLI subprocesses emit un-colorized, parseable output.

    CI exports ``FORCE_COLOR=1`` globally. Integration helpers pass
    ``os.environ.copy()`` to the CLI, so without this the CLI would render
    ANSI-colored stdout — breaking ``--format json`` parsing and exact-text
    assertions. ``FORCE_COLOR`` overrides ``NO_COLOR`` in Rich, so we must
    *remove* it (setting ``NO_COLOR`` alone is not enough). ``monkeypatch``
    restores the original environment after each test.
    """
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    monkeypatch.setenv("NO_COLOR", "1")


def _force_utf8_subprocess_kwargs(kwargs: dict) -> None:
    """Default a text-mode subprocess to UTF-8 decoding (errors='replace')."""
    if (kwargs.get("text") or kwargs.get("universal_newlines")) and not kwargs.get("encoding"):
        kwargs["encoding"] = "utf-8"
        kwargs.setdefault("errors", "replace")


@pytest.fixture(autouse=True)
def _utf8_subprocess_on_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    """Decode integration subprocess output as UTF-8 on Windows.

    The envdrift CLI emits UTF-8 — it reconfigures its streams so it never
    crashes on Windows' cp1252 (``cli._force_utf8_output``). But Python's
    ``text=True`` decodes a child's stdout with the *locale* encoding, which is
    cp1252 on Windows and raises ``UnicodeDecodeError`` on those UTF-8 bytes in
    the subprocess reader thread. Default text-mode subprocesses to UTF-8 so the
    harness reads the tool's real output. No-op off Windows (already UTF-8); the
    CLI still runs under the default cp1252 locale here, so the tool's own
    reconfigure fix is genuinely exercised.
    """
    if sys.platform != "win32":
        return

    real_run = subprocess.run
    real_popen = subprocess.Popen

    def patched_run(*args, **kwargs):  # type: ignore[no-untyped-def]
        _force_utf8_subprocess_kwargs(kwargs)
        return real_run(*args, **kwargs)

    class PatchedPopen(real_popen):  # type: ignore[misc]
        def __init__(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            _force_utf8_subprocess_kwargs(kwargs)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(subprocess, "run", patched_run)
    monkeypatch.setattr(subprocess, "Popen", PatchedPopen)


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
def integration_env(integration_pythonpath: str) -> dict[str, str]:
    """Return the child env for running the envdrift CLI as a subprocess.

    Regression for #331: integration tests previously built the child env as a
    bare ``{"PYTHONPATH": ...}`` dict, which strips ``PATH``/``HOME`` so the
    child cannot resolve ``uv``/``dotenvx``/``sops`` (PATH) or auto-install
    binaries under ``$HOME``. Building from ``os.environ.copy()`` preserves the
    parent environment and layers ``PYTHONPATH`` on top.

    Function-scoped: returns a *fresh* dict each call. Call sites that need to
    add more env keys must start from a copy (``dict(integration_env)``) so the
    shared fixture value is never mutated.
    """
    env = os.environ.copy()
    env["PYTHONPATH"] = integration_pythonpath
    return env


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
