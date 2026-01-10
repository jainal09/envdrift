# Testing Guide

envdrift has a comprehensive test suite covering unit tests, integration tests, and end-to-end workflows.

## Running Tests

### Quick Commands

```bash
# Run all tests (unit + integration)
make test

# Run only unit tests
uv run pytest -m "not integration"

# Run only integration tests
uv run pytest -m integration

# Run integration tests with Docker containers
make test-integration
```

### Integration Tests with Docker

Some integration tests require Docker containers (LocalStack, HashiCorp Vault, Azure emulator):

```bash
# Start test containers
docker-compose -f tests/docker-compose.test.yml up -d

# Run integration tests
uv run pytest tests/integration/ -v

# Stop containers when done
docker-compose -f tests/docker-compose.test.yml down
```

## Test Categories

### Unit Tests (`tests/unit/`)

Fast, isolated tests that mock external dependencies.

| Module | Coverage |
|--------|----------|
| CLI commands | Command parsing, output formatting |
| Encryption | dotenvx/SOPS wrapper logic |
| Config parsing | pyproject.toml/envdrift.toml loading |
| Vault clients | AWS, HashiCorp, Azure, GCP client logic |
| Git utilities | Hook installation, status detection |

### Integration Tests (`tests/integration/`)

Tests that exercise real components, potentially with external services.

#### Infrastructure Tests

| File | Purpose |
|------|---------|
| `test_infrastructure.py` | Verifies Docker containers are accessible |
| `conftest.py` | Session-scoped fixtures for containers |

#### Encryption Tests

| File | Tests |
|------|-------|
| `test_encryption_tools.py` | dotenvx/SOPS encrypt/decrypt roundtrips |
| `test_encryption_edge_cases.py` | Unicode, multiline, empty files, mixed state |
| `test_ephemeral_keys.py` | Ephemeral mode (no local key storage) |

#### Vault Provider Tests

| File | Provider | Tests |
|------|----------|-------|
| `test_aws_integration.py` | AWS Secrets Manager (LocalStack) | Sync, push, list, error handling |
| `test_hashicorp_integration.py` | HashiCorp Vault | KV v2 operations, token auth |
| `test_azure_integration.py` | Azure Key Vault (Lowkey Vault) | Secret operations |

#### Workflow Tests

| File | Tests |
|------|-------|
| `test_e2e_workflows.py` | Full pull→decrypt, lock→push, monorepo, CI mode |
| `test_hook_setup.py` | Git hook installation |
| `test_git_hooks_advanced.py` | Hooks block/allow commits, pre-push checks |

#### Error Handling & Concurrency

| File | Tests |
|------|-------|
| `test_error_handling.py` | Network timeouts, partial failures, corrupt files |
| `test_concurrency.py` | Thread safety, race conditions, parallel operations |

## Test Markers

Tests are tagged with pytest markers for selective execution:

```bash
# Run only AWS-related tests
uv run pytest -m aws

# Run only HashiCorp Vault tests
uv run pytest -m vault

# Run only Azure tests
uv run pytest -m azure

# Skip slow tests
uv run pytest -m "not slow"
```

Available markers:

| Marker | Description |
|--------|-------------|
| `integration` | Requires external tools (dotenvx, sops) |
| `aws` | Requires LocalStack container |
| `vault` | Requires HashiCorp Vault container |
| `azure` | Requires Lowkey Vault container |
| `slow` | Tests that take >10 seconds |

## CI Pipelines

### Main CI (`ci.yml`)

Runs on every PR:

- Python 3.12
- Unit tests + integration tests (containers skipped if unavailable)
- Linting and coverage upload

### Integration Tests (`integration-tests.yml`)

Runs on every PR with full Docker support:

- Python 3.11, 3.12, 3.13, 3.14 matrix
- Service containers: LocalStack, HashiCorp Vault, Lowkey Vault
- Full integration test suite
- Coverage reporting to Codecov

## Writing New Tests

### Unit Test Guidelines

```python
# tests/unit/test_example.py
import pytest
from unittest.mock import MagicMock, patch

def test_something_simple():
    """Test description."""
    result = my_function("input")
    assert result == "expected"

@patch("envdrift.vault.aws.boto3")
def test_with_mock(mock_boto3):
    """Mock external dependencies."""
    mock_boto3.client.return_value = MagicMock()
    # ... test logic
```

### Integration Test Guidelines

```python
# tests/integration/test_example.py
import pytest
from pathlib import Path

pytestmark = [pytest.mark.integration]

class TestMyFeature:
    """Test class description."""

    def test_with_fixtures(
        self,
        work_dir: Path,
        integration_pythonpath: str,
    ) -> None:
        """Test using common fixtures."""
        # work_dir is a temporary directory
        # integration_pythonpath sets up imports
        pass

    @pytest.mark.aws
    def test_with_aws(
        self,
        localstack_endpoint: str,
        aws_test_env: dict[str, str],
    ) -> None:
        """Test requiring AWS (LocalStack)."""
        # Skips automatically if LocalStack not available
        pass
```

### Available Fixtures

| Fixture | Scope | Description |
|---------|-------|-------------|
| `work_dir` | function | Clean temporary directory |
| `git_repo` | function | Initialized git repository |
| `integration_pythonpath` | session | PYTHONPATH for imports |
| `localstack_endpoint` | session | LocalStack URL (skips if unavailable) |
| `aws_test_env` | session | Environment variables for AWS |
| `aws_secrets_client` | session | boto3 Secrets Manager client |
| `vault_endpoint` | session | HashiCorp Vault URL |
| `vault_test_env` | session | Environment variables for Vault |
| `vault_client` | session | hvac client |
| `lowkey_vault_endpoint` | session | Azure emulator URL |
| `azure_test_env` | session | Environment variables for Azure |

## Test Infrastructure

### Docker Compose Services

The `tests/docker-compose.test.yml` provides:

| Service | Port | Purpose |
|---------|------|---------|
| LocalStack | 4566 | AWS Secrets Manager emulator |
| Vault | 8200 | HashiCorp Vault (dev mode) |
| Lowkey Vault | 8443 | Azure Key Vault emulator |

### Health Checks

All services include health checks. The CI pipeline waits for services to be ready before running tests.
