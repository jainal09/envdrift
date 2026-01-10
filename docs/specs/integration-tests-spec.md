# Integration Test Expansion Specification

## Current State

### Existing Coverage (10 tests)

- dotenvx encrypt/decrypt roundtrip
- SOPS encrypt/decrypt roundtrip
- Smart encryption (git restore on unchanged content)
- Partial encryption push/gitignore handling
- Git hook auto-installation (pre-commit framework + direct hooks)
- Full lock → pull --merge → lock cycle (partial encryption workflow)

### Major Gaps

The current integration tests **do not** test actual cloud provider interactions. All vault operations are either mocked or skipped.

---

## Proposed Infrastructure

### 1. LocalStack (AWS Secrets Manager)

**Container Setup:**

```yaml
# docker-compose.test.yml
services:
  localstack:
    image: localstack/localstack:4.0
    ports:
      - "4566:4566"
    environment:
      - SERVICES=secretsmanager
      - DEBUG=0
    volumes:
      - "/var/run/docker.sock:/var/run/docker.sock"
```

**Test Configuration:**

```python
@pytest.fixture(scope="session")
def localstack_aws():
    """Start LocalStack and return endpoint URL."""
    # Use testcontainers-python or docker-compose
    endpoint = "http://localhost:4566"
    os.environ["AWS_ENDPOINT_URL"] = endpoint
    os.environ["AWS_ACCESS_KEY_ID"] = "test"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "test"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
    yield endpoint
```

### 2. HashiCorp Vault (Dev Mode Container)

**Container Setup:**

```yaml
# docker-compose.test.yml
services:
  vault:
    image: hashicorp/vault:1.18
    ports:
      - "8200:8200"
    environment:
      - VAULT_DEV_ROOT_TOKEN_ID=test-root-token
      - VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200
    cap_add:
      - IPC_LOCK
```

**Test Configuration:**

```python
@pytest.fixture(scope="session")
def vault_server():
    """Start Vault dev server and return client."""
    os.environ["VAULT_ADDR"] = "http://localhost:8200"
    os.environ["VAULT_TOKEN"] = "test-root-token"
    yield "http://localhost:8200"
```

### 3. GCP Secret Manager

**Status:** No official local emulator exists.

**Options:**

1. **Fake Server** - Use `google-cloud-secret-manager` with a custom gRPC server (complex)
2. **Conditional Skip** - Skip GCP tests unless `ENVDRIFT_TEST_GCP=1` is set with real credentials
3. **Mock at SDK Level** - Use `unittest.mock` to patch `google.cloud.secretmanager` client

**Recommendation:** Option 2 (conditional skip) for CI, with mocked unit tests for core logic.

### 4. Azure Key Vault (Lowkey Vault)

**Container Setup:**

```yaml
# docker-compose.test.yml
services:
  lowkey-vault:
    image: nagyesta/lowkey-vault:2.4
    ports:
      - "8443:8443"
    environment:
      - LOWKEY_VAULT_NAMES=envdrift-test-vault
```

**Test Configuration:**

```python
@pytest.fixture(scope="session")
def azure_keyvault():
    """Start Lowkey Vault and return vault URL."""
    # Lowkey Vault uses self-signed certs, disable verification
    os.environ["AZURE_KEYVAULT_URL"] = "https://localhost:8443"
    os.environ["CURL_CA_BUNDLE"] = ""  # Disable cert verification
    yield "https://localhost:8443"
```

**Notes:**

- [Lowkey Vault](https://github.com/nagyesta/lowkey-vault) is a test double for Azure Key Vault
- Compatible with Azure SDK clients
- Some encryption algorithms not supported (acceptable for secrets testing)

---

## Test Categories

### Category A: AWS Secrets Manager (LocalStack)

| Test | Description | Priority |
|------|-------------|----------|
| `test_aws_sync_pull_single_secret` | Pull one secret from vault to .env.keys | P0 |
| `test_aws_sync_pull_multiple_secrets` | Pull multiple secrets with max_workers parallelism | P0 |
| `test_aws_vault_push_from_env_keys` | Push local .env.keys to vault | P0 |
| `test_aws_vault_push_direct_value` | Push a direct key=value to vault | P1 |
| `test_aws_sync_verify_only` | Verify vault keys match local without modifying | P1 |
| `test_aws_sync_verify_vault` | Compare local keys against vault values | P1 |
| `test_aws_sync_force_overwrite` | Force overwrite local keys from vault | P1 |
| `test_aws_secret_not_found` | Graceful handling of missing secrets | P1 |
| `test_aws_secret_versioning` | Retrieve specific secret versions | P2 |
| `test_aws_auth_failure` | Handle invalid credentials gracefully | P2 |
| `test_aws_region_override` | CLI --region flag overrides config | P2 |

### Category B: HashiCorp Vault (Container)

| Test | Description | Priority |
|------|-------------|----------|
| `test_hcv_sync_pull_kv_secret` | Pull from KV v2 secrets engine | P0 |
| `test_hcv_vault_push_kv_secret` | Push to KV v2 secrets engine | P0 |
| `test_hcv_sync_multiple_paths` | Sync multiple secret paths | P1 |
| `test_hcv_token_auth` | Authenticate with VAULT_TOKEN | P1 |
| `test_hcv_secret_not_found` | Handle missing secret path | P1 |
| `test_hcv_url_override` | CLI --vault-url overrides config | P2 |
| `test_hcv_namespace_support` | Enterprise namespace support | P3 |

### Category B2: Azure Key Vault (Lowkey Vault)

| Test | Description | Priority |
|------|-------------|----------|
| `test_azure_sync_pull_secret` | Pull secret from Key Vault | P0 |
| `test_azure_vault_push_secret` | Push secret to Key Vault | P0 |
| `test_azure_sync_multiple_secrets` | Sync multiple secrets | P1 |
| `test_azure_secret_not_found` | Handle missing secret | P1 |
| `test_azure_vault_url_override` | CLI --vault-url overrides config | P2 |

### Category C: End-to-End Workflows

| Test | Description | Priority |
|------|-------------|----------|
| `test_e2e_pull_decrypt_workflow` | Full `envdrift pull` from vault → decrypt | P0 |
| `test_e2e_lock_push_workflow` | Full `envdrift lock` encrypt → verify → push | P0 |
| `test_e2e_monorepo_multi_service` | Multiple services with different vaults | P1 |
| `test_e2e_profile_activation` | Profile filtering with activate_to copy | P1 |
| `test_e2e_ci_mode_noninteractive` | --ci flag prevents prompts, returns codes | P1 |
| `test_e2e_partial_encryption_full_cycle` | push → commit → pull-partial cycle | P1 |
| `test_e2e_key_rotation` | Rotate keys, re-encrypt, push new keys | P2 |

### Category D: Encryption Edge Cases

| Test | Description | Priority |
|------|-------------|----------|
| `test_encrypt_empty_file` | Handle empty .env file | P1 |
| `test_encrypt_large_file` | Performance with 1000+ variables | P2 |
| `test_encrypt_unicode_values` | Unicode characters in values | P1 |
| `test_encrypt_multiline_values` | Multiline values with quotes | P1 |
| `test_encrypt_special_chars_keys` | Keys with dots, dashes, underscores | P1 |
| `test_encrypt_already_encrypted` | Re-encrypt already encrypted file | P1 |
| `test_encrypt_mixed_state` | File with some encrypted, some plain values | P1 |
| `test_encrypt_wrong_backend` | File encrypted with dotenvx, config says SOPS | P2 |
| `test_decrypt_missing_key` | Decrypt without private key available | P1 |
| `test_decrypt_wrong_key` | Decrypt with mismatched key | P1 |
| `test_sops_aws_kms` | SOPS with AWS KMS (via LocalStack) | P2 |

### Category E: Validation Edge Cases

| Test | Description | Priority |
|------|-------------|----------|
| `test_validate_nested_pydantic_model` | Nested BaseSettings with sub-models | P2 |
| `test_validate_custom_validators` | Pydantic field validators | P2 |
| `test_validate_optional_vs_required` | Optional fields with/without defaults | P1 |
| `test_validate_extra_forbid` | strict_extra=true rejects unknown vars | P1 |
| `test_validate_sensitive_patterns` | Custom sensitive_patterns config | P2 |
| `test_validate_type_coercion` | String "true" → bool, "123" → int | P2 |

### Category F: Concurrency & Race Conditions

| Test | Description | Priority |
|------|-------------|----------|
| `test_parallel_sync_thread_safety` | Multiple threads syncing different secrets | P1 |
| `test_parallel_encrypt_same_file` | Concurrent encrypt attempts (lock behavior) | P2 |
| `test_parallel_decrypt_different_files` | Parallel decrypt of multiple files | P2 |

### Category G: Error Handling & Recovery

| Test | Description | Priority |
|------|-------------|----------|
| `test_network_timeout_vault` | Vault unreachable, graceful timeout | P1 |
| `test_partial_sync_failure` | Some secrets fail, others succeed | P1 |
| `test_corrupt_env_file` | Malformed .env file parsing | P1 |
| `test_corrupt_encrypted_file` | Tampered ciphertext detection | P2 |
| `test_disk_full_atomic_write` | Atomic write fails, original preserved | P3 |
| `test_permission_denied_env_keys` | Cannot write to .env.keys (permissions) | P2 |

### Category H: Git Integration

| Test | Description | Priority |
|------|-------------|----------|
| `test_hook_blocks_unencrypted_commit` | Pre-commit hook fails on plaintext secrets | P0 |
| `test_hook_allows_encrypted_commit` | Pre-commit passes with encrypted files | P0 |
| `test_hook_pre_push_lock_check` | Pre-push verifies lock --check passes | P1 |
| `test_smart_encrypt_dirty_workdir` | Smart encryption with uncommitted changes | P1 |
| `test_smart_encrypt_no_git_repo` | Graceful fallback when not in git repo | P2 |

---

## Implementation Plan (PR-Based Phases)

Each phase is a single PR. Phases are designed to be independently mergeable.

---

### Phase 1: Infrastructure Setup

**PR Title:** `test: add integration test infrastructure with LocalStack and Vault`

**Deliverables:**

- [ ] `tests/docker-compose.test.yml` - LocalStack + Vault containers
- [ ] `tests/integration/conftest.py` - Session-scoped container fixtures
- [ ] `pyproject.toml` - New markers (`aws`, `vault`, `slow`) and `test-integration` deps
- [ ] `Makefile` - `test-integration` target
- [ ] Smoke test to verify containers start and are accessible

**Files Changed:**

```text
tests/docker-compose.test.yml      (new)
tests/integration/conftest.py      (modify - add fixtures)
pyproject.toml                     (modify - deps + markers)
Makefile                           (modify - new target)
```

**Acceptance Criteria:**

- `make test-integration` starts containers and runs existing integration tests
- Fixtures auto-skip if Docker unavailable
- No changes to existing test behavior

---

### Phase 2: AWS Secrets Manager Tests (LocalStack)

**PR Title:** `test: add AWS Secrets Manager integration tests via LocalStack`

**Deliverables:**

- [ ] `tests/integration/test_aws_integration.py` - Category A tests (P0 + P1)
- [ ] Fixture to pre-populate LocalStack with test secrets
- [ ] Test `sync`, `vault-push`, and error handling

**Tests Included:**

- `test_aws_sync_pull_single_secret`
- `test_aws_sync_pull_multiple_secrets`
- `test_aws_vault_push_from_env_keys`
- `test_aws_vault_push_direct_value`
- `test_aws_sync_verify_only`
- `test_aws_sync_force_overwrite`
- `test_aws_secret_not_found`

**Acceptance Criteria:**

- All tests pass with LocalStack
- Tests skip gracefully without Docker
- Coverage for `src/envdrift/vault/aws.py`

---

### Phase 3: HashiCorp Vault + Azure Key Vault Tests

**PR Title:** `test: add HashiCorp Vault and Azure Key Vault integration tests`

**Deliverables:**

- [ ] `tests/integration/test_hashicorp_integration.py` - Category B tests
- [ ] `tests/integration/test_azure_integration.py` - Category B2 tests
- [ ] Fixtures for Vault KV v2 and Lowkey Vault
- [ ] Test sync/push with token auth (HashiCorp) and managed identity mock (Azure)

**Tests Included (HashiCorp):**

- `test_hcv_sync_pull_kv_secret`
- `test_hcv_vault_push_kv_secret`
- `test_hcv_sync_multiple_paths`
- `test_hcv_token_auth`
- `test_hcv_secret_not_found`

**Tests Included (Azure):**

- `test_azure_sync_pull_secret`
- `test_azure_vault_push_secret`
- `test_azure_sync_multiple_secrets`
- `test_azure_secret_not_found`

**Acceptance Criteria:**

- All tests pass with Vault + Lowkey Vault containers
- Tests skip gracefully without Docker
- Coverage for `src/envdrift/vault/hashicorp.py` and `src/envdrift/vault/azure.py`

---

### Phase 4: End-to-End Workflow Tests

**PR Title:** `test: add end-to-end workflow integration tests`

**Deliverables:**

- [ ] `tests/integration/test_e2e_workflows.py` - Category C tests
- [ ] Full `pull` → decrypt → edit → encrypt → `lock` cycle
- [ ] Multi-service monorepo scenarios

**Tests Included:**

- `test_e2e_pull_decrypt_workflow`
- `test_e2e_lock_push_workflow`
- `test_e2e_monorepo_multi_service`
- `test_e2e_profile_activation`
- `test_e2e_ci_mode_noninteractive`

**Acceptance Criteria:**

- Tests exercise real CLI commands end-to-end
- Uses LocalStack for vault operations
- Documents realistic usage patterns

---

### Phase 5: Encryption Edge Cases

**PR Title:** `test: add encryption edge case tests`

**Deliverables:**

- [ ] `tests/integration/test_encryption_edge_cases.py` - Category D tests
- [ ] Edge cases for unicode, multiline, empty files, wrong backend

**Tests Included:**

- `test_encrypt_empty_file`
- `test_encrypt_unicode_values`
- `test_encrypt_multiline_values`
- `test_encrypt_special_chars_keys`
- `test_encrypt_already_encrypted`
- `test_encrypt_mixed_state`
- `test_decrypt_missing_key`
- `test_decrypt_wrong_key`

**Acceptance Criteria:**

- All edge cases handled gracefully
- Clear error messages for failure cases

---

### Phase 6: Git Hook Advanced Tests

**PR Title:** `test: add advanced git hook integration tests`

**Deliverables:**

- [ ] `tests/integration/test_git_hooks_advanced.py` - Category H tests
- [ ] Test hooks actually block/allow commits

**Tests Included:**

- `test_hook_blocks_unencrypted_commit`
- `test_hook_allows_encrypted_commit`
- `test_hook_pre_push_lock_check`
- `test_smart_encrypt_dirty_workdir`

**Acceptance Criteria:**

- Simulates real git commit/push operations
- Validates hook scripts work correctly

---

### Phase 7: Error Handling & Concurrency

**PR Title:** `test: add error handling and concurrency tests`

**Deliverables:**

- [ ] `tests/integration/test_error_handling.py` - Category G tests
- [ ] `tests/integration/test_concurrency.py` - Category F tests

**Tests Included:**

- `test_network_timeout_vault`
- `test_partial_sync_failure`
- `test_corrupt_env_file`
- `test_parallel_sync_thread_safety`

**Acceptance Criteria:**

- Error scenarios don't crash, provide helpful messages
- Concurrent operations are thread-safe

---

### Phase 8: CI Pipeline Integration

**PR Title:** `ci: add integration test workflow with containers`

**Deliverables:**

- [ ] `.github/workflows/integration-tests.yml`
- [ ] Matrix for Python 3.11, 3.12, 3.13, 3.14
- [ ] Docker service containers for LocalStack + Vault
- [ ] Optional GCP/Azure tests with repository secrets

**Acceptance Criteria:**

- Integration tests run on every PR
- Clear pass/fail status
- Reasonable runtime (<10 minutes)

---

## Test Execution

```bash
# Run all integration tests (requires Docker)
make test-integration

# Run only AWS tests
uv run pytest -m "integration and aws"

# Run only Vault tests
uv run pytest -m "integration and vault"

# Run without containers (skips cloud tests)
uv run pytest -m "integration and not (aws or vault or gcp or azure)"

# Run with real GCP credentials
ENVDRIFT_TEST_GCP=1 uv run pytest -m "integration and gcp"
```

---

## Configuration Examples

### LocalStack Test Secret Setup

```python
@pytest.fixture(scope="session")
def aws_test_secrets(localstack_aws):
    """Pre-populate LocalStack with test secrets."""
    import boto3

    client = boto3.client(
        "secretsmanager",
        endpoint_url=localstack_aws,
        region_name="us-east-1",
    )

    secrets = {
        "myapp/production/dotenv-key": "DOTENV_PRIVATE_KEY_PRODUCTION=abc123",
        "myapp/staging/dotenv-key": "DOTENV_PRIVATE_KEY_STAGING=def456",
        "shared/api-keys": "API_KEY=secret123\nAPI_SECRET=secret456",
    }

    for name, value in secrets.items():
        client.create_secret(Name=name, SecretString=value)

    yield secrets

    # Cleanup
    for name in secrets:
        client.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True)
```

### Vault Test Secret Setup

```python
@pytest.fixture(scope="session")
def vault_test_secrets(vault_server):
    """Pre-populate Vault with test secrets."""
    import hvac

    client = hvac.Client(url=vault_server, token="test-token")

    # Enable KV v2 at secret/
    client.sys.enable_secrets_engine("kv", path="secret", options={"version": "2"})

    secrets = {
        "myapp/production": {"DOTENV_PRIVATE_KEY_PRODUCTION": "abc123"},
        "myapp/staging": {"DOTENV_PRIVATE_KEY_STAGING": "def456"},
    }

    for path, data in secrets.items():
        client.secrets.kv.v2.create_or_update_secret(path=path, secret=data)

    yield secrets
```

---

## Dependencies to Add

```toml
# pyproject.toml [project.optional-dependencies]
test-integration = [
    "pytest-docker>=2.0.0",
    "testcontainers>=3.7.0",
    "boto3>=1.28.0",
    "hvac>=1.2.0",
    "docker>=6.0.0",
]
```

---

## File Structure

```text
tests/
├── integration/
│   ├── conftest.py              # Shared fixtures, container setup
│   ├── test_encryption_tools.py # Existing
│   ├── test_hook_setup.py       # Existing
│   ├── test_aws_integration.py  # NEW: LocalStack tests
│   ├── test_vault_integration.py # NEW: HashiCorp Vault tests
│   ├── test_e2e_workflows.py    # NEW: Full workflow tests
│   ├── test_encryption_edge_cases.py # NEW
│   ├── test_validation_edge_cases.py # NEW
│   ├── test_concurrency.py      # NEW
│   ├── test_error_handling.py   # NEW
│   └── test_git_hooks_advanced.py # NEW
├── docker-compose.test.yml      # NEW: Test infrastructure
└── unit/
    └── ... (existing)
```

---

## Markers Configuration

```toml
# pyproject.toml
[tool.pytest.ini_options]
markers = [
    "integration: Integration tests that download dotenvx/sops binaries.",
    "aws: Tests requiring LocalStack (AWS Secrets Manager).",
    "vault: Tests requiring HashiCorp Vault container.",
    "gcp: Tests requiring GCP credentials (skipped by default).",
    "azure: Tests requiring Azure credentials (skipped by default).",
    "slow: Tests that take >10 seconds.",
]
```

---

## Notes

### Why No GCP Emulator?

Google does not provide a local emulator for Secret Manager. Options:

- Use real GCP project with test credentials in CI secrets
- Mock at the SDK level for unit tests
- Skip in local development, run in CI only

### Why No Azure Emulator?

Azurite only supports Storage services, not Key Vault. Same approach as GCP.

### Container Startup Time

LocalStack and Vault containers add ~5-10 seconds startup time. Use session-scoped fixtures to start once per test run.

### CI Considerations

- Use GitHub Actions services for containers
- Cache Docker images between runs
- Consider separate CI job for integration tests
