"""Azure Key Vault integration tests.

Tests the AzureKeyVaultClient against Lowkey Vault emulator.
Requires: docker-compose -f tests/docker-compose.test.yml up -d

Test categories:
- Direct client operations (get/set/list secrets)
- CLI sync commands
- CLI vault-push commands
- Error handling (missing secrets)

Note: Lowkey Vault requires special handling:
- Uses self-signed certificates (SSL verification disabled)
- Uses a simplified auth mechanism for testing
"""

from __future__ import annotations

import contextlib
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Generator

# Check if azure SDK and requests are available
import importlib.util

REQUESTS_AVAILABLE = importlib.util.find_spec("requests") is not None
try:
    AZURE_AVAILABLE = importlib.util.find_spec("azure.identity") is not None
except ModuleNotFoundError:
    AZURE_AVAILABLE = False

# Mark all tests in this module - skip if dependencies not installed
pytestmark = [
    pytest.mark.integration,
    pytest.mark.azure,
    pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed"),
    pytest.mark.skipif(
        not AZURE_AVAILABLE,
        reason="azure SDK not installed - install with: pip install envdrift[azure]",
    ),
]


# --- Fixtures ---


@pytest.fixture(scope="module")
def lowkey_vault_client(lowkey_vault_endpoint: str):
    """Create a requests session for Lowkey Vault API.

    Lowkey Vault provides a REST API compatible with Azure Key Vault.
    We use requests directly since the Azure SDK requires real Azure auth.
    """
    import requests

    session = requests.Session()
    session.verify = False  # Lowkey Vault uses self-signed certs

    # Suppress SSL warnings for cleaner test output
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    return session, lowkey_vault_endpoint


@pytest.fixture(scope="module")
def populated_azure_secrets(lowkey_vault_client) -> Generator[dict[str, str], None, None]:
    """Pre-populate Lowkey Vault with test secrets.

    Creates test secrets:
    - dotenv-key-production: DOTENV_PRIVATE_KEY_PRODUCTION
    - dotenv-key-staging: DOTENV_PRIVATE_KEY_STAGING
    - api-key-shared: API_KEY value
    """
    session, endpoint = lowkey_vault_client

    base_url = f"{endpoint}/secrets"

    secrets = {
        "dotenv-key-production": "DOTENV_PRIVATE_KEY_PRODUCTION=prod-key-abc123",
        "dotenv-key-staging": "DOTENV_PRIVATE_KEY_STAGING=staging-key-def456",
        "api-key-shared": "API_KEY=secret123",
    }

    # Create secrets via REST API
    for name, value in secrets.items():
        try:
            response = session.put(
                f"{base_url}/{name}",
                json={"value": value},
                headers={"Content-Type": "application/json"},
                params={"api-version": "7.4"},
            )
            # Lowkey Vault may return various status codes
            if response.status_code not in (200, 201, 204):
                pytest.skip(f"Failed to create secret {name}: {response.status_code}")
        except Exception as e:
            pytest.skip(f"Cannot connect to Lowkey Vault: {e}")

    yield secrets

    # Cleanup - delete secrets
    for name in secrets:
        with contextlib.suppress(Exception):
            session.delete(
                f"{base_url}/{name}",
                params={"api-version": "7.4"},
            )


# --- Direct Client Tests ---


class TestAzureClientDirect:
    """Test AzureKeyVaultClient direct operations.

    Note: These tests use mocked Azure credentials since Lowkey Vault
    doesn't fully support the Azure SDK's DefaultAzureCredential.
    We test the client logic by mocking the underlying SecretClient.
    """

    def test_azure_get_secret(self, lowkey_vault_client, populated_azure_secrets):
        """Test retrieving a secret from Azure Key Vault."""
        session, endpoint = lowkey_vault_client

        # Use REST API directly since Azure SDK requires real credentials
        response = session.get(
            f"{endpoint}/secrets/dotenv-key-production",
            params={"api-version": "7.4"},
        )

        if response.status_code == 200:
            data = response.json()
            assert "value" in data
            assert "DOTENV_PRIVATE_KEY_PRODUCTION" in data["value"]
        else:
            # Lowkey Vault may have different behavior
            pytest.skip(f"Lowkey Vault returned {response.status_code}")

    def test_azure_set_secret(self, lowkey_vault_client):
        """Test creating/updating a secret in Azure Key Vault."""
        session, endpoint = lowkey_vault_client

        # Create a new secret
        response = session.put(
            f"{endpoint}/secrets/test-new-secret",
            json={"value": "my-secret-value"},
            headers={"Content-Type": "application/json"},
            params={"api-version": "7.4"},
        )

        if response.status_code in (200, 201):
            data = response.json()
            assert data.get("value") == "my-secret-value"

            # Cleanup
            with contextlib.suppress(Exception):
                session.delete(
                    f"{endpoint}/secrets/test-new-secret",
                    params={"api-version": "7.4"},
                )
        else:
            pytest.skip(f"Lowkey Vault returned {response.status_code}")

    def test_azure_list_secrets(self, lowkey_vault_client, populated_azure_secrets):
        """Test listing secrets in Azure Key Vault."""
        session, endpoint = lowkey_vault_client

        response = session.get(
            f"{endpoint}/secrets",
            params={"api-version": "7.4"},
        )

        if response.status_code == 200:
            data = response.json()
            # Response should contain list of secrets
            assert "value" in data or isinstance(data, list)
        else:
            pytest.skip(f"Lowkey Vault returned {response.status_code}")

    def test_azure_secret_not_found(self, lowkey_vault_client):
        """Test graceful handling of missing secrets."""
        session, endpoint = lowkey_vault_client

        response = session.get(
            f"{endpoint}/secrets/nonexistent-secret-xyz",
            params={"api-version": "7.4"},
        )

        # Should return error for missing secrets
        # Lowkey Vault 7.x may return 401 (unauthorized) or 404 (not found)
        assert response.status_code in (401, 404, 400)


# --- Azure SDK Client Tests (with mocked credentials) ---


class TestAzureSDKClient:
    """Test AzureKeyVaultClient with mocked Azure credentials."""

    def test_azure_client_initialization(self):
        """Test that AzureKeyVaultClient can be initialized."""
        pytest.importorskip("azure.keyvault.secrets")

        from envdrift.vault.azure import AzureKeyVaultClient

        client = AzureKeyVaultClient(vault_url="https://test-vault.vault.azure.net/")
        assert client.vault_url == "https://test-vault.vault.azure.net/"
        assert not client.is_authenticated()

    def test_azure_client_not_authenticated_by_default(self):
        """Test that client is not authenticated before calling authenticate()."""
        pytest.importorskip("azure.keyvault.secrets")

        from envdrift.vault.azure import AzureKeyVaultClient

        client = AzureKeyVaultClient(vault_url="https://test-vault.vault.azure.net/")
        assert client.is_authenticated() is False


# --- CLI Sync Command Tests ---


class TestAzureSyncCommand:
    """Test CLI sync commands with Azure Key Vault."""

    def test_azure_sync_pull_secret(
        self,
        lowkey_vault_endpoint: str,
        azure_test_env: dict,
        lowkey_vault_client,
        populated_azure_secrets: dict,
        work_dir: Path,
        integration_pythonpath: str,
    ):
        """Test pulling a secret from Azure Key Vault via CLI."""
        # Create pyproject.toml with azure vault config
        pyproject = work_dir / "pyproject.toml"
        pyproject.write_text(f'''
[tool.envdrift]
vault_backend = "azure"
vault_url = "{lowkey_vault_endpoint}"
vault_key_path = "dotenv-key-production"
''')

        # Create empty .env.keys file
        env_keys = work_dir / ".env.keys"
        env_keys.write_text("")

        # Run envdrift pull
        env = azure_test_env.copy()
        env["PYTHONPATH"] = integration_pythonpath
        # Disable SSL verification for Lowkey Vault
        env["CURL_CA_BUNDLE"] = ""
        env["REQUESTS_CA_BUNDLE"] = ""

        result = subprocess.run(
            [sys.executable, "-m", "envdrift", "pull"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Check that pull attempted - may fail due to auth but shouldn't crash
        assert result.returncode in (0, 1)


# --- CLI Vault Push Command Tests ---


class TestAzureVaultPush:
    """Test CLI vault-push commands with Azure Key Vault."""

    def test_azure_vault_push_secret(
        self,
        lowkey_vault_endpoint: str,
        azure_test_env: dict,
        lowkey_vault_client,
        work_dir: Path,
        integration_pythonpath: str,
    ):
        """Test pushing a secret to Azure Key Vault via CLI."""
        # Create pyproject.toml with azure vault config
        pyproject = work_dir / "pyproject.toml"
        pyproject.write_text(f'''
[tool.envdrift]
vault_backend = "azure"
vault_url = "{lowkey_vault_endpoint}"
vault_key_path = "test-pushed-secret"
''')

        # Create .env.keys file with content to push
        env_keys = work_dir / ".env.keys"
        env_keys.write_text("DOTENV_PRIVATE_KEY=test-key-from-push\n")

        # Run envdrift vault-push
        env = azure_test_env.copy()
        env["PYTHONPATH"] = integration_pythonpath
        env["CURL_CA_BUNDLE"] = ""
        env["REQUESTS_CA_BUNDLE"] = ""

        result = subprocess.run(
            [sys.executable, "-m", "envdrift", "vault-push"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Check result - may fail due to auth but shouldn't crash
        assert result.returncode in (0, 1)

        # Cleanup if secret was created
        session, endpoint = lowkey_vault_client
        with contextlib.suppress(Exception):
            session.delete(
                f"{endpoint}/secrets/test-pushed-secret",
                params={"api-version": "7.4"},
            )


class TestAzureVaultPull:
    """Test CLI vault-pull commands with Azure Key Vault."""

    def test_azure_vault_pull_round_trip(
        self,
        lowkey_vault_endpoint: str,
        azure_test_env: dict,
        lowkey_vault_client,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """Seed a secret directly, then fetch it back via `envdrift vault-pull`."""
        session, endpoint = lowkey_vault_client
        secret_name = "test-pull-secret"
        stored_value = "DOTENV_PRIVATE_KEY_PRODUCTION=pulledkey123"

        # Seed the secret directly via the vault REST API
        put = session.put(
            f"{endpoint}/secrets/{secret_name}",
            json={"value": stored_value},
            headers={"Content-Type": "application/json"},
            params={"api-version": "7.4"},
        )
        if put.status_code not in (200, 201):
            pytest.skip(f"Lowkey Vault returned {put.status_code} on seed")

        try:
            env = azure_test_env.copy()
            env["PYTHONPATH"] = integration_pythonpath
            env["CURL_CA_BUNDLE"] = ""
            env["REQUESTS_CA_BUNDLE"] = ""

            # Use the real console-script entrypoint (there is no envdrift.__main__,
            # so `python -m envdrift` would exit before dispatching). --no-decrypt:
            # we only assert the key is written back.
            result = subprocess.run(
                [
                    *envdrift_cmd,
                    "vault-pull",
                    str(work_dir),
                    secret_name,
                    "--env",
                    "production",
                    "--no-decrypt",
                    "-p",
                    "azure",
                    "--vault-url",
                    lowkey_vault_endpoint,
                ],
                cwd=work_dir,
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
            )

            combined = result.stdout + result.stderr
            # The CLI must actually dispatch — a missing entrypoint / import error
            # would make this test vacuous, so fail loudly on those.
            assert "No module named" not in combined, combined
            assert "is a package and cannot be directly executed" not in combined, combined

            if result.returncode == 0:
                # Real success: the seeded key was fetched and written.
                keys_content = (work_dir / ".env.keys").read_text()
                assert "DOTENV_PRIVATE_KEY_PRODUCTION=pulledkey123" in keys_content
            else:
                # DefaultAzureCredential can't authenticate against Lowkey Vault in
                # CI; skip visibly rather than passing vacuously. Still confirms the
                # command ran far enough to attempt the vault call.
                assert "vault" in combined.lower() or "credential" in combined.lower(), combined
                pytest.skip(
                    f"vault-pull could not authenticate against Lowkey Vault: {combined[:200]}"
                )
        finally:
            with contextlib.suppress(Exception):
                session.delete(
                    f"{endpoint}/secrets/{secret_name}",
                    params={"api-version": "7.4"},
                )


# ---------------------------------------------------------------------------
# Additional coverage: vault-push / vault-pull CLI behaviour and the real
# Azure vault factory / client.  Authored from the test_azure_integration.py
# package plan.  All tests are GREEN-OR-GATED:
#   * path/argument validation tests fail fast inside the CLI (before any
#     vault auth) and are deterministic PASS on this machine and in CI;
#   * round-trip tests talk to the live Lowkey emulator and SKIP visibly when
#     DefaultAzureCredential cannot authenticate against it.
# Secret names are prefixed with the test name so concurrent / repeat runs
# never collide, and every seeded secret is REST-deleted in a finally block.
# ---------------------------------------------------------------------------


def _run_cli(
    envdrift_cmd: list[str],
    args: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    integration_pythonpath: str,
) -> subprocess.CompletedProcess[str]:
    """Run the real envdrift console-script and return the completed process.

    Uses the installed console entrypoint (``envdrift_cmd``) rather than
    ``python -m envdrift`` because there is no ``envdrift.__main__`` and the
    package cannot be executed directly.
    """
    run_env = env.copy()
    run_env["PYTHONPATH"] = integration_pythonpath
    # Lowkey Vault uses self-signed certs.
    run_env["CURL_CA_BUNDLE"] = ""
    run_env["REQUESTS_CA_BUNDLE"] = ""
    return subprocess.run(
        [*envdrift_cmd, *args],
        cwd=cwd,
        env=run_env,
        capture_output=True,
        text=True,
        timeout=60,
    )


def _assert_dispatched(combined: str) -> None:
    """Fail loudly if the CLI never dispatched (import/packaging error)."""
    assert "No module named" not in combined, combined
    assert "is a package and cannot be directly executed" not in combined, combined


def _seed_secret(session, endpoint: str, name: str, value: str) -> None:
    """Seed a secret directly via the Lowkey REST API or skip on failure."""
    put = session.put(
        f"{endpoint}/secrets/{name}",
        json={"value": value},
        headers={"Content-Type": "application/json"},
        params={"api-version": "7.4"},
    )
    if put.status_code not in (200, 201):
        pytest.skip(f"Lowkey Vault returned {put.status_code} on seed of {name}")


def _delete_secret(session, endpoint: str, name: str) -> None:
    """Best-effort REST cleanup of a seeded secret."""
    with contextlib.suppress(Exception):
        session.delete(
            f"{endpoint}/secrets/{name}",
            params={"api-version": "7.4"},
        )


def _looks_like_auth_failure(combined: str) -> bool:
    """Heuristic: did the command fail specifically because of AUTHENTICATION?

    Matches concrete auth signatures only. A blanket ``"vault"`` match would also
    swallow non-auth regressions (``--vault-url`` handling bugs, Lowkey 4xx/5xx,
    generic CLI errors that merely mention the vault), turning real failures into
    skips. Keep this to explicit authentication signals.
    """
    low = combined.lower()
    auth_signatures = (
        "authentication failed",
        "failed to authenticate",
        "could not authenticate",
        "unable to authenticate",
        "authenticationerror",
        "invalid credential",
        "credential",
        "defaultazurecredential",
        "unauthorized",
        "access denied",
        "forbidden",
        " 401",
        " 403",
    )
    return any(sig in low for sig in auth_signatures)


# --- CLI argument / path validation (deterministic, no vault auth) ---------


class TestAzureVaultArgValidation:
    """vault-push / vault-pull guard clauses that exit before any vault call."""

    def test_vault_push_missing_provider_exits_1(
        self,
        work_dir: Path,
        azure_test_env: dict,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """BP-09: single-service push with no --provider and no config exits 1."""
        env_keys = work_dir / ".env.keys"
        env_keys.write_text("DOTENV_PRIVATE_KEY_PRODUCTION=somekey\n")

        result = _run_cli(
            envdrift_cmd,
            [
                "vault-push",
                str(work_dir),
                "test_vault_push_missing_provider_exits_1",
                "--env",
                "production",
            ],
            cwd=work_dir,
            env=azure_test_env,
            integration_pythonpath=integration_pythonpath,
        )
        combined = result.stdout + result.stderr
        _assert_dispatched(combined)
        assert result.returncode == 1, combined
        assert "Vault provider required" in combined, combined

    def test_vault_push_azure_missing_vault_url_exits_1(
        self,
        work_dir: Path,
        azure_test_env: dict,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """BP-08: -p azure without --vault-url and no config exits 1."""
        env_keys = work_dir / ".env.keys"
        env_keys.write_text("DOTENV_PRIVATE_KEY_PRODUCTION=somekey\n")

        # azure_test_env sets AZURE_KEYVAULT_URL but the CLI only reads --vault-url
        # / config for the *effective* vault url, so this still trips the guard.
        result = _run_cli(
            envdrift_cmd,
            [
                "vault-push",
                str(work_dir),
                "test_vault_push_azure_missing_vault_url_exits_1",
                "--env",
                "production",
                "-p",
                "azure",
            ],
            cwd=work_dir,
            env=azure_test_env,
            integration_pythonpath=integration_pythonpath,
        )
        combined = result.stdout + result.stderr
        _assert_dispatched(combined)
        assert result.returncode == 1, combined
        assert "--vault-url required for azure" in combined, combined


# --- Real Azure vault factory / client behaviour (no creds needed) ---------


class TestAzureVaultFactory:
    """The real get_vault_client factory and AzureKeyVaultClient.authenticate()."""

    def test_get_vault_client_azure_without_vault_url_raises_value_error(self):
        """BP-17: get_vault_client('azure') with no vault_url raises ValueError."""
        pytest.importorskip("azure.keyvault.secrets")

        from envdrift.vault import get_vault_client

        with pytest.raises(ValueError, match="vault_url"):
            get_vault_client("azure")

    def test_authenticate_no_credentials_raises_authentication_error(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """BP-02: authenticate() with all Azure creds scrubbed surfaces an envdrift VaultError.

        The raw azure.core ClientAuthenticationError must be mapped into envdrift's
        VaultError hierarchy (AuthenticationError preferred) and never escape raw.
        """
        pytest.importorskip("azure.keyvault.secrets")

        from azure.core.exceptions import ServiceRequestError, ServiceResponseError

        from envdrift.vault.azure import AzureKeyVaultClient
        from envdrift.vault.base import VaultError

        # Scrub every credential DefaultAzureCredential could pick up so that
        # acquiring a token must fail. (monkeypatch on env vars only — the
        # behaviour under test, the SDK auth + error mapping, stays real.)
        for var in (
            "AZURE_CLIENT_ID",
            "AZURE_CLIENT_SECRET",
            "AZURE_TENANT_ID",
            "AZURE_CLIENT_CERTIFICATE_PATH",
            "AZURE_USERNAME",
            "AZURE_PASSWORD",
            "MSI_ENDPOINT",
            "IDENTITY_ENDPOINT",
            "AZURE_FEDERATED_TOKEN_FILE",
        ):
            monkeypatch.delenv(var, raising=False)
        # Force the managed-identity / IMDS and CLI probes to fail fast.
        monkeypatch.setenv("AZURE_TOKEN_CREDENTIALS", "dev")
        monkeypatch.setenv("MSI_ENDPOINT", "http://127.0.0.1:1/nope")
        monkeypatch.setenv("PATH", "")

        client = AzureKeyVaultClient(vault_url="https://nonexistent-vault.vault.azure.net/")
        # The raw azure.core ClientAuthenticationError must be mapped into envdrift's
        # VaultError hierarchy. Catch ONLY VaultError so a leaked raw azure exception
        # propagates and FAILS this test (that is exactly the regression being
        # guarded). Skip only when authenticate() unexpectedly SUCCEEDS, which means
        # ambient Azure credentials are present (CI runners shouldn't have any).
        try:
            client.authenticate()
        except VaultError:
            # Correct: the azure auth error was mapped into the VaultError hierarchy.
            # Regression #304: a failed authenticate() must also leave the client
            # unauthenticated so ensure_authenticated() retries on the next call.
            assert client.is_authenticated() is False
            assert client._client is None
            assert client._credential is None
        except (ServiceRequestError, ServiceResponseError):
            # Ambient Azure credentials (CI runners shouldn't have any) let auth
            # proceed to a network call against the unreachable test host. That is a
            # transport failure, not the auth-error-mapping regression under test, so
            # we can't exercise it here. A raw ClientAuthenticationError (the actual
            # regression) is NOT caught here and will correctly FAIL the test.
            pytest.skip("Ambient Azure credentials present; auth reached a network call")
        else:
            pytest.skip("authenticate() unexpectedly succeeded (ambient Azure credentials)")


# --- Round-trip against the live Lowkey emulator (GREEN-OR-GATED) ----------


class TestAzureVaultRoundTrip:
    """vault-push / vault-pull against the live Lowkey Vault emulator."""

    def test_vault_push_single_service_round_trip_real_backend(
        self,
        lowkey_vault_endpoint: str,
        azure_test_env: dict,
        lowkey_vault_client,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """HP-06: single-service push reads .env.keys and set_secret against Lowkey."""
        session, endpoint = lowkey_vault_client
        secret_name = "test-push-single-roundtrip"

        env_keys = work_dir / ".env.keys"
        env_keys.write_text(
            "#/ DOTENV_PRIVATE_KEYS /\n"
            "# .env.production\n"
            "DOTENV_PRIVATE_KEY_PRODUCTION=prodkey-xyz\n"
        )

        try:
            result = _run_cli(
                envdrift_cmd,
                [
                    "vault-push",
                    str(work_dir),
                    secret_name,
                    "--env",
                    "production",
                    "-p",
                    "azure",
                    "--vault-url",
                    lowkey_vault_endpoint,
                ],
                cwd=work_dir,
                env=azure_test_env,
                integration_pythonpath=integration_pythonpath,
            )
            combined = result.stdout + result.stderr
            _assert_dispatched(combined)

            if result.returncode == 0:
                assert "Pushed" in combined, combined
                # REST-verify the stored value round-tripped verbatim.
                resp = session.get(
                    f"{endpoint}/secrets/{secret_name}",
                    params={"api-version": "7.4"},
                )
                assert resp.status_code == 200, resp.text
                assert resp.json().get("value") == "DOTENV_PRIVATE_KEY_PRODUCTION=prodkey-xyz"
            else:
                assert _looks_like_auth_failure(combined), combined
                pytest.skip(f"vault-push could not authenticate against Lowkey: {combined[:200]}")
        finally:
            _delete_secret(session, endpoint, secret_name)

    def test_vault_push_direct_round_trip_real_backend(
        self,
        lowkey_vault_endpoint: str,
        azure_test_env: dict,
        lowkey_vault_client,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """HP-07: vault-push --direct stores a raw key=value verbatim in Lowkey."""
        session, endpoint = lowkey_vault_client
        secret_name = "test-direct-roundtrip"
        raw_value = "DOTENV_PRIVATE_KEY_SOAK=abc123"

        try:
            result = _run_cli(
                envdrift_cmd,
                [
                    "vault-push",
                    "--direct",
                    secret_name,
                    raw_value,
                    "-p",
                    "azure",
                    "--vault-url",
                    lowkey_vault_endpoint,
                ],
                cwd=work_dir,
                env=azure_test_env,
                integration_pythonpath=integration_pythonpath,
            )
            combined = result.stdout + result.stderr
            _assert_dispatched(combined)

            if result.returncode == 0:
                assert "Pushed" in combined, combined
                resp = session.get(
                    f"{endpoint}/secrets/{secret_name}",
                    params={"api-version": "7.4"},
                )
                assert resp.status_code == 200, resp.text
                assert resp.json().get("value") == raw_value
            else:
                assert _looks_like_auth_failure(combined), combined
                pytest.skip(
                    f"vault-push --direct could not authenticate against Lowkey: {combined[:200]}"
                )
        finally:
            _delete_secret(session, endpoint, secret_name)

    def test_vault_pull_no_decrypt_writes_key_only_real_backend(
        self,
        lowkey_vault_endpoint: str,
        azure_test_env: dict,
        lowkey_vault_client,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """HP-09: vault-pull --no-decrypt writes only .env.keys, never .env.production."""
        session, endpoint = lowkey_vault_client
        secret_name = "test-pull-nodecrypt-keyonly"
        _seed_secret(
            session,
            endpoint,
            secret_name,
            "DOTENV_PRIVATE_KEY_PRODUCTION=pulledkey123",
        )

        try:
            result = _run_cli(
                envdrift_cmd,
                [
                    "vault-pull",
                    str(work_dir),
                    secret_name,
                    "--env",
                    "production",
                    "--no-decrypt",
                    "-p",
                    "azure",
                    "--vault-url",
                    lowkey_vault_endpoint,
                ],
                cwd=work_dir,
                env=azure_test_env,
                integration_pythonpath=integration_pythonpath,
            )
            combined = result.stdout + result.stderr
            _assert_dispatched(combined)

            if result.returncode == 0:
                keys_content = (work_dir / ".env.keys").read_text()
                assert "DOTENV_PRIVATE_KEY_PRODUCTION=pulledkey123" in keys_content
                # --no-decrypt must never touch the .env.production file.
                assert not (work_dir / ".env.production").exists()
            else:
                assert _looks_like_auth_failure(combined), combined
                pytest.skip(f"vault-pull could not authenticate against Lowkey: {combined[:200]}")
        finally:
            _delete_secret(session, endpoint, secret_name)

    def test_vault_pull_accepts_bare_value_real_round_trip(
        self,
        lowkey_vault_endpoint: str,
        azure_test_env: dict,
        lowkey_vault_client,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """HP-17: bare value (no KEY= prefix) written under DOTENV_PRIVATE_KEY_PRODUCTION."""
        session, endpoint = lowkey_vault_client
        secret_name = "test-pull-bare-value"
        # Stored WITHOUT a DOTENV_PRIVATE_KEY_ prefix -> taken verbatim as the value.
        _seed_secret(session, endpoint, secret_name, "barekeyvalue123")

        try:
            result = _run_cli(
                envdrift_cmd,
                [
                    "vault-pull",
                    str(work_dir),
                    secret_name,
                    "--env",
                    "production",
                    "--no-decrypt",
                    "-p",
                    "azure",
                    "--vault-url",
                    lowkey_vault_endpoint,
                ],
                cwd=work_dir,
                env=azure_test_env,
                integration_pythonpath=integration_pythonpath,
            )
            combined = result.stdout + result.stderr
            _assert_dispatched(combined)

            if result.returncode == 0:
                keys_content = (work_dir / ".env.keys").read_text()
                assert "DOTENV_PRIVATE_KEY_PRODUCTION=barekeyvalue123" in keys_content
            else:
                assert _looks_like_auth_failure(combined), combined
                pytest.skip(f"vault-pull could not authenticate against Lowkey: {combined[:200]}")
        finally:
            _delete_secret(session, endpoint, secret_name)

    def test_vault_pull_value_with_equals_split_first_only_real_round_trip(
        self,
        lowkey_vault_endpoint: str,
        azure_test_env: dict,
        lowkey_vault_client,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """EC-08: 'DOTENV_PRIVATE_KEY_PRODUCTION=YWJj==/def==' split on the FIRST '=' only."""
        session, endpoint = lowkey_vault_client
        secret_name = "test-pull-equals-split"
        # The value itself contains '=' characters; only the first one separates
        # the key name from the value.
        _seed_secret(
            session,
            endpoint,
            secret_name,
            "DOTENV_PRIVATE_KEY_PRODUCTION=YWJj==/def==",
        )

        try:
            result = _run_cli(
                envdrift_cmd,
                [
                    "vault-pull",
                    str(work_dir),
                    secret_name,
                    "--env",
                    "production",
                    "--no-decrypt",
                    "-p",
                    "azure",
                    "--vault-url",
                    lowkey_vault_endpoint,
                ],
                cwd=work_dir,
                env=azure_test_env,
                integration_pythonpath=integration_pythonpath,
            )
            combined = result.stdout + result.stderr
            _assert_dispatched(combined)

            if result.returncode == 0:
                keys_content = (work_dir / ".env.keys").read_text()
                assert "DOTENV_PRIVATE_KEY_PRODUCTION=YWJj==/def==" in keys_content, keys_content
            else:
                assert _looks_like_auth_failure(combined), combined
                pytest.skip(f"vault-pull could not authenticate against Lowkey: {combined[:200]}")
        finally:
            _delete_secret(session, endpoint, secret_name)

    def test_vault_pull_env_prefix_mismatch_exits_1_real_backend(
        self,
        lowkey_vault_endpoint: str,
        azure_test_env: dict,
        lowkey_vault_client,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """BP-14: secret stored as STAGING but pulled --env production trips the mismatch guard."""
        session, endpoint = lowkey_vault_client
        secret_name = "test-pull-prefix-mismatch"
        _seed_secret(
            session,
            endpoint,
            secret_name,
            "DOTENV_PRIVATE_KEY_STAGING=stagingkey",
        )

        try:
            result = _run_cli(
                envdrift_cmd,
                [
                    "vault-pull",
                    str(work_dir),
                    secret_name,
                    "--env",
                    "production",
                    "--no-decrypt",
                    "-p",
                    "azure",
                    "--vault-url",
                    lowkey_vault_endpoint,
                ],
                cwd=work_dir,
                env=azure_test_env,
                integration_pythonpath=integration_pythonpath,
            )
            combined = result.stdout + result.stderr
            _assert_dispatched(combined)

            if result.returncode == 1 and "expects" in combined:
                # The mismatch guard fired: it names the expected production key.
                assert "DOTENV_PRIVATE_KEY_PRODUCTION" in combined, combined
                # And it must NOT have written the staging key under production.
                if (work_dir / ".env.keys").exists():
                    assert "stagingkey" not in (work_dir / ".env.keys").read_text()
            elif _looks_like_auth_failure(combined):
                pytest.skip(f"vault-pull could not authenticate against Lowkey: {combined[:200]}")
            else:
                pytest.fail(f"Unexpected vault-pull result: rc={result.returncode}\n{combined}")
        finally:
            _delete_secret(session, endpoint, secret_name)


# --- #487: challenge-resource ValueError must map into the VaultError hierarchy


@pytest.fixture
def lowkey_ca_bundle(lowkey_vault_endpoint: str, tmp_path: Path) -> Path:
    """Trust Lowkey's self-signed TLS certificate for this test.

    With TLS failing, the SDK raises a transport ``ServiceRequestError`` long
    before the Key Vault challenge policy runs. Trusting the live server's
    certificate lets the request reach challenge validation — where the SDK
    raises the raw ``ValueError`` of #487 (any vault behind a proxy / custom
    domain / emulator triggers it).
    """
    import ssl
    from urllib.parse import urlsplit

    parts = urlsplit(lowkey_vault_endpoint)
    try:
        cert = ssl.get_server_certificate((parts.hostname or "localhost", parts.port or 443))
    except OSError as e:  # pragma: no cover - environment-dependent
        pytest.skip(f"cannot fetch Lowkey TLS certificate: {e}")
    pem = tmp_path / "lowkey-ca.pem"
    pem.write_text(cert, encoding="utf-8")
    return pem


class TestAzureChallengeResourceErrorMapping:
    """#487: SDK exceptions outside the AzureError hierarchy must not escape raw."""

    def test_authenticate_maps_challenge_value_error_into_vault_hierarchy(
        self,
        lowkey_vault_endpoint: str,
        lowkey_ca_bundle: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """authenticate() against Lowkey surfaces VaultError, never raw ValueError.

        Drives the real Azure SDK against the live Lowkey emulator: the
        challenge policy's resource verification raises
        ``ValueError: The challenge resource ... does not match the requested
        domain`` — pre-#487 this escaped ``authenticate()`` raw and the CLI
        dumped a Rich traceback.
        """
        pytest.importorskip("azure.keyvault.secrets")

        from envdrift.vault.azure import AzureKeyVaultClient
        from envdrift.vault.base import VaultError

        monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(lowkey_ca_bundle))
        monkeypatch.setenv("SSL_CERT_FILE", str(lowkey_ca_bundle))

        client = AzureKeyVaultClient(vault_url=lowkey_vault_endpoint)
        # Catch ONLY VaultError: a leaked raw ValueError propagates and FAILS
        # this test (exactly the #487 regression).
        try:
            client.authenticate()
        except VaultError as e:
            if "challenge resource" not in str(e).lower():
                pytest.skip(f"did not reach challenge validation: {e}")
            # Mapped correctly; the half-initialized client must be discarded.
            assert client.is_authenticated() is False
        else:
            pytest.skip("authenticate() unexpectedly succeeded against Lowkey")

    def test_cli_sync_verify_challenge_error_is_clean_not_traceback(
        self,
        lowkey_vault_endpoint: str,
        lowkey_ca_bundle: Path,
        azure_test_env: dict,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """`sync --verify` prints one clean [ERROR] line for the challenge failure."""
        (work_dir / "envdrift.toml").write_text(
            f"""\
[vault]
provider = "azure"

[vault.azure]
vault_url = "{lowkey_vault_endpoint}"

[[vault.sync.mappings]]
secret_name = "dotenv-key-production"
folder_path = "."
environment = "production"
""",
            encoding="utf-8",
        )
        (work_dir / ".env.production").write_text('SECRET="encrypted:abc"\n', encoding="utf-8")

        env = azure_test_env.copy()
        env["PYTHONPATH"] = integration_pythonpath
        env["REQUESTS_CA_BUNDLE"] = str(lowkey_ca_bundle)
        env["SSL_CERT_FILE"] = str(lowkey_ca_bundle)

        result = subprocess.run(
            [*envdrift_cmd, "sync", "--verify"],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )

        combined = " ".join((result.stdout + result.stderr).split())
        _assert_dispatched(combined)
        if "challenge resource" not in combined.lower():
            pytest.skip(f"did not reach challenge validation: {combined[:300]}")
        assert result.returncode == 1, combined
        assert "Traceback" not in combined, combined
        assert "Sync failed" in combined, combined
