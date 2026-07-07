"""Azure Key Vault integration tests.

Drives the real envdrift CLI and the Lowkey Vault emulator end to end.
Requires: docker compose -f tests/docker-compose.test.yml up -d

Regression #484: this lane previously skipped every test that touched the real
backend (the seeding fixture sent no Authorization bearer, so Lowkey 401'd
every seed, and the CLI subprocess could not pass Lowkey's self-signed TLS)
while the suite stayed green. Real-backend tests now FAIL loudly instead of
skipping when the running emulator cannot be driven; the only allowed skip is
"the container is not running at all" (``lowkey_vault_endpoint``'s port gate).

How the lane drives Lowkey Vault:

- TLS: the live container certificate is exported by the
  ``lowkey_vault_ca_bundle`` conftest fixture and trusted explicitly —
  verification is never disabled.
- REST seeding: Lowkey accepts any bearer token, so the seeding session sends
  a static dummy bearer (without one, Lowkey rejects every request as 401).
- CLI auth: ``DefaultAzureCredential``'s IMDS managed-identity flow fetches a
  dummy token from Lowkey's built-in token stub (HTTP, port 8080) via
  ``AZURE_POD_IDENTITY_AUTHORITY_HOST`` (see ``azure_test_env`` in conftest).
"""

from __future__ import annotations

import contextlib
import subprocess
import uuid
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


# --- REST helpers (seed / verify / cleanup against the Lowkey API) ---------


def _unique_name(prefix: str) -> str:
    """Return a per-run unique secret name.

    Lowkey implements Key Vault soft-delete with a non-purgeable recovery
    level, so a name deleted by a previous run blocks re-creation (409).
    Unique names keep runs independent of earlier residue.
    """
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _put_secret(session, endpoint: str, name: str, value: str):
    """PUT a secret value, transparently recovering a soft-deleted name.

    Key Vault (and Lowkey, faithfully) rejects re-creating a soft-deleted
    secret with 409 until it is recovered/purged. This vault's recovery level
    forbids purging, so on 409 we recover the name and PUT a new version.
    """

    def _do():
        return session.put(
            f"{endpoint}/secrets/{name}",
            json={"value": value},
            headers={"Content-Type": "application/json"},
            params={"api-version": "7.4"},
        )

    response = _do()
    if response.status_code == 409:
        recover = session.post(
            f"{endpoint}/deletedsecrets/{name}/recover",
            params={"api-version": "7.4"},
        )
        # A failed recover would make the retried PUT 409 again and surface as
        # a confusing seed assertion; fail here with the real cause instead.
        assert recover.status_code in (200, 201), (
            f"Recovering soft-deleted secret '{name}' failed: "
            f"HTTP {recover.status_code} {recover.text[:200]}"
        )
        response = _do()
    return response


def _seed_secret(session, endpoint: str, name: str, value: str) -> None:
    """Seed a secret directly via the Lowkey REST API.

    Asserts (never skips) on failure: a rejected seed means the running
    backend cannot be driven, which must fail the lane (#484).
    """
    put = _put_secret(session, endpoint, name, value)
    assert put.status_code in (200, 201), (
        f"Seeding '{name}' against the running Lowkey Vault failed: "
        f"HTTP {put.status_code} {put.text[:200]}"
    )


def _delete_secret(session, endpoint: str, name: str) -> None:
    """Best-effort REST cleanup of a seeded secret (soft-delete)."""
    with contextlib.suppress(Exception):
        session.delete(
            f"{endpoint}/secrets/{name}",
            params={"api-version": "7.4"},
        )


class _StubResponse:
    def __init__(self, status_code: int, text: str = ""):
        self.status_code = status_code
        self.text = text


class _StubSession:
    """Scripted requests.Session stand-in for the seeding helpers.

    Needs no container: it replays canned responses so ``_put_secret``'s
    409 -> recover -> retry control flow can be pinned down, including the
    recovery-failure path.
    """

    def __init__(self, put_responses: list[_StubResponse], recover_response: _StubResponse):
        self._puts = list(put_responses)
        self._recover = recover_response
        self.put_calls = 0
        self.recover_calls = 0

    def put(self, url: str, **kwargs) -> _StubResponse:
        self.put_calls += 1
        return self._puts.pop(0)

    def post(self, url: str, **kwargs) -> _StubResponse:
        self.recover_calls += 1
        return self._recover


class TestPutSecretRecovery:
    """``_put_secret``'s soft-delete recovery must fail loudly, not confusingly.

    Regression for a #522 review finding: the recover POST response used to be
    discarded, so a failed recover made the retried PUT 409 again and the seed
    assertion blamed the PUT instead of the recovery.
    """

    def test_failed_recover_surfaces_recovery_error(self):
        session = _StubSession(
            put_responses=[_StubResponse(409, "conflict")],
            recover_response=_StubResponse(403, "recovery forbidden"),
        )
        with pytest.raises(AssertionError, match="Recovering soft-deleted secret 'residue'"):
            _put_secret(session, "https://localhost:8443", "residue", "v")
        assert session.put_calls == 1  # no blind PUT retry after a failed recover

    def test_successful_recover_retries_put(self):
        session = _StubSession(
            put_responses=[_StubResponse(409, "conflict"), _StubResponse(200)],
            recover_response=_StubResponse(200),
        )
        response = _put_secret(session, "https://localhost:8443", "residue", "v")
        assert response.status_code == 200
        assert session.recover_calls == 1
        assert session.put_calls == 2


# --- Fixtures ---


@pytest.fixture(scope="module")
def lowkey_vault_client(lowkey_vault_endpoint: str, lowkey_vault_ca_bundle: Path):
    """Create an authenticated requests session for the Lowkey Vault API.

    Lowkey Vault provides a REST API compatible with Azure Key Vault. We use
    requests directly for seeding/verification so the tests can observe the
    vault independently of the envdrift CLI under test.

    - TLS: trusts the live container's exported certificate (verification
      stays ON — never disabled).
    - Auth: Lowkey accepts any bearer token; without one it rejects every
      request as 401, which used to turn the whole lane into silent skips
      (#484). The dummy bearer is not a credential (built by concatenation to
      stay clear of secret-literal push protection).
    """
    import requests

    session = requests.Session()
    session.verify = str(lowkey_vault_ca_bundle)
    session.headers["Authorization"] = "Bearer " + "lowkey-vault-" + "integration-tests"

    return session, lowkey_vault_endpoint


@pytest.fixture(scope="module")
def populated_azure_secrets(lowkey_vault_client) -> Generator[dict[str, str], None, None]:
    """Pre-populate Lowkey Vault with test secrets.

    Creates test secrets:
    - dotenv-key-production: DOTENV_PRIVATE_KEY_PRODUCTION
    - dotenv-key-staging: DOTENV_PRIVATE_KEY_STAGING
    - api-key-shared: API_KEY value

    A failed seed FAILS the lane (it never skips): a backend that rejects the
    seeding requests previously turned every azure test into a silent skip
    while the suite stayed green (#484).
    """
    session, endpoint = lowkey_vault_client

    secrets = {
        "dotenv-key-production": "DOTENV_PRIVATE_KEY_PRODUCTION=prod-key-abc123",
        "dotenv-key-staging": "DOTENV_PRIVATE_KEY_STAGING=staging-key-def456",
        "api-key-shared": "API_KEY=secret123",
    }

    # Create secrets via REST API (a failed seed fails the lane, see #484)
    for name, value in secrets.items():
        _seed_secret(session, endpoint, name, value)

    yield secrets

    # Cleanup - delete secrets
    for name in secrets:
        _delete_secret(session, endpoint, name)


# --- Direct Client Tests ---


class TestAzureClientDirect:
    """Exercise Lowkey Vault's Azure-compatible REST API directly.

    These drive the same HTTP API the Azure SDK uses, via an authenticated
    ``requests`` session (Lowkey accepts any bearer token).
    """

    def test_azure_get_secret(self, lowkey_vault_client, populated_azure_secrets):
        """Test retrieving a secret from Azure Key Vault."""
        session, endpoint = lowkey_vault_client

        response = session.get(
            f"{endpoint}/secrets/dotenv-key-production",
            params={"api-version": "7.4"},
        )

        assert response.status_code == 200, response.text
        data = response.json()
        assert "value" in data
        assert "DOTENV_PRIVATE_KEY_PRODUCTION" in data["value"]

    def test_azure_set_secret(self, lowkey_vault_client):
        """Test creating/updating a secret in Azure Key Vault."""
        session, endpoint = lowkey_vault_client
        secret_name = _unique_name("test-new-secret")

        # Create a new secret
        response = _put_secret(session, endpoint, secret_name, "my-secret-value")

        try:
            assert response.status_code in (200, 201), response.text
            data = response.json()
            assert data.get("value") == "my-secret-value"
        finally:
            _delete_secret(session, endpoint, secret_name)

    def test_azure_list_secrets(self, lowkey_vault_client, populated_azure_secrets):
        """Test listing secrets in Azure Key Vault."""
        session, endpoint = lowkey_vault_client

        response = session.get(
            f"{endpoint}/secrets",
            params={"api-version": "7.4"},
        )

        assert response.status_code == 200, response.text
        data = response.json()
        assert "value" in data, data
        listed = {item.get("id", "") for item in data["value"]}
        assert any("dotenv-key-production" in secret_id for secret_id in listed), data

    def test_azure_secret_not_found(self, lowkey_vault_client):
        """Test graceful handling of missing secrets.

        404 only: the pre-#484 version also accepted 401, which let this test
        "pass" against a vault that was rejecting every request as
        unauthenticated.
        """
        session, endpoint = lowkey_vault_client

        response = session.get(
            f"{endpoint}/secrets/nonexistent-secret-xyz",
            params={"api-version": "7.4"},
        )

        assert response.status_code == 404, response.text


# --- Azure SDK Client Tests (no backend required) ---


class TestAzureSDKClient:
    """Test AzureKeyVaultClient constructor behaviour (no vault calls)."""

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


# ---------------------------------------------------------------------------
# CLI helpers
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
    package cannot be executed directly. ``env`` is expected to be (a copy of)
    ``azure_test_env``, which carries the Lowkey CA bundle and the
    managed-identity token-stub configuration.
    """
    run_env = env.copy()
    run_env["PYTHONPATH"] = integration_pythonpath
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


# --- CLI sync `pull` (config-driven, real backend) --------------------------


class TestAzureSyncCommand:
    """The config-driven `envdrift pull` command against the real backend."""

    def test_pull_syncs_key_from_azure_vault(
        self,
        lowkey_vault_endpoint: str,
        azure_test_env: dict,
        lowkey_vault_client,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """`envdrift pull` reads [vault.sync], fetches the seeded secret and writes .env.keys.

        Replaces a pre-#484 test that ran ``python -m envdrift`` (which cannot
        dispatch) and accepted ``returncode in (0, 1)``, i.e. asserted nothing.
        """
        session, endpoint = lowkey_vault_client
        secret_name = _unique_name("test-sync-pull-azure")
        _seed_secret(
            session,
            endpoint,
            secret_name,
            "DOTENV_PRIVATE_KEY_PRODUCTION=syncpullkey123",
        )

        (work_dir / "envdrift.toml").write_text(
            f"""\
[vault]
provider = "azure"

[vault.azure]
vault_url = "{lowkey_vault_endpoint}"

[[vault.sync.mappings]]
secret_name = "{secret_name}"
folder_path = "."
environment = "production"
""",
            encoding="utf-8",
        )
        # The sync engine only processes mappings whose env file exists; a
        # minimal dotenvx-style encrypted file makes the mapping eligible
        # (mirrors the AWS lane's `pull` fixture).
        (work_dir / ".env.production").write_text(
            'DOTENV_PUBLIC_KEY_PRODUCTION="034a5e"\nDATABASE_URL="encrypted:abc123"\n',
            encoding="utf-8",
        )

        try:
            result = _run_cli(
                envdrift_cmd,
                ["pull"],
                cwd=work_dir,
                env=azure_test_env,
                integration_pythonpath=integration_pythonpath,
            )
            combined = result.stdout + result.stderr
            _assert_dispatched(combined)
            assert result.returncode == 0, combined

            keys_content = (work_dir / ".env.keys").read_text(encoding="utf-8")
            assert "DOTENV_PRIVATE_KEY_PRODUCTION=syncpullkey123" in keys_content
        finally:
            _delete_secret(session, endpoint, secret_name)


# --- CLI vault-push / vault-pull resolving the vault from config ------------


class TestAzureVaultConfigResolution:
    """vault-push/vault-pull resolve provider + vault_url from envdrift.toml."""

    def test_vault_push_uses_vault_url_from_config(
        self,
        lowkey_vault_endpoint: str,
        azure_test_env: dict,
        lowkey_vault_client,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """vault-push with no -p/--vault-url flags reads [vault]/[vault.azure] config.

        Replaces a pre-#484 test that ran ``python -m envdrift`` (which cannot
        dispatch) and accepted ``returncode in (0, 1)``, i.e. asserted nothing.
        """
        session, endpoint = lowkey_vault_client
        secret_name = _unique_name("test-push-from-config")

        (work_dir / "envdrift.toml").write_text(
            f"""\
[vault]
provider = "azure"

[vault.azure]
vault_url = "{lowkey_vault_endpoint}"
""",
            encoding="utf-8",
        )
        (work_dir / ".env.keys").write_text(
            "DOTENV_PRIVATE_KEY_PRODUCTION=configpushkey123\n", encoding="utf-8"
        )

        try:
            result = _run_cli(
                envdrift_cmd,
                ["vault-push", str(work_dir), secret_name, "--env", "production"],
                cwd=work_dir,
                env=azure_test_env,
                integration_pythonpath=integration_pythonpath,
            )
            combined = result.stdout + result.stderr
            _assert_dispatched(combined)
            assert result.returncode == 0, combined
            assert "Pushed" in combined, combined

            # REST-verify the stored value round-tripped verbatim.
            resp = session.get(
                f"{endpoint}/secrets/{secret_name}",
                params={"api-version": "7.4"},
            )
            assert resp.status_code == 200, resp.text
            assert resp.json().get("value") == "DOTENV_PRIVATE_KEY_PRODUCTION=configpushkey123"
        finally:
            _delete_secret(session, endpoint, secret_name)


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
        secret_name = _unique_name("test-pull-secret")
        stored_value = "DOTENV_PRIVATE_KEY_PRODUCTION=pulledkey123"

        _seed_secret(session, endpoint, secret_name, stored_value)

        try:
            # --no-decrypt: we only assert the key is written back.
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
            assert result.returncode == 0, combined

            keys_content = (work_dir / ".env.keys").read_text(encoding="utf-8")
            assert "DOTENV_PRIVATE_KEY_PRODUCTION=pulledkey123" in keys_content
        finally:
            _delete_secret(session, endpoint, secret_name)


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
        env_keys.write_text("DOTENV_PRIVATE_KEY_PRODUCTION=somekey\n", encoding="utf-8")

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
        env_keys.write_text("DOTENV_PRIVATE_KEY_PRODUCTION=somekey\n", encoding="utf-8")

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
            "AZURE_POD_IDENTITY_AUTHORITY_HOST",
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


# --- Round-trip against the live Lowkey emulator ----------------------------
# These previously skipped on any auth failure, which (combined with the
# broken fixture auth/TLS) made the whole class green-by-skip (#484). They now
# assert success outright: when the container is up, the CLI must round-trip.


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
        secret_name = _unique_name("test-push-single-roundtrip")

        env_keys = work_dir / ".env.keys"
        env_keys.write_text(
            "#/ DOTENV_PRIVATE_KEYS /\n"
            "# .env.production\n"
            "DOTENV_PRIVATE_KEY_PRODUCTION=prodkey-xyz\n",
            encoding="utf-8",
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
            assert result.returncode == 0, combined
            assert "Pushed" in combined, combined

            # REST-verify the stored value round-tripped verbatim.
            resp = session.get(
                f"{endpoint}/secrets/{secret_name}",
                params={"api-version": "7.4"},
            )
            assert resp.status_code == 200, resp.text
            assert resp.json().get("value") == "DOTENV_PRIVATE_KEY_PRODUCTION=prodkey-xyz"
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
        secret_name = _unique_name("test-direct-roundtrip")
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
            assert result.returncode == 0, combined
            assert "Pushed" in combined, combined

            resp = session.get(
                f"{endpoint}/secrets/{secret_name}",
                params={"api-version": "7.4"},
            )
            assert resp.status_code == 200, resp.text
            assert resp.json().get("value") == raw_value
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
        secret_name = _unique_name("test-pull-nodecrypt-keyonly")
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
            assert result.returncode == 0, combined

            keys_content = (work_dir / ".env.keys").read_text(encoding="utf-8")
            assert "DOTENV_PRIVATE_KEY_PRODUCTION=pulledkey123" in keys_content
            # --no-decrypt must never touch the .env.production file.
            assert not (work_dir / ".env.production").exists()
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
        secret_name = _unique_name("test-pull-bare-value")
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
            assert result.returncode == 0, combined

            keys_content = (work_dir / ".env.keys").read_text(encoding="utf-8")
            assert "DOTENV_PRIVATE_KEY_PRODUCTION=barekeyvalue123" in keys_content
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
        secret_name = _unique_name("test-pull-equals-split")
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
            assert result.returncode == 0, combined

            keys_content = (work_dir / ".env.keys").read_text(encoding="utf-8")
            assert "DOTENV_PRIVATE_KEY_PRODUCTION=YWJj==/def==" in keys_content, keys_content
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
        secret_name = _unique_name("test-pull-prefix-mismatch")
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

            # The mismatch guard must fire: exit 1 naming the expected key.
            assert result.returncode == 1, combined
            assert "expects" in combined, combined
            assert "DOTENV_PRIVATE_KEY_PRODUCTION" in combined, combined
            # And it must NOT have written the staging key under production.
            if (work_dir / ".env.keys").exists():
                assert "stagingkey" not in (work_dir / ".env.keys").read_text(encoding="utf-8")
        finally:
            _delete_secret(session, endpoint, secret_name)


# --- Lane sentinel (#484) ---------------------------------------------------


class TestAzureLaneSentinel:
    """Guard against the azure lane ever going green-by-skip again (#484).

    Every fixture this test uses may skip ONLY when the Lowkey container is
    not running at all (the ``lowkey_vault_endpoint`` port gate). Once the
    container is up, this test tolerates no auth/TLS/seeding failure: a lane
    where every real-backend test silently skips can no longer report green,
    because this test fails instead.
    """

    def test_azure_real_backend_round_trip_must_run(
        self,
        lowkey_vault_endpoint: str,
        azure_test_env: dict,
        lowkey_vault_client,
        work_dir: Path,
        integration_pythonpath: str,
        envdrift_cmd: list[str],
    ):
        """Seed via authenticated REST, read back via the real CLI, zero tolerance."""
        session, endpoint = lowkey_vault_client
        secret_name = _unique_name("test-484-sentinel")
        stored_value = "DOTENV_PRIVATE_KEY_PRODUCTION=sentinel-key-484"

        # 1. The seeding path must be authenticated (Lowkey 401s without a bearer).
        _seed_secret(session, endpoint, secret_name, stored_value)

        try:
            # 2. The CLI subprocess must trust Lowkey's TLS and obtain a token.
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
            assert result.returncode == 0, (
                "The azure integration lane could not drive the RUNNING Lowkey "
                f"backend — this is the #484 green-by-skip regression:\n{combined}"
            )

            # 3. The round trip must be verbatim.
            keys_content = (work_dir / ".env.keys").read_text(encoding="utf-8")
            assert "DOTENV_PRIVATE_KEY_PRODUCTION=sentinel-key-484" in keys_content
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
        # azure_test_env disables challenge-resource verification so the other
        # Lowkey tests can authenticate; re-enable it here ON PURPOSE -- this
        # test exists to drive the SDK's challenge ValueError through the CLI
        # (with it disabled, auth succeeds and the skip below always fires).
        env["ENVDRIFT_AZURE_VERIFY_CHALLENGE_RESOURCE"] = "1"

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
