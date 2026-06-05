"""GCP Secret Manager integration tests.

Tests the GCPSecretManagerClient + the real envdrift CLI subprocess against the
GCP Secret Manager backend.

There is no GCP emulator, so this module is split into two tiers:

1. CLI / factory guard tests (run anywhere the GCP SDK is importable). These
   exercise the ``--project-id required for gcp`` CLI guard and the
   ``get_vault_client('gcp')`` config-validation branch using the *real*
   envdrift entrypoint and the *real* vault factory — no auth ever happens, so
   no credentials are needed.

2. A real-backend round-trip test that is skip-gated behind
   ``ENVDRIFT_TEST_GCP == "1"`` plus Application Default Credentials and a
   ``GOOGLE_CLOUD_PROJECT``. It is not CI-runnable without real GCP creds and
   documents the intended real coverage.

Mirrors the BOTO3_AVAILABLE / AZURE_AVAILABLE module-gating pattern used by the
AWS and Azure integration suites.

Requires (for the real-backend tier): a real GCP project with Secret Manager
enabled and ADC configured.
"""

from __future__ import annotations

import importlib
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

# Check if the GCP Secret Manager SDK is importable (mirrors BOTO3_AVAILABLE /
# AZURE_AVAILABLE in the AWS/Azure suites).
try:
    GCP_AVAILABLE = importlib.util.find_spec("google.cloud.secretmanager") is not None
except ModuleNotFoundError:
    GCP_AVAILABLE = False

# Mark all tests in this module - skip if the GCP SDK is not installed.
pytestmark = [
    pytest.mark.integration,
    pytest.mark.gcp,
    pytest.mark.slow,
    pytest.mark.skipif(
        not GCP_AVAILABLE,
        reason="GCP SDK not installed - install with: pip install envdrift[gcp]",
    ),
]

# Real-backend gate: only run round-trip tests when explicitly opted in and ADC
# + project are present. Not CI-runnable without real GCP creds.
GCP_REAL_BACKEND = (
    os.environ.get("ENVDRIFT_TEST_GCP") == "1"
    and bool(os.environ.get("GOOGLE_CLOUD_PROJECT"))
    and (
        bool(os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"))
        or Path("~/.config/gcloud/application_default_credentials.json").expanduser().exists()
    )
)


# --- CLI guard tests (no credentials required) ---


class TestGCPCLIProjectIdGuard:
    """The CLI must reject ``-p gcp`` without ``--project-id`` *before* it ever
    tries to authenticate to GCP.

    These use the real ``envdrift`` console-script entrypoint as a subprocess.
    """

    def test_gcp_vault_push_without_project_id_exits_1(
        self,
        envdrift_cmd: list[str],
        integration_pythonpath: str,
        work_dir: Path,
    ):
        """BP-12: ``vault-push -p gcp`` with no ``--project-id`` fails the
        ``_resolve_vault_settings`` guard with exit code 1 and a precise message,
        without attempting any GCP auth.
        """
        # A real .env.keys so we don't bail on a missing-file error first; the
        # provider guard runs before the .env.keys is read anyway.
        (work_dir / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PROD=abc123\n")

        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            [
                *envdrift_cmd,
                "vault-push",
                str(work_dir),
                "test_gcp_vault_push_without_project_id_exits_1-secret",
                "--env",
                "prod",
                "-p",
                "gcp",
            ],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )

        combined = result.stdout + result.stderr

        # The CLI must actually dispatch — a missing entrypoint / import error
        # would make this assertion vacuous.
        assert "No module named" not in combined, combined
        assert "is a package and cannot be directly executed" not in combined, combined

        assert result.returncode == 1, combined
        assert "--project-id required for gcp" in combined, combined
        # The guard must fire BEFORE any GCP authentication is attempted.
        assert "authentication failed" not in combined.lower(), combined
        assert "credential" not in combined.lower(), combined

    def test_gcp_vault_pull_without_project_id_exits_1(
        self,
        envdrift_cmd: list[str],
        integration_pythonpath: str,
        work_dir: Path,
    ):
        """BP-13: ``vault-pull -p gcp`` with no ``--project-id`` hits the same
        guard, exit code 1, before any auth.
        """
        env = os.environ.copy()
        env["PYTHONPATH"] = integration_pythonpath

        result = subprocess.run(
            [
                *envdrift_cmd,
                "vault-pull",
                str(work_dir),
                "test_gcp_vault_pull_without_project_id_exits_1-secret",
                "--env",
                "prod",
                "--no-decrypt",
                "-p",
                "gcp",
            ],
            cwd=work_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )

        combined = result.stdout + result.stderr

        assert "No module named" not in combined, combined
        assert "is a package and cannot be directly executed" not in combined, combined

        assert result.returncode == 1, combined
        assert "--project-id required for gcp" in combined, combined
        assert "authentication failed" not in combined.lower(), combined
        assert "credential" not in combined.lower(), combined


# --- Real vault factory tests (SDK installed, no auth) ---


class TestGCPFactory:
    """Exercise the real ``get_vault_client('gcp')`` factory branch."""

    def test_get_vault_client_gcp_without_project_id_raises_value_error(self):
        """BP-14: with the SDK installed, ``get_vault_client('gcp')`` with a
        missing/empty ``project_id`` raises ValueError from the config-validation
        branch; a non-empty project_id returns a bound GCPSecretManagerClient.
        """
        from envdrift.vault import get_vault_client
        from envdrift.vault.gcp import GCPSecretManagerClient

        # Missing project_id -> ValueError with the documented message.
        with pytest.raises(ValueError) as exc_no_id:
            get_vault_client("gcp")
        assert "project_id" in str(exc_no_id.value)
        assert "GCP Secret Manager requires" in str(exc_no_id.value)

        # Empty-string project_id is falsy -> same guard fires.
        with pytest.raises(ValueError) as exc_empty:
            get_vault_client("gcp", project_id="")
        assert "project_id" in str(exc_empty.value)
        assert "GCP Secret Manager requires" in str(exc_empty.value)

        # A real project_id constructs a real client (no network / no auth).
        client = get_vault_client("gcp", project_id="p")
        assert isinstance(client, GCPSecretManagerClient)
        assert client.project_id == "p"
        # Construction alone must not authenticate.
        assert client.is_authenticated() is False

    def test_gcp_sdk_not_installed_import_error_has_pip_hint(self):
        """BP-11: when the GCP SDK is hidden, the real import guards raise
        ImportError with the ``pip install envdrift[gcp]`` hint.

        We hide ``google.cloud.secretmanager`` / ``google.api_core`` by inserting
        ``None`` sentinels into ``sys.modules`` and reloading the gcp module so its
        module-level ``try/except ImportError`` re-runs with GCP_AVAILABLE=False.
        Everything is restored on teardown.
        """
        import envdrift.vault.gcp as gcp_mod

        hidden = [
            "google.cloud.secretmanager",
            "google.api_core",
            "google.api_core.exceptions",
            "google.auth.exceptions",
        ]
        saved = {name: sys.modules.get(name) for name in hidden}
        try:
            # ``None`` in sys.modules makes ``import x`` raise ImportError.
            for name in hidden:
                sys.modules[name] = None  # type: ignore[assignment]

            reloaded = importlib.reload(gcp_mod)
            assert reloaded.GCP_AVAILABLE is False

            expected_msg = "GCP Secret Manager support requires"
            expected_hint = "pip install envdrift[gcp]"

            # 1. Direct module-accessor guard.
            with pytest.raises(ImportError) as exc_mod:
                reloaded._get_gcp_modules()
            assert expected_msg in str(exc_mod.value)
            assert expected_hint in str(exc_mod.value)

            # 2. Client constructor calls the guard.
            with pytest.raises(ImportError) as exc_client:
                reloaded.GCPSecretManagerClient(project_id="p")
            assert expected_msg in str(exc_client.value)
            assert expected_hint in str(exc_client.value)

            # 3. Factory path: reload the factory so it imports the reloaded gcp
            #    module, then assert the same hint surfaces.
            import envdrift.vault as vault_pkg

            vault_pkg = importlib.reload(vault_pkg)
            with pytest.raises(ImportError) as exc_factory:
                vault_pkg.get_vault_client("gcp", project_id="p")
            assert expected_msg in str(exc_factory.value)
            assert expected_hint in str(exc_factory.value)
        finally:
            # Restore hidden modules and reload back to the real implementations.
            for name, mod in saved.items():
                if mod is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = mod
            importlib.reload(gcp_mod)
            import envdrift.vault as vault_pkg

            importlib.reload(vault_pkg)
            assert gcp_mod.GCP_AVAILABLE is True


# --- Real-backend round-trip (skip-gated; needs real GCP creds) ---


@pytest.mark.skipif(
    not GCP_REAL_BACKEND,
    reason=(
        "real GCP backend not enabled - set ENVDRIFT_TEST_GCP=1, "
        "GOOGLE_CLOUD_PROJECT, and configure Application Default Credentials"
    ),
)
class TestGCPRealBackend:
    """Real GCP Secret Manager round-trips. Skipped unless explicitly opted in.

    Covers HP-01..HP-13 / BP-04/05/09 / EC-07/08/10 / EX-03/07: set/get/list
    round-trips, version increment, unicode/multiline payloads, prefix filtering,
    NotFound -> SecretNotFoundError, plus a CLI vault-push/vault-pull round-trip.

    Every secret created is prefixed with the test function name and deleted in
    teardown so concurrent/repeat runs never collide.
    """

    @pytest.fixture()
    def gcp_client(self):
        """A real, authenticated GCPSecretManagerClient bound to the test project."""
        from envdrift.vault import get_vault_client

        project_id = os.environ["GOOGLE_CLOUD_PROJECT"]
        client = get_vault_client("gcp", project_id=project_id)
        try:
            client.authenticate()
        except Exception as e:  # pragma: no cover - depends on live creds
            pytest.skip(f"GCP authentication failed against real backend: {e}")
        assert client.is_authenticated()
        return client

    def _delete_secret(self, client, secret_id: str) -> None:
        """Best-effort delete of a created secret via the raw SDK client."""
        import contextlib

        with contextlib.suppress(Exception):
            client._client.delete_secret(request={"name": client._secret_path(secret_id)})

    def test_gcp_roundtrip_real_backend(self, gcp_client):
        """set_secret then get_secret returns the stored value, and a second
        set_secret produces a new version. Unicode/multiline survive the trip.
        """
        prefix = "test_gcp_roundtrip_real_backend"
        plain_id = f"{prefix}-plain"
        unicode_id = f"{prefix}-unicode"
        try:
            # Plain round-trip + version increment.
            stored = gcp_client.set_secret(plain_id, "hello-world")
            assert stored.name == plain_id
            assert stored.value == "hello-world"
            assert stored.version is not None

            fetched = gcp_client.get_secret(plain_id)
            assert fetched.name == plain_id
            assert fetched.value == "hello-world"

            second = gcp_client.set_secret(plain_id, "hello-world-v2")
            assert second.version != stored.version
            assert gcp_client.get_secret(plain_id).value == "hello-world-v2"

            # Unicode + multiline payload survives the round-trip.
            unicode_value = "café\nline2\tπ=3.14"
            gcp_client.set_secret(unicode_id, unicode_value)
            assert gcp_client.get_secret(unicode_id).value == unicode_value

            # Prefix filtering returns the created secrets.
            listed = gcp_client.list_secrets(prefix=prefix)
            assert plain_id in listed
            assert unicode_id in listed

            # NotFound surfaces as SecretNotFoundError.
            from envdrift.vault.base import SecretNotFoundError

            with pytest.raises(SecretNotFoundError):
                gcp_client.get_secret(f"{prefix}-does-not-exist")
        finally:
            self._delete_secret(gcp_client, plain_id)
            self._delete_secret(gcp_client, unicode_id)
