"""Verify-mode tests for the sync engine (``sync --verify`` semantics).

Split out of ``test_sync_engine.py`` (which was over the file-level function
threshold) — all verify-only behavior lives here: no-modification guarantees,
diagnosable missing-key reasons (#487), the vault-secret existence/usability
probe on skip paths (#441), and mapping identity in progress output (#441).
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from envdrift.sync.config import ServiceMapping, SyncConfig
from envdrift.sync.engine import SyncEngine, SyncMode
from envdrift.sync.result import SyncAction
from envdrift.vault.base import SecretValue, VaultClient
from tests.unit.test_sync_engine import _StoredVaultClient


@pytest.fixture
def mock_vault_client() -> MagicMock:
    """Create a mock vault client."""
    client = MagicMock(spec=VaultClient)
    client.is_authenticated.return_value = True
    return client


class TestSyncEngineVerifyMode:
    """Tests for verify mode."""

    def test_verify_mode_no_modifications(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """Test verify mode doesn't modify files."""
        mock_vault_client.get_secret.return_value = SecretValue(name="test-key", value="secret123")

        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        (service_dir / ".env.production").write_text("DB_URL=encrypted:xyz\n")

        config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="test-key",
                    folder_path=service_dir,
                ),
            ],
        )

        engine = SyncEngine(
            config=config,
            vault_client=mock_vault_client,
            mode=SyncMode(verify_only=True),
        )
        result = engine.sync_all()

        # Should report error (key file doesn't exist) but not create it
        assert result.services[0].action == SyncAction.ERROR
        assert not (service_dir / ".env.keys").exists()

    def test_verify_mode_reports_mismatch(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """Test verify mode reports mismatches as errors."""
        mock_vault_client.get_secret.return_value = SecretValue(name="test-key", value="new_secret")

        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        (service_dir / ".env.production").write_text("DB_URL=encrypted:xyz\n")
        (service_dir / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=old_secret\n")

        config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="test-key",
                    folder_path=service_dir,
                ),
            ],
        )

        engine = SyncEngine(
            config=config,
            vault_client=mock_vault_client,
            mode=SyncMode(verify_only=True),
        )
        result = engine.sync_all()

        assert result.services[0].action == SyncAction.ERROR
        assert "mismatch" in result.services[0].message.lower()


class TestVerifyModeMissingKeyReasons:
    """#487: verify-only must populate ``error`` with a diagnosable reason.

    Pre-fix the verify branch for a missing local key set only ``message`` —
    which the renderer never printed — and the one message it did set ("Key
    file does not exist") was wrong when the file existed but lacked the key.
    """

    def _make_service(self, tmp_path: Path) -> tuple[SyncConfig, Path]:
        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        (service_dir / ".env.production").write_text('SECRET="encrypted:abc"\n')
        config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="test-key",
                    folder_path=service_dir,
                    environment="production",
                ),
            ],
        )
        return config, service_dir

    def test_verify_missing_keys_file_reports_file_reason(self, tmp_path: Path) -> None:
        """No .env.keys at all: error names the missing file (#487)."""
        config, _service_dir = self._make_service(tmp_path)
        client = _StoredVaultClient({"test-key": "DOTENV_PRIVATE_KEY_PRODUCTION=secret123"})

        engine = SyncEngine(config=config, vault_client=client, mode=SyncMode(verify_only=True))
        result = engine.sync_all()

        service = result.services[0]
        assert service.action == SyncAction.ERROR
        assert service.error, "verify-only must populate error with a reason (#487)"
        assert ".env.keys" in service.error
        assert "does not exist" in service.error

    def test_verify_key_missing_from_existing_file_names_the_key(self, tmp_path: Path) -> None:
        """.env.keys exists but lacks the expected key: error names the key (#487)."""
        config, service_dir = self._make_service(tmp_path)
        (service_dir / ".env.keys").write_text("DOTENV_PRIVATE_KEY_OTHERENV=deadbeef\n")
        client = _StoredVaultClient({"test-key": "DOTENV_PRIVATE_KEY_PRODUCTION=secret123"})

        engine = SyncEngine(config=config, vault_client=client, mode=SyncMode(verify_only=True))
        result = engine.sync_all()

        service = result.services[0]
        assert service.action == SyncAction.ERROR
        assert service.error, "verify-only must populate error with a reason (#487)"
        assert "DOTENV_PRIVATE_KEY_PRODUCTION" in service.error
        assert "missing" in service.error
        # Must NOT claim the file is missing — it exists.
        assert "does not exist" not in service.error


class TestVerifyModeVaultSecretExistence:
    """#441: verify mode must check the configured secret even when it skips.

    Pre-fix, a mapping without a local env file returned SKIPPED before the
    vault was ever consulted, so a deleted vault secret passed
    ``sync --verify`` (and ``--verify --ci``) with "All services synced
    successfully" and exit 0.
    """

    def _make_config(self, tmp_path: Path) -> tuple[SyncConfig, Path]:
        """A mapping whose folder exists (with .env.keys) but has NO env file."""
        service_dir = tmp_path / "svc"
        service_dir.mkdir()
        (service_dir / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=deadbeef\n")
        config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="test-key",
                    folder_path=service_dir,
                    environment="production",
                ),
            ],
        )
        return config, service_dir

    def test_verify_missing_secret_without_env_file_is_error(self, tmp_path: Path) -> None:
        """A configured secret absent from the vault must FAIL verify (#441)."""
        config, _service_dir = self._make_config(tmp_path)
        client = _StoredVaultClient({})  # secret deleted / never created

        engine = SyncEngine(config=config, vault_client=client, mode=SyncMode(verify_only=True))
        result = engine.sync_all()

        service = result.services[0]
        assert service.action == SyncAction.ERROR
        assert service.error and "test-key" in service.error, service
        assert result.has_errors and result.exit_code == 1

    def test_verify_missing_secret_with_ambiguous_env_files_is_error(self, tmp_path: Path) -> None:
        """The ambiguous-mapping skip must not hide a missing secret either (#441)."""
        config, service_dir = self._make_config(tmp_path)
        (service_dir / ".env.alpha").write_text("A=1\n")
        (service_dir / ".env.beta").write_text("A=1\n")
        client = _StoredVaultClient({})

        engine = SyncEngine(config=config, vault_client=client, mode=SyncMode(verify_only=True))
        result = engine.sync_all()

        assert result.services[0].action == SyncAction.ERROR
        assert result.has_errors

    def test_verify_existing_secret_without_env_file_stays_skipped(self, tmp_path: Path) -> None:
        """No local env file + secret present in vault = legitimate skip (#441)."""
        config, _service_dir = self._make_config(tmp_path)
        client = _StoredVaultClient({"test-key": "DOTENV_PRIVATE_KEY_PRODUCTION=secret123"})

        engine = SyncEngine(config=config, vault_client=client, mode=SyncMode(verify_only=True))
        result = engine.sync_all()

        service = result.services[0]
        assert service.action == SyncAction.SKIPPED
        assert "No .env.production file found" in service.message
        assert not result.has_errors

    def test_non_verify_missing_env_file_skips_without_vault_call(self, tmp_path: Path) -> None:
        """Plain sync keeps the benign skip: no env file, vault never consulted."""
        config, _service_dir = self._make_config(tmp_path)
        client = MagicMock(spec=VaultClient)

        engine = SyncEngine(config=config, vault_client=client)
        result = engine.sync_all()

        assert result.services[0].action == SyncAction.SKIPPED
        client.get_secret.assert_not_called()

    def test_verify_unusable_secret_without_env_file_is_error(self, tmp_path: Path) -> None:
        """A secret that exists but holds unusable key material fails verify.

        #661 review (Greptile P1): the existence-only probe let a secret whose
        value the consuming path would reject (KeyMaterialError for a JSON
        document without a usable key field, #480) verify cleanly as SKIPPED.
        The probe applies the same shape validation as ``_fetch_vault_secret``.
        """
        config, _service_dir = self._make_config(tmp_path)
        client = _StoredVaultClient({"test-key": '{"username": "admin", "password": "p"}'})

        engine = SyncEngine(config=config, vault_client=client, mode=SyncMode(verify_only=True))
        result = engine.sync_all()

        service = result.services[0]
        assert service.action == SyncAction.ERROR
        assert service.error and "test-key" in service.error, service
        assert result.has_errors

    def test_verify_env_label_mismatch_without_env_file_is_error(self, tmp_path: Path) -> None:
        """A key labeled for another environment fails verify like a real sync.

        The consuming path refuses to relabel a ``DOTENV_PRIVATE_KEY_<SUFFIX>``
        value into a different environment (#348); the verify-mode probe must
        apply the same check (#661 review).
        """
        config, _service_dir = self._make_config(tmp_path)
        client = _StoredVaultClient({"test-key": "DOTENV_PRIVATE_KEY_STAGING=secret123"})

        engine = SyncEngine(config=config, vault_client=client, mode=SyncMode(verify_only=True))
        result = engine.sync_all()

        service = result.services[0]
        assert service.action == SyncAction.ERROR
        assert service.error and "STAGING" in service.error, service
        assert result.has_errors


class TestVerifySkippedSecretsMode:
    """#663: sync workflows that claim verification must probe skip paths."""

    @pytest.mark.parametrize(
        ("vault_values", "expected_error"),
        [
            pytest.param({}, "test-key", id="missing"),
            pytest.param(
                {"test-key": '{"username": "admin", "password": "value"}'},
                "JSON",
                id="unusable",
            ),
        ],
    )
    def test_missing_or_unusable_secret_without_env_file_is_error(
        self,
        tmp_path: Path,
        vault_values: dict[str, str],
        expected_error: str,
    ) -> None:
        """A sync-capable verify step must reject unusable vault state."""
        service_dir = tmp_path / "svc"
        service_dir.mkdir()
        config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="test-key",
                    folder_path=service_dir,
                    environment="production",
                ),
            ],
        )
        client = _StoredVaultClient(vault_values)

        engine = SyncEngine(
            config=config,
            vault_client=client,
            mode=SyncMode(force_update=True, verify_skipped_secrets=True),
        )
        result = engine.sync_all()

        service = result.services[0]
        assert service.action == SyncAction.ERROR
        assert service.error and expected_error in service.error, service
        assert result.has_errors and result.exit_code == 1

    def test_existing_env_file_still_syncs(self, tmp_path: Path) -> None:
        """Skip-path verification must not make lock key sync read-only."""
        service_dir = tmp_path / "svc"
        service_dir.mkdir()
        (service_dir / ".env.production").write_text("SECRET=encrypted:value\n")
        (service_dir / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=old-key\n")
        config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="current-key",
                    folder_path=service_dir,
                    environment="production",
                ),
            ],
        )
        client = _StoredVaultClient({"current-key": "DOTENV_PRIVATE_KEY_PRODUCTION=new-key"})

        engine = SyncEngine(
            config=config,
            vault_client=client,
            mode=SyncMode(force_update=True, verify_skipped_secrets=True),
        )
        result = engine.sync_all()

        assert result.services[0].action == SyncAction.UPDATED
        assert "DOTENV_PRIVATE_KEY_PRODUCTION=new-key" in (service_dir / ".env.keys").read_text()


class TestProcessingLineIdentity:
    """#441: progress lines identify the mapping, not just the folder."""

    def test_processing_lines_name_secret_and_environment(self, tmp_path: Path) -> None:
        """Two mappings sharing a folder_path emit distinguishable lines (#441)."""
        service_dir = tmp_path / "svc"
        service_dir.mkdir()
        config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="test/svc-production",
                    folder_path=service_dir,
                    environment="production",
                ),
                ServiceMapping(
                    secret_name="test/svc-staging",
                    folder_path=service_dir,
                    environment="staging",
                ),
            ],
        )
        client = _StoredVaultClient(
            {
                "test/svc-production": "DOTENV_PRIVATE_KEY_PRODUCTION=secret123",
                "test/svc-staging": "DOTENV_PRIVATE_KEY_STAGING=secret456",
            }
        )
        messages: list[str] = []

        engine = SyncEngine(
            config=config,
            vault_client=client,
            mode=SyncMode(verify_only=True),
            progress_callback=messages.append,
        )
        engine.sync_all()

        processing = [m for m in messages if m.startswith("Processing:")]
        assert len(processing) == 2, messages
        assert processing[0] != processing[1], processing
        assert "test/svc-production" in processing[0], processing[0]
        assert "env: production" in processing[0], processing[0]
        assert "test/svc-staging" in processing[1], processing[1]
        assert "env: staging" in processing[1], processing[1]
