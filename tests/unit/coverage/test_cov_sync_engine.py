"""Coverage-focused tests for envdrift.sync.engine.

These tests target previously-uncovered branches in SyncEngine:
schema validation in sync_all, env-file auto-detection, the
folder-does-not-exist branches, the interactive prompt path,
the generic-exception handler, decryption-test edge cases, and the
default interactive prompt.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from textwrap import dedent
from unittest.mock import MagicMock

import pytest

from envdrift.sync.config import ServiceMapping, SyncConfig
from envdrift.sync.engine import SyncEngine, SyncMode
from envdrift.sync.result import DecryptionTestResult, SyncAction
from envdrift.vault.base import SecretValue, VaultClient


@pytest.fixture
def mock_vault_client() -> MagicMock:
    """Create a mock vault client that is authenticated."""
    client = MagicMock(spec=VaultClient)
    client.is_authenticated.return_value = True
    return client


def _make_service(tmp_path: Path, *, env_name: str = ".env.production") -> Path:
    """Create a service dir with an encrypted-looking env file."""
    service_dir = tmp_path / "service"
    service_dir.mkdir()
    (service_dir / env_name).write_text("DB_URL=encrypted:xyz\n")
    return service_dir


class TestSyncAllSchemaValidation:
    """sync_all should run schema validation when enabled (lines 78-80)."""

    def test_sync_all_runs_schema_validation(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        mock_vault_client.get_secret.return_value = SecretValue(name="k", value="secret")

        service_dir = tmp_path / "service"
        service_dir.mkdir()
        (service_dir / ".env.production").write_text("NAME=envdrift\n")
        (service_dir / "service_settings.py").write_text(
            dedent(
                """
                from pydantic_settings import BaseSettings

                class Settings(BaseSettings):
                    NAME: str
                """
            ).lstrip()
        )

        progress_msgs: list[str] = []
        mapping = ServiceMapping(secret_name="k", folder_path=service_dir)
        config = SyncConfig(mappings=[mapping])
        engine = SyncEngine(
            config=config,
            vault_client=mock_vault_client,
            mode=SyncMode(
                validate_schema=True,
                schema_path="service_settings:Settings",
                service_dir=service_dir,
            ),
            progress_callback=progress_msgs.append,
        )

        result = engine.sync_all()

        assert result.services[0].schema_valid is True
        assert any("Validating schema" in m for m in progress_msgs)


class TestAutoDetectEnvFile:
    """When .env.<env> is missing, a detected file is used (lines 93-95)."""

    def test_uses_detected_env_file_for_key_name(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        mock_vault_client.get_secret.return_value = SecretValue(name="k", value="secret")

        service_dir = tmp_path / "service"
        service_dir.mkdir()
        # No .env.production, but a single .env.staging file exists.
        (service_dir / ".env.staging").write_text("DB_URL=encrypted:xyz\n")

        mapping = ServiceMapping(secret_name="k", folder_path=service_dir)
        config = SyncConfig(mappings=[mapping])
        engine = SyncEngine(config=config, vault_client=mock_vault_client)

        result = engine.sync_all()

        assert result.services[0].action == SyncAction.CREATED
        # Detected environment "staging" should drive the key name written.
        content = (service_dir / ".env.keys").read_text()
        assert "DOTENV_PRIVATE_KEY_STAGING=secret" in content


class TestFolderDoesNotExist:
    """Folder-missing branches (lines 126-135)."""

    @staticmethod
    def _patch_folder_missing(monkeypatch: pytest.MonkeyPatch, service_dir: Path) -> None:
        """Make only `service_dir.exists()` report False; everything else real."""
        real_exists = Path.exists

        def fake_exists(self: Path) -> bool:
            if self == service_dir:
                return False
            return real_exists(self)

        monkeypatch.setattr("envdrift.sync.engine.Path.exists", fake_exists)

    def test_verify_only_errors_when_folder_missing(
        self, mock_vault_client: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock_vault_client.get_secret.return_value = SecretValue(name="k", value="secret")

        service_dir = tmp_path / "service"
        service_dir.mkdir()
        (service_dir / ".env.production").write_text("DB_URL=encrypted:xyz\n")

        mapping = ServiceMapping(secret_name="k", folder_path=service_dir)
        engine = SyncEngine(
            config=SyncConfig(mappings=[mapping]),
            vault_client=mock_vault_client,
            mode=SyncMode(verify_only=True),
        )

        # env_file.exists() stays True; only the folder check returns False.
        self._patch_folder_missing(monkeypatch, service_dir)
        result = engine.sync_all()

        assert result.services[0].action == SyncAction.ERROR
        assert "Folder does not exist" in result.services[0].message

    def test_creates_folder_when_missing(
        self, mock_vault_client: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Non-verify mode creates the missing folder (line 135)."""
        mock_vault_client.get_secret.return_value = SecretValue(name="k", value="secret")

        service_dir = tmp_path / "service"
        service_dir.mkdir()
        (service_dir / ".env.production").write_text("DB_URL=encrypted:xyz\n")

        mapping = ServiceMapping(secret_name="k", folder_path=service_dir)
        engine = SyncEngine(config=SyncConfig(mappings=[mapping]), vault_client=mock_vault_client)

        ensure_called: list[Path] = []
        self._patch_folder_missing(monkeypatch, service_dir)
        monkeypatch.setattr(
            "envdrift.sync.engine.ensure_directory",
            lambda path: ensure_called.append(path),
        )
        result = engine.sync_all()

        # ensure_directory must have been invoked for the missing folder.
        assert ensure_called == [service_dir]
        assert result.services[0].action == SyncAction.CREATED


class TestPromptCallbackPath:
    """Interactive prompt path on mismatch (lines 190-197, 213)."""

    def test_prompt_accepts_update(self, mock_vault_client: MagicMock, tmp_path: Path) -> None:
        mock_vault_client.get_secret.return_value = SecretValue(name="k", value="new_secret")
        service_dir = _make_service(tmp_path)
        (service_dir / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=old_secret\n")

        received: list[str] = []

        def prompt(msg: str) -> bool:
            received.append(msg)
            return True

        mapping = ServiceMapping(secret_name="k", folder_path=service_dir)
        engine = SyncEngine(
            config=SyncConfig(mappings=[mapping]),
            vault_client=mock_vault_client,
            prompt_callback=prompt,
        )
        result = engine.sync_all()

        assert result.services[0].action == SyncAction.UPDATED
        # The prompt message should be built from the secret name + previews.
        assert received
        assert "Value mismatch for k" in received[0]
        assert "new_secret" in (service_dir / ".env.keys").read_text()

    def test_prompt_declines_update_is_skipped(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        mock_vault_client.get_secret.return_value = SecretValue(name="k", value="new_secret")
        service_dir = _make_service(tmp_path)
        (service_dir / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=old_secret\n")

        mapping = ServiceMapping(secret_name="k", folder_path=service_dir)
        engine = SyncEngine(
            config=SyncConfig(mappings=[mapping]),
            vault_client=mock_vault_client,
            prompt_callback=lambda _msg: False,
        )
        result = engine.sync_all()

        assert result.services[0].action == SyncAction.SKIPPED
        assert "Update skipped by user" in result.services[0].message
        # File must remain untouched.
        assert "old_secret" in (service_dir / ".env.keys").read_text()


class TestGenericExceptionHandler:
    """Unexpected (non-vault) exceptions become ERROR results (lines 238-239)."""

    def test_unexpected_error_is_captured(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        # get_secret raises a plain RuntimeError, which is neither
        # SecretNotFoundError nor VaultError.
        mock_vault_client.get_secret.side_effect = RuntimeError("boom unexpected")

        service_dir = _make_service(tmp_path)
        mapping = ServiceMapping(secret_name="k", folder_path=service_dir)
        engine = SyncEngine(config=SyncConfig(mappings=[mapping]), vault_client=mock_vault_client)
        result = engine.sync_all()

        assert result.services[0].action == SyncAction.ERROR
        assert result.services[0].message == "Unexpected error"
        assert "boom unexpected" in (result.services[0].error or "")


class TestDecryptionTestEdgeCases:
    """Edge cases in _test_decryption (lines 312, 342-356)."""

    def _encrypted_mapping(self, tmp_path: Path) -> ServiceMapping:
        env_file = tmp_path / ".env.production"
        env_file.write_text('DOTENV_PUBLIC_KEY="abc"\nSECRET="encrypted:xyz"\n')
        return ServiceMapping(secret_name="k", folder_path=tmp_path, environment="production")

    def test_skipped_when_dotenvx_not_installed(
        self, mock_vault_client: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mapping = self._encrypted_mapping(tmp_path)
        monkeypatch.setattr("envdrift.sync.engine.shutil.which", lambda _: None)

        engine = SyncEngine(
            config=SyncConfig(mappings=[mapping]),
            vault_client=mock_vault_client,
            mode=SyncMode(),
        )
        assert engine._test_decryption(mapping) == DecryptionTestResult.SKIPPED

    def test_failed_when_reencrypt_fails_restores_file(
        self, mock_vault_client: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Decrypt succeeds but re-encrypt fails -> FAILED + restore (343-344)."""
        mapping = self._encrypted_mapping(tmp_path)
        env_file = tmp_path / ".env.production"
        original = env_file.read_text()

        monkeypatch.setattr("envdrift.sync.engine.shutil.which", lambda _: "/usr/bin/dotenvx")

        runner = MagicMock()
        runner.side_effect = [
            subprocess.CompletedProcess(["decrypt"], 0),
            subprocess.CompletedProcess(["encrypt"], 1),
        ]
        monkeypatch.setattr("envdrift.sync.engine.subprocess.run", runner)

        engine = SyncEngine(
            config=SyncConfig(mappings=[mapping]),
            vault_client=mock_vault_client,
            mode=SyncMode(),
        )
        result = engine._test_decryption(mapping)

        assert result == DecryptionTestResult.FAILED
        assert runner.call_count == 2
        # Original content restored from backup.
        assert env_file.read_text() == original
        assert not env_file.with_suffix(".backup_decryption_test").exists()

    def test_skipped_on_file_not_found(
        self, mock_vault_client: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """FileNotFoundError during run -> SKIPPED (lines 348-350)."""
        mapping = self._encrypted_mapping(tmp_path)
        monkeypatch.setattr("envdrift.sync.engine.shutil.which", lambda _: "/usr/bin/dotenvx")

        def raise_fnf(*_a: object, **_k: object) -> subprocess.CompletedProcess[str]:
            raise FileNotFoundError("dotenvx vanished")

        monkeypatch.setattr("envdrift.sync.engine.subprocess.run", raise_fnf)

        engine = SyncEngine(
            config=SyncConfig(mappings=[mapping]),
            vault_client=mock_vault_client,
            mode=SyncMode(),
        )
        result = engine._test_decryption(mapping)

        assert result == DecryptionTestResult.SKIPPED
        assert not (tmp_path / ".env.production").with_suffix(".backup_decryption_test").exists()

    def test_failed_on_generic_exception_restores_file(
        self, mock_vault_client: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A generic exception during run -> FAILED + restore (lines 354-356)."""
        mapping = self._encrypted_mapping(tmp_path)
        env_file = tmp_path / ".env.production"
        original = env_file.read_text()
        monkeypatch.setattr("envdrift.sync.engine.shutil.which", lambda _: "/usr/bin/dotenvx")

        def raise_runtime(*_a: object, **_k: object) -> subprocess.CompletedProcess[str]:
            raise RuntimeError("unexpected decrypt failure")

        monkeypatch.setattr("envdrift.sync.engine.subprocess.run", raise_runtime)

        engine = SyncEngine(
            config=SyncConfig(mappings=[mapping]),
            vault_client=mock_vault_client,
            mode=SyncMode(),
        )
        result = engine._test_decryption(mapping)

        assert result == DecryptionTestResult.FAILED
        assert env_file.read_text() == original


class TestValidateSchema:
    """_validate_schema branches (lines 363-364, 394-395)."""

    def test_returns_true_when_no_schema_path(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        service_dir = tmp_path / "service"
        service_dir.mkdir()
        (service_dir / ".env.production").write_text("NAME=x\n")

        mapping = ServiceMapping(secret_name="k", folder_path=service_dir)
        engine = SyncEngine(
            config=SyncConfig(mappings=[mapping]),
            vault_client=mock_vault_client,
            mode=SyncMode(validate_schema=True, schema_path=None),
        )
        assert engine._validate_schema(mapping) is True

    def test_returns_false_on_schema_load_error(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """A bad/unresolvable schema path causes the exception branch -> False."""
        service_dir = tmp_path / "service"
        service_dir.mkdir()
        (service_dir / ".env.production").write_text("NAME=x\n")

        mapping = ServiceMapping(secret_name="k", folder_path=service_dir)
        engine = SyncEngine(
            config=SyncConfig(mappings=[mapping]),
            vault_client=mock_vault_client,
            mode=SyncMode(
                validate_schema=True,
                schema_path="does_not_exist_module:Missing",
                service_dir=service_dir,
            ),
        )
        assert engine._validate_schema(mapping) is False


class TestDefaultPrompt:
    """_default_prompt reads from stdin (lines 405-406)."""

    @pytest.mark.parametrize(
        ("answer", "expected"),
        [("y", True), ("yes", True), ("n", False), ("", False), ("nope", False)],
    )
    def test_default_prompt_parses_input(
        self, monkeypatch: pytest.MonkeyPatch, answer: str, expected: bool
    ) -> None:
        monkeypatch.setattr("builtins.input", lambda _prompt: answer)
        assert SyncEngine._default_prompt("Update?") is expected
