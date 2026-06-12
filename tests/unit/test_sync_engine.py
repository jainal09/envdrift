"""Tests for sync engine."""

from __future__ import annotations

import subprocess
from pathlib import Path
from textwrap import dedent
from unittest.mock import MagicMock

import pytest

from envdrift.sync.config import ServiceMapping, SyncConfig
from envdrift.sync.engine import SyncEngine, SyncMode, normalize_vault_key_value
from envdrift.sync.result import DecryptionTestResult, SyncAction
from envdrift.vault.base import SecretNotFoundError, SecretValue, VaultClient, VaultError


@pytest.fixture
def mock_vault_client() -> MagicMock:
    """Create a mock vault client."""
    client = MagicMock(spec=VaultClient)
    client.is_authenticated.return_value = True
    return client


@pytest.fixture
def simple_config(tmp_path: Path) -> SyncConfig:
    """Create a simple sync config."""
    return SyncConfig(
        mappings=[
            ServiceMapping(
                secret_name="test-key",
                folder_path=tmp_path / "service1",
            ),
        ],
    )


class _StoredVaultClient(VaultClient):
    """Real in-process VaultClient backed by a dict (value source, not a behavior mock)."""

    def __init__(self, store: dict[str, str]) -> None:
        self._store = store

    def get_secret(self, name: str) -> SecretValue:
        if name not in self._store:
            raise SecretNotFoundError(name)
        return SecretValue(name=name, value=self._store[name])

    def list_secrets(self, prefix: str = "") -> list[str]:
        return [k for k in self._store if k.startswith(prefix)]

    def is_authenticated(self) -> bool:
        return True

    def authenticate(self) -> None:  # pragma: no cover - always authed
        return None

    def set_secret(self, name: str, value: str) -> SecretValue:
        self._store[name] = value
        return SecretValue(name=name, value=value)


class TestSyncEngineBasic:
    """Basic sync engine tests."""

    def test_sync_creates_new_file(self, mock_vault_client: MagicMock, tmp_path: Path) -> None:
        """Test syncing creates new .env.keys file."""
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

        engine = SyncEngine(config=config, vault_client=mock_vault_client)
        result = engine.sync_all()

        assert len(result.services) == 1
        assert result.services[0].action == SyncAction.CREATED
        assert (service_dir / ".env.keys").exists()

    def test_sync_uses_custom_env_file(self, mock_vault_client: MagicMock, tmp_path: Path) -> None:
        """Sync should use mapping.env_file when deciding whether a service exists."""
        mock_vault_client.get_secret.return_value = SecretValue(name="test-key", value="secret123")

        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        (service_dir / "postgresql.env").write_text("DB_URL=encrypted:xyz\n")

        config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="test-key",
                    folder_path=service_dir,
                    environment="production",
                    env_file=Path("postgresql.env"),
                ),
            ],
        )

        engine = SyncEngine(config=config, vault_client=mock_vault_client)
        result = engine.sync_all()

        assert len(result.services) == 1
        assert result.services[0].action == SyncAction.CREATED
        assert "DOTENV_PRIVATE_KEY_PRODUCTION=secret123" in (service_dir / ".env.keys").read_text()

    def test_sync_skips_when_env_file_does_not_exist(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """Test syncing skips when .env.<environment> file doesn't exist."""
        mock_vault_client.get_secret.return_value = SecretValue(name="test-key", value="secret123")

        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        # No .env.production file created

        config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="test-key",
                    folder_path=service_dir,
                ),
            ],
        )

        engine = SyncEngine(config=config, vault_client=mock_vault_client)
        result = engine.sync_all()

        assert result.services[0].action == SyncAction.SKIPPED
        assert ".env.production" in result.services[0].message
        assert not (service_dir / ".env.keys").exists()

    def test_sync_errors_when_mapping_folder_does_not_exist(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """#488: a typo'd/nonexistent folder_path is a config ERROR, not a green skip.

        It must fail ``sync --ci`` / ``pull`` instead of reporting full success,
        and the row must state the real reason (folder missing), distinguishing
        it from "env file not created yet" (which stays a skip).
        """
        mock_vault_client.get_secret.return_value = SecretValue(name="test-key", value="secret123")

        config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="test-key",
                    folder_path=tmp_path / "servces" / "api",  # typo'd, never created
                ),
            ],
        )

        engine = SyncEngine(config=config, vault_client=mock_vault_client)
        result = engine.sync_all()

        assert result.services[0].action == SyncAction.ERROR
        assert "does not exist" in (result.services[0].error or "")
        assert "folder_path" in (result.services[0].error or "")
        assert result.has_errors
        assert result.exit_code == 1

    def test_sync_errors_when_explicit_env_file_folder_does_not_exist(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """#488: same loud error when the mapping uses an explicit env_file."""
        mock_vault_client.get_secret.return_value = SecretValue(name="test-key", value="secret123")

        config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="test-key",
                    folder_path=tmp_path / "missing-svc",
                    env_file=Path("custom.env"),
                ),
            ],
        )

        engine = SyncEngine(config=config, vault_client=mock_vault_client)
        result = engine.sync_all()

        assert result.services[0].action == SyncAction.ERROR
        assert "does not exist" in (result.services[0].error or "")

    def test_sync_updates_mismatched_file(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """Test syncing updates when values don't match."""
        mock_vault_client.get_secret.return_value = SecretValue(name="test-key", value="new_secret")

        # Create existing file with different value
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
            mode=SyncMode(force_update=True),
        )
        result = engine.sync_all()

        assert result.services[0].action == SyncAction.UPDATED
        content = (service_dir / ".env.keys").read_text()
        assert "new_secret" in content

    def test_sync_skips_when_values_match(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """Test syncing skips when values already match."""
        mock_vault_client.get_secret.return_value = SecretValue(
            name="test-key", value="same_secret"
        )

        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        (service_dir / ".env.production").write_text("DB_URL=encrypted:xyz\n")
        (service_dir / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=same_secret\n")

        config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="test-key",
                    folder_path=service_dir,
                ),
            ],
        )

        engine = SyncEngine(config=config, vault_client=mock_vault_client)
        result = engine.sync_all()

        assert result.services[0].action == SyncAction.SKIPPED


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


class TestSyncEngineForceMode:
    """Tests for force mode."""

    def test_force_mode_updates_without_prompt(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """Test force mode updates without prompting."""
        mock_vault_client.get_secret.return_value = SecretValue(name="test-key", value="new_secret")

        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        (service_dir / ".env.production").write_text("DB_URL=encrypted:xyz\n")
        (service_dir / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=old_secret\n")

        prompt_called = False

        def prompt_callback(msg: str) -> bool:
            nonlocal prompt_called
            prompt_called = True
            return True

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
            mode=SyncMode(force_update=True),
            prompt_callback=prompt_callback,
        )
        result = engine.sync_all()

        assert result.services[0].action == SyncAction.UPDATED
        assert not prompt_called  # Prompt should not be called in force mode


class TestSyncEngineErrorHandling:
    """Tests for error handling."""

    def test_handles_secret_not_found(self, mock_vault_client: MagicMock, tmp_path: Path) -> None:
        """Test handling when secret is not found in vault."""
        mock_vault_client.get_secret.side_effect = SecretNotFoundError("Secret not found")

        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        (service_dir / ".env.production").write_text("DB_URL=encrypted:xyz\n")

        config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="missing-key",
                    folder_path=service_dir,
                ),
            ],
        )

        engine = SyncEngine(config=config, vault_client=mock_vault_client)
        result = engine.sync_all()

        assert result.services[0].action == SyncAction.ERROR
        assert "not found" in result.services[0].message.lower()

    def test_handles_vault_error(self, mock_vault_client: MagicMock, tmp_path: Path) -> None:
        """Test handling generic vault errors."""
        mock_vault_client.get_secret.side_effect = VaultError("Connection failed")

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

        engine = SyncEngine(config=config, vault_client=mock_vault_client)
        result = engine.sync_all()

        assert result.services[0].action == SyncAction.ERROR


class TestSyncEngineMultipleServices:
    """Tests for multiple service handling."""

    def test_processes_multiple_services(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """Test processing multiple services."""
        mock_vault_client.get_secret.return_value = SecretValue(name="key", value="secret")

        # Create all service directories with .env.production files
        for i in range(1, 4):
            service_dir = tmp_path / f"service{i}"
            service_dir.mkdir()
            (service_dir / ".env.production").write_text("DB_URL=encrypted:xyz\n")

        config = SyncConfig(
            mappings=[
                ServiceMapping(secret_name="key1", folder_path=tmp_path / "service1"),
                ServiceMapping(secret_name="key2", folder_path=tmp_path / "service2"),
                ServiceMapping(secret_name="key3", folder_path=tmp_path / "service3"),
            ],
        )

        engine = SyncEngine(config=config, vault_client=mock_vault_client)
        result = engine.sync_all()

        assert len(result.services) == 3
        assert result.total_processed == 3
        assert result.created_count == 3


class TestSyncEngineDecryptionTest:
    """Tests for decryption verification."""

    def test_decryption_test_skipped_no_env_file(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """Test decryption test is skipped when no env file exists.

        The folder must exist: a missing *folder* is a config ERROR (#488)
        and the decryption test never runs for errored mappings.
        """
        mock_vault_client.get_secret.return_value = SecretValue(name="test-key", value="secret123")

        service_dir = tmp_path / "service1"
        service_dir.mkdir()  # folder exists, but holds no env file

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
            mode=SyncMode(check_decryption=True),
        )
        result = engine.sync_all()

        assert result.services[0].decryption_result == DecryptionTestResult.SKIPPED

    def test_decryption_test_skipped_not_encrypted(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """Test decryption test is skipped for non-encrypted files."""
        mock_vault_client.get_secret.return_value = SecretValue(name="test-key", value="secret123")

        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        (service_dir / ".env.production").write_text("DB_URL=localhost\n")

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
            mode=SyncMode(check_decryption=True),
        )
        result = engine.sync_all()

        assert result.services[0].decryption_result == DecryptionTestResult.SKIPPED

    def test_decryption_test_passes_single_decrypt_on_temp_copy(
        self, mock_vault_client: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A passing check runs ONE dotenvx decrypt against a temp-dir copy (#473).

        The old implementation decrypted the LIVE file in place and re-encrypted
        it afterwards (two subprocess calls), churning the ciphertext on every
        passing run. The check must decrypt a copy in an isolated temp dir, pass
        only the file NAME with cwd set to that dir, and never touch the live
        file or leave a backup behind.
        """
        mapping = ServiceMapping(
            secret_name="test-key", folder_path=tmp_path, environment="production"
        )
        env_file = tmp_path / ".env.production"
        env_file.write_text('DOTENV_PUBLIC_KEY="abc"\nSECRET="encrypted:xyz"\n', encoding="utf-8")
        original = env_file.read_bytes()

        monkeypatch.setattr("envdrift.sync.engine.shutil.which", lambda _: "/usr/bin/dotenvx")
        calls: list[dict] = []

        def fake_run(cmd, **kwargs):
            calls.append({"cmd": list(cmd), "kwargs": kwargs})
            return subprocess.CompletedProcess(cmd, 0)

        monkeypatch.setattr("envdrift.sync.engine.subprocess.run", fake_run)

        engine = SyncEngine(
            config=SyncConfig(mappings=[mapping]), vault_client=mock_vault_client, mode=SyncMode()
        )

        result = engine._test_decryption(mapping)

        assert result == DecryptionTestResult.PASSED
        # Exactly one decrypt; the old roundtrip's re-encrypt stage is gone.
        assert len(calls) == 1
        assert "encrypt" not in calls[0]["cmd"] or "decrypt" in calls[0]["cmd"]
        assert calls[0]["cmd"][1] == "decrypt"
        # dotenvx gets the file NAME with cwd set to the isolated temp dir —
        # never the live path, never the mapping folder as cwd.
        tested_name = calls[0]["cmd"][-1]
        run_cwd = Path(calls[0]["kwargs"]["cwd"])
        assert tested_name == ".env.production"
        assert run_cwd != tmp_path
        assert (run_cwd / tested_name).exists() is False  # temp dir already cleaned up
        # The live file is byte-identical and no backup byproduct exists.
        assert env_file.read_bytes() == original
        assert not env_file.with_suffix(".backup_decryption_test").exists()

    def test_decryption_test_live_file_untouched_even_when_decrypt_writes(
        self, mock_vault_client: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The file dotenvx rewrites is the temp COPY, never the live file (#473).

        Simulates dotenvx faithfully: the fake decrypt rewrites whatever file it
        is pointed at with plaintext. With the old in-place roundtrip that was
        the live working-tree file; now it must be the temp copy, so the live
        bytes stay identical even though the subprocess "decrypted" something.
        """
        mapping = ServiceMapping(
            secret_name="test-key", folder_path=tmp_path, environment="production"
        )
        env_file = tmp_path / ".env.production"
        env_file.write_text('DOTENV_PUBLIC_KEY="abc"\nSECRET="encrypted:xyz"\n', encoding="utf-8")
        original = env_file.read_bytes()

        monkeypatch.setattr("envdrift.sync.engine.shutil.which", lambda _: "/usr/bin/dotenvx")

        def fake_run(cmd, **kwargs):
            # Resolve the file exactly like dotenvx would: -f arg against cwd.
            target = Path(kwargs["cwd"]) / cmd[-1]
            assert target.exists(), f"dotenvx pointed at a non-existent file: {target}"
            target.write_text("SECRET=plaintext-secret\n", encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0)

        monkeypatch.setattr("envdrift.sync.engine.subprocess.run", fake_run)

        engine = SyncEngine(
            config=SyncConfig(mappings=[mapping]), vault_client=mock_vault_client, mode=SyncMode()
        )

        result = engine._test_decryption(mapping)

        assert result == DecryptionTestResult.PASSED
        assert env_file.read_bytes() == original
        assert b"plaintext-secret" not in env_file.read_bytes()

    def test_decryption_test_relative_folder_path_resolves(
        self, mock_vault_client: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A relative folder_path must yield a resolvable dotenvx invocation (#473).

        The old roundtrip ran ``dotenvx decrypt -f services/api/.env.production``
        with ``cwd=services/api`` — dotenvx resolved the doubled relative path
        ``services/api/services/api/.env.production`` (MISSING_ENV_FILE) and
        every relative monorepo mapping reported FAILED. The fake dotenvx below
        succeeds only when the path it is given actually exists from its cwd,
        exactly like the real binary.
        """
        service_dir = tmp_path / "services" / "api"
        service_dir.mkdir(parents=True)
        env_file = service_dir / ".env.production"
        env_file.write_text('DOTENV_PUBLIC_KEY="abc"\nSECRET="encrypted:xyz"\n', encoding="utf-8")
        (service_dir / ".env.keys").write_text(
            "DOTENV_PRIVATE_KEY_PRODUCTION=key\n", encoding="utf-8"
        )

        monkeypatch.chdir(tmp_path)
        mapping = ServiceMapping(
            secret_name="test-key",
            folder_path=Path("services/api"),
            environment="production",
        )

        monkeypatch.setattr("envdrift.sync.engine.shutil.which", lambda _: "/usr/bin/dotenvx")

        def fake_run(cmd, **kwargs):
            target = Path(kwargs["cwd"]) / cmd[-1]
            returncode = 0 if target.exists() else 1
            return subprocess.CompletedProcess(cmd, returncode)

        monkeypatch.setattr("envdrift.sync.engine.subprocess.run", fake_run)

        engine = SyncEngine(
            config=SyncConfig(mappings=[mapping]), vault_client=mock_vault_client, mode=SyncMode()
        )

        assert engine._test_decryption(mapping) == DecryptionTestResult.PASSED

    def test_decryption_test_fails_on_subprocess_error(
        self, mock_vault_client: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A failing dotenvx decrypt returns FAILED with the live file untouched."""
        mapping = ServiceMapping(
            secret_name="test-key", folder_path=tmp_path, environment="production"
        )
        env_file = tmp_path / ".env.production"
        env_file.write_text('DOTENV_PUBLIC_KEY="abc"\nSECRET="encrypted:xyz"\n', encoding="utf-8")
        original = env_file.read_bytes()

        def fake_run(cmd, **kwargs):
            """Simulate a dotenvx decrypt failure (wrong key)."""
            return subprocess.CompletedProcess(cmd, 1)

        monkeypatch.setattr("envdrift.sync.engine.shutil.which", lambda _: "/usr/bin/dotenvx")
        monkeypatch.setattr("envdrift.sync.engine.subprocess.run", fake_run)

        engine = SyncEngine(
            config=SyncConfig(mappings=[mapping]), vault_client=mock_vault_client, mode=SyncMode()
        )
        result = engine._test_decryption(mapping)

        assert result == DecryptionTestResult.FAILED
        # The live file was never part of the test run: byte-identical, no backup.
        assert env_file.read_bytes() == original
        assert not env_file.with_suffix(".backup_decryption_test").exists()

    def test_decryption_test_timeout_returns_failed_file_untouched(
        self, mock_vault_client: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Timeouts are FAILED; the live file is untouched (no restore needed)."""
        mapping = ServiceMapping(
            secret_name="test-key", folder_path=tmp_path, environment="production"
        )
        env_file = tmp_path / ".env.production"
        original = 'DOTENV_PUBLIC_KEY="abc"\nSECRET="encrypted:xyz"\n'
        env_file.write_text(original, encoding="utf-8")

        def fake_run(cmd, **kwargs):
            """Simulate dotenvx hanging until the timeout fires."""
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=30)

        monkeypatch.setattr("envdrift.sync.engine.shutil.which", lambda _: "/usr/bin/dotenvx")
        monkeypatch.setattr("envdrift.sync.engine.subprocess.run", fake_run)

        engine = SyncEngine(
            config=SyncConfig(mappings=[mapping]), vault_client=mock_vault_client, mode=SyncMode()
        )
        result = engine._test_decryption(mapping)

        assert result == DecryptionTestResult.FAILED
        assert env_file.read_text(encoding="utf-8") == original

    def test_decryption_test_copy_failure_returns_failed(
        self, mock_vault_client: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A failed temp-dir copy is FAILED, and dotenvx is never invoked."""
        mapping = ServiceMapping(
            secret_name="test-key", folder_path=tmp_path, environment="production"
        )
        env_file = tmp_path / ".env.production"
        original = 'DOTENV_PUBLIC_KEY="abc"\nSECRET="encrypted:xyz"\n'
        env_file.write_text(original, encoding="utf-8")

        monkeypatch.setattr("envdrift.sync.engine.shutil.which", lambda _: "/usr/bin/dotenvx")

        def failing_copy(src, dst, *args, **kwargs):
            raise PermissionError(f"cannot copy to: {dst}")

        monkeypatch.setattr("envdrift.sync.engine.shutil.copy2", failing_copy)

        def unreachable_run(*args, **kwargs):
            raise AssertionError("subprocess.run must not run after a failed copy")

        monkeypatch.setattr("envdrift.sync.engine.subprocess.run", unreachable_run)

        engine = SyncEngine(
            config=SyncConfig(mappings=[mapping]), vault_client=mock_vault_client, mode=SyncMode()
        )

        result = engine._test_decryption(mapping)

        assert result == DecryptionTestResult.FAILED
        assert env_file.read_text(encoding="utf-8") == original

    def test_decryption_test_scrubs_stray_private_keys_from_env(
        self, mock_vault_client: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Stray DOTENV_PRIVATE_KEY*/DOTENV_KEY shell vars must not leak in (#473).

        The check verifies the SYNCED keys file; a correct key exported in the
        parent shell must not turn a broken .env.keys into a false PASS.
        """
        mapping = ServiceMapping(
            secret_name="test-key", folder_path=tmp_path, environment="production"
        )
        env_file = tmp_path / ".env.production"
        env_file.write_text('DOTENV_PUBLIC_KEY="abc"\nSECRET="encrypted:xyz"\n', encoding="utf-8")

        monkeypatch.setenv("DOTENV_PRIVATE_KEY_PRODUCTION", "stray-shell-key")
        monkeypatch.setenv("DOTENV_KEY", "stray-dotenv-key")
        monkeypatch.setattr("envdrift.sync.engine.shutil.which", lambda _: "/usr/bin/dotenvx")

        captured_env: dict[str, str] = {}

        def fake_run(cmd, **kwargs):
            captured_env.update(kwargs["env"])
            return subprocess.CompletedProcess(cmd, 0)

        monkeypatch.setattr("envdrift.sync.engine.subprocess.run", fake_run)

        engine = SyncEngine(
            config=SyncConfig(mappings=[mapping]), vault_client=mock_vault_client, mode=SyncMode()
        )

        assert engine._test_decryption(mapping) == DecryptionTestResult.PASSED
        assert "DOTENV_PRIVATE_KEY_PRODUCTION" not in captured_env
        assert "DOTENV_KEY" not in captured_env

    def test_decryption_test_copies_custom_keys_filename_as_env_keys(
        self, mock_vault_client: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A custom env_keys_filename is staged as `.env.keys` so dotenvx finds it."""
        mapping = ServiceMapping(
            secret_name="test-key", folder_path=tmp_path, environment="production"
        )
        env_file = tmp_path / ".env.production"
        env_file.write_text('DOTENV_PUBLIC_KEY="abc"\nSECRET="encrypted:xyz"\n', encoding="utf-8")
        (tmp_path / "custom.keys").write_text(
            "DOTENV_PRIVATE_KEY_PRODUCTION=key\n", encoding="utf-8"
        )

        monkeypatch.setattr("envdrift.sync.engine.shutil.which", lambda _: "/usr/bin/dotenvx")

        staged: dict[str, bool] = {}

        def fake_run(cmd, **kwargs):
            staged["env_keys_present"] = (Path(kwargs["cwd"]) / ".env.keys").exists()
            return subprocess.CompletedProcess(cmd, 0)

        monkeypatch.setattr("envdrift.sync.engine.subprocess.run", fake_run)

        engine = SyncEngine(
            config=SyncConfig(mappings=[mapping], env_keys_filename="custom.keys"),
            vault_client=mock_vault_client,
            mode=SyncMode(),
        )

        assert engine._test_decryption(mapping) == DecryptionTestResult.PASSED
        assert staged["env_keys_present"] is True

    def test_decryption_test_fnf_returns_skipped(
        self, mock_vault_client: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """dotenvx vanishing between which() and run() is a SKIP; file untouched."""
        mapping = ServiceMapping(
            secret_name="test-key", folder_path=tmp_path, environment="production"
        )
        env_file = tmp_path / ".env.production"
        original = 'DOTENV_PUBLIC_KEY="abc"\nSECRET="encrypted:xyz"\n'
        env_file.write_text(original, encoding="utf-8")

        monkeypatch.setattr("envdrift.sync.engine.shutil.which", lambda _: "/usr/bin/dotenvx")

        def raise_fnf(*_a: object, **_k: object) -> subprocess.CompletedProcess[str]:
            raise FileNotFoundError(2, "No such file or directory: 'dotenvx'")

        monkeypatch.setattr("envdrift.sync.engine.subprocess.run", raise_fnf)

        engine = SyncEngine(
            config=SyncConfig(mappings=[mapping]), vault_client=mock_vault_client, mode=SyncMode()
        )
        result = engine._test_decryption(mapping)

        assert result == DecryptionTestResult.SKIPPED
        assert env_file.read_text(encoding="utf-8") == original

    def test_decryption_test_non_utf8_file_returns_failed(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """A non-UTF-8 env file yields FAILED, never an uncaught traceback (#413).

        Regression for #413: the ``resolve_mapping_env_file()`` /
        ``target_file.read_text()`` preamble ran *outside* the method's try/except.
        A genuinely non-UTF-8 env file (e.g. one with stray ``0xff 0xfe`` bytes)
        made ``read_text()`` raise ``UnicodeDecodeError``, which escaped
        ``_test_decryption`` and crashed the whole ``sync --check-decryption`` run
        with a traceback. The read is now guarded and returns FAILED.
        """
        mapping = ServiceMapping(
            secret_name="test-key", folder_path=tmp_path, environment="production"
        )
        env_file = tmp_path / ".env.production"
        # Real undecodable bytes: a plausible "encrypted" value with raw 0xff 0xfe
        # that is not valid UTF-8 — write_bytes so no encoding step sanitizes it.
        env_file.write_bytes(b"FOO=encrypted:abc\xff\xfe\n")

        engine = SyncEngine(
            config=SyncConfig(mappings=[mapping]),
            vault_client=mock_vault_client,
            mode=SyncMode(check_decryption=True),
        )

        # Must NOT raise UnicodeDecodeError; must return FAILED.
        result = engine._test_decryption(mapping)

        assert result == DecryptionTestResult.FAILED

    def test_sync_all_non_utf8_file_does_not_crash(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """sync_all with check_decryption survives a non-UTF-8 env file (#413).

        End-to-end guard: the full ``sync_all`` path (the real call site at
        engine.py invoking ``_test_decryption``) must record FAILED for the
        service rather than propagating ``UnicodeDecodeError``.
        """
        mock_vault_client.get_secret.return_value = SecretValue(name="test-key", value="secret123")

        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        (service_dir / ".env.production").write_bytes(b"FOO=encrypted:abc\xff\xfe\n")

        config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="test-key",
                    folder_path=service_dir,
                    environment="production",
                ),
            ],
        )

        engine = SyncEngine(
            config=config,
            vault_client=mock_vault_client,
            mode=SyncMode(check_decryption=True),
        )

        # Must complete without raising.
        result = engine.sync_all()

        assert result.services[0].decryption_result == DecryptionTestResult.FAILED


class TestSyncEngineFetchVaultSecret:
    """Tests for vault secret fetching."""

    def test_strips_key_prefix_from_value(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """Test that KEY= prefix is stripped from vault value."""
        # Some vaults store full line: KEY=value
        mock_vault_client.get_secret.return_value = SecretValue(
            name="test-key",
            value="DOTENV_PRIVATE_KEY_PRODUCTION=actual_secret",
        )

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

        engine = SyncEngine(config=config, vault_client=mock_vault_client)
        engine.sync_all()

        content = (service_dir / ".env.keys").read_text()
        # Should not have double KEY= prefix
        assert "DOTENV_PRIVATE_KEY_PRODUCTION=actual_secret" in content
        assert "DOTENV_PRIVATE_KEY_PRODUCTION=DOTENV_PRIVATE_KEY" not in content

    def test_rejects_cross_environment_key_prefix(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """#348: a vault value labeled for one environment must NOT be relabeled.

        A ``DOTENV_PRIVATE_KEY_STAGING=...`` value fetched for a ``production``
        mapping previously had its prefix stripped and was re-written as
        ``DOTENV_PRIVATE_KEY_PRODUCTION=...`` — silently installing the staging
        key as the production key. The engine must error instead.
        """
        # Vault stores a key labeled STAGING, mapping targets production.
        mock_vault_client.get_secret.return_value = SecretValue(
            name="test-key",
            value="DOTENV_PRIVATE_KEY_STAGING=actual_secret",
        )

        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        (service_dir / ".env.production").write_text("DB_URL=encrypted:xyz\n")

        config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="test-key",
                    folder_path=service_dir,
                    environment="production",
                ),
            ],
        )

        engine = SyncEngine(config=config, vault_client=mock_vault_client)
        result = engine.sync_all()

        # Mismatch -> ERROR, and NOTHING is written under the production label.
        assert result.services[0].action == SyncAction.ERROR
        assert result.services[0].error is not None
        assert "STAGING" in result.services[0].error
        assert "PRODUCTION" in result.services[0].error
        assert not (service_dir / ".env.keys").exists()

    def test_matching_environment_key_prefix_is_stripped(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """#348: when the suffix matches the target env, strip and write normally."""
        mock_vault_client.get_secret.return_value = SecretValue(
            name="test-key",
            value="DOTENV_PRIVATE_KEY_PRODUCTION=actual_secret",
        )

        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        (service_dir / ".env.production").write_text("DB_URL=encrypted:xyz\n")

        config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="test-key",
                    folder_path=service_dir,
                    environment="production",
                ),
            ],
        )

        engine = SyncEngine(config=config, vault_client=mock_vault_client)
        result = engine.sync_all()

        assert result.services[0].action == SyncAction.CREATED
        content = (service_dir / ".env.keys").read_text()
        assert "DOTENV_PRIVATE_KEY_PRODUCTION=actual_secret" in content
        assert "DOTENV_PRIVATE_KEY_PRODUCTION=DOTENV_PRIVATE_KEY" not in content

    def test_bare_value_without_prefix_is_unaffected(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """#348: a bare value (no DOTENV_PRIVATE_KEY_* prefix) is written as-is."""
        mock_vault_client.get_secret.return_value = SecretValue(
            name="test-key",
            value="actual_secret",
        )

        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        (service_dir / ".env.production").write_text("DB_URL=encrypted:xyz\n")

        config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="test-key",
                    folder_path=service_dir,
                    environment="production",
                ),
            ],
        )

        engine = SyncEngine(config=config, vault_client=mock_vault_client)
        result = engine.sync_all()

        assert result.services[0].action == SyncAction.CREATED
        content = (service_dir / ".env.keys").read_text()
        assert "DOTENV_PRIVATE_KEY_PRODUCTION=actual_secret" in content

    def test_strips_lowercase_key_prefix_from_value(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """Test that lowercase DOTENV_PRIVATE_KEY_*= prefix is stripped from vault value."""
        # Vault stores key with lowercase environment name like "soak", "local", "prod"
        mock_vault_client.get_secret.return_value = SecretValue(
            name="test-key",
            value="DOTENV_PRIVATE_KEY_soak=actual_secret",
        )

        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        (service_dir / ".env.soak").write_text("DB_URL=encrypted:xyz\n")

        config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="test-key",
                    folder_path=service_dir,
                    environment="soak",
                ),
            ],
        )

        engine = SyncEngine(config=config, vault_client=mock_vault_client)
        engine.sync_all()

        content = (service_dir / ".env.keys").read_text()
        # Should strip the soak prefix and write with SOAK key (uppercase in .env.keys)
        assert "DOTENV_PRIVATE_KEY_SOAK=actual_secret" in content
        assert "DOTENV_PRIVATE_KEY_soak=" not in content

    def test_strips_mixed_case_key_prefix_with_digits(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """Test that mixed case with digits DOTENV_PRIVATE_KEY_*= prefix is stripped."""
        # Vault stores key with mixed case and digits
        mock_vault_client.get_secret.return_value = SecretValue(
            name="test-key",
            value="DOTENV_PRIVATE_KEY_Prod2=actual_secret",
        )

        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        (service_dir / ".env.prod2").write_text("DB_URL=encrypted:xyz\n")

        config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="test-key",
                    folder_path=service_dir,
                    environment="prod2",
                ),
            ],
        )

        engine = SyncEngine(config=config, vault_client=mock_vault_client)
        engine.sync_all()

        content = (service_dir / ".env.keys").read_text()
        # Should strip the Prod2 prefix and write with PROD2 key
        assert "DOTENV_PRIVATE_KEY_PROD2=actual_secret" in content
        assert "DOTENV_PRIVATE_KEY_Prod2=" not in content

    def test_quoted_vault_value_converges_with_unquoted_local(self, tmp_path: Path) -> None:
        """#356: vault stores value quoted, local stores it unquoted -> they converge.

        read_key strips quotes; before the fix _fetch_vault_secret did not, so the
        comparison was a permanent false mismatch. After the fix: SKIPPED (values match).
        """
        secret = "abc" + "123" + "def"  # fake secret via concatenation
        client = _StoredVaultClient({"test-key": f'"{secret}"'})  # quoted in vault

        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        (service_dir / ".env.production").write_text("DB_URL=encrypted:xyz\n")
        # Local stores it unquoted (as read_key would normalize it).
        (service_dir / ".env.keys").write_text(f"DOTENV_PRIVATE_KEY_PRODUCTION={secret}\n")

        config = SyncConfig(
            mappings=[ServiceMapping(secret_name="test-key", folder_path=service_dir)]
        )
        engine = SyncEngine(config=config, vault_client=client)
        result = engine.sync_all()

        assert result.services[0].action == SyncAction.SKIPPED
        # And the file is not rewritten with quotes.
        assert (service_dir / ".env.keys").read_text().count(secret) == 1

    def test_fetch_vault_secret_strips_surrounding_quotes(self, tmp_path: Path) -> None:
        """#356 (direct): _fetch_vault_secret normalizes quotes like read_key does."""
        secret = "xyz" + "789"
        client = _StoredVaultClient({"test-key": f'"{secret}"'})
        mapping = ServiceMapping(secret_name="test-key", folder_path=tmp_path)
        engine = SyncEngine(config=SyncConfig(mappings=[mapping]), vault_client=client)

        assert engine._fetch_vault_secret(mapping, "production") == secret

    def test_fetch_vault_secret_quoted_full_line_strips_prefix(self, tmp_path: Path) -> None:
        """#356 review: a quoted full `KEY=value` line strips quotes BEFORE the
        DOTENV_PRIVATE_KEY_*= prefix, so the prefix doesn't leak; whitespace too.

        The prefix suffix (PROD) matches the effective environment, so it strips.
        """
        secret = "abc" + "123"
        client = _StoredVaultClient({"k": f'  "DOTENV_PRIVATE_KEY_PROD={secret}"  '})
        mapping = ServiceMapping(secret_name="k", folder_path=tmp_path)
        engine = SyncEngine(config=SyncConfig(mappings=[mapping]), vault_client=client)

        assert engine._fetch_vault_secret(mapping, "prod") == secret

    def test_fetch_vault_secret_cross_environment_raises(self, tmp_path: Path) -> None:
        """#348 (direct): a prefix labeled for a different env raises VaultError."""
        secret = "abc" + "123"
        client = _StoredVaultClient({"k": f"DOTENV_PRIVATE_KEY_STAGING={secret}"})
        mapping = ServiceMapping(secret_name="k", folder_path=tmp_path)
        engine = SyncEngine(config=SyncConfig(mappings=[mapping]), vault_client=client)

        with pytest.raises(VaultError, match=r"STAGING.*PRODUCTION"):
            engine._fetch_vault_secret(mapping, "production")


class TestSyncResult:
    """Tests for SyncResult aggregation."""

    def test_exit_code_success(self, mock_vault_client: MagicMock, tmp_path: Path) -> None:
        """Test exit code is 0 on success."""
        mock_vault_client.get_secret.return_value = SecretValue(name="key", value="secret")

        service_dir = tmp_path / "service"
        service_dir.mkdir()
        (service_dir / ".env.production").write_text("DB_URL=encrypted:xyz\n")

        config = SyncConfig(
            mappings=[
                ServiceMapping(secret_name="key", folder_path=service_dir),
            ],
        )

        engine = SyncEngine(config=config, vault_client=mock_vault_client)
        result = engine.sync_all()

        assert result.exit_code == 0
        assert not result.has_errors

    def test_exit_code_error(self, mock_vault_client: MagicMock, tmp_path: Path) -> None:
        """Test exit code is 1 on error."""
        mock_vault_client.get_secret.side_effect = SecretNotFoundError("Not found")

        service_dir = tmp_path / "service"
        service_dir.mkdir()
        (service_dir / ".env.production").write_text("DB_URL=encrypted:xyz\n")

        config = SyncConfig(
            mappings=[
                ServiceMapping(secret_name="key", folder_path=service_dir),
            ],
        )

        engine = SyncEngine(config=config, vault_client=mock_vault_client)
        result = engine.sync_all()

        assert result.exit_code == 1
        assert result.has_errors


class TestSyncEngineEphemeralKeys:
    """Tests for ephemeral keys mode."""

    def test_ephemeral_mode_fetches_key_but_does_not_write_file(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """Test ephemeral mode returns key but doesn't create .env.keys file."""
        mock_vault_client.get_secret.return_value = SecretValue(
            name="test-key", value="ephemeral_secret_123"
        )

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
            ephemeral_keys=True,  # Central ephemeral mode
        )

        engine = SyncEngine(config=config, vault_client=mock_vault_client)
        result = engine.sync_all()

        assert result.services[0].action == SyncAction.EPHEMERAL
        assert result.services[0].vault_key_value == "ephemeral_secret_123"
        assert not (service_dir / ".env.keys").exists()

    def test_ephemeral_mode_per_mapping_override(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """Test per-mapping ephemeral override takes precedence over central."""
        mock_vault_client.get_secret.return_value = SecretValue(
            name="test-key", value="secret_value"
        )

        service_dir = tmp_path / "service1"
        service_dir.mkdir()
        (service_dir / ".env.production").write_text("DB_URL=encrypted:xyz\n")

        config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="test-key",
                    folder_path=service_dir,
                    ephemeral_keys=True,  # Override: enable ephemeral for this mapping
                ),
            ],
            ephemeral_keys=False,  # Central: disabled
        )

        engine = SyncEngine(config=config, vault_client=mock_vault_client)
        result = engine.sync_all()

        # Per-mapping ephemeral=True should override central False
        assert result.services[0].action == SyncAction.EPHEMERAL
        assert not (service_dir / ".env.keys").exists()

    def test_ephemeral_count_in_result(self, mock_vault_client: MagicMock, tmp_path: Path) -> None:
        """Test ephemeral_count property in SyncResult."""
        mock_vault_client.get_secret.return_value = SecretValue(name="test-key", value="secret")

        for i in range(3):
            service_dir = tmp_path / f"service{i}"
            service_dir.mkdir()
            (service_dir / ".env.production").write_text("DB_URL=encrypted:xyz\n")

        config = SyncConfig(
            mappings=[
                ServiceMapping(secret_name="key1", folder_path=tmp_path / "service0"),
                ServiceMapping(secret_name="key2", folder_path=tmp_path / "service1"),
                ServiceMapping(secret_name="key3", folder_path=tmp_path / "service2"),
            ],
            ephemeral_keys=True,
        )

        engine = SyncEngine(config=config, vault_client=mock_vault_client)
        result = engine.sync_all()

        assert result.ephemeral_count == 3
        assert result.created_count == 0

    def test_ephemeral_mode_skips_decryption_test(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """Test that decryption test is skipped in ephemeral mode."""
        mock_vault_client.get_secret.return_value = SecretValue(
            name="test-key", value="ephemeral_secret"
        )

        service_dir = tmp_path / "service"
        service_dir.mkdir()
        (service_dir / ".env.production").write_text(
            'DOTENV_PUBLIC_KEY="xyz"\nSECRET="encrypted:abc"\n'
        )

        config = SyncConfig(
            mappings=[
                ServiceMapping(secret_name="test-key", folder_path=service_dir),
            ],
            ephemeral_keys=True,
        )

        engine = SyncEngine(
            config=config,
            vault_client=mock_vault_client,
            mode=SyncMode(check_decryption=True),  # Enable decryption test
        )
        result = engine.sync_all()

        # Should be ephemeral action with no decryption result (skipped)
        assert result.services[0].action == SyncAction.EPHEMERAL
        assert result.services[0].decryption_result is None


class TestSyncEngineSchemaValidation:
    """Schema validation behavior tests."""

    def test_validate_schema_uses_detected_env_file(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """Validation should use detected .env.* files when expected env is missing."""
        service_dir = tmp_path / "service"
        service_dir.mkdir()
        (service_dir / ".env.staging").write_text("NAME=envdrift\n")

        module_path = service_dir / "service_settings.py"
        module_path.write_text(
            dedent(
                """
                from pydantic_settings import BaseSettings

                class Settings(BaseSettings):
                    NAME: str
                """
            ).lstrip()
        )

        mapping = ServiceMapping(secret_name="test-key", folder_path=service_dir)
        config = SyncConfig(mappings=[mapping])

        engine = SyncEngine(
            config=config,
            vault_client=mock_vault_client,
            mode=SyncMode(schema_path="service_settings:Settings", service_dir=service_dir),
        )

        assert engine._validate_schema(mapping) is True

    def test_validate_schema_returns_true_without_env_file(
        self, mock_vault_client: MagicMock, tmp_path: Path
    ) -> None:
        """Validation should skip when no env file exists."""
        service_dir = tmp_path / "service"
        service_dir.mkdir()

        mapping = ServiceMapping(secret_name="test-key", folder_path=service_dir)
        config = SyncConfig(mappings=[mapping])

        engine = SyncEngine(
            config=config,
            vault_client=mock_vault_client,
            mode=SyncMode(schema_path="service_settings:Settings"),
        )

        assert engine._validate_schema(mapping) is True


class TestNormalizeVaultKeyValue:
    """Tests for the shared vault-value normalizer used by the engine and
    ``lock --verify-vault`` so they parse identically (#413)."""

    def test_bare_value_unchanged(self) -> None:
        assert normalize_vault_key_value("abc123") == ("abc123", None)

    def test_strips_surrounding_whitespace(self) -> None:
        assert normalize_vault_key_value("  abc123  ") == ("abc123", None)

    def test_strips_double_quotes(self) -> None:
        assert normalize_vault_key_value('"abc123"') == ("abc123", None)

    def test_strips_single_quotes(self) -> None:
        assert normalize_vault_key_value("'abc123'") == ("abc123", None)

    def test_strips_prefix_and_returns_suffix(self) -> None:
        assert normalize_vault_key_value("DOTENV_PRIVATE_KEY_PROD=abc123") == ("abc123", "PROD")

    def test_quotes_come_off_before_prefix(self) -> None:
        # A quoted full ``KEY=value`` line still has its prefix stripped because
        # quotes are removed first.
        assert normalize_vault_key_value('  "DOTENV_PRIVATE_KEY_PROD=abc123"  ') == (
            "abc123",
            "PROD",
        )

    def test_value_without_prefix_keeps_embedded_equals(self) -> None:
        # No DOTENV_PRIVATE_KEY_ prefix -> the whole (dequoted) value is the key
        # material, even if it contains '='.
        assert normalize_vault_key_value("opaque=keymaterial") == ("opaque=keymaterial", None)

    def test_strips_inner_double_quotes_after_prefix(self) -> None:
        # The value after the prefix is itself dequoted (matches read_key).
        assert normalize_vault_key_value('DOTENV_PRIVATE_KEY_PROD="abc123"') == ("abc123", "PROD")

    def test_strips_inner_single_quotes_after_prefix(self) -> None:
        assert normalize_vault_key_value("DOTENV_PRIVATE_KEY_PROD='abc123'") == ("abc123", "PROD")

    def test_strips_inner_whitespace_after_prefix(self) -> None:
        assert normalize_vault_key_value("DOTENV_PRIVATE_KEY_PROD=  abc123  ") == ("abc123", "PROD")

    def test_converges_with_read_key_for_inner_quoted_prefixed_value(self, tmp_path: Path) -> None:
        """normalize_vault_key_value matches read_key for an inner-quoted prefixed
        value, so verify-vault and the engine don't false-mismatch (#413 review)."""
        from envdrift.sync.operations import EnvKeysFile

        vault_value = 'DOTENV_PRIVATE_KEY_PRODUCTION="abc123"'
        env_keys = tmp_path / ".env.keys"
        env_keys.write_text(f"{vault_value}\n")
        local = EnvKeysFile(env_keys).read_key("DOTENV_PRIVATE_KEY_PRODUCTION")

        vault_key, suffix = normalize_vault_key_value(vault_value)
        assert vault_key == local == "abc123"
        assert suffix == "PRODUCTION"
