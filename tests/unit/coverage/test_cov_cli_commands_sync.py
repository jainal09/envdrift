"""Coverage-focused unit tests for envdrift.cli_commands.sync.

These tests exercise error branches, profile filtering, partial-encryption
handling and the verify/sync key paths in the ``pull`` and ``lock`` commands,
plus the config-loading/validation helpers in ``load_sync_config_and_client``.

External processes (vault clients, encryption backends, git hooks) are mocked
so the suite is hermetic and fast.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import typer
from typer.testing import CliRunner

from envdrift.cli import app
from envdrift.encryption import EncryptionProvider
from envdrift.encryption.base import EncryptionBackendError, EncryptionResult
from envdrift.sync.config import ServiceMapping, SyncConfig
from envdrift.sync.result import ServiceSyncResult, SyncAction, SyncResult
from envdrift.vault.base import SecretNotFoundError, SecretValue, VaultError
from tests.helpers import DummyEncryptionBackend

runner = CliRunner()


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _sync_config(mappings: list[ServiceMapping]) -> SyncConfig:
    return SyncConfig(mappings=mappings, env_keys_filename=".env.keys", max_workers=1)


def _empty_sync_result() -> SyncResult:
    return SyncResult(services=[])


def _patch_engine(monkeypatch, sync_result: SyncResult) -> MagicMock:
    """Patch SyncEngine so .sync_all() returns the provided result."""
    engine = MagicMock()
    engine.sync_all.return_value = sync_result
    factory = MagicMock(return_value=engine)
    monkeypatch.setattr("envdrift.sync.engine.SyncEngine", factory)
    return engine


@pytest.fixture
def no_git_hook(monkeypatch):
    """ensure_git_hook_setup returns no errors."""
    monkeypatch.setattr(
        "envdrift.integrations.hook_check.ensure_git_hook_setup",
        lambda **kwargs: [],
    )


@pytest.fixture
def loaded_config(monkeypatch):
    """Factory: patch load_sync_config_and_client to return given config + client."""

    def _apply(sync_config: SyncConfig, client: MagicMock | None = None):
        client = client or MagicMock()
        monkeypatch.setattr(
            "envdrift.cli_commands.sync.load_sync_config_and_client",
            lambda **kwargs: (sync_config, client, "azure", "https://v", None, None),
        )
        return client

    return _apply


# --------------------------------------------------------------------------
# load_sync_config_and_client - validation / error branches
# --------------------------------------------------------------------------
class TestLoadSyncConfigAndClient:
    def test_missing_config_file_exits(self, tmp_path):
        from envdrift.cli_commands.sync import load_sync_config_and_client

        missing = tmp_path / "nope.txt"
        with pytest.raises(typer.Exit):
            load_sync_config_and_client(
                config_file=missing,
                provider="azure",
                vault_url="https://v",
                region=None,
                project_id=None,
            )

    def test_no_sync_config_found_exits(self, monkeypatch, tmp_path):
        from envdrift.cli_commands.sync import load_sync_config_and_client

        # No config discovered at all -> "No sync configuration found"
        monkeypatch.setattr("envdrift.config.find_config", lambda: None)
        with pytest.raises(typer.Exit):
            load_sync_config_and_client(
                config_file=None,
                provider="azure",
                vault_url="https://v",
                region=None,
                project_id=None,
            )

    def test_azure_without_vault_url_exits(self, tmp_path):
        from envdrift.cli_commands.sync import load_sync_config_and_client

        cfg = tmp_path / "sync.toml"
        cfg.write_text(
            '[vault.sync]\n[[vault.sync.mappings]]\nsecret_name="s"\nfolder_path="svc"\n'
        )
        with pytest.raises(typer.Exit):
            load_sync_config_and_client(
                config_file=cfg,
                provider="azure",
                vault_url=None,
                region=None,
                project_id=None,
            )

    def test_gcp_without_project_id_exits(self, tmp_path):
        from envdrift.cli_commands.sync import load_sync_config_and_client

        cfg = tmp_path / "sync.toml"
        cfg.write_text(
            '[vault.sync]\n[[vault.sync.mappings]]\nsecret_name="s"\nfolder_path="svc"\n'
        )
        with pytest.raises(typer.Exit):
            load_sync_config_and_client(
                config_file=cfg,
                provider="gcp",
                vault_url=None,
                region=None,
                project_id=None,
            )

    def test_import_error_from_get_client_exits(self, tmp_path):
        from envdrift.cli_commands.sync import load_sync_config_and_client

        cfg = tmp_path / "sync.toml"
        cfg.write_text(
            '[vault.sync]\n[[vault.sync.mappings]]\nsecret_name="s"\nfolder_path="svc"\n'
        )
        with patch(
            "envdrift.vault.get_vault_client",
            side_effect=ImportError("missing azure extras"),
        ):
            with pytest.raises(typer.Exit):
                load_sync_config_and_client(
                    config_file=cfg,
                    provider="azure",
                    vault_url="https://v",
                    region=None,
                    project_id=None,
                )

    def test_value_error_from_get_client_exits(self, tmp_path):
        from envdrift.cli_commands.sync import load_sync_config_and_client

        cfg = tmp_path / "sync.toml"
        cfg.write_text(
            '[vault.sync]\n[[vault.sync.mappings]]\nsecret_name="s"\nfolder_path="svc"\n'
        )
        with patch(
            "envdrift.vault.get_vault_client",
            side_effect=ValueError("bad provider value"),
        ):
            with pytest.raises(typer.Exit):
                load_sync_config_and_client(
                    config_file=cfg,
                    provider="hashicorp",
                    vault_url="https://v",
                    region=None,
                    project_id=None,
                )

    def test_aws_default_region_passed(self, tmp_path):
        from envdrift.cli_commands.sync import load_sync_config_and_client

        cfg = tmp_path / "sync.toml"
        cfg.write_text(
            '[vault.sync]\n[[vault.sync.mappings]]\nsecret_name="s"\nfolder_path="svc"\n'
        )
        captured = {}

        def fake_get_client(provider, **kwargs):
            captured["provider"] = provider
            captured["kwargs"] = kwargs
            return MagicMock()

        with patch("envdrift.vault.get_vault_client", side_effect=fake_get_client):
            sync_config, _client, prov, *_ = load_sync_config_and_client(
                config_file=cfg,
                provider="aws",
                vault_url=None,
                region=None,
                project_id=None,
            )
        assert prov == "aws"
        assert captured["kwargs"]["region"] == "us-east-1"
        assert sync_config.mappings


# --------------------------------------------------------------------------
# _load_partial_encryption_paths / _find_config_path
# --------------------------------------------------------------------------
class TestPartialEncryptionPaths:
    def test_find_config_path_explicit_toml(self, tmp_path):
        from envdrift.cli_commands.sync import _find_config_path

        cfg = tmp_path / "envdrift.toml"
        cfg.write_text("[vault]\n")
        assert _find_config_path(cfg) == cfg

    def test_find_config_path_non_toml_returns_none(self, tmp_path):
        from envdrift.cli_commands.sync import _find_config_path

        pair = tmp_path / "pair.txt"
        pair.write_text("a=b\n")
        assert _find_config_path(pair) is None

    def test_paths_empty_when_no_config(self, monkeypatch):
        from envdrift.cli_commands.sync import _load_partial_encryption_paths

        monkeypatch.setattr("envdrift.cli_commands.sync._find_config_path", lambda c: None)
        assert _load_partial_encryption_paths(None) == (set(), set(), set())

    def test_paths_collected_for_enabled_partial(self, tmp_path):
        from envdrift.cli_commands.sync import _load_partial_encryption_paths

        cfg = tmp_path / "envdrift.toml"
        # TOML literal strings (single quotes) so Windows backslash paths are not
        # parsed as escapes (C:\Users -> invalid \U).
        clear_file = tmp_path / ".env.clear"
        secret_file = tmp_path / ".env.secret"
        combined_file = tmp_path / ".env"
        cfg.write_text(
            "[partial_encryption]\nenabled = true\n"
            "[[partial_encryption.environments]]\n"
            'name = "prod"\n'
            f"clear_file = '{clear_file}'\n"
            f"secret_file = '{secret_file}'\n"
            f"combined_file = '{combined_file}'\n"
        )
        clear, secret, combined = _load_partial_encryption_paths(cfg)
        assert (tmp_path / ".env.clear").resolve() in clear
        assert (tmp_path / ".env.secret").resolve() in secret
        assert (tmp_path / ".env").resolve() in combined

    def test_secrets_only_environment_skipped(self, tmp_path):
        from envdrift.cli_commands.sync import _load_partial_encryption_paths

        cfg = tmp_path / "envdrift.toml"
        # TOML literal string (single quotes) so a Windows backslash path is not
        # parsed as an escape (C:\Users -> invalid \U).
        secrets_dir = tmp_path / "secrets"
        cfg.write_text(
            "[partial_encryption]\nenabled = true\n"
            "[[partial_encryption.environments]]\n"
            'name = "prod"\n'
            "secrets_only = true\n"
            f"secrets_dir = '{secrets_dir}'\n"
        )
        clear, secret, combined = _load_partial_encryption_paths(cfg)
        # secrets-only env contributes nothing
        assert clear == set()
        assert secret == set()
        assert combined == set()


# --------------------------------------------------------------------------
# pull command
# --------------------------------------------------------------------------
class TestPullCommand:
    def test_pull_no_mappings_for_profile_exits(self, monkeypatch, loaded_config, no_git_hook):
        cfg = _sync_config([])
        loaded_config(cfg)
        result = runner.invoke(app, ["pull", "--profile", "ghost"])
        assert result.exit_code == 1
        assert "No mappings found for profile 'ghost'" in result.output

    def test_pull_no_nonprofile_mappings_exits(self, monkeypatch, loaded_config, no_git_hook):
        cfg = _sync_config([])
        loaded_config(cfg)
        result = runner.invoke(app, ["pull"])
        assert result.exit_code == 1
        assert "No non-profile mappings found" in result.output

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    def test_pull_skip_sync_decrypts_encrypted_file(
        self, mock_resolve, monkeypatch, tmp_path, loaded_config, no_git_hook
    ):
        backend = DummyEncryptionBackend()
        mock_resolve.return_value = (backend, EncryptionProvider.DOTENVX, None)

        env_file = tmp_path / ".env.production"
        env_file.write_text("#/---BEGIN DOTENV ENCRYPTED---/\nSECRET=encrypted:xyz\n")

        mapping = ServiceMapping(secret_name="s", folder_path=tmp_path, environment="production")
        loaded_config(_sync_config([mapping]))

        result = runner.invoke(app, ["pull", "--skip-sync"])
        assert result.exit_code == 0, result.output
        assert "Step 1: Skipped" in result.output
        assert backend.decrypt_calls == [env_file.resolve()]
        assert "Setup complete" in result.output

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    def test_pull_backend_not_installed_exits(
        self, mock_resolve, tmp_path, loaded_config, no_git_hook
    ):
        mock_resolve.return_value = (
            DummyEncryptionBackend(installed=False),
            EncryptionProvider.DOTENVX,
            None,
        )
        mapping = ServiceMapping(secret_name="s", folder_path=tmp_path, environment="production")
        loaded_config(_sync_config([mapping]))
        result = runner.invoke(app, ["pull", "--skip-sync"])
        assert result.exit_code == 1
        assert "not installed" in result.output.lower()

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    def test_pull_unsupported_backend_value_error_exits(
        self, mock_resolve, tmp_path, loaded_config, no_git_hook
    ):
        mock_resolve.side_effect = ValueError("nope backend")
        mapping = ServiceMapping(secret_name="s", folder_path=tmp_path, environment="production")
        loaded_config(_sync_config([mapping]))
        result = runner.invoke(app, ["pull", "--skip-sync"])
        assert result.exit_code == 1
        assert "Unsupported encryption backend" in result.output

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    def test_pull_skips_not_found_and_not_encrypted(
        self, mock_resolve, tmp_path, loaded_config, no_git_hook
    ):
        backend = DummyEncryptionBackend()
        mock_resolve.return_value = (backend, EncryptionProvider.DOTENVX, None)

        # folder_a: no env file at all -> skipped (not found)
        folder_a = tmp_path / "a"
        folder_a.mkdir()
        # folder_b: plaintext env file -> skipped (not encrypted)
        folder_b = tmp_path / "b"
        folder_b.mkdir()
        (folder_b / ".env.production").write_text("PLAIN=value\n")

        mappings = [
            ServiceMapping(secret_name="a", folder_path=folder_a, environment="production"),
            ServiceMapping(secret_name="b", folder_path=folder_b, environment="production"),
        ]
        loaded_config(_sync_config(mappings))

        result = runner.invoke(app, ["pull", "--skip-sync"])
        assert result.exit_code == 0, result.output
        assert "skipped (not found)" in result.output
        assert "skipped (not encrypted)" in result.output
        assert backend.decrypt_calls == []

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    def test_pull_activates_already_decrypted_profile_file(
        self, mock_resolve, tmp_path, loaded_config, no_git_hook
    ):
        """An already-decrypted profile file is still activated (#413).

        It hits the "skipped (not encrypted)" branch, but activate_to must still
        copy it so `pull --profile` is idempotent — a file committed decrypted or
        decrypted by an earlier run isn't left un-activated.
        """
        backend = DummyEncryptionBackend()
        mock_resolve.return_value = (backend, EncryptionProvider.DOTENVX, None)

        folder = tmp_path / "svc"
        folder.mkdir()
        # Already-decrypted (plaintext) profile env file.
        (folder / ".env.production").write_text("PLAIN=value\n")

        mapping = ServiceMapping(
            secret_name="s",
            folder_path=folder,
            environment="production",
            profile="local",
            activate_to=Path("active.env"),
        )
        loaded_config(_sync_config([mapping]))

        result = runner.invoke(app, ["pull", "--profile", "local", "--skip-sync"])

        assert result.exit_code == 0, result.output
        assert "skipped (not encrypted)" in result.output
        # The already-decrypted file is still activated (idempotent).
        active = folder / "active.env"
        assert active.exists()
        assert active.read_text() == "PLAIN=value\n"
        assert backend.decrypt_calls == []  # never decrypted (already plaintext)

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    def test_pull_already_decrypted_activation_error_is_not_decrypt_error(
        self, mock_resolve, tmp_path, loaded_config, no_git_hook
    ):
        """An activation failure on an already-decrypted file reports an
        activation error, not a misleading "could not be decrypted" (#413)."""
        backend = DummyEncryptionBackend()
        mock_resolve.return_value = (backend, EncryptionProvider.DOTENVX, None)

        folder = tmp_path / "svc"
        folder.mkdir()
        (folder / ".env.production").write_text("PLAIN=value\n")

        mapping = ServiceMapping(
            secret_name="s",
            folder_path=folder,
            environment="production",
            profile="local",
            activate_to=Path("../escape.env"),  # escapes folder -> activation error
        )
        loaded_config(_sync_config([mapping]))

        result = runner.invoke(app, ["pull", "--profile", "local", "--skip-sync"])

        assert result.exit_code == 1, result.output
        # Collapse whitespace so a narrow-width Rich soft-wrap can't split the
        # asserted phrases across lines.
        normalized = " ".join(result.output.lower().split())
        assert "could not be activated" in normalized
        assert "could not be decrypted" not in normalized
        assert backend.decrypt_calls == []  # never decrypted (already plaintext)

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    def test_pull_decrypt_backend_error_exits(
        self, mock_resolve, tmp_path, loaded_config, no_git_hook
    ):
        backend = DummyEncryptionBackend(decrypt_side_effect=EncryptionBackendError("decrypt boom"))
        mock_resolve.return_value = (backend, EncryptionProvider.DOTENVX, None)

        (tmp_path / ".env.production").write_text(
            "#/---BEGIN DOTENV ENCRYPTED---/\nSECRET=encrypted:xyz\n"
        )
        mapping = ServiceMapping(secret_name="s", folder_path=tmp_path, environment="production")
        loaded_config(_sync_config([mapping]))

        result = runner.invoke(app, ["pull", "--skip-sync"])
        assert result.exit_code == 1
        assert "decrypt boom" in result.output
        assert "could not be decrypted" in result.output.lower()

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    def test_pull_sync_step_runs_and_reports(
        self, mock_resolve, monkeypatch, tmp_path, loaded_config, no_git_hook
    ):
        backend = DummyEncryptionBackend()
        mock_resolve.return_value = (backend, EncryptionProvider.DOTENVX, None)

        (tmp_path / ".env.production").write_text(
            "#/---BEGIN DOTENV ENCRYPTED---/\nSECRET=encrypted:xyz\n"
        )
        mapping = ServiceMapping(secret_name="s", folder_path=tmp_path, environment="production")
        loaded_config(_sync_config([mapping]))

        _patch_engine(monkeypatch, _empty_sync_result())

        result = runner.invoke(app, ["pull"])
        assert result.exit_code == 0, result.output
        assert "Step 1:" in result.output
        assert "Syncing keys from vault" in result.output

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    def test_pull_ephemeral_injects_environment_key_name_not_folder_name(
        self, mock_resolve, monkeypatch, tmp_path, loaded_config, no_git_hook
    ):
        """#325: ephemeral pull injects the ENV-derived key name, not the folder name.

        Folder basename ``svc-a`` differs from the mapping environment
        ``production``. The decrypt env override must carry
        ``DOTENV_PRIVATE_KEY_PRODUCTION`` (env-derived), never
        ``DOTENV_PRIVATE_KEY_SVC-A`` (folder-derived).

        This is load-bearing: the ``ServiceSyncResult.folder_path`` is a DISTINCT
        ``Path`` value from the mapping's ``folder_path`` — the mapping uses the
        absolute/resolved dir while the result uses a relative ``Path("svc-a")``
        — so ``result.folder_path != mapping.folder_path`` as raw Paths, yet
        both ``.resolve()`` to the same directory (cwd is ``tmp_path``). The
        pre-fix code's raw ``==`` match therefore FAILS and falls back to the
        folder-name key, while the fix's ``.resolve()``-based lookup still
        matches and injects the environment key. (A same-``Path``-object
        construction passes on pre-fix code, so it would not exercise #325.)
        """
        backend = DummyEncryptionBackend()
        mock_resolve.return_value = (backend, EncryptionProvider.DOTENVX, None)

        # cwd == tmp_path so a relative "svc-a" resolves to tmp_path/"svc-a".
        monkeypatch.chdir(tmp_path)

        svc_abs = (tmp_path / "svc-a").resolve()
        svc_abs.mkdir()
        (svc_abs / ".env.production").write_text(
            "#/---BEGIN DOTENV ENCRYPTED---/\nSECRET=encrypted:xyz\n"
        )

        # Mapping carries the ABSOLUTE, resolved folder path.
        mapping = ServiceMapping(secret_name="s", folder_path=svc_abs, environment="production")
        loaded_config(_sync_config([mapping]))

        # Engine returns an EPHEMERAL result whose folder_path is a DISTINCT
        # Path value (relative) that resolves to the SAME directory. This is the
        # #325 trigger: a result path that is not object/value-equal to the
        # mapping path but points at the same dir.
        svc_rel = Path("svc-a")
        assert svc_rel != mapping.folder_path  # distinct as raw Paths
        assert svc_rel.resolve() == mapping.folder_path.resolve()  # same dir
        ephemeral_result = SyncResult(
            services=[
                ServiceSyncResult(
                    secret_name="s",
                    folder_path=svc_rel,
                    action=SyncAction.EPHEMERAL,
                    message="ephemeral",
                    vault_key_value="the-private-key-value",
                )
            ]
        )
        _patch_engine(monkeypatch, ephemeral_result)

        result = runner.invoke(app, ["pull"])
        assert result.exit_code == 0, result.output
        assert backend.decrypt_calls == [(svc_abs / ".env.production").resolve()]
        injected_env = backend.decrypt_kwargs[0]["env"]
        assert isinstance(injected_env, dict)
        assert injected_env["DOTENV_PRIVATE_KEY_PRODUCTION"] == "the-private-key-value"
        assert "DOTENV_PRIVATE_KEY_SVC-A" not in injected_env

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    def test_pull_ephemeral_falls_back_to_folder_name_when_no_mapping_matches(
        self, mock_resolve, monkeypatch, tmp_path, loaded_config, no_git_hook
    ):
        """#325 defensive fallback: an ephemeral result with no matching mapping
        derives the key name from the folder basename (last-resort path).

        This should not happen in normal CLI flow (every ephemeral result comes
        from a mapping), but the branch must stay correct and covered.
        """
        backend = DummyEncryptionBackend()
        mock_resolve.return_value = (backend, EncryptionProvider.DOTENVX, None)

        svc = tmp_path / "svc-a"
        svc.mkdir()
        (svc / ".env.production").write_text(
            "#/---BEGIN DOTENV ENCRYPTED---/\nSECRET=encrypted:xyz\n"
        )
        mapping = ServiceMapping(secret_name="s", folder_path=svc, environment="production")
        loaded_config(_sync_config([mapping]))

        # Engine returns an EPHEMERAL result for a DIFFERENT, unmapped folder so
        # the resolved-path lookup misses and the folder-name fallback is used.
        orphan = tmp_path / "orphan-folder"
        ephemeral_result = SyncResult(
            services=[
                ServiceSyncResult(
                    secret_name="other",
                    folder_path=orphan,
                    action=SyncAction.EPHEMERAL,
                    message="ephemeral",
                    vault_key_value="orphan-key",
                )
            ]
        )
        _patch_engine(monkeypatch, ephemeral_result)

        result = runner.invoke(app, ["pull"])
        # The orphan result has no env file to decrypt (its key is never injected
        # into svc-a's decrypt env), so the mapped file decrypts with no override.
        assert result.exit_code == 0, result.output
        injected_env = backend.decrypt_kwargs[0]["env"]
        # The svc-a mapping found no ephemeral entry for its own folder, so no
        # ephemeral override is injected (env stays None).
        assert injected_env is None

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    def test_pull_sync_errors_exit(
        self, mock_resolve, monkeypatch, tmp_path, loaded_config, no_git_hook
    ):
        backend = DummyEncryptionBackend()
        mock_resolve.return_value = (backend, EncryptionProvider.DOTENVX, None)
        mapping = ServiceMapping(secret_name="s", folder_path=tmp_path, environment="production")
        loaded_config(_sync_config([mapping]))

        err_result = SyncResult(
            services=[
                ServiceSyncResult(
                    secret_name="s",
                    folder_path=tmp_path,
                    action=SyncAction.ERROR,
                    message="boom",
                )
            ]
        )
        _patch_engine(monkeypatch, err_result)

        result = runner.invoke(app, ["pull"])
        assert result.exit_code == 1
        assert "Setup incomplete" in result.output

    def test_pull_sync_raises_vault_error_exits(
        self, monkeypatch, tmp_path, loaded_config, no_git_hook
    ):
        mapping = ServiceMapping(secret_name="s", folder_path=tmp_path, environment="production")
        loaded_config(_sync_config([mapping]))

        engine = MagicMock()
        engine.sync_all.side_effect = VaultError("vault down")
        monkeypatch.setattr("envdrift.sync.engine.SyncEngine", MagicMock(return_value=engine))

        result = runner.invoke(app, ["pull"])
        assert result.exit_code == 1
        assert "Sync failed" in result.output


# --------------------------------------------------------------------------
# lock command
# --------------------------------------------------------------------------
class TestLockCommand:
    def test_lock_no_mappings_for_profile_exits(self, loaded_config, no_git_hook):
        loaded_config(_sync_config([]))
        result = runner.invoke(app, ["lock", "--profile", "ghost"])
        assert result.exit_code == 1
        assert "No mappings found for profile 'ghost'" in result.output

    def test_lock_no_nonprofile_mappings_exits(self, loaded_config, no_git_hook):
        loaded_config(_sync_config([]))
        result = runner.invoke(app, ["lock"])
        assert result.exit_code == 1
        assert "No non-profile mappings found" in result.output

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    def test_lock_check_only_reports_would_encrypt(
        self, mock_resolve, tmp_path, loaded_config, no_git_hook
    ):
        backend = DummyEncryptionBackend()
        mock_resolve.return_value = (backend, EncryptionProvider.DOTENVX, None)
        # plaintext file -> would be encrypted
        (tmp_path / ".env.production").write_text("PLAIN=val\n")
        (tmp_path / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=k\n")
        mapping = ServiceMapping(secret_name="s", folder_path=tmp_path, environment="production")
        loaded_config(_sync_config([mapping]))

        result = runner.invoke(app, ["lock", "--check"])
        # check mode + files needing encryption -> exit 1
        assert result.exit_code == 1
        assert "would be encrypted" in result.output
        assert backend.encrypt_calls == []

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    def test_lock_check_only_all_encrypted_succeeds(
        self, mock_resolve, tmp_path, loaded_config, no_git_hook
    ):
        backend = DummyEncryptionBackend()
        mock_resolve.return_value = (backend, EncryptionProvider.DOTENVX, None)
        # already-encrypted file (>=90% encrypted) -> nothing to encrypt
        (tmp_path / ".env.production").write_text(
            "#/---BEGIN DOTENV ENCRYPTED---/\nSECRET=encrypted:abc\n"
        )
        (tmp_path / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=k\n")
        mapping = ServiceMapping(secret_name="s", folder_path=tmp_path, environment="production")
        loaded_config(_sync_config([mapping]))

        result = runner.invoke(app, ["lock", "--check"])
        assert result.exit_code == 0, result.output
        assert "All files are already encrypted" in result.output

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    def test_lock_force_encrypts_plaintext(
        self, mock_resolve, tmp_path, loaded_config, no_git_hook
    ):
        backend = DummyEncryptionBackend()
        mock_resolve.return_value = (backend, EncryptionProvider.DOTENVX, None)
        (tmp_path / ".env.production").write_text("PLAIN=val\n")
        (tmp_path / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=k\n")
        mapping = ServiceMapping(secret_name="s", folder_path=tmp_path, environment="production")
        loaded_config(_sync_config([mapping]))

        result = runner.invoke(app, ["lock", "--force"])
        assert result.exit_code == 0, result.output
        assert "Lock complete" in result.output
        assert (tmp_path / ".env.production").resolve() in backend.encrypt_calls

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    def test_lock_skips_not_found_with_warning(
        self, mock_resolve, tmp_path, loaded_config, no_git_hook
    ):
        backend = DummyEncryptionBackend()
        mock_resolve.return_value = (backend, EncryptionProvider.DOTENVX, None)
        # empty folder, no env file
        mapping = ServiceMapping(secret_name="s", folder_path=tmp_path, environment="production")
        loaded_config(_sync_config([mapping]))

        result = runner.invoke(app, ["lock", "--force"])
        assert result.exit_code == 0, result.output
        assert "skipped (not found)" in result.output
        assert "Warnings" in result.output

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    def test_lock_force_encrypt_failure_exits(
        self, mock_resolve, tmp_path, loaded_config, no_git_hook
    ):
        def fail_encrypt(env_file, **kwargs):
            return EncryptionResult(success=False, message="enc failed", file_path=Path(env_file))

        backend = DummyEncryptionBackend()
        backend.encrypt = fail_encrypt  # type: ignore[method-assign]
        mock_resolve.return_value = (backend, EncryptionProvider.DOTENVX, None)
        (tmp_path / ".env.production").write_text("PLAIN=val\n")
        (tmp_path / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=k\n")
        mapping = ServiceMapping(secret_name="s", folder_path=tmp_path, environment="production")
        loaded_config(_sync_config([mapping]))

        result = runner.invoke(app, ["lock", "--force"])
        assert result.exit_code == 1
        assert "enc failed" in result.output

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    def test_lock_verify_vault_keys_match(self, mock_resolve, tmp_path, loaded_config, no_git_hook):
        backend = DummyEncryptionBackend()
        mock_resolve.return_value = (backend, EncryptionProvider.DOTENVX, None)
        (tmp_path / ".env.production").write_text(
            "#/---BEGIN DOTENV ENCRYPTED---/\nSECRET=encrypted:abc\n"
        )
        (tmp_path / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=matchme\n")

        client = MagicMock()
        client.get_secret.return_value = SecretValue(
            name="s", value="DOTENV_PRIVATE_KEY_PRODUCTION=matchme"
        )
        mapping = ServiceMapping(secret_name="s", folder_path=tmp_path, environment="production")
        loaded_config(_sync_config([mapping]), client)

        result = runner.invoke(app, ["lock", "--verify-vault", "--force"])
        assert result.exit_code == 0, result.output
        assert "keys match vault" in result.output

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    def test_lock_verify_vault_key_mismatch_exits(
        self, mock_resolve, tmp_path, loaded_config, no_git_hook
    ):
        backend = DummyEncryptionBackend()
        mock_resolve.return_value = (backend, EncryptionProvider.DOTENVX, None)
        (tmp_path / ".env.production").write_text(
            "#/---BEGIN DOTENV ENCRYPTED---/\nSECRET=encrypted:abc\n"
        )
        (tmp_path / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=localkey\n")

        client = MagicMock()
        client.get_secret.return_value = SecretValue(
            name="s", value="DOTENV_PRIVATE_KEY_PRODUCTION=differentkey"
        )
        mapping = ServiceMapping(secret_name="s", folder_path=tmp_path, environment="production")
        loaded_config(_sync_config([mapping]), client)

        # no --force so mismatch triggers exit
        result = runner.invoke(app, ["lock", "--verify-vault"])
        assert result.exit_code == 1
        assert "KEY MISMATCH" in result.output

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    def test_lock_verify_vault_missing_keys_file_warns(
        self, mock_resolve, tmp_path, loaded_config, no_git_hook
    ):
        backend = DummyEncryptionBackend()
        mock_resolve.return_value = (backend, EncryptionProvider.DOTENVX, None)
        (tmp_path / ".env.production").write_text(
            "#/---BEGIN DOTENV ENCRYPTED---/\nSECRET=encrypted:abc\n"
        )
        # no .env.keys present -> warning branch
        client = MagicMock()
        mapping = ServiceMapping(secret_name="s", folder_path=tmp_path, environment="production")
        loaded_config(_sync_config([mapping]), client)

        result = runner.invoke(app, ["lock", "--verify-vault", "--force"])
        assert result.exit_code == 0, result.output
        assert ".env.keys not found" in result.output

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    def test_lock_verify_vault_secret_not_found_warns(
        self, mock_resolve, tmp_path, loaded_config, no_git_hook
    ):
        backend = DummyEncryptionBackend()
        mock_resolve.return_value = (backend, EncryptionProvider.DOTENVX, None)
        (tmp_path / ".env.production").write_text(
            "#/---BEGIN DOTENV ENCRYPTED---/\nSECRET=encrypted:abc\n"
        )
        (tmp_path / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=localkey\n")

        client = MagicMock()
        client.get_secret.side_effect = SecretNotFoundError("missing")
        mapping = ServiceMapping(secret_name="s", folder_path=tmp_path, environment="production")
        loaded_config(_sync_config([mapping]), client)

        result = runner.invoke(app, ["lock", "--verify-vault", "--force"])
        assert result.exit_code == 0, result.output
        assert "vault secret 's' not found" in result.output

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    def test_lock_verify_vault_error_records_error(
        self, mock_resolve, tmp_path, loaded_config, no_git_hook
    ):
        backend = DummyEncryptionBackend()
        mock_resolve.return_value = (backend, EncryptionProvider.DOTENVX, None)
        (tmp_path / ".env.production").write_text(
            "#/---BEGIN DOTENV ENCRYPTED---/\nSECRET=encrypted:abc\n"
        )
        (tmp_path / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=localkey\n")

        client = MagicMock()
        client.get_secret.side_effect = VaultError("access denied")
        mapping = ServiceMapping(secret_name="s", folder_path=tmp_path, environment="production")
        loaded_config(_sync_config([mapping]), client)

        # vault error -> recorded as error -> overall exit 1
        result = runner.invoke(app, ["lock", "--verify-vault", "--force"])
        assert result.exit_code == 1
        assert "vault access failed" in result.output

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    def test_lock_sync_keys_runs_engine(
        self, mock_resolve, monkeypatch, tmp_path, loaded_config, no_git_hook
    ):
        backend = DummyEncryptionBackend()
        mock_resolve.return_value = (backend, EncryptionProvider.DOTENVX, None)
        (tmp_path / ".env.production").write_text(
            "#/---BEGIN DOTENV ENCRYPTED---/\nSECRET=encrypted:abc\n"
        )
        (tmp_path / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=k\n")
        mapping = ServiceMapping(secret_name="s", folder_path=tmp_path, environment="production")
        loaded_config(_sync_config([mapping]))
        engine = _patch_engine(monkeypatch, _empty_sync_result())

        result = runner.invoke(app, ["lock", "--sync-keys", "--force"])
        assert result.exit_code == 0, result.output
        engine.sync_all.assert_called_once()
        assert "Verifying keys with vault" in result.output

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    def test_lock_sync_keys_failure_raises_exits(
        self, mock_resolve, monkeypatch, tmp_path, loaded_config, no_git_hook
    ):
        backend = DummyEncryptionBackend()
        mock_resolve.return_value = (backend, EncryptionProvider.DOTENVX, None)
        mapping = ServiceMapping(secret_name="s", folder_path=tmp_path, environment="production")
        loaded_config(_sync_config([mapping]))

        engine = MagicMock()
        engine.sync_all.side_effect = SecretNotFoundError("no secret")
        monkeypatch.setattr("envdrift.sync.engine.SyncEngine", MagicMock(return_value=engine))

        result = runner.invoke(app, ["lock", "--sync-keys"])
        assert result.exit_code == 1
        assert "Key sync failed" in result.output

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    def test_lock_dotenvx_partially_encrypted_reencrypts(
        self, mock_resolve, tmp_path, loaded_config, no_git_hook
    ):
        backend = DummyEncryptionBackend()
        mock_resolve.return_value = (backend, EncryptionProvider.DOTENVX, None)
        # Two value lines, only one encrypted -> 50% -> partially encrypted re-encrypt
        (tmp_path / ".env.production").write_text(
            "#/---BEGIN DOTENV ENCRYPTED---/\nA=encrypted:abc\nB=plain\n"
        )
        (tmp_path / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=k\n")
        mapping = ServiceMapping(secret_name="s", folder_path=tmp_path, environment="production")
        loaded_config(_sync_config([mapping]))

        result = runner.invoke(app, ["lock", "--force"])
        assert result.exit_code == 0, result.output
        assert "partially encrypted" in result.output
        # re-encryption attempted
        assert (tmp_path / ".env.production").resolve() in backend.encrypt_calls


# --------------------------------------------------------------------------
# lock command - canonical encryption-state predicates (#470)
# --------------------------------------------------------------------------
class TestLockCanonicalEncryptionState:
    """Regressions for #470: lock shares the push paths' encryption predicates.

    The old inline >=90%-ciphertext-line ratio cut both ways: a mixed file with
    one fresh plaintext secret was blessed "already encrypted" (false PASS),
    while a fully-encrypted file with fewer than 9 variables was forever
    "partially encrypted" because the plaintext DOTENV_PUBLIC_KEY_* header
    counted in the ratio denominator (false FAIL).
    """

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    def test_lock_check_passes_small_fully_encrypted_file_with_header(
        self, mock_resolve, tmp_path, loaded_config, no_git_hook
    ):
        """A fully-encrypted 3-var file is not 'partially encrypted (75%)'."""
        backend = DummyEncryptionBackend()
        mock_resolve.return_value = (backend, EncryptionProvider.DOTENVX, None)
        (tmp_path / ".env.production").write_text(
            'DOTENV_PUBLIC_KEY_PRODUCTION="pub"\n'
            "API_KEY=encrypted:aaa\nDB_PASS=encrypted:bbb\nTOKEN=encrypted:ccc\n"
        )
        (tmp_path / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=k\n")
        mapping = ServiceMapping(secret_name="s", folder_path=tmp_path, environment="production")
        loaded_config(_sync_config([mapping]))

        result = runner.invoke(app, ["lock", "--check"])
        assert result.exit_code == 0, result.output
        assert "All files are already encrypted" in result.output

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    def test_lock_check_fails_mixed_file_above_old_ratio(
        self, mock_resolve, tmp_path, loaded_config, no_git_hook
    ):
        """>=90% ciphertext lines no longer bless a fresh plaintext secret."""
        backend = DummyEncryptionBackend()
        mock_resolve.return_value = (backend, EncryptionProvider.DOTENVX, None)
        lines = ['DOTENV_PUBLIC_KEY_PRODUCTION="pub"']
        lines += [f"SECRET_{i}=encrypted:cipher{i}" for i in range(1, 19)]
        lines += ["NEW_SECRET=plaintext-added-later"]
        (tmp_path / ".env.production").write_text("\n".join(lines) + "\n")
        (tmp_path / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=k\n")
        mapping = ServiceMapping(secret_name="s", folder_path=tmp_path, environment="production")
        loaded_config(_sync_config([mapping]))

        result = runner.invoke(app, ["lock", "--check"])
        assert result.exit_code == 1, result.output
        assert "would re-encrypt (plaintext values remain)" in result.output
        assert backend.encrypt_calls == []

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    def test_lock_force_reencrypts_mixed_file_above_old_ratio(
        self, mock_resolve, tmp_path, loaded_config, no_git_hook
    ):
        """lock --force re-encrypts the mixed file instead of skipping it."""
        backend = DummyEncryptionBackend()
        mock_resolve.return_value = (backend, EncryptionProvider.DOTENVX, None)
        lines = ['DOTENV_PUBLIC_KEY_PRODUCTION="pub"']
        lines += [f"SECRET_{i}=encrypted:cipher{i}" for i in range(1, 19)]
        lines += ["NEW_SECRET=plaintext-added-later"]
        (tmp_path / ".env.production").write_text("\n".join(lines) + "\n")
        (tmp_path / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=k\n")
        mapping = ServiceMapping(secret_name="s", folder_path=tmp_path, environment="production")
        loaded_config(_sync_config([mapping]))

        result = runner.invoke(app, ["lock", "--force"])
        assert result.exit_code == 0, result.output
        assert "partially encrypted" in result.output
        assert (tmp_path / ".env.production").resolve() in backend.encrypt_calls


# --------------------------------------------------------------------------
# lock command - key-name-mismatch rekey path (sync.py 1411-1465)
# --------------------------------------------------------------------------
class TestLockRekeyOnKeyNameMismatch:
    def _setup_mismatched_keys(self, tmp_path):
        # Fully encrypted file (>=90% encrypted) so the rekey branch is reached.
        (tmp_path / ".env.production").write_text(
            "#/---BEGIN DOTENV ENCRYPTED---/\nSECRET=encrypted:abc\n"
        )
        # .env.keys has an OLD key name that does NOT match the expected
        # DOTENV_PRIVATE_KEY_PRODUCTION -> triggers needs_rekey.
        (tmp_path / ".env.keys").write_text("DOTENV_PRIVATE_KEY_STAGING=oldkey\n")

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    def test_lock_rekey_decrypt_reencrypt_success(
        self, mock_resolve, tmp_path, loaded_config, no_git_hook
    ):
        backend = DummyEncryptionBackend()
        mock_resolve.return_value = (backend, EncryptionProvider.DOTENVX, None)
        self._setup_mismatched_keys(tmp_path)
        mapping = ServiceMapping(secret_name="s", folder_path=tmp_path, environment="production")
        loaded_config(_sync_config([mapping]))

        result = runner.invoke(app, ["lock", "--force"])
        assert result.exit_code == 0, result.output
        assert "key name mismatch" in result.output
        assert "re-encrypted with new key" in result.output
        # decrypt then encrypt were both attempted on the file
        target = (tmp_path / ".env.production").resolve()
        assert target in backend.decrypt_calls
        assert target in backend.encrypt_calls

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    def test_lock_check_rekey_is_read_only(
        self, mock_resolve, tmp_path, loaded_config, no_git_hook
    ):
        """#303: under --check the re-key branch reports but never decrypts/encrypts."""
        backend = DummyEncryptionBackend()
        mock_resolve.return_value = (backend, EncryptionProvider.DOTENVX, None)
        self._setup_mismatched_keys(tmp_path)
        keys_before = (tmp_path / ".env.keys").read_bytes()
        env_before = (tmp_path / ".env.production").read_bytes()
        mapping = ServiceMapping(secret_name="s", folder_path=tmp_path, environment="production")
        loaded_config(_sync_config([mapping]))

        result = runner.invoke(app, ["lock", "--check"])

        # --check reports drift (a file that "would" be re-keyed) and exits 1, the
        # standard check-mode "needs action" signal — but it must not mutate.
        assert result.exit_code == 1, result.output
        assert "would re-key" in result.output
        assert "re-encrypted with new key" not in result.output
        # Dry run: neither decrypt nor encrypt is invoked, files untouched.
        assert backend.decrypt_calls == []
        assert backend.encrypt_calls == []
        assert (tmp_path / ".env.keys").read_bytes() == keys_before
        assert (tmp_path / ".env.production").read_bytes() == env_before

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    def test_lock_rekey_decrypt_failure_records_error(
        self, mock_resolve, tmp_path, loaded_config, no_git_hook
    ):
        backend = DummyEncryptionBackend()

        def fail_decrypt(env_file, **kwargs):
            return EncryptionResult(
                success=False, message="cannot decrypt", file_path=Path(env_file)
            )

        backend.decrypt = fail_decrypt  # type: ignore[method-assign]
        mock_resolve.return_value = (backend, EncryptionProvider.DOTENVX, None)
        self._setup_mismatched_keys(tmp_path)
        mapping = ServiceMapping(secret_name="s", folder_path=tmp_path, environment="production")
        loaded_config(_sync_config([mapping]))

        result = runner.invoke(app, ["lock", "--force"])
        assert result.exit_code == 1
        assert "decrypt failed" in result.output

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    def test_lock_rekey_reencrypt_failure_records_error(
        self, mock_resolve, tmp_path, loaded_config, no_git_hook
    ):
        backend = DummyEncryptionBackend()

        def fail_encrypt(env_file, **kwargs):
            return EncryptionResult(success=False, message="reenc broke", file_path=Path(env_file))

        backend.encrypt = fail_encrypt  # type: ignore[method-assign]
        mock_resolve.return_value = (backend, EncryptionProvider.DOTENVX, None)
        self._setup_mismatched_keys(tmp_path)
        mapping = ServiceMapping(secret_name="s", folder_path=tmp_path, environment="production")
        loaded_config(_sync_config([mapping]))

        result = runner.invoke(app, ["lock", "--force"])
        assert result.exit_code == 1
        assert "re-encrypt failed" in result.output

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    def test_lock_rekey_decrypt_exception_records_error(
        self, mock_resolve, tmp_path, loaded_config, no_git_hook
    ):
        backend = DummyEncryptionBackend(decrypt_side_effect=EncryptionBackendError("boom rekey"))
        mock_resolve.return_value = (backend, EncryptionProvider.DOTENVX, None)
        self._setup_mismatched_keys(tmp_path)
        mapping = ServiceMapping(secret_name="s", folder_path=tmp_path, environment="production")
        loaded_config(_sync_config([mapping]))

        result = runner.invoke(app, ["lock", "--force"])
        assert result.exit_code == 1
        assert "rekey error" in result.output


# --------------------------------------------------------------------------
# lock command - interactive (non-force) prompt path (sync.py 1511-1543)
# --------------------------------------------------------------------------
class TestLockInteractivePrompt:
    @patch("envdrift.cli_commands.sync.console")
    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    def test_lock_user_declines_skips(
        self, mock_resolve, mock_console, tmp_path, loaded_config, no_git_hook
    ):
        backend = DummyEncryptionBackend()
        mock_resolve.return_value = (backend, EncryptionProvider.DOTENVX, None)
        mock_console.input.return_value = "n"
        (tmp_path / ".env.production").write_text("PLAIN=val\n")
        (tmp_path / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=k\n")
        mapping = ServiceMapping(secret_name="s", folder_path=tmp_path, environment="production")
        loaded_config(_sync_config([mapping]))

        # no --force => prompt is shown; we answer "n" => declined => skipped
        result = runner.invoke(app, ["lock"])
        assert result.exit_code == 0, result.output
        mock_console.input.assert_called_once()
        # declining means nothing was encrypted
        assert backend.encrypt_calls == []
        # the "skipped (user declined)" message was rendered
        printed = " ".join(str(c.args[0]) for c in mock_console.print.call_args_list if c.args)
        assert "user declined" in printed

    @patch("envdrift.cli_commands.sync.console")
    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    def test_lock_user_accepts_encrypts_inline(
        self, mock_resolve, mock_console, tmp_path, loaded_config, no_git_hook
    ):
        backend = DummyEncryptionBackend()
        mock_resolve.return_value = (backend, EncryptionProvider.DOTENVX, None)
        mock_console.input.return_value = "y"
        (tmp_path / ".env.production").write_text("PLAIN=val\n")
        (tmp_path / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=k\n")
        mapping = ServiceMapping(secret_name="s", folder_path=tmp_path, environment="production")
        loaded_config(_sync_config([mapping]))

        result = runner.invoke(app, ["lock"])
        assert result.exit_code == 0, result.output
        # accepting => the inline (non-force) encrypt path runs
        assert (tmp_path / ".env.production").resolve() in backend.encrypt_calls

    @patch("envdrift.cli_commands.sync.console")
    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    def test_lock_inline_encrypt_failure_records_error(
        self, mock_resolve, mock_console, tmp_path, loaded_config, no_git_hook
    ):
        backend = DummyEncryptionBackend()

        def fail_encrypt(env_file, **kwargs):
            return EncryptionResult(success=False, message="inline boom", file_path=Path(env_file))

        backend.encrypt = fail_encrypt  # type: ignore[method-assign]
        mock_resolve.return_value = (backend, EncryptionProvider.DOTENVX, None)
        mock_console.input.return_value = "yes"
        (tmp_path / ".env.production").write_text("PLAIN=val\n")
        (tmp_path / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=k\n")
        mapping = ServiceMapping(secret_name="s", folder_path=tmp_path, environment="production")
        loaded_config(_sync_config([mapping]))

        result = runner.invoke(app, ["lock"])
        assert result.exit_code == 1
        printed = " ".join(str(c.args[0]) for c in mock_console.print.call_args_list if c.args)
        assert "inline boom" in printed


# --------------------------------------------------------------------------
# lock command - partial encryption --all path (sync.py 1586-1697)
# --------------------------------------------------------------------------
def _write_partial_config(tmp_path, secret_file, combined_file, *, secrets_only=False):
    cfg = tmp_path / "envdrift.toml"
    # Emit paths as TOML *literal* strings (single quotes): a Windows path's
    # backslashes must not be parsed as escapes (``C:\\Users`` -> invalid ``\\U``).
    secrets_dir = tmp_path / "secrets"
    clear_file = tmp_path / ".env.clear"
    if secrets_only:
        cfg.write_text(
            "[partial_encryption]\nenabled = true\n"
            "[[partial_encryption.environments]]\n"
            'name = "prod"\n'
            "secrets_only = true\n"
            f"secrets_dir = '{secrets_dir}'\n"
        )
    else:
        cfg.write_text(
            "[partial_encryption]\nenabled = true\n"
            "[[partial_encryption.environments]]\n"
            'name = "prod"\n'
            f"clear_file = '{clear_file}'\n"
            f"secret_file = '{secret_file}'\n"
            f"combined_file = '{combined_file}'\n"
        )
    return cfg


class TestLockPartialEncryptionAll:
    @patch("envdrift.core.partial_encryption.encrypt_secret_file")
    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    def test_all_encrypts_secret_and_deletes_combined(
        self, mock_resolve, mock_encrypt_secret, tmp_path, loaded_config, no_git_hook
    ):
        backend = DummyEncryptionBackend()
        mock_resolve.return_value = (backend, EncryptionProvider.DOTENVX, None)

        secret_file = tmp_path / ".env.secret"
        secret_file.write_text("API_KEY=plain\n")
        combined_file = tmp_path / ".env"
        combined_file.write_text("API_KEY=plain\nPUBLIC=ok\n")
        cfg = _write_partial_config(tmp_path, secret_file, combined_file)

        # A regular mapping that is already encrypted so step 2 is uneventful.
        (tmp_path / ".env.production").write_text(
            "#/---BEGIN DOTENV ENCRYPTED---/\nSECRET=encrypted:abc\n"
        )
        (tmp_path / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=k\n")
        mapping = ServiceMapping(secret_name="s", folder_path=tmp_path, environment="production")
        loaded_config(_sync_config([mapping]))

        result = runner.invoke(app, ["lock", "--force", "--all", "--config", str(cfg)])
        assert result.exit_code == 0, result.output
        assert "Processing partial encryption files" in result.output
        # The .secret was encrypted through the partial-encryption lifecycle seam
        # (encrypt_secret_file: read-back verification + skip-worktree handling),
        # NOT the raw backend.encrypt — this is the #507-review alignment with push.
        assert mock_encrypt_secret.call_count == 1
        # combined file was deleted (the .secret reached a good encrypted state)
        assert not combined_file.exists()
        assert "deleted (combined file)" in result.output

    @patch("envdrift.core.partial_encryption.encrypt_secret_file")
    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    def test_all_keeps_combined_when_secret_encryption_fails(
        self, mock_resolve, mock_encrypt_secret, tmp_path, loaded_config, no_git_hook
    ):
        """#507 review: a failed .secret encryption must keep the combined file."""
        from envdrift.core.partial_encryption import PartialEncryptionError

        backend = DummyEncryptionBackend()
        mock_resolve.return_value = (backend, EncryptionProvider.DOTENVX, None)
        mock_encrypt_secret.side_effect = PartialEncryptionError("did not take effect")

        secret_file = tmp_path / ".env.secret"
        secret_file.write_text("API_KEY=plain\n")
        combined_file = tmp_path / ".env"
        combined_file.write_text("API_KEY=plain\nPUBLIC=ok\n")
        cfg = _write_partial_config(tmp_path, secret_file, combined_file)

        (tmp_path / ".env.production").write_text(
            "#/---BEGIN DOTENV ENCRYPTED---/\nSECRET=encrypted:abc\n"
        )
        (tmp_path / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=k\n")
        mapping = ServiceMapping(secret_name="s", folder_path=tmp_path, environment="production")
        loaded_config(_sync_config([mapping]))

        result = runner.invoke(app, ["lock", "--force", "--all", "--config", str(cfg)])
        assert result.exit_code == 1, result.output
        assert combined_file.exists(), "combined file deleted despite failed encryption"
        assert "kept (encryption failed)" in result.output

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    def test_all_check_only_reports_would_actions(
        self, mock_resolve, tmp_path, loaded_config, no_git_hook
    ):
        backend = DummyEncryptionBackend()
        mock_resolve.return_value = (backend, EncryptionProvider.DOTENVX, None)

        secret_file = tmp_path / ".env.secret"
        secret_file.write_text("API_KEY=plain\n")
        combined_file = tmp_path / ".env"
        combined_file.write_text("API_KEY=plain\n")
        cfg = _write_partial_config(tmp_path, secret_file, combined_file)

        (tmp_path / ".env.production").write_text(
            "#/---BEGIN DOTENV ENCRYPTED---/\nSECRET=encrypted:abc\n"
        )
        (tmp_path / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=k\n")
        mapping = ServiceMapping(secret_name="s", folder_path=tmp_path, environment="production")
        loaded_config(_sync_config([mapping]))

        result = runner.invoke(app, ["lock", "--check", "--all", "--config", str(cfg)])
        # The plaintext .secret would be encrypted by a real run, so the dry run
        # reports pending work and fails the gate (#470) - it must not exit 0.
        assert result.exit_code == 1, result.output
        assert "would be encrypted" in result.output
        assert "would be deleted" in result.output
        assert "need encryption" in result.output
        # check mode must not touch the filesystem
        assert combined_file.exists()
        assert backend.encrypt_calls == []

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    def test_all_secret_already_encrypted_and_missing_combined(
        self, mock_resolve, tmp_path, loaded_config, no_git_hook
    ):
        backend = DummyEncryptionBackend()
        mock_resolve.return_value = (backend, EncryptionProvider.DOTENVX, None)

        secret_file = tmp_path / ".env.secret"
        # already encrypted secret -> "already encrypted" branch
        secret_file.write_text("#/---BEGIN DOTENV ENCRYPTED---/\nAPI_KEY=encrypted:zzz\n")
        # combined file does not exist
        combined_file = tmp_path / ".env"
        cfg = _write_partial_config(tmp_path, secret_file, combined_file)

        (tmp_path / ".env.production").write_text(
            "#/---BEGIN DOTENV ENCRYPTED---/\nSECRET=encrypted:abc\n"
        )
        (tmp_path / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=k\n")
        mapping = ServiceMapping(secret_name="s", folder_path=tmp_path, environment="production")
        loaded_config(_sync_config([mapping]))

        result = runner.invoke(app, ["lock", "--force", "--all", "--config", str(cfg)])
        assert result.exit_code == 0, result.output
        # secret already encrypted -> not encrypted again
        assert secret_file.resolve() not in backend.encrypt_calls
        assert "already encrypted" in result.output

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    def test_all_secrets_only_environment_skipped(
        self, mock_resolve, tmp_path, loaded_config, no_git_hook
    ):
        backend = DummyEncryptionBackend()
        mock_resolve.return_value = (backend, EncryptionProvider.DOTENVX, None)
        cfg = _write_partial_config(tmp_path, None, None, secrets_only=True)

        (tmp_path / ".env.production").write_text(
            "#/---BEGIN DOTENV ENCRYPTED---/\nSECRET=encrypted:abc\n"
        )
        (tmp_path / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=k\n")
        mapping = ServiceMapping(secret_name="s", folder_path=tmp_path, environment="production")
        loaded_config(_sync_config([mapping]))

        result = runner.invoke(app, ["lock", "--force", "--all", "--config", str(cfg)])
        assert result.exit_code == 0, result.output
        assert "secrets-only, managed by 'envdrift push'" in result.output
        # The secrets_dir does not exist, so the plaintext check cannot run;
        # that is surfaced as a warning, not silently swallowed (#470).
        normalized = " ".join(result.output.split())
        assert "could not be checked" in normalized

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    def test_all_secrets_only_pending_plaintext_fails(
        self, mock_resolve, tmp_path, loaded_config, no_git_hook
    ):
        """#470: a skipped secrets-only env that still holds plaintext fails the lock.

        The old code printed the unconditional "ready to commit" banner and
        exited 0 while a plaintext secret sat on disk in the skipped env.
        """
        backend = DummyEncryptionBackend()
        mock_resolve.return_value = (backend, EncryptionProvider.DOTENVX, None)
        cfg = _write_partial_config(tmp_path, None, None, secrets_only=True)
        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()
        (secrets_dir / ".env.api").write_text("API_TOKEN=plain\n")

        (tmp_path / ".env.production").write_text(
            "#/---BEGIN DOTENV ENCRYPTED---/\nSECRET=encrypted:abc\n"
        )
        (tmp_path / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=k\n")
        mapping = ServiceMapping(secret_name="s", folder_path=tmp_path, environment="production")
        loaded_config(_sync_config([mapping]))

        result = runner.invoke(app, ["lock", "--force", "--all", "--config", str(cfg)])
        assert result.exit_code == 1, result.output
        normalized = " ".join(result.output.split())
        assert "Secrets-only environments skipped: 1" in normalized
        assert "envdrift push" in normalized
        assert "ready to commit" not in normalized
        # lock --all does not own secrets-only files; push does. Untouched.
        assert (secrets_dir / ".env.api").read_text() == "API_TOKEN=plain\n"
        assert backend.encrypt_calls == []

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    def test_all_secrets_only_fully_encrypted_passes(
        self, mock_resolve, tmp_path, loaded_config, no_git_hook
    ):
        """#470: a fully-encrypted secrets-only env is a benign, reported skip."""
        backend = DummyEncryptionBackend()
        mock_resolve.return_value = (backend, EncryptionProvider.DOTENVX, None)
        cfg = _write_partial_config(tmp_path, None, None, secrets_only=True)
        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()
        (secrets_dir / ".env.api").write_text("API_TOKEN=encrypted:abc\n")

        (tmp_path / ".env.production").write_text(
            "#/---BEGIN DOTENV ENCRYPTED---/\nSECRET=encrypted:abc\n"
        )
        (tmp_path / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=k\n")
        mapping = ServiceMapping(secret_name="s", folder_path=tmp_path, environment="production")
        loaded_config(_sync_config([mapping]))

        result = runner.invoke(app, ["lock", "--force", "--all", "--config", str(cfg)])
        assert result.exit_code == 0, result.output
        normalized = " ".join(result.output.split())
        assert "Secrets-only environments skipped: 1" in normalized
        assert "ready to commit" in normalized
