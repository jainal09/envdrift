"""Tests for envdrift.cli module - Command Line Interface."""

from __future__ import annotations

import tomllib
from pathlib import Path
from textwrap import dedent
from types import SimpleNamespace

from typer.testing import CliRunner

from envdrift.cli import app
from envdrift.cli_commands.encryption import (
    _load_encryption_config,
    _resolve_config_path,
    _verify_decryption_with_vault,
)
from envdrift.config import EnvdriftConfig
from envdrift.encryption import EncryptionProvider
from envdrift.encryption.base import EncryptionBackendError, EncryptionResult
from envdrift.integrations.dotenvx import DotenvxError
from envdrift.vault import VaultError
from tests.helpers import DummyEncryptionBackend

runner = CliRunner()


def _mock_sync_engine_success(monkeypatch):
    """Patch SyncEngine to return a successful result and silence output."""

    class DummyEngine:
        def __init__(self, *_args, **_kwargs):
            pass

        def sync_all(self):
            return SimpleNamespace(services=[], has_errors=False)

    monkeypatch.setattr("envdrift.sync.engine.SyncEngine", DummyEngine)
    monkeypatch.setattr("envdrift.output.rich.print_service_sync_status", lambda *_, **__: None)
    monkeypatch.setattr("envdrift.output.rich.print_sync_result", lambda *_, **__: None)
    return DummyEngine


def _mock_encryption_backend(
    monkeypatch,
    *,
    provider: EncryptionProvider = EncryptionProvider.DOTENVX,
    installed: bool = True,
    decrypt_side_effect: Exception | None = None,
    decrypted_paths: list[Path] | None = None,
    encrypt_side_effect: Exception | None = None,
    encrypted_paths: list[Path] | None = None,
):
    """Patch resolve_encryption_backend with a configurable test double."""
    dummy = DummyEncryptionBackend(
        name=provider.value,
        installed=installed,
        encrypt_side_effect=encrypt_side_effect,
        decrypt_side_effect=decrypt_side_effect,
    )
    if encrypted_paths is not None:
        original_encrypt = dummy.encrypt

        def _encrypt(env_file, **kwargs):
            result = original_encrypt(env_file, **kwargs)
            encrypted_paths.append(Path(env_file))
            return result

        dummy.encrypt = _encrypt  # type: ignore[method-assign]
    if decrypted_paths is not None:
        original_decrypt = dummy.decrypt

        def _decrypt(env_file, **kwargs):
            result = original_decrypt(env_file, **kwargs)
            decrypted_paths.append(Path(env_file))
            return result

        dummy.decrypt = _decrypt  # type: ignore[method-assign]
    monkeypatch.setattr(
        "envdrift.cli_commands.encryption_helpers.resolve_encryption_backend",
        lambda *_args, **_kwargs: (dummy, provider, None),
    )
    return dummy


class TestSyncHelpers:
    """Tests for sync CLI helpers."""

    def test_normalize_max_workers_invalid_values_warn(self, monkeypatch):
        """Invalid max_workers values should warn and return None."""
        from envdrift.cli_commands import sync as sync_module

        warnings: list[str] = []
        monkeypatch.setattr(sync_module, "print_warning", lambda msg: warnings.append(msg))

        assert sync_module._normalize_max_workers("bad") is None
        assert sync_module._normalize_max_workers(True) is None

        assert any("Invalid max_workers value" in msg for msg in warnings)

    def test_normalize_max_workers_negative_warns(self, monkeypatch):
        """Negative max_workers values should warn and return None."""
        from envdrift.cli_commands import sync as sync_module

        warnings: list[str] = []
        monkeypatch.setattr(sync_module, "print_warning", lambda msg: warnings.append(msg))

        assert sync_module._normalize_max_workers(0) is None
        assert sync_module._normalize_max_workers(-2) is None
        assert sync_module._normalize_max_workers(2) == 2

        assert any("max_workers must be >= 1" in msg for msg in warnings)


class TestValidateCommand:
    """Tests for the validate CLI command."""

    def test_validate_requires_schema(self, tmp_path: Path):
        """Test validate command requires --schema option."""
        env_file = tmp_path / ".env"
        env_file.write_text("FOO=bar")

        result = runner.invoke(app, ["validate", str(env_file)])
        assert result.exit_code == 1
        assert "schema" in result.output.lower()

    def test_validate_missing_env_file(self, tmp_path: Path):
        """Test validate command with non-existent env file."""
        result = runner.invoke(
            app, ["validate", str(tmp_path / "missing.env"), "--schema", "config:Settings"]
        )
        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_validate_invalid_schema(self, tmp_path: Path):
        """Test validate command with invalid schema path."""
        env_file = tmp_path / ".env"
        env_file.write_text("FOO=bar")

        result = runner.invoke(app, ["validate", str(env_file), "--schema", "nonexistent:Settings"])
        assert result.exit_code == 1

    def test_validate_success(self, tmp_path: Path):
        """Test validate command succeeds with valid schema."""
        env_file = tmp_path / ".env"
        env_file.write_text("APP_NAME=test\nDEBUG=true")

        schema_file = tmp_path / "myconfig.py"
        schema_file.write_text("""
from pydantic_settings import BaseSettings

class MySettings(BaseSettings):
    APP_NAME: str
    DEBUG: bool = True
""")

        result = runner.invoke(
            app,
            [
                "validate",
                str(env_file),
                "--schema",
                "myconfig:MySettings",
                "--service-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 0
        assert "PASSED" in result.output or "valid" in result.output.lower()

    def test_validate_ci_mode_fails_on_invalid(self, tmp_path: Path):
        """Test validate --ci exits with code 1 on validation failure."""
        env_file = tmp_path / ".env"
        env_file.write_text("DEBUG=true")

        schema_file = tmp_path / "ci_config.py"
        schema_file.write_text("""
from pydantic_settings import BaseSettings

class CiSettings(BaseSettings):
    REQUIRED_VAR: str
    DEBUG: bool = True
""")

        result = runner.invoke(
            app,
            [
                "validate",
                str(env_file),
                "--schema",
                "ci_config:CiSettings",
                "--service-dir",
                str(tmp_path),
                "--ci",
            ],
        )
        assert result.exit_code == 1

    def test_validate_with_fix_flag(self, tmp_path: Path):
        """Test validate --fix outputs fix template."""
        env_file = tmp_path / ".env"
        env_file.write_text("DEBUG=true")

        schema_file = tmp_path / "fix_config.py"
        schema_file.write_text("""
from pydantic_settings import BaseSettings

class FixSettings(BaseSettings):
    MISSING_VAR: str
    DEBUG: bool = True
""")

        result = runner.invoke(
            app,
            [
                "validate",
                str(env_file),
                "--schema",
                "fix_config:FixSettings",
                "--service-dir",
                str(tmp_path),
                "--fix",
            ],
        )
        # Should show fix template for missing vars
        assert "MISSING_VAR" in result.output or "template" in result.output.lower()


class TestDiffCommand:
    """Tests for the diff CLI command."""

    def test_diff_missing_first_file(self, tmp_path: Path):
        """Test diff command with missing first file."""
        env2 = tmp_path / "env2"
        env2.write_text("FOO=bar")

        result = runner.invoke(app, ["diff", str(tmp_path / "missing.env"), str(env2)])
        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_diff_missing_second_file(self, tmp_path: Path):
        """Test diff command with missing second file."""
        env1 = tmp_path / "env1"
        env1.write_text("FOO=bar")

        result = runner.invoke(app, ["diff", str(env1), str(tmp_path / "missing.env")])
        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_diff_identical_files(self, tmp_path: Path):
        """Test diff command with identical files."""
        env1 = tmp_path / "env1"
        env2 = tmp_path / "env2"
        env1.write_text("FOO=bar\nBAZ=qux")
        env2.write_text("FOO=bar\nBAZ=qux")

        result = runner.invoke(app, ["diff", str(env1), str(env2)])
        assert result.exit_code == 0
        assert "no drift" in result.output.lower() or "match" in result.output.lower()

    def test_diff_basic(self, tmp_path: Path):
        """diff exits successfully on simple files."""

        env1 = tmp_path / ".env.dev"
        env2 = tmp_path / ".env.prod"
        env1.write_text("FOO=one\nBAR=two\n")
        env2.write_text("FOO=one\nBAR=three\nNEW=val\n")

        result = runner.invoke(app, ["diff", str(env1), str(env2)])

        assert result.exit_code == 0
        assert "Comparing" in result.output

    def test_diff_with_changes(self, tmp_path: Path):
        """Test diff command shows differences."""
        env1 = tmp_path / "env1"
        env2 = tmp_path / "env2"
        env1.write_text("FOO=old\nREMOVED=val")
        env2.write_text("FOO=new\nADDED=val")

        result = runner.invoke(app, ["diff", str(env1), str(env2)])
        assert result.exit_code == 0
        # Should show the changes
        assert "FOO" in result.output or "changed" in result.output.lower()

    def test_diff_json_format(self, tmp_path: Path):
        """Test diff --format json outputs JSON."""
        env1 = tmp_path / "env1"
        env2 = tmp_path / "env2"
        env1.write_text("FOO=bar")
        env2.write_text("FOO=baz")

        result = runner.invoke(app, ["diff", str(env1), str(env2), "--format", "json"])
        assert result.exit_code == 0
        # JSON output should be parseable
        assert "{" in result.output

    def test_diff_include_unchanged(self, tmp_path: Path):
        """Test diff --include-unchanged shows all vars."""
        env1 = tmp_path / "env1"
        env2 = tmp_path / "env2"
        env1.write_text("SAME=value\nDIFF=old")
        env2.write_text("SAME=value\nDIFF=new")

        result = runner.invoke(app, ["diff", str(env1), str(env2), "--include-unchanged"])
        assert result.exit_code == 0
        assert "SAME" in result.output


class TestEncryptCommand:
    """Tests for the encrypt CLI command."""

    def test_encrypt_check_missing_file(self, tmp_path: Path):
        """Test encrypt --check with missing file."""
        result = runner.invoke(app, ["encrypt", str(tmp_path / "missing.env"), "--check"])
        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_encrypt_hook_check_errors_exit(self, monkeypatch, tmp_path: Path):
        """Encrypt should stop early when hook checks fail."""
        env_file = tmp_path / ".env"
        env_file.write_text("SECRET=encrypted:abc123")

        monkeypatch.setattr(
            "envdrift.integrations.hook_check.ensure_git_hook_setup",
            lambda **_kwargs: ["hook check failed"],
        )
        monkeypatch.setattr(
            "envdrift.cli_commands.encryption.get_encryption_backend",
            lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("should not run")),
        )

        result = runner.invoke(app, ["encrypt", str(env_file)])

        assert result.exit_code == 1
        assert "hook check failed" in result.output.lower()

    def test_encrypt_check_unencrypted_file(self, tmp_path: Path):
        """Test encrypt --check on plaintext file with secrets."""
        env_file = tmp_path / ".env"
        env_file.write_text("SECRET_KEY=mysupersecretkey123\nAPI_TOKEN=abc123")

        result = runner.invoke(app, ["encrypt", str(env_file), "--check"])
        # Should report encryption status
        assert (
            "encrypt" in result.output.lower()
            or "secret" in result.output.lower()
            or result.exit_code == 1
        )

    def test_encrypt_check_encrypted_file(self, tmp_path: Path):
        """Test encrypt --check on encrypted file."""
        env_file = tmp_path / ".env"
        env_file.write_text('#DOTENV_PUBLIC_KEY="abc123"\nSECRET="encrypted:abcdef1234567890"')

        result = runner.invoke(app, ["encrypt", str(env_file), "--check"])
        # Should pass for encrypted file
        assert result.exit_code == 0 or "encrypt" in result.output.lower()

    def test_encrypt_perform_encryption(self, monkeypatch, tmp_path: Path):
        """Test encrypt without --check calls encryption backend."""
        from unittest.mock import MagicMock

        from envdrift.encryption.base import EncryptionResult

        env_file = tmp_path / ".env"
        env_file.write_text("FOO=bar")

        # Create a mock encryption backend
        mock_backend = MagicMock()
        mock_backend.name = "dotenvx"
        mock_backend.is_installed.return_value = True
        mock_backend.encrypt.return_value = EncryptionResult(
            success=True,
            message=f"Encrypted {env_file}",
            file_path=env_file,
        )

        monkeypatch.setattr(
            "envdrift.cli_commands.encryption.get_encryption_backend",
            lambda *args, **kwargs: mock_backend,
        )

        result = runner.invoke(app, ["encrypt", str(env_file)])

        assert result.exit_code == 0
        mock_backend.encrypt.assert_called_once()

    def test_encrypt_prompts_install_when_missing_dotenvx(self, monkeypatch, tmp_path: Path):
        """Encrypt should surface install instructions when backend is absent."""
        from unittest.mock import MagicMock

        env_file = tmp_path / ".env"
        env_file.write_text("FOO=bar")

        # Create a mock encryption backend that is not installed
        mock_backend = MagicMock()
        mock_backend.name = "dotenvx"
        mock_backend.is_installed.return_value = False
        mock_backend.install_instructions.return_value = "npm install -g dotenvx"

        monkeypatch.setattr(
            "envdrift.cli_commands.encryption.get_encryption_backend",
            lambda *args, **kwargs: mock_backend,
        )

        result = runner.invoke(app, ["encrypt", str(env_file)])

        assert result.exit_code == 1
        assert "dotenvx is not installed" in result.output
        assert "npm install" in result.output

    def test_encrypt_uses_sops_config_defaults(self, monkeypatch, tmp_path: Path):
        """Encrypt should honor SOPS defaults from config when backend is omitted."""
        from unittest.mock import MagicMock

        from envdrift.encryption import EncryptionProvider
        from envdrift.encryption.base import EncryptionResult

        env_file = tmp_path / ".env"
        env_file.write_text("FOO=bar")

        config_file = tmp_path / "envdrift.toml"
        config_file.write_text(
            dedent(
                """
                [encryption]
                backend = "sops"

                [encryption.sops]
                config_file = ".sops.yaml"
                age_key_file = "keys.txt"
                age_recipients = "age1example"
                """
            ).strip()
            + "\n"
        )
        (tmp_path / ".sops.yaml").write_text("creation_rules:\n  - age: age1example\n")
        (tmp_path / "keys.txt").write_text("AGE-SECRET-KEY-1EXAMPLE\n")

        monkeypatch.chdir(tmp_path)

        mock_backend = MagicMock()
        mock_backend.name = "sops"
        mock_backend.is_installed.return_value = True
        mock_backend.encrypt.return_value = EncryptionResult(
            success=True,
            message="Encrypted",
            file_path=env_file,
        )

        mock_get_backend = MagicMock(return_value=mock_backend)
        monkeypatch.setattr(
            "envdrift.cli_commands.encryption.get_encryption_backend",
            mock_get_backend,
        )

        result = runner.invoke(app, ["encrypt", str(env_file)])

        assert result.exit_code == 0
        args, kwargs = mock_get_backend.call_args
        assert args[0] == EncryptionProvider.SOPS
        assert kwargs["config_file"] == (tmp_path / ".sops.yaml").resolve()
        assert kwargs["age_key_file"] == (tmp_path / "keys.txt").resolve()
        mock_backend.encrypt.assert_called_once()
        _, encrypt_kwargs = mock_backend.encrypt.call_args
        assert encrypt_kwargs["age_recipients"] == "age1example"

    def test_encrypt_uses_sops_auto_install_from_config(self, monkeypatch, tmp_path: Path):
        """Encrypt should pass SOPS auto_install from config."""
        from unittest.mock import MagicMock

        from envdrift.encryption import EncryptionProvider
        from envdrift.encryption.base import EncryptionResult

        env_file = tmp_path / ".env"
        env_file.write_text("FOO=bar")

        config_file = tmp_path / "envdrift.toml"
        config_file.write_text(
            dedent(
                """
                [encryption]
                backend = "sops"

                [encryption.sops]
                auto_install = true
                """
            ).strip()
            + "\n"
        )

        monkeypatch.chdir(tmp_path)

        mock_backend = MagicMock()
        mock_backend.name = "sops"
        mock_backend.is_installed.return_value = True
        mock_backend.encrypt.return_value = EncryptionResult(
            success=True,
            message="Encrypted",
            file_path=env_file,
        )

        mock_get_backend = MagicMock(return_value=mock_backend)
        monkeypatch.setattr(
            "envdrift.cli_commands.encryption.get_encryption_backend",
            mock_get_backend,
        )

        result = runner.invoke(app, ["encrypt", str(env_file)])

        assert result.exit_code == 0
        args, kwargs = mock_get_backend.call_args
        assert args[0] == EncryptionProvider.SOPS
        assert kwargs["auto_install"] is True

    def test_encrypt_unknown_backend(self, tmp_path: Path):
        """Encrypt should error on unknown backend."""
        env_file = tmp_path / ".env"
        env_file.write_text("FOO=bar")

        result = runner.invoke(app, ["encrypt", str(env_file), "--backend", "unknown"])

        assert result.exit_code == 1
        assert "unknown encryption backend" in result.output.lower()

    def test_encrypt_backend_error(self, monkeypatch, tmp_path: Path):
        """Encrypt should surface backend errors."""
        from unittest.mock import MagicMock

        from envdrift.encryption.base import EncryptionBackendError

        env_file = tmp_path / ".env"
        env_file.write_text("FOO=bar")

        mock_backend = MagicMock()
        mock_backend.name = "dotenvx"
        mock_backend.is_installed.return_value = True
        mock_backend.encrypt.side_effect = EncryptionBackendError("boom")

        monkeypatch.setattr(
            "envdrift.cli_commands.encryption.get_encryption_backend",
            lambda *args, **kwargs: mock_backend,
        )

        result = runner.invoke(app, ["encrypt", str(env_file)])

        assert result.exit_code == 1
        assert "encryption failed" in result.output.lower()


class TestDecryptCommand:
    """Tests for the decrypt CLI command."""

    def test_decrypt_missing_file(self, tmp_path: Path):
        """Test decrypt with missing file."""
        result = runner.invoke(app, ["decrypt", str(tmp_path / "missing.env")])
        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_decrypt_hook_check_errors_exit(self, monkeypatch, tmp_path: Path):
        """Decrypt should stop early when hook checks fail."""
        env_file = tmp_path / ".env"
        env_file.write_text("SECRET=encrypted:abc123")

        monkeypatch.setattr(
            "envdrift.integrations.hook_check.ensure_git_hook_setup",
            lambda **_kwargs: ["hook check failed"],
        )
        monkeypatch.setattr(
            "envdrift.cli_commands.encryption.get_encryption_backend",
            lambda *a, **k: (_ for _ in ()).throw(AssertionError("should not run")),
        )

        result = runner.invoke(app, ["decrypt", str(env_file)])

        assert result.exit_code == 1
        assert "hook check failed" in result.output.lower()

    def test_decrypt_verify_vault_only(self, monkeypatch, tmp_path: Path):
        """--verify-vault should call verification and not decrypt the file."""

        env_file = tmp_path / ".env.production"
        env_file.write_text("SECRET=encrypted")

        called = {"verify": False}

        def fake_verify(**kwargs):
            """
            Test stub that simulates a successful verification and records that it was invoked.

            Parameters:
                **kwargs: Arbitrary keyword arguments accepted and ignored by the stub.

            Returns:
                True indicating the verification succeeded.
            """
            called["verify"] = True
            return True

        monkeypatch.setattr(
            "envdrift.cli_commands.encryption._verify_decryption_with_vault", fake_verify
        )

        # If decrypt were called, raise to fail the test
        monkeypatch.setattr(
            "envdrift.integrations.dotenvx.DotenvxWrapper.decrypt",
            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("should not decrypt")),
        )

        result = runner.invoke(
            app,
            [
                "decrypt",
                str(env_file),
                "--verify-vault",
                "-p",
                "azure",
                "--vault-url",
                "https://example.vault.azure.net",
                "--secret",
                "env-drift-production-key",
                "--ci",
            ],
        )

        assert result.exit_code == 0
        assert called["verify"] is True
        assert "not decrypted" in result.output.lower()

    def test_encrypt_verify_vault_is_deprecated(self, tmp_path: Path):
        """Using --verify-vault on encrypt should surface a helpful error."""

        env_file = tmp_path / ".env.production"
        env_file.write_text("SECRET=encrypted")

        result = runner.invoke(
            app,
            [
                "encrypt",
                str(env_file),
                "--check",
                "--verify-vault",
            ],
        )

        assert result.exit_code == 1
        assert "moved" in result.output.lower()

    def test_decrypt_calls_backend_when_installed(self, monkeypatch, tmp_path: Path):
        """Decrypt should call encryption backend when available."""
        from unittest.mock import MagicMock

        from envdrift.encryption.base import EncryptionResult

        env_file = tmp_path / ".env"
        env_file.write_text("SECRET=encrypted")

        # Create a mock encryption backend
        mock_backend = MagicMock()
        mock_backend.name = "dotenvx"
        mock_backend.is_installed.return_value = True
        mock_backend.decrypt.return_value = EncryptionResult(
            success=True,
            message=f"Decrypted {env_file}",
            file_path=env_file,
        )

        monkeypatch.setattr(
            "envdrift.cli_commands.encryption.get_encryption_backend",
            lambda *args, **kwargs: mock_backend,
        )
        # Also mock the detector to return a backend
        monkeypatch.setattr(
            "envdrift.cli_commands.encryption.EncryptionDetector.detect_backend_for_file",
            lambda self, path: "dotenvx",
        )

        result = runner.invoke(app, ["decrypt", str(env_file)])

        assert result.exit_code == 0
        mock_backend.decrypt.assert_called_once()

    def test_decrypt_uses_sops_config_auto_install(self, monkeypatch, tmp_path: Path):
        """Decrypt should honor SOPS config defaults when auto-detect fails."""
        from unittest.mock import MagicMock

        from envdrift.encryption import EncryptionProvider
        from envdrift.encryption.base import EncryptionResult

        env_file = tmp_path / ".env"
        env_file.write_text('KEY="ENC[AES256_GCM,data:abc]"')

        config_file = tmp_path / "envdrift.toml"
        config_file.write_text(
            dedent(
                """
                [encryption]
                backend = "sops"

                [encryption.sops]
                auto_install = true
                config_file = ".sops.yaml"
                age_key_file = "age.key"
                """
            ).strip()
            + "\n"
        )
        (tmp_path / ".sops.yaml").write_text("creation_rules:\n  - age: age1example\n")
        (tmp_path / "age.key").write_text("AGE-SECRET-KEY-1EXAMPLE\n")

        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(
            "envdrift.cli_commands.encryption.EncryptionDetector.detect_backend_for_file",
            lambda *_args, **_kwargs: None,
        )

        mock_backend = MagicMock()
        mock_backend.name = "sops"
        mock_backend.is_installed.return_value = True
        mock_backend.decrypt.return_value = EncryptionResult(
            success=True,
            message="Decrypted",
            file_path=env_file,
        )

        mock_get_backend = MagicMock(return_value=mock_backend)
        monkeypatch.setattr(
            "envdrift.cli_commands.encryption.get_encryption_backend",
            mock_get_backend,
        )

        result = runner.invoke(app, ["decrypt", str(env_file)])

        assert result.exit_code == 0
        args, kwargs = mock_get_backend.call_args
        assert args[0] == EncryptionProvider.SOPS
        assert kwargs["auto_install"] is True
        assert kwargs["config_file"] == (tmp_path / ".sops.yaml").resolve()
        assert kwargs["age_key_file"] == (tmp_path / "age.key").resolve()

    def test_decrypt_verify_vault_requires_provider(self, tmp_path: Path):
        """Verify-vault should require provider and secret arguments."""

        env_file = tmp_path / ".env"
        env_file.write_text("SECRET=encrypted")

        result = runner.invoke(app, ["decrypt", str(env_file), "--verify-vault", "--secret", "key"])

        assert result.exit_code == 1
        assert "provider" in result.output.lower()

    def test_decrypt_verify_vault_requires_secret(self, tmp_path: Path):
        """Verify-vault should require secret argument."""
        env_file = tmp_path / ".env"
        env_file.write_text("SECRET=encrypted")

        result = runner.invoke(
            app,
            [
                "decrypt",
                str(env_file),
                "--verify-vault",
                "--provider",
                "azure",
                "--vault-url",
                "https://example.vault.azure.net",
            ],
        )

        assert result.exit_code == 1
        assert "secret" in result.output.lower()

    def test_decrypt_verify_vault_requires_project_id_for_gcp(self, tmp_path: Path):
        """Verify-vault should require --project-id for gcp provider."""

        env_file = tmp_path / ".env"
        env_file.write_text("SECRET=encrypted")

        result = runner.invoke(
            app,
            [
                "decrypt",
                str(env_file),
                "--verify-vault",
                "--provider",
                "gcp",
                "--secret",
                "key",
            ],
        )

        assert result.exit_code == 1
        assert "project-id" in result.output.lower()

    def test_decrypt_verify_vault_disallows_sops(self, tmp_path: Path):
        """Verify-vault should be blocked for SOPS backend."""
        env_file = tmp_path / ".env"
        env_file.write_text('KEY="ENC[AES256_GCM,data:abc]"')

        result = runner.invoke(
            app,
            ["decrypt", str(env_file), "--backend", "sops", "--verify-vault"],
        )

        assert result.exit_code == 1
        assert "only supported" in result.output.lower()

    def test_decrypt_unknown_backend(self, tmp_path: Path):
        """Decrypt should error on unknown backend."""
        env_file = tmp_path / ".env"
        env_file.write_text("SECRET=encrypted")

        result = runner.invoke(app, ["decrypt", str(env_file), "--backend", "unknown"])

        assert result.exit_code == 1
        assert "unknown encryption backend" in result.output.lower()

    def test_decrypt_backend_not_installed(self, monkeypatch, tmp_path: Path):
        """Decrypt should print install guidance when backend is missing."""
        from unittest.mock import MagicMock

        env_file = tmp_path / ".env"
        env_file.write_text("SECRET=encrypted")

        mock_backend = MagicMock()
        mock_backend.name = "dotenvx"
        mock_backend.is_installed.return_value = False
        mock_backend.install_instructions.return_value = "install dotenvx"

        monkeypatch.setattr(
            "envdrift.cli_commands.encryption.get_encryption_backend",
            lambda *args, **kwargs: mock_backend,
        )
        monkeypatch.setattr(
            "envdrift.cli_commands.encryption.EncryptionDetector.detect_backend_for_file",
            lambda *_args, **_kwargs: "dotenvx",
        )

        result = runner.invoke(app, ["decrypt", str(env_file)])

        assert result.exit_code == 1
        assert "not installed" in result.output.lower()
        assert "install dotenvx" in result.output

    def test_decrypt_backend_error(self, monkeypatch, tmp_path: Path):
        """Decrypt should surface backend errors."""
        from unittest.mock import MagicMock

        from envdrift.encryption.base import EncryptionBackendError

        env_file = tmp_path / ".env"
        env_file.write_text("SECRET=encrypted")

        mock_backend = MagicMock()
        mock_backend.name = "dotenvx"
        mock_backend.is_installed.return_value = True
        mock_backend.decrypt.side_effect = EncryptionBackendError("boom")

        monkeypatch.setattr(
            "envdrift.cli_commands.encryption.get_encryption_backend",
            lambda *args, **kwargs: mock_backend,
        )
        monkeypatch.setattr(
            "envdrift.cli_commands.encryption.EncryptionDetector.detect_backend_for_file",
            lambda *_args, **_kwargs: "dotenvx",
        )

        result = runner.invoke(app, ["decrypt", str(env_file)])

        assert result.exit_code == 1
        assert "decryption failed" in result.output.lower()


class TestEncryptionHelpers:
    """Tests for encryption helper functions."""

    def test_load_encryption_config_handles_toml_error(self, monkeypatch, tmp_path: Path):
        """Invalid TOML should return default config and no path."""
        config_path = tmp_path / "envdrift.toml"
        config_path.write_text("invalid = [")

        def fake_load(_path):
            raise tomllib.TOMLDecodeError("bad", "invalid = [", 10)

        warnings = []

        monkeypatch.setattr("envdrift.config.find_config", lambda: config_path)
        monkeypatch.setattr("envdrift.config.load_config", fake_load)
        monkeypatch.setattr("envdrift.cli_commands.encryption.print_warning", warnings.append)

        config, resolved = _load_encryption_config()

        assert isinstance(config, EnvdriftConfig)
        assert resolved is None
        assert warnings

    def test_resolve_config_path_relative(self, tmp_path: Path):
        """Relative paths should resolve relative to config file."""
        config_path = tmp_path / "envdrift.toml"
        resolved = _resolve_config_path(config_path, "configs/.sops.yaml")
        assert resolved == (tmp_path / "configs" / ".sops.yaml").resolve()


class TestInitCommand:
    """Tests for the init CLI command."""

    def test_init_missing_env_file(self, tmp_path: Path):
        """Test init with missing env file."""
        result = runner.invoke(app, ["init", str(tmp_path / "missing.env")])
        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_init_generates_settings(self, tmp_path: Path):
        """Test init generates a settings file."""
        env_file = tmp_path / ".env"
        env_file.write_text("APP_NAME=myapp\nDEBUG=true\nPORT=8080")

        output_file = tmp_path / "generated_settings.py"
        result = runner.invoke(
            app,
            ["init", str(env_file), "--output", str(output_file), "--class-name", "AppSettings"],
        )

        assert result.exit_code == 0
        assert output_file.exists()
        content = output_file.read_text()
        assert "class AppSettings" in content
        assert "APP_NAME" in content
        assert "DEBUG" in content
        assert "PORT" in content

    def test_init_detects_sensitive_vars(self, tmp_path: Path):
        """Test init --detect-sensitive marks sensitive vars."""
        env_file = tmp_path / ".env"
        env_file.write_text("SECRET_KEY=abc123\nPASSWORD=hunter2\nAPP_NAME=myapp")

        output_file = tmp_path / "settings_sens.py"
        result = runner.invoke(
            app, ["init", str(env_file), "--output", str(output_file), "--detect-sensitive"]
        )

        assert result.exit_code == 0
        content = output_file.read_text()
        assert "sensitive" in content.lower()

    def test_init_without_detect_sensitive(self, tmp_path: Path):
        """Test init without --detect-sensitive flag."""
        env_file = tmp_path / ".env"
        env_file.write_text("SECRET_KEY=abc123")

        output_file = tmp_path / "settings_no_sens.py"
        # Default is --detect-sensitive, so just run without the flag
        result = runner.invoke(
            app,
            [
                "init",
                str(env_file),
                "--output",
                str(output_file),
            ],
        )

        assert result.exit_code == 0
        content = output_file.read_text()
        assert "SECRET_KEY" in content


class TestHookCommand:
    """Tests for the hook CLI command."""

    def test_hook_show_config(self):
        """Test hook --config shows pre-commit config."""
        result = runner.invoke(app, ["hook", "--config"])
        assert result.exit_code == 0
        assert "pre-commit" in result.output.lower() or "hooks" in result.output.lower()
        assert "envdrift" in result.output

    def test_hook_without_options(self):
        """Test hook without options shows config."""
        result = runner.invoke(app, ["hook"])
        assert result.exit_code == 0
        assert "envdrift" in result.output


class TestVersionCommand:
    """Tests for the version CLI command."""

    def test_version_shows_version(self):
        """Test version command shows version."""
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "envdrift" in result.output
        # Should contain version number pattern
        import re

        assert re.search(r"\d+\.\d+", result.output)


class TestVaultVerification:
    """Tests for vault verification helper."""

    def test_verify_vault_uses_isolated_keys(self, monkeypatch, tmp_path: Path):
        """Ensure vault verification only exposes the vault key to dotenvx."""

        env_file = tmp_path / ".env.production"
        env_file.write_text("SECRET=encrypted")

        secret_value = SimpleNamespace(value="DOTENV_PRIVATE_KEY_PRODUCTION=vault-key")

        class DummyVault:
            def ensure_authenticated(self) -> None:
                """
                Ensure the command runner is authenticated before performing operations.

                Implementations should verify or establish the required authentication state for subsequent CLI actions.
                """
                return None

            def get_secret(self, name: str):
                """
                Retrieve a secret value by its name.

                Parameters:
                    name (str): The key/name of the secret to retrieve.

                Returns:
                    secret_value: The secret associated with the provided name.
                """
                return secret_value

        # Set an unrelated key that should be stripped from the subprocess environment
        monkeypatch.setenv("DOTENV_PRIVATE_KEY_STAGING", "should-be-ignored")

        monkeypatch.setattr("envdrift.vault.get_vault_client", lambda *_, **__: DummyVault())
        monkeypatch.setattr(
            "envdrift.integrations.dotenvx.DotenvxWrapper.is_installed",
            lambda self: True,
        )

        captured: dict = {}

        def fake_decrypt(self, env_path, env_keys_file=None, env=None, cwd=None):
            """
            Record the decrypt call arguments for tests and assert the supplied env_path exists and is located in the provided cwd.

            Parameters:
                env_path (Path): Path to the environment file passed to the fake decrypt.
                env_keys_file (Path | None): Optional path to the keys file (captured but not validated).
                env (dict | None): Optional environment mapping passed to the call (captured for inspection).
                cwd (Path | None): Expected working directory; the function asserts env_path.parent == cwd.

            Raises:
                AssertionError: If `env_path` does not exist or if `env_path.parent` is not equal to `cwd`.
            """
            captured["env_path"] = env_path
            captured["env"] = env
            captured["cwd"] = cwd

            assert env_path.exists()
            assert env_path.parent == cwd

        monkeypatch.setattr(
            "envdrift.integrations.dotenvx.DotenvxWrapper.decrypt",
            fake_decrypt,
        )

        result = _verify_decryption_with_vault(
            env_file=env_file,
            provider="azure",
            vault_url="https://example.vault.azure.net",
            region=None,
            project_id=None,
            secret_name="env-drift-production-key",
        )

        assert result is True
        subprocess_env = captured["env"]
        assert subprocess_env.get("DOTENV_PRIVATE_KEY_PRODUCTION") == "vault-key"
        assert "DOTENV_PRIVATE_KEY_STAGING" not in subprocess_env
        assert captured["cwd"] is not None and captured["cwd"] != env_file.parent

    def test_verify_vault_failure_suggests_restore(self, monkeypatch, tmp_path: Path):
        """Vault verification failure should guide restoring encrypted file and keys."""

        env_file = tmp_path / ".env.production"
        env_file.write_text("SECRET=encrypted")

        secret_value = SimpleNamespace(value="DOTENV_PRIVATE_KEY_PRODUCTION=vault-key")

        class DummyVault:
            def ensure_authenticated(self) -> None:
                """
                Ensure the command runner is authenticated before performing operations.

                Implementations should verify or establish the required authentication state for subsequent CLI actions.
                """
                return None

            def get_secret(self, name: str):
                """
                Retrieve a secret value by its name.

                Parameters:
                    name (str): The key/name of the secret to retrieve.

                Returns:
                    secret_value: The secret associated with the provided name.
                """
                return secret_value

        monkeypatch.setattr("envdrift.vault.get_vault_client", lambda *_, **__: DummyVault())
        monkeypatch.setattr(
            "envdrift.integrations.dotenvx.DotenvxWrapper.is_installed",
            lambda self: True,
        )
        monkeypatch.setattr(
            "envdrift.integrations.dotenvx.DotenvxWrapper.decrypt",
            lambda *_, **__: (_ for _ in ()).throw(DotenvxError("bad key")),
        )

        printed: list[str] = []
        monkeypatch.setattr(
            "envdrift.output.rich.console.print", lambda msg="", *a, **k: printed.append(str(msg))
        )

        result = _verify_decryption_with_vault(
            env_file=env_file,
            provider="azure",
            vault_url="https://example.vault.azure.net",
            region=None,
            project_id=None,
            secret_name="env-drift-production-key",
        )

        assert result is False
        joined = " ".join(printed)
        assert "git restore" in joined
        assert str(env_file) in joined
        assert "envdrift sync --force" in joined

    def test_verify_vault_gcp_passes_project_id(self, monkeypatch, tmp_path: Path):
        """GCP provider should pass project_id through to the vault client."""
        env_file = tmp_path / ".env.production"
        env_file.write_text("SECRET=encrypted")

        secret_value = SimpleNamespace(value="DOTENV_PRIVATE_KEY_PRODUCTION=vault-key")
        captured: dict[str, object] = {}

        class DummyVault:
            def ensure_authenticated(self) -> None:
                return None

            def get_secret(self, name: str):
                return secret_value

        def fake_get_vault_client(provider, **kwargs):
            captured["provider"] = provider
            captured["kwargs"] = kwargs
            return DummyVault()

        monkeypatch.setattr("envdrift.vault.get_vault_client", fake_get_vault_client)
        monkeypatch.setattr(
            "envdrift.integrations.dotenvx.DotenvxWrapper.is_installed",
            lambda self: True,
        )
        monkeypatch.setattr(
            "envdrift.integrations.dotenvx.DotenvxWrapper.decrypt",
            lambda *_, **__: None,
        )

        result = _verify_decryption_with_vault(
            env_file=env_file,
            provider="gcp",
            vault_url=None,
            region=None,
            project_id="my-gcp-project",
            secret_name="env-drift-production-key",
        )

        assert result is True
        assert captured["provider"] == "gcp"
        assert captured["kwargs"]["project_id"] == "my-gcp-project"

    def test_verify_vault_gcp_failure_includes_project_id(self, monkeypatch, tmp_path: Path):
        """Failure guidance should include gcp project-id in sync command."""
        env_file = tmp_path / ".env.production"
        env_file.write_text("SECRET=encrypted")

        secret_value = SimpleNamespace(value="DOTENV_PRIVATE_KEY_PRODUCTION=vault-key")

        class DummyVault:
            def ensure_authenticated(self) -> None:
                return None

            def get_secret(self, name: str):
                return secret_value

        monkeypatch.setattr("envdrift.vault.get_vault_client", lambda *_, **__: DummyVault())
        monkeypatch.setattr(
            "envdrift.integrations.dotenvx.DotenvxWrapper.is_installed",
            lambda self: True,
        )
        monkeypatch.setattr(
            "envdrift.integrations.dotenvx.DotenvxWrapper.decrypt",
            lambda *_, **__: (_ for _ in ()).throw(DotenvxError("bad key")),
        )

        printed: list[str] = []
        monkeypatch.setattr(
            "envdrift.output.rich.console.print", lambda msg="", *a, **k: printed.append(str(msg))
        )

        result = _verify_decryption_with_vault(
            env_file=env_file,
            provider="gcp",
            vault_url=None,
            region=None,
            project_id="my-gcp-project",
            secret_name="env-drift-production-key",
        )

        assert result is False
        joined = " ".join(printed)
        assert "--project-id my-gcp-project" in joined

    def test_verify_vault_aws_with_raw_secret(self, monkeypatch, tmp_path: Path):
        """Vault verification should accept raw secrets and derive key name."""

        env_file = tmp_path / ".env"
        env_file.write_text("SECRET=encrypted")

        class DummyVault:
            def ensure_authenticated(self) -> None:
                """
                Ensure the command runner is authenticated before performing operations.

                Implementations should verify or establish the required authentication state for subsequent CLI actions.
                """
                return None

            def get_secret(self, name: str):
                """
                Return the fixed plaintext key for the "dotenv-key" secret.

                Parameters:
                    name (str): The secret name; must be "dotenv-key".

                Returns:
                    str: The plaintext secret "plainawskey".

                Raises:
                    AssertionError: If `name` is not "dotenv-key".
                """
                assert name == "dotenv-key"
                return "plainawskey"

        captured: dict = {}

        class DummyDotenvx:
            def is_installed(self):
                """
                Check whether the component is installed.

                This implementation always reports the component as installed.

                Returns:
                    `true` if the component is installed, `false` otherwise.
                """
                return True

            def decrypt(self, env_path, env_keys_file=None, env=None, cwd=None):
                """
                Test stub that simulates a decrypt call by recording the production private key and working directory and asserting the env file exists.

                Parameters:
                    env_path (Path): Path to the environment file to be decrypted; must exist.
                    env_keys_file (Path|None): Optional path to the keys file (not used by the stub).
                    env (Mapping|None): Environment mapping; the stub reads `DOTENV_PRIVATE_KEY_PRODUCTION` from this mapping.
                    cwd (str|Path|None): Working directory passed to the stub; recorded for inspection.

                Raises:
                    AssertionError: If `env_path` does not exist.
                """
                captured["env_var"] = env.get("DOTENV_PRIVATE_KEY_PRODUCTION")
                captured["cwd"] = cwd
                assert env_path.exists()

        monkeypatch.setattr("envdrift.vault.get_vault_client", lambda *_, **__: DummyVault())
        monkeypatch.setattr(
            "envdrift.integrations.dotenvx.DotenvxWrapper",
            lambda *_, **__: DummyDotenvx(),
        )

        result = _verify_decryption_with_vault(
            env_file=env_file,
            provider="aws",
            vault_url=None,
            region="us-east-1",
            project_id=None,
            secret_name="dotenv-key",
        )

        assert result is True
        assert captured["env_var"] == "plainawskey"


class TestAppHelp:
    """Tests for app help and no args behavior."""

    def test_no_args_shows_help(self):
        """Test running app with no args shows help."""
        result = runner.invoke(app, [])
        # no_args_is_help=True means it shows help
        assert "validate" in result.output.lower() or "help" in result.output.lower()

    def test_help_flag(self):
        """Test --help shows help."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "envdrift" in result.output.lower()
        assert "validate" in result.output.lower()
        assert "diff" in result.output.lower()


class TestHookInstall:
    """Tests for hook install path."""

    def test_hook_install_calls_install_hooks(self, monkeypatch):
        """hook --install should call install_hooks."""

        called = {"installed": False}

        def fake_install_hooks(config_path=None):
            """
            Mark that the hook installation path was invoked by setting called["installed"] to True.

            Parameters:
                config_path (str | None): Optional path to a hooks configuration file; this argument is accepted but ignored.

            Returns:
                bool: True to indicate the (fake) installation succeeded.
            """
            called["installed"] = True
            return True

        monkeypatch.setattr("envdrift.integrations.precommit.install_hooks", fake_install_hooks)

        result = runner.invoke(app, ["hook", "--install"])

        assert result.exit_code == 0
        assert called["installed"] is True


class TestSyncCommand:
    """Tests for the sync CLI command."""

    def test_sync_requires_config_and_provider(self, tmp_path: Path, monkeypatch):
        """Sync should enforce required options."""
        # Run from isolated tmp directory to prevent auto-discovery of parent config
        monkeypatch.chdir(tmp_path)

        missing_config = runner.invoke(
            app, ["sync", "-p", "azure", "--vault-url", "https://example.vault.azure.net/"]
        )
        assert missing_config.exit_code == 1
        assert "--config" in missing_config.output

        config_file = tmp_path / "pair.txt"
        config_file.write_text("secret=service")

        missing_provider = runner.invoke(app, ["sync", "-c", str(config_file)])
        assert missing_provider.exit_code == 1
        assert "--provider" in missing_provider.output

    def test_sync_hook_check_errors_exit(self, monkeypatch, tmp_path: Path):
        """Sync should stop early when hook checks fail."""
        config_file = tmp_path / "envdrift.toml"
        config_file.write_text('[vault]\nprovider = "aws"\n')

        dummy_config = SimpleNamespace(mappings=[])
        monkeypatch.setattr(
            "envdrift.cli_commands.sync.load_sync_config_and_client",
            lambda *args, **kwargs: (dummy_config, SimpleNamespace(), "aws", None, None, None),
        )
        monkeypatch.setattr(
            "envdrift.integrations.hook_check.ensure_git_hook_setup",
            lambda **_kwargs: ["hook check failed"],
        )

        result = runner.invoke(app, ["sync", "-c", str(config_file), "-p", "aws"])

        assert result.exit_code == 1
        assert "hook check failed" in result.output.lower()

    def test_sync_requires_vault_url_for_azure(self, tmp_path: Path):
        """Azure provider must supply --vault-url."""

        config_file = tmp_path / "pair.txt"
        config_file.write_text("secret=service")

        result = runner.invoke(app, ["sync", "-c", str(config_file), "-p", "azure"])

        assert result.exit_code == 1
        assert "vault-url" in result.output.lower()

    def test_sync_happy_path(self, monkeypatch, tmp_path: Path):
        """Sync succeeds and prints results when engine reports no errors."""

        config_file = tmp_path / "pair.txt"
        config_file.write_text("secret=service")

        monkeypatch.setattr("envdrift.vault.get_vault_client", lambda *_, **__: SimpleNamespace())
        monkeypatch.setattr("envdrift.output.rich.print_service_sync_status", lambda *_, **__: None)
        monkeypatch.setattr("envdrift.output.rich.print_sync_result", lambda *_, **__: None)
        monkeypatch.setattr(
            "envdrift.sync.engine.SyncMode",
            lambda **kwargs: SimpleNamespace(**kwargs),
        )

        class DummyEngine:
            def __init__(self, config, vault_client, mode, prompt_callback, progress_callback):
                """Test stub for SyncEngine."""
                self.config = config
                self.vault_client = vault_client
                self.mode = mode
                self.prompt_callback = prompt_callback
                self.progress_callback = progress_callback

            def sync_all(self):
                """Return a successful sync result."""
                return SimpleNamespace(services=[], has_errors=False)

        monkeypatch.setattr("envdrift.sync.engine.SyncEngine", DummyEngine)

        result = runner.invoke(
            app,
            [
                "sync",
                "-c",
                str(config_file),
                "-p",
                "aws",
                "--region",
                "us-east-2",
            ],
        )

        assert result.exit_code == 0

    def test_sync_ci_exits_on_errors(self, monkeypatch, tmp_path: Path):
        """Sync in CI should exit non-zero when engine reports errors."""

        config_file = tmp_path / "pair.txt"
        config_file.write_text("secret=service")

        monkeypatch.setattr("envdrift.vault.get_vault_client", lambda *_, **__: SimpleNamespace())
        monkeypatch.setattr("envdrift.output.rich.print_service_sync_status", lambda *_, **__: None)
        monkeypatch.setattr("envdrift.output.rich.print_sync_result", lambda *_, **__: None)
        monkeypatch.setattr(
            "envdrift.sync.engine.SyncMode",
            lambda **kwargs: SimpleNamespace(**kwargs),
        )

        class ErrorEngine:
            def __init__(self, *_args, **_kwargs):
                """Test stub that returns a failed sync result."""
                pass

            def sync_all(self):
                """Return a sync result with errors."""
                return SimpleNamespace(services=[], has_errors=True)

        monkeypatch.setattr("envdrift.sync.engine.SyncEngine", ErrorEngine)

        result = runner.invoke(
            app,
            [
                "sync",
                "-c",
                str(config_file),
                "-p",
                "hashicorp",
                "--vault-url",
                "http://localhost:8200",
                "--ci",
            ],
        )

        assert result.exit_code == 1

    def test_sync_autodiscovery_uses_config_defaults(self, monkeypatch, tmp_path: Path):
        """Auto-discovered envdrift.toml should supply provider, vault URL, and mappings."""

        config_file = tmp_path / "envdrift.toml"
        config_file.write_text(
            dedent(
                """
                [vault]
                provider = "azure"

                [vault.azure]
                vault_url = "https://example.vault.azure.net/"

                [vault.sync]
                default_vault_name = "main"
                env_keys_filename = ".env.keys"

                [[vault.sync.mappings]]
                secret_name = "dotenv-key"
                folder_path = "services/api"
                environment = "production"
                """
            )
        )

        monkeypatch.chdir(tmp_path)
        captured: dict[str, object] = {}

        monkeypatch.setattr(
            "envdrift.vault.get_vault_client",
            lambda *_args, **_kwargs: SimpleNamespace(ensure_authenticated=lambda: None),
        )
        monkeypatch.setattr("envdrift.output.rich.print_service_sync_status", lambda *_, **__: None)
        monkeypatch.setattr("envdrift.output.rich.print_sync_result", lambda *_, **__: None)

        class DummyEngine:
            def __init__(self, config, vault_client, mode, prompt_callback, progress_callback):
                captured["config"] = config

            def sync_all(self):
                return SimpleNamespace(services=[], has_errors=False)

        monkeypatch.setattr("envdrift.sync.engine.SyncEngine", DummyEngine)

        result = runner.invoke(app, ["sync"])

        assert result.exit_code == 0
        sync_config = captured["config"]
        assert sync_config.default_vault_name == "main"
        assert sync_config.env_keys_filename == ".env.keys"
        assert sync_config.mappings[0].secret_name == "dotenv-key"
        assert sync_config.mappings[0].folder_path == Path("services/api")

    def test_sync_config_file_toml_supplies_defaults(self, monkeypatch, tmp_path: Path):
        """Explicit TOML config should supply provider defaults when CLI flags are absent."""

        config_file = tmp_path / "sync.toml"
        config_file.write_text(
            dedent(
                """
                [vault]
                provider = "aws"

                [vault.aws]
                region = "eu-west-2"

                [vault.sync]
                default_vault_name = "aws-vault"
                env_keys_filename = "keys.env"

                [[vault.sync.mappings]]
                secret_name = "dotenv-key"
                folder_path = "services/api"
                vault_name = "aws-vault"
                """
            )
        )

        captured: dict[str, object] = {}

        def fake_get_vault_client(provider, **kwargs):
            captured["provider"] = provider
            captured["kwargs"] = kwargs
            return SimpleNamespace(ensure_authenticated=lambda: None)

        monkeypatch.setattr("envdrift.vault.get_vault_client", fake_get_vault_client)
        monkeypatch.setattr("envdrift.output.rich.print_service_sync_status", lambda *_, **__: None)
        monkeypatch.setattr("envdrift.output.rich.print_sync_result", lambda *_, **__: None)

        class DummyEngine:
            def __init__(self, config, vault_client, mode, prompt_callback, progress_callback):
                captured["config"] = config

            def sync_all(self):
                return SimpleNamespace(services=[], has_errors=False)

        monkeypatch.setattr("envdrift.sync.engine.SyncEngine", DummyEngine)

        result = runner.invoke(app, ["sync", "-c", str(config_file)])

        assert result.exit_code == 0
        assert captured["provider"] == "aws"
        assert captured["kwargs"]["region"] == "eu-west-2"
        sync_config = captured["config"]
        assert sync_config.env_keys_filename == "keys.env"
        assert sync_config.default_vault_name == "aws-vault"
        assert sync_config.mappings[0].vault_name == "aws-vault"

    def test_sync_falls_back_to_sync_config_when_load_config_fails(
        self, monkeypatch, tmp_path: Path
    ):
        """If config loading fails, still attempt to read sync config from the TOML path."""

        config_file = tmp_path / "envdrift.toml"
        config_file.write_text(
            dedent(
                """
                [vault.sync]
                default_vault_name = "fallback"

                [[vault.sync.mappings]]
                secret_name = "dotenv-key"
                folder_path = "services/api"
                """
            )
        )

        def broken_load_config(*_args, **_kwargs):
            raise tomllib.TOMLDecodeError("boom", "", 0)

        monkeypatch.setattr("envdrift.config.find_config", lambda *_args, **_kwargs: config_file)
        monkeypatch.setattr("envdrift.config.load_config", broken_load_config)
        monkeypatch.setattr(
            "envdrift.vault.get_vault_client",
            lambda *_args, **_kwargs: SimpleNamespace(ensure_authenticated=lambda: None),
        )
        monkeypatch.setattr("envdrift.output.rich.print_service_sync_status", lambda *_, **__: None)
        monkeypatch.setattr("envdrift.output.rich.print_sync_result", lambda *_, **__: None)

        captured: dict[str, object] = {}

        class DummyEngine:
            def __init__(self, config, vault_client, mode, prompt_callback, progress_callback):
                captured["config"] = config

            def sync_all(self):
                return SimpleNamespace(services=[], has_errors=False)

        monkeypatch.setattr("envdrift.sync.engine.SyncEngine", DummyEngine)

        result = runner.invoke(
            app,
            [
                "sync",
                "-p",
                "azure",
                "--vault-url",
                "https://example.vault.azure.net/",
            ],
        )

        assert result.exit_code == 0
        assert captured["config"].default_vault_name == "fallback"

    def test_sync_missing_config_file_errors(self, tmp_path: Path):
        """Missing provided config file should exit with error."""

        missing_file = tmp_path / "nope.toml"

        result = runner.invoke(app, ["sync", "-c", str(missing_file), "-p", "aws"])

        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_sync_requires_vault_url_for_hashicorp(self, tmp_path: Path):
        """HashiCorp provider must supply --vault-url."""

        config_file = tmp_path / "pair.txt"
        config_file.write_text("secret=service")

        result = runner.invoke(app, ["sync", "-c", str(config_file), "-p", "hashicorp"])

        assert result.exit_code == 1
        assert "vault-url" in result.output.lower()

    def test_sync_requires_project_id_for_gcp(self, tmp_path: Path):
        """GCP provider must supply --project-id."""

        config_file = tmp_path / "pair.txt"
        config_file.write_text("secret=service")

        result = runner.invoke(app, ["sync", "-c", str(config_file), "-p", "gcp"])

        assert result.exit_code == 1
        assert "project-id" in result.output.lower()

    def test_sync_autodiscovery_hashicorp_defaults(self, monkeypatch, tmp_path: Path):
        """HashiCorp provider and URL should be read from discovered config."""

        config_file = tmp_path / "envdrift.toml"
        config_file.write_text(
            dedent(
                """
                [vault]
                provider = "hashicorp"

                [vault.hashicorp]
                url = "http://localhost:8200"

                [vault.sync]
                default_vault_name = "hc"

                [[vault.sync.mappings]]
                secret_name = "dotenv-key"
                folder_path = "services/api"
                """
            )
        )

        monkeypatch.chdir(tmp_path)
        captured: dict[str, object] = {}

        def fake_get_vault_client(provider, **kwargs):
            captured["provider"] = provider
            captured["kwargs"] = kwargs
            return SimpleNamespace(ensure_authenticated=lambda: None)

        monkeypatch.setattr("envdrift.vault.get_vault_client", fake_get_vault_client)
        monkeypatch.setattr("envdrift.output.rich.print_service_sync_status", lambda *_, **__: None)
        monkeypatch.setattr("envdrift.output.rich.print_sync_result", lambda *_, **__: None)

        class DummyEngine:
            def __init__(self, config, vault_client, mode, prompt_callback, progress_callback):
                captured["config"] = config

            def sync_all(self):
                return SimpleNamespace(services=[], has_errors=False)

        monkeypatch.setattr("envdrift.sync.engine.SyncEngine", DummyEngine)

        result = runner.invoke(app, ["sync"])

        assert result.exit_code == 0
        assert captured["provider"] == "hashicorp"
        assert captured["kwargs"]["url"] == "http://localhost:8200"
        assert captured["config"].default_vault_name == "hc"

    def test_sync_autodiscovery_gcp_defaults(self, monkeypatch, tmp_path: Path):
        """GCP provider and project ID should be read from discovered config."""
        config_file = tmp_path / "envdrift.toml"
        config_file.write_text(
            dedent(
                """
                [vault]
                provider = "gcp"

                [vault.gcp]
                project_id = "my-gcp-project"

                [vault.sync]
                default_vault_name = "gcp"

                [[vault.sync.mappings]]
                secret_name = "dotenv-key"
                folder_path = "services/api"
                """
            )
        )

        monkeypatch.chdir(tmp_path)
        captured: dict[str, object] = {}

        def fake_get_vault_client(provider, **kwargs):
            captured["provider"] = provider
            captured["kwargs"] = kwargs
            return SimpleNamespace(ensure_authenticated=lambda: None)

        monkeypatch.setattr("envdrift.vault.get_vault_client", fake_get_vault_client)
        monkeypatch.setattr("envdrift.output.rich.print_service_sync_status", lambda *_, **__: None)
        monkeypatch.setattr("envdrift.output.rich.print_sync_result", lambda *_, **__: None)

        class DummyEngine:
            def __init__(self, config, vault_client, mode, prompt_callback, progress_callback):
                captured["config"] = config

            def sync_all(self):
                return SimpleNamespace(services=[], has_errors=False)

        monkeypatch.setattr("envdrift.sync.engine.SyncEngine", DummyEngine)

        result = runner.invoke(app, ["sync"])

        assert result.exit_code == 0
        assert captured["provider"] == "gcp"
        assert captured["kwargs"]["project_id"] == "my-gcp-project"
        assert captured["config"].default_vault_name == "gcp"

    def test_sync_invalid_toml_config_errors(self, monkeypatch, tmp_path: Path):
        """Invalid TOML sync config should raise a SyncConfigError."""

        bad_config = tmp_path / "bad.toml"
        bad_config.write_text(
            dedent(
                """
                [vault.sync]

                [[vault.sync.mappings]]
                # missing secret_name
                folder_path = "services/api"
                """
            )
        )

        def skip_load_config(*_args, **_kwargs):
            from envdrift.config import ConfigNotFoundError

            raise ConfigNotFoundError("skip load for test")

        monkeypatch.setattr("envdrift.config.load_config", skip_load_config)

        result = runner.invoke(app, ["sync", "-c", str(bad_config), "-p", "aws"])

        assert result.exit_code == 1
        assert "invalid config file" in result.output.lower()

    def test_sync_reports_toml_syntax_error_for_explicit_config(self, tmp_path: Path):
        """Explicit TOML config with syntax errors should surface a user-facing error."""

        bad_config = tmp_path / "bad.toml"
        bad_config.write_text("invalid = [")

        result = runner.invoke(
            app,
            [
                "sync",
                "-c",
                str(bad_config),
                "-p",
                "aws",
            ],
        )

        assert result.exit_code == 1
        assert "toml syntax error" in result.output.lower()

    def test_sync_warns_on_autodiscovered_toml_syntax_error(self, monkeypatch, tmp_path: Path):
        """Auto-discovery should warn about TOML syntax errors instead of silently skipping."""

        bad_config = tmp_path / "envdrift.toml"
        bad_config.write_text("bad = [")

        monkeypatch.chdir(tmp_path)

        result = runner.invoke(
            app,
            [
                "sync",
                "-p",
                "azure",
                "--vault-url",
                "https://example.vault.azure.net/",
            ],
        )

        assert result.exit_code == 1
        assert "toml syntax error" in result.output.lower()


class TestPullCommand:
    """Tests for the pull CLI command."""

    def test_pull_hook_check_errors_exit(self, monkeypatch, tmp_path: Path):
        """Pull should stop early when hook checks fail."""
        config_file = tmp_path / "envdrift.toml"
        config_file.write_text('[vault]\nprovider = "aws"\n')

        dummy_config = SimpleNamespace()

        monkeypatch.setattr(
            "envdrift.cli_commands.sync.load_sync_config_and_client",
            lambda *args, **kwargs: (dummy_config, SimpleNamespace(), "aws", None, None, None),
        )
        monkeypatch.setattr(
            "envdrift.integrations.hook_check.ensure_git_hook_setup",
            lambda **_kwargs: ["hook check failed"],
        )

        result = runner.invoke(app, ["pull", "-c", str(config_file), "-p", "aws"])

        assert result.exit_code == 1
        assert "hook check failed" in result.output.lower()

    def test_pull_happy_path_decrypts_files(self, monkeypatch, tmp_path: Path):
        """Pull should sync and decrypt encrypted env files successfully."""
        service_dir = tmp_path / "service"
        service_dir.mkdir()
        env_file = service_dir / ".env.production"
        env_file.write_text("SECRET=encrypted:abc123")

        config_file = tmp_path / "envdrift.toml"
        config_file.write_text(
            dedent(
                f"""
                [vault]
                provider = "aws"

                [vault.aws]
                region = "us-east-1"

                [vault.sync]
                default_vault_name = "main"
                env_keys_filename = ".env.keys"

                [[vault.sync.mappings]]
                secret_name = "dotenv-key"
                folder_path = "{service_dir.as_posix()}"
                environment = "production"
                """
            ).lstrip()
        )

        monkeypatch.setattr("envdrift.vault.get_vault_client", lambda *_, **__: SimpleNamespace())
        monkeypatch.setattr("envdrift.output.rich.print_service_sync_status", lambda *_, **__: None)
        monkeypatch.setattr("envdrift.output.rich.print_sync_result", lambda *_, **__: None)

        _mock_sync_engine_success(monkeypatch)

        decrypted: list[Path] = []
        _mock_encryption_backend(monkeypatch, decrypted_paths=decrypted)

        result = runner.invoke(app, ["pull", "-c", str(config_file)])

        assert result.exit_code == 0
        assert env_file in decrypted
        assert "setup complete" in result.output.lower()

    def test_pull_skips_partial_combined_file(self, monkeypatch, tmp_path: Path):
        """Pull should skip combined partial-encryption files."""
        service_dir = tmp_path / "service"
        service_dir.mkdir()
        env_file = service_dir / ".env.production"
        env_file.write_text("SECRET=encrypted:abc123")

        config_file = tmp_path / "envdrift.toml"
        config_file.write_text(
            dedent(
                f"""
                [vault]
                provider = "aws"

                [vault.aws]
                region = "us-east-1"

                [vault.sync]
                env_keys_filename = ".env.keys"

                [[vault.sync.mappings]]
                secret_name = "dotenv-key"
                folder_path = "{service_dir.as_posix()}"
                environment = "production"

                [partial_encryption]
                enabled = true

                [[partial_encryption.environments]]
                name = "production"
                clear_file = "{(service_dir / ".env.production.clear").as_posix()}"
                secret_file = "{(service_dir / ".env.production.secret").as_posix()}"
                combined_file = "{env_file.as_posix()}"
                """
            ).lstrip()
        )

        monkeypatch.setattr("envdrift.vault.get_vault_client", lambda *_, **__: SimpleNamespace())
        monkeypatch.setattr(
            "envdrift.integrations.hook_check.ensure_git_hook_setup",
            lambda **_kwargs: [],
        )

        _mock_sync_engine_success(monkeypatch)

        decrypted: list[Path] = []
        _mock_encryption_backend(monkeypatch, decrypted_paths=decrypted)

        printed: list[str] = []
        monkeypatch.setattr(
            "envdrift.output.rich.console.print", lambda msg="", *a, **k: printed.append(str(msg))
        )

        result = runner.invoke(app, ["pull", "-c", str(config_file), "--skip-sync"])

        assert result.exit_code == 0
        assert env_file not in decrypted
        assert "partial encryption combined file" in " ".join(printed).lower()

    def test_pull_reports_service_status(self, monkeypatch, tmp_path: Path):
        """Pull should report service sync status when sync results include services."""
        service_dir = tmp_path / "service"
        service_dir.mkdir()
        env_file = service_dir / ".env.production"
        env_file.write_text("SECRET=encrypted:abc123")

        config_file = tmp_path / "envdrift.toml"
        config_file.write_text(
            dedent(
                f"""
                [vault]
                provider = "aws"

                [vault.aws]
                region = "us-east-1"

                [vault.sync]
                default_vault_name = "main"
                env_keys_filename = ".env.keys"

                [[vault.sync.mappings]]
                secret_name = "dotenv-key"
                folder_path = "{service_dir.as_posix()}"
                environment = "production"
                """
            ).lstrip()
        )

        monkeypatch.setattr("envdrift.vault.get_vault_client", lambda *_, **__: SimpleNamespace())

        reported: list[object] = []
        monkeypatch.setattr(
            "envdrift.output.rich.print_service_sync_status",
            lambda service: reported.append(service),
        )
        monkeypatch.setattr("envdrift.output.rich.print_sync_result", lambda *_, **__: None)

        class DummyEngine:
            def __init__(self, *_args, **_kwargs):
                pass

            def sync_all(self):
                return SimpleNamespace(services=[SimpleNamespace()], has_errors=False)

        monkeypatch.setattr("envdrift.sync.engine.SyncEngine", DummyEngine)

        decrypted: list[Path] = []
        _mock_encryption_backend(monkeypatch, decrypted_paths=decrypted)

        result = runner.invoke(app, ["pull", "-c", str(config_file)])

        assert result.exit_code == 0
        assert reported
        assert env_file in decrypted

    def test_pull_sync_failure_exits(self, monkeypatch, tmp_path: Path):
        """Pull should exit when vault sync fails."""
        service_dir = tmp_path / "service"
        service_dir.mkdir()
        (service_dir / ".env.production").write_text("SECRET=encrypted:abc123")

        config_file = tmp_path / "envdrift.toml"
        config_file.write_text(
            dedent(
                f"""
                [vault]
                provider = "aws"

                [vault.aws]
                region = "us-east-1"

                [vault.sync]
                default_vault_name = "main"
                env_keys_filename = ".env.keys"

                [[vault.sync.mappings]]
                secret_name = "dotenv-key"
                folder_path = "{service_dir.as_posix()}"
                environment = "production"
                """
            ).lstrip()
        )

        monkeypatch.setattr("envdrift.vault.get_vault_client", lambda *_, **__: SimpleNamespace())
        monkeypatch.setattr("envdrift.output.rich.print_service_sync_status", lambda *_, **__: None)
        monkeypatch.setattr("envdrift.output.rich.print_sync_result", lambda *_, **__: None)

        class FailingEngine:
            def __init__(self, *_args, **_kwargs):
                pass

            def sync_all(self):
                raise VaultError("boom")

        monkeypatch.setattr("envdrift.sync.engine.SyncEngine", FailingEngine)

        result = runner.invoke(app, ["pull", "-c", str(config_file)])

        assert result.exit_code == 1
        assert "sync failed" in result.output.lower()

    def test_pull_sync_result_errors_exits(self, monkeypatch, tmp_path: Path):
        """Pull should exit when sync results contain errors."""
        service_dir = tmp_path / "service"
        service_dir.mkdir()
        (service_dir / ".env.production").write_text("SECRET=encrypted:abc123")

        config_file = tmp_path / "envdrift.toml"
        config_file.write_text(
            dedent(
                f"""
                [vault]
                provider = "aws"

                [vault.aws]
                region = "us-east-1"

                [vault.sync]
                default_vault_name = "main"
                env_keys_filename = ".env.keys"

                [[vault.sync.mappings]]
                secret_name = "dotenv-key"
                folder_path = "{service_dir.as_posix()}"
                environment = "production"
                """
            ).lstrip()
        )

        monkeypatch.setattr("envdrift.vault.get_vault_client", lambda *_, **__: SimpleNamespace())
        monkeypatch.setattr("envdrift.output.rich.print_service_sync_status", lambda *_, **__: None)
        monkeypatch.setattr("envdrift.output.rich.print_sync_result", lambda *_, **__: None)

        class ErrorEngine:
            def __init__(self, *_args, **_kwargs):
                pass

            def sync_all(self):
                return SimpleNamespace(services=[], has_errors=True)

        monkeypatch.setattr("envdrift.sync.engine.SyncEngine", ErrorEngine)

        result = runner.invoke(app, ["pull", "-c", str(config_file)])

        assert result.exit_code == 1
        assert "setup incomplete due to sync errors" in result.output.lower()

    def test_pull_profile_activation_invalid_path_errors(self, monkeypatch, tmp_path: Path):
        """Pull should report invalid activation paths and exit non-zero."""
        service_a = tmp_path / "service-a"
        service_a.mkdir()
        env_a = service_a / ".env.production"
        env_a.write_text("SECRET=encrypted:abc")

        service_b = tmp_path / "service-b"
        service_b.mkdir()
        env_b = service_b / ".env.production"
        env_b.write_text("SECRET=encrypted:def")

        config_file = tmp_path / "envdrift.toml"
        config_file.write_text(
            dedent(
                f"""
                [vault]
                provider = "aws"

                [vault.aws]
                region = "us-east-1"

                [vault.sync]
                default_vault_name = "main"
                env_keys_filename = ".env.keys"

                [[vault.sync.mappings]]
                secret_name = "dotenv-key-a"
                folder_path = "{service_a.as_posix()}"
                environment = "production"
                profile = "local"
                activate_to = "active.env"

                [[vault.sync.mappings]]
                secret_name = "dotenv-key-b"
                folder_path = "{service_b.as_posix()}"
                environment = "production"
                profile = "local"
                activate_to = "../outside.env"
                """
            ).lstrip()
        )

        monkeypatch.setattr("envdrift.vault.get_vault_client", lambda *_, **__: SimpleNamespace())
        monkeypatch.setattr("envdrift.output.rich.print_service_sync_status", lambda *_, **__: None)
        monkeypatch.setattr("envdrift.output.rich.print_sync_result", lambda *_, **__: None)

        _mock_sync_engine_success(monkeypatch)

        decrypted: list[Path] = []
        _mock_encryption_backend(monkeypatch, decrypted_paths=decrypted)

        result = runner.invoke(app, ["pull", "-c", str(config_file), "--profile", "local"])

        assert result.exit_code == 1
        assert env_a in decrypted
        assert env_b in decrypted
        assert (service_a / "active.env").exists()

    def test_pull_dotenvx_missing_exits(self, monkeypatch, tmp_path: Path):
        """Pull should exit if dotenvx is not installed."""
        service_dir = tmp_path / "service"
        service_dir.mkdir()
        env_file = service_dir / ".env.production"
        env_file.write_text("SECRET=encrypted:abc123")

        config_file = tmp_path / "envdrift.toml"
        config_file.write_text(
            dedent(
                f"""
                [vault]
                provider = "aws"

                [vault.aws]
                region = "us-east-1"

                [vault.sync]
                env_keys_filename = ".env.keys"

                [[vault.sync.mappings]]
                secret_name = "dotenv-key"
                folder_path = "{service_dir.as_posix()}"
                environment = "production"
                """
            ).lstrip()
        )

        monkeypatch.setattr("envdrift.vault.get_vault_client", lambda *_, **__: SimpleNamespace())

        _mock_sync_engine_success(monkeypatch)
        _mock_encryption_backend(monkeypatch, installed=False)

        result = runner.invoke(app, ["pull", "-c", str(config_file)])

        assert result.exit_code == 1
        assert "dotenvx is not installed" in result.output.lower()

    def test_pull_decrypt_error_exits(self, monkeypatch, tmp_path: Path):
        """Pull should exit when dotenvx fails to decrypt."""
        service_dir = tmp_path / "service"
        service_dir.mkdir()
        env_file = service_dir / ".env.production"
        env_file.write_text("SECRET=encrypted:abc123")

        config_file = tmp_path / "envdrift.toml"
        config_file.write_text(
            dedent(
                f"""
                [vault]
                provider = "aws"

                [vault.aws]
                region = "us-east-1"

                [vault.sync]
                env_keys_filename = ".env.keys"

                [[vault.sync.mappings]]
                secret_name = "dotenv-key"
                folder_path = "{service_dir.as_posix()}"
                environment = "production"
                """
            ).lstrip()
        )

        monkeypatch.setattr("envdrift.vault.get_vault_client", lambda *_, **__: SimpleNamespace())

        _mock_sync_engine_success(monkeypatch)
        _mock_encryption_backend(monkeypatch, decrypt_side_effect=EncryptionBackendError("boom"))

        result = runner.invoke(app, ["pull", "-c", str(config_file)])

        assert result.exit_code == 1
        assert "could not be decrypted" in result.output.lower()

    def test_pull_profile_missing_errors(self, monkeypatch, tmp_path: Path):
        """Pull should fail when profile has no mappings."""
        service_dir = tmp_path / "service"
        service_dir.mkdir()
        (service_dir / ".env.production").write_text("SECRET=encrypted:abc123")

        config_file = tmp_path / "envdrift.toml"
        config_file.write_text(
            dedent(
                f"""
                [vault]
                provider = "aws"

                [vault.aws]
                region = "us-east-1"

                [vault.sync]
                env_keys_filename = ".env.keys"

                [[vault.sync.mappings]]
                secret_name = "dotenv-key"
                folder_path = "{service_dir.as_posix()}"
                environment = "production"
                profile = "local"
                """
            ).lstrip()
        )

        monkeypatch.setattr("envdrift.vault.get_vault_client", lambda *_, **__: SimpleNamespace())

        _mock_sync_engine_success(monkeypatch)
        _mock_encryption_backend(monkeypatch)

        result = runner.invoke(app, ["pull", "-c", str(config_file), "--profile", "prod"])

        assert result.exit_code == 1
        assert "no mappings found" in result.output.lower()

    def test_pull_multiple_env_files_skips(self, monkeypatch, tmp_path: Path):
        """Pull should skip when multiple .env.* files are present."""
        service_dir = tmp_path / "service"
        service_dir.mkdir()
        (service_dir / ".env.dev").write_text("SECRET=encrypted:abc123")
        (service_dir / ".env.staging").write_text("SECRET=encrypted:def456")

        config_file = tmp_path / "envdrift.toml"
        config_file.write_text(
            dedent(
                f"""
                [vault]
                provider = "aws"

                [vault.aws]
                region = "us-east-1"

                [vault.sync]
                env_keys_filename = ".env.keys"

                [[vault.sync.mappings]]
                secret_name = "dotenv-key"
                folder_path = "{service_dir.as_posix()}"
                environment = "production"
                """
            ).lstrip()
        )

        monkeypatch.setattr("envdrift.vault.get_vault_client", lambda *_, **__: SimpleNamespace())

        _mock_sync_engine_success(monkeypatch)
        _mock_encryption_backend(monkeypatch)

        result = runner.invoke(app, ["pull", "-c", str(config_file)])

        assert result.exit_code == 0
        assert "multiple .env" in result.output.lower()

    def test_pull_dotenvx_mismatch_errors(self, monkeypatch, tmp_path: Path):
        """Pull should error if file is dotenvx-encrypted but backend is sops."""
        service_dir = tmp_path / "service"
        service_dir.mkdir()
        env_file = service_dir / ".env.production"
        env_file.write_text(
            "#/---BEGIN DOTENV ENCRYPTED---/\nDOTENV_PUBLIC_KEY=abc\nSECRET=encrypted:abc123\n"
        )

        config_file = tmp_path / "envdrift.toml"
        config_file.write_text(
            dedent(
                f"""
                [vault]
                provider = "aws"

                [vault.aws]
                region = "us-east-1"

                [vault.sync]
                env_keys_filename = ".env.keys"

                [[vault.sync.mappings]]
                secret_name = "dotenv-key"
                folder_path = "{service_dir.as_posix()}"
                environment = "production"

                [encryption]
                backend = "sops"
                """
            ).lstrip()
        )

        monkeypatch.setattr("envdrift.vault.get_vault_client", lambda *_, **__: SimpleNamespace())
        _mock_sync_engine_success(monkeypatch)

        def sops_only_header(content: str) -> bool:
            return "ENC[AES256_GCM," in content or "sops:" in content

        dummy_backend = DummyEncryptionBackend(name="sops", has_encrypted_header=sops_only_header)
        monkeypatch.setattr(
            "envdrift.cli_commands.encryption_helpers.resolve_encryption_backend",
            lambda *_args, **_kwargs: (dummy_backend, EncryptionProvider.SOPS, None),
        )

        result = runner.invoke(app, ["pull", "-c", str(config_file)])

        assert result.exit_code == 1
        output = " ".join(result.output.lower().split())
        assert "encrypted with dotenvx" in output

    def test_pull_skip_sync_skips_vault_sync(self, monkeypatch, tmp_path: Path):
        """Pull with --skip-sync should skip vault sync and only decrypt files."""
        service_dir = tmp_path / "service"
        service_dir.mkdir()
        env_file = service_dir / ".env.production"
        env_file.write_text("SECRET=encrypted:abc123")

        config_file = tmp_path / "envdrift.toml"
        config_file.write_text(
            dedent(
                f"""
                [vault]
                provider = "aws"

                [vault.aws]
                region = "us-east-1"

                [vault.sync]
                default_vault_name = "main"
                env_keys_filename = ".env.keys"

                [[vault.sync.mappings]]
                secret_name = "dotenv-key"
                folder_path = "{service_dir.as_posix()}"
                environment = "production"
                """
            ).lstrip()
        )

        monkeypatch.setattr("envdrift.vault.get_vault_client", lambda *_, **__: SimpleNamespace())

        # Track whether sync_all was called
        sync_all_called = []

        class TrackingEngine:
            def __init__(self, *_args, **_kwargs):
                pass

            def sync_all(self):
                sync_all_called.append(True)
                return SimpleNamespace(services=[], has_errors=False)

        monkeypatch.setattr("envdrift.sync.engine.SyncEngine", TrackingEngine)
        monkeypatch.setattr("envdrift.output.rich.print_service_sync_status", lambda *_, **__: None)
        monkeypatch.setattr("envdrift.output.rich.print_sync_result", lambda *_, **__: None)

        decrypted: list[Path] = []
        _mock_encryption_backend(monkeypatch, decrypted_paths=decrypted)

        result = runner.invoke(app, ["pull", "-c", str(config_file), "--skip-sync"])

        assert result.exit_code == 0
        assert len(sync_all_called) == 0, "sync_all should not be called with --skip-sync"
        assert env_file in decrypted
        assert "skipped (--skip-sync)" in result.output.lower()
        assert "setup complete" in result.output.lower()

    def test_pull_uses_threadpool_when_configured(self, monkeypatch, tmp_path: Path):
        """Pull should use ThreadPoolExecutor when max_workers is configured."""
        service_a = tmp_path / "service-a"
        service_a.mkdir()
        env_a = service_a / ".env.production"
        env_a.write_text("SECRET=encrypted:abc123")

        service_b = tmp_path / "service-b"
        service_b.mkdir()
        env_b = service_b / ".env.production"
        env_b.write_text("SECRET=encrypted:def456")

        from envdrift.sync.config import ServiceMapping, SyncConfig

        sync_config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="key-a", folder_path=service_a, environment="production"
                ),
                ServiceMapping(
                    secret_name="key-b", folder_path=service_b, environment="production"
                ),
            ],
            env_keys_filename=".env.keys",
            max_workers=2,
        )

        monkeypatch.setattr(
            "envdrift.cli_commands.sync.load_sync_config_and_client",
            lambda *args, **kwargs: (sync_config, SimpleNamespace(), "aws", None, None, None),
        )
        monkeypatch.setattr(
            "envdrift.integrations.hook_check.ensure_git_hook_setup",
            lambda **_kwargs: [],
        )

        captured = {}

        class DummyExecutor:
            def __init__(self, max_workers=None):
                captured["max_workers"] = max_workers

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def map(self, func, iterable):
                return [func(item) for item in iterable]

        monkeypatch.setattr("envdrift.cli_commands.sync.ThreadPoolExecutor", DummyExecutor)
        _mock_encryption_backend(monkeypatch)

        result = runner.invoke(app, ["pull", "--skip-sync"])

        assert result.exit_code == 0
        assert captured.get("max_workers") == 2

    def test_pull_decrypt_result_failure_exits(self, monkeypatch, tmp_path: Path):
        """Pull should exit when decrypt returns an unsuccessful result."""
        service_dir = tmp_path / "service"
        service_dir.mkdir()
        env_file = service_dir / ".env.production"
        env_file.write_text("SECRET=encrypted:abc123")

        from envdrift.sync.config import ServiceMapping, SyncConfig

        sync_config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="dotenv-key",
                    folder_path=service_dir,
                    environment="production",
                )
            ],
            env_keys_filename=".env.keys",
        )

        monkeypatch.setattr(
            "envdrift.cli_commands.sync.load_sync_config_and_client",
            lambda *args, **kwargs: (sync_config, SimpleNamespace(), "aws", None, None, None),
        )
        monkeypatch.setattr(
            "envdrift.integrations.hook_check.ensure_git_hook_setup",
            lambda **_kwargs: [],
        )

        backend = DummyEncryptionBackend(name="dotenvx")

        def _decrypt_failure(env_path, **_kwargs):
            return EncryptionResult(success=False, message="bad decrypt", file_path=Path(env_path))

        backend.decrypt = _decrypt_failure  # type: ignore[method-assign]
        monkeypatch.setattr(
            "envdrift.cli_commands.encryption_helpers.resolve_encryption_backend",
            lambda *_args, **_kwargs: (backend, EncryptionProvider.DOTENVX, None),
        )

        result = runner.invoke(app, ["pull", "--skip-sync"])

        assert result.exit_code == 1
        assert "could not be decrypted" in result.output.lower()

    def test_pull_activation_copy_failure_exits(self, monkeypatch, tmp_path: Path):
        """Pull should report activation failures and exit non-zero."""
        service_dir = tmp_path / "service"
        service_dir.mkdir()
        env_file = service_dir / ".env.production"
        env_file.write_text("SECRET=encrypted:abc123")

        from envdrift.sync.config import ServiceMapping, SyncConfig

        sync_config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="dotenv-key",
                    folder_path=service_dir,
                    environment="production",
                    profile="local",
                    activate_to=Path("active.env"),
                )
            ],
            env_keys_filename=".env.keys",
        )

        monkeypatch.setattr(
            "envdrift.cli_commands.sync.load_sync_config_and_client",
            lambda *args, **kwargs: (sync_config, SimpleNamespace(), "aws", None, None, None),
        )
        monkeypatch.setattr(
            "envdrift.integrations.hook_check.ensure_git_hook_setup",
            lambda **_kwargs: [],
        )

        def _raise_copy_error(*_args, **_kwargs):
            raise OSError("copy failed")

        monkeypatch.setattr(
            "envdrift.cli_commands.sync.shutil.copy2",
            _raise_copy_error,
        )

        _mock_encryption_backend(monkeypatch)

        result = runner.invoke(app, ["pull", "--profile", "local", "--skip-sync"])

        assert result.exit_code == 1
        assert "activation failed" in result.output.lower()

    def test_pull_with_partial_encryption_decrypts_secret_files(
        self,
        monkeypatch,
        tmp_path: Path,
    ):
        """Pull should decrypt partial encryption .secret files when enabled."""
        service_dir = tmp_path / "service"
        service_dir.mkdir()

        # Create partial encryption files
        clear_file = service_dir / ".env.prod.clear"
        secret_file = service_dir / ".env.prod.secret"
        clear_file.write_text("APP_NAME=myapp\nDEBUG=true\n")
        secret_file.write_text("API_KEY=encrypted:abc123\nDB_PASS=encrypted:secret\n")

        config_file = tmp_path / "envdrift.toml"
        config_file.write_text(
            dedent(
                f"""
                [vault]
                provider = "aws"

                [vault.sync]
                [[vault.sync.mappings]]
                secret_name = "key"
                folder_path = "{service_dir.as_posix()}"
                environment = "prod"

                [partial_encryption]
                enabled = true

                [[partial_encryption.environments]]
                name = "prod"
                clear_file = "{clear_file.as_posix()}"
                secret_file = "{secret_file.as_posix()}"
                combined_file = "{(service_dir / ".env.prod").as_posix()}"
                """
            ).lstrip()
        )

        monkeypatch.setattr(
            "envdrift.cli_commands.encryption_helpers.resolve_encryption_backend",
            lambda *_args, **_kwargs: (
                DummyEncryptionBackend(
                    name="dotenvx",
                    installed=True,
                    has_encrypted_header=lambda _: False,
                ),
                EncryptionProvider.DOTENVX,
                None,
            ),
        )

        # Mock partial encryption pull
        decrypted_secrets = []

        def mock_pull_partial(env_config):
            decrypted_secrets.append(env_config.name)
            # Simulate decryption
            secret_path = Path(env_config.secret_file)
            secret_path.write_text("API_KEY=decrypted_key\nDB_PASS=decrypted_pass\n")
            return True

        monkeypatch.setattr(
            "envdrift.core.partial_encryption.pull_partial_encryption",
            mock_pull_partial,
        )

        from envdrift.sync.config import ServiceMapping, SyncConfig

        sync_config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="key",
                    folder_path=service_dir,
                    environment="prod",
                )
            ],
        )

        monkeypatch.setattr(
            "envdrift.cli_commands.sync.load_sync_config_and_client",
            lambda *_args, **_kwargs: (sync_config, SimpleNamespace(), "aws", None, None, None),
        )
        monkeypatch.setattr(
            "envdrift.integrations.hook_check.ensure_git_hook_setup",
            lambda **_kwargs: [],
        )

        result = runner.invoke(app, ["pull", "-c", str(config_file), "--skip-sync"])

        assert result.exit_code == 0
        assert "Step 3" in result.output
        assert "Partial Encryption Summary" in result.output
        assert "prod" in decrypted_secrets

    def test_pull_merge_creates_combined_file(
        self,
        monkeypatch,
        tmp_path: Path,
    ):
        """Pull --merge should create combined decrypted file from .clear + .secret."""
        service_dir = tmp_path / "service"
        service_dir.mkdir()

        # Create partial encryption files
        clear_file = service_dir / ".env.prod.clear"
        secret_file = service_dir / ".env.prod.secret"
        combined_file = service_dir / ".env.prod"

        clear_file.write_text("APP_NAME=myapp\nDEBUG=true\n")
        secret_file.write_text("API_KEY=decrypted_key\nDB_PASS=decrypted_pass\n")

        config_file = tmp_path / "envdrift.toml"
        config_file.write_text(
            dedent(
                f"""
                [vault]
                provider = "aws"

                [vault.sync]
                [[vault.sync.mappings]]
                secret_name = "key"
                folder_path = "{service_dir.as_posix()}"
                environment = "prod"

                [partial_encryption]
                enabled = true

                [[partial_encryption.environments]]
                name = "prod"
                clear_file = "{clear_file.as_posix()}"
                secret_file = "{secret_file.as_posix()}"
                combined_file = "{combined_file.as_posix()}"
                """
            ).lstrip()
        )

        monkeypatch.setattr(
            "envdrift.cli_commands.encryption_helpers.resolve_encryption_backend",
            lambda *_args, **_kwargs: (
                DummyEncryptionBackend(
                    name="dotenvx",
                    installed=True,
                    has_encrypted_header=lambda _: False,
                ),
                EncryptionProvider.DOTENVX,
                None,
            ),
        )

        # Mock partial encryption pull (already decrypted)
        monkeypatch.setattr(
            "envdrift.core.partial_encryption.pull_partial_encryption",
            lambda _: False,  # Already decrypted
        )

        from envdrift.sync.config import ServiceMapping, SyncConfig

        sync_config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="key",
                    folder_path=service_dir,
                    environment="prod",
                )
            ],
        )

        monkeypatch.setattr(
            "envdrift.cli_commands.sync.load_sync_config_and_client",
            lambda *_args, **_kwargs: (sync_config, SimpleNamespace(), "aws", None, None, None),
        )
        monkeypatch.setattr(
            "envdrift.integrations.hook_check.ensure_git_hook_setup",
            lambda **_kwargs: [],
        )

        result = runner.invoke(app, ["pull", "-c", str(config_file), "--skip-sync", "--merge"])

        assert result.exit_code == 0
        assert "merged (decrypted)" in result.output.lower()
        assert combined_file.exists()

        # Check combined file content
        content = combined_file.read_text()
        assert "APP_NAME=myapp" in content
        assert "DEBUG=true" in content
        assert "API_KEY=decrypted_key" in content
        assert "DB_PASS=decrypted_pass" in content


class TestLockCommand:
    """Tests for the lock CLI command."""

    def test_lock_hook_check_errors_exit(self, monkeypatch, tmp_path: Path):
        """Lock should stop early when hook checks fail."""
        config_file = tmp_path / "envdrift.toml"
        config_file.write_text('[vault]\nprovider = "aws"\n')

        dummy_config = SimpleNamespace()
        monkeypatch.setattr(
            "envdrift.cli_commands.sync.load_sync_config_and_client",
            lambda *args, **kwargs: (dummy_config, SimpleNamespace(), "aws", None, None, None),
        )
        monkeypatch.setattr(
            "envdrift.integrations.hook_check.ensure_git_hook_setup",
            lambda **_kwargs: ["hook check failed"],
        )

        result = runner.invoke(app, ["lock", "-c", str(config_file), "-p", "aws"])

        assert result.exit_code == 1
        assert "hook check failed" in result.output.lower()

    def test_lock_check_mode_exits_when_unencrypted(self, monkeypatch, tmp_path: Path):
        """Check mode should fail when a file needs encryption."""
        service_dir = tmp_path / "service"
        service_dir.mkdir()
        env_file = service_dir / ".env.production"
        env_file.write_text("SECRET=value")

        config_file = tmp_path / "envdrift.toml"
        config_file.write_text(
            dedent(
                f"""
                [vault]
                provider = "aws"

                [vault.aws]
                region = "us-east-1"

                [vault.sync]
                env_keys_filename = ".env.keys"

                [[vault.sync.mappings]]
                secret_name = "dotenv-key"
                folder_path = "{service_dir.as_posix()}"
                environment = "production"
                """
            ).lstrip()
        )

        monkeypatch.setattr("envdrift.vault.get_vault_client", lambda *_, **__: SimpleNamespace())
        _mock_encryption_backend(monkeypatch)

        result = runner.invoke(app, ["lock", "-c", str(config_file), "--check"])

        assert result.exit_code == 1
        assert "need encryption" in result.output.lower()

    def test_lock_skips_partial_combined_file(self, monkeypatch, tmp_path: Path):
        """Lock should skip combined partial-encryption files."""
        service_dir = tmp_path / "service"
        service_dir.mkdir()
        env_file = service_dir / ".env.production"
        env_file.write_text("SECRET=encrypted:abc123")

        config_file = tmp_path / "envdrift.toml"
        config_file.write_text(
            dedent(
                f"""
                [vault]
                provider = "aws"

                [vault.aws]
                region = "us-east-1"

                [vault.sync]
                env_keys_filename = ".env.keys"

                [[vault.sync.mappings]]
                secret_name = "dotenv-key"
                folder_path = "{service_dir.as_posix()}"
                environment = "production"

                [partial_encryption]
                enabled = true

                [[partial_encryption.environments]]
                name = "production"
                clear_file = "{(service_dir / ".env.production.clear").as_posix()}"
                secret_file = "{(service_dir / ".env.production.secret").as_posix()}"
                combined_file = "{env_file.as_posix()}"
                """
            ).lstrip()
        )

        monkeypatch.setattr("envdrift.vault.get_vault_client", lambda *_, **__: SimpleNamespace())
        monkeypatch.setattr(
            "envdrift.integrations.hook_check.ensure_git_hook_setup",
            lambda **_kwargs: [],
        )

        encrypted: list[Path] = []
        _mock_encryption_backend(monkeypatch, encrypted_paths=encrypted)

        printed: list[str] = []
        monkeypatch.setattr(
            "envdrift.output.rich.console.print", lambda msg="", *a, **k: printed.append(str(msg))
        )

        result = runner.invoke(app, ["lock", "-c", str(config_file), "--force"])

        assert result.exit_code == 0
        assert env_file not in encrypted
        printed_output = " ".join(printed).lower()
        assert "partial encryption combined file" in printed_output
        assert "use --all" in printed_output

    def test_lock_all_processes_partial_encryption_files(self, monkeypatch, tmp_path: Path):
        """Lock --all should encrypt .secret files and delete combined files."""
        service_dir = tmp_path / "service"
        service_dir.mkdir()
        env_file = service_dir / ".env.production"
        env_file.write_text("SECRET=value")
        secret_file = service_dir / ".env.production.secret"
        secret_file.write_text("DB_PASSWORD=secret123")
        clear_file = service_dir / ".env.production.clear"
        clear_file.write_text("APP_NAME=myapp")

        config_file = tmp_path / "envdrift.toml"
        config_file.write_text(
            dedent(
                f"""
                [vault]
                provider = "aws"

                [vault.aws]
                region = "us-east-1"

                [vault.sync]
                env_keys_filename = ".env.keys"

                [[vault.sync.mappings]]
                secret_name = "dotenv-key"
                folder_path = "{service_dir.as_posix()}"
                environment = "production"

                [partial_encryption]
                enabled = true

                [[partial_encryption.environments]]
                name = "production"
                clear_file = "{clear_file.as_posix()}"
                secret_file = "{secret_file.as_posix()}"
                combined_file = "{env_file.as_posix()}"
                """
            ).lstrip()
        )

        monkeypatch.setattr("envdrift.vault.get_vault_client", lambda *_, **__: SimpleNamespace())
        monkeypatch.setattr(
            "envdrift.integrations.hook_check.ensure_git_hook_setup",
            lambda **_kwargs: [],
        )

        encrypted: list[Path] = []
        _mock_encryption_backend(monkeypatch, encrypted_paths=encrypted)

        result = runner.invoke(app, ["lock", "-c", str(config_file), "--force", "--all"])

        assert result.exit_code == 0
        # Both the main env file and the secret file should be encrypted
        assert env_file.resolve() in [p.resolve() for p in encrypted]
        assert secret_file.resolve() in [p.resolve() for p in encrypted]
        # Combined file should be deleted
        assert not env_file.exists()
        assert "combined files deleted" in result.output.lower()
        assert "including partial encryption" in result.output.lower()

    def test_lock_all_deletes_combined_file(self, monkeypatch, tmp_path: Path):
        """Lock --all should delete combined files after processing."""
        service_dir = tmp_path / "service"
        service_dir.mkdir()
        env_file = service_dir / ".env.production"
        env_file.write_text("SECRET=encrypted:abc123")  # Already encrypted
        secret_file = service_dir / ".env.production.secret"
        secret_file.write_text("DB_PASSWORD=encrypted:xyz789")  # Already encrypted

        config_file = tmp_path / "envdrift.toml"
        config_file.write_text(
            dedent(
                f"""
                [vault]
                provider = "aws"

                [vault.aws]
                region = "us-east-1"

                [vault.sync]
                env_keys_filename = ".env.keys"

                [[vault.sync.mappings]]
                secret_name = "dotenv-key"
                folder_path = "{service_dir.as_posix()}"
                environment = "production"

                [partial_encryption]
                enabled = true

                [[partial_encryption.environments]]
                name = "production"
                clear_file = "{(service_dir / ".env.production.clear").as_posix()}"
                secret_file = "{secret_file.as_posix()}"
                combined_file = "{env_file.as_posix()}"
                """
            ).lstrip()
        )

        monkeypatch.setattr("envdrift.vault.get_vault_client", lambda *_, **__: SimpleNamespace())
        monkeypatch.setattr(
            "envdrift.integrations.hook_check.ensure_git_hook_setup",
            lambda **_kwargs: [],
        )

        # Mark content as already encrypted
        dummy = _mock_encryption_backend(monkeypatch)
        dummy.is_encrypted = lambda content: "encrypted:" in content

        result = runner.invoke(app, ["lock", "-c", str(config_file), "--force", "--all"])

        assert result.exit_code == 0
        # Combined file should be deleted even if secret was already encrypted
        assert not env_file.exists()

    def test_lock_all_check_mode_reports_but_does_not_modify(self, monkeypatch, tmp_path: Path):
        """Lock --all --check should report what would be done without modifying."""
        service_dir = tmp_path / "service"
        service_dir.mkdir()
        env_file = service_dir / ".env.production"
        env_file.write_text("SECRET=value")
        secret_file = service_dir / ".env.production.secret"
        secret_file.write_text("DB_PASSWORD=secret123")

        config_file = tmp_path / "envdrift.toml"
        config_file.write_text(
            dedent(
                f"""
                [vault]
                provider = "aws"

                [vault.aws]
                region = "us-east-1"

                [vault.sync]
                env_keys_filename = ".env.keys"

                [[vault.sync.mappings]]
                secret_name = "dotenv-key"
                folder_path = "{service_dir.as_posix()}"
                environment = "production"

                [partial_encryption]
                enabled = true

                [[partial_encryption.environments]]
                name = "production"
                clear_file = "{(service_dir / ".env.production.clear").as_posix()}"
                secret_file = "{secret_file.as_posix()}"
                combined_file = "{env_file.as_posix()}"
                """
            ).lstrip()
        )

        monkeypatch.setattr("envdrift.vault.get_vault_client", lambda *_, **__: SimpleNamespace())
        monkeypatch.setattr(
            "envdrift.integrations.hook_check.ensure_git_hook_setup",
            lambda **_kwargs: [],
        )

        encrypted: list[Path] = []
        _mock_encryption_backend(monkeypatch, encrypted_paths=encrypted)

        result = runner.invoke(app, ["lock", "-c", str(config_file), "--check", "--all"])

        # Check mode should exit with 1 when files need encryption
        assert result.exit_code == 1
        # Files should NOT be modified
        assert env_file.exists()
        assert secret_file.exists()
        # No files should have been encrypted
        assert len(encrypted) == 0
        # Normalize whitespace to handle terminal line wrapping
        normalized_output = " ".join(result.output.lower().split())
        assert "would be encrypted" in normalized_output
        assert "would be deleted" in normalized_output

    def test_lock_verify_vault_mismatch_fails(self, monkeypatch, tmp_path: Path):
        """Verify vault should fail on key mismatch."""
        service_dir = tmp_path / "service"
        service_dir.mkdir()
        env_keys = service_dir / ".env.keys"
        env_keys.write_text("DOTENV_PRIVATE_KEY_PRODUCTION=local")

        config_file = tmp_path / "envdrift.toml"
        config_file.write_text(
            dedent(
                f"""
                [vault]
                provider = "aws"

                [vault.aws]
                region = "us-east-1"

                [vault.sync]
                env_keys_filename = ".env.keys"

                [[vault.sync.mappings]]
                secret_name = "dotenv-key"
                folder_path = "{service_dir.as_posix()}"
                environment = "production"
                """
            ).lstrip()
        )

        class DummyVault:
            def ensure_authenticated(self):
                """
                Ensure the current context is authenticated for subsequent operations.

                Verify or establish an authenticated session so callers can assume valid credentials afterwards.
                """
                return None

            def get_secret(self, _name):
                """
                Provide a mocked secret object containing a production DOTENV private key.

                Parameters:
                    _name: Ignored; present to match the expected secret-retrieval signature.

                Returns:
                    SimpleNamespace: An object with a `value` attribute set to "DOTENV_PRIVATE_KEY_PRODUCTION=remote".
                """
                return SimpleNamespace(value="DOTENV_PRIVATE_KEY_PRODUCTION=remote")

        monkeypatch.setattr("envdrift.vault.get_vault_client", lambda *_, **__: DummyVault())

        result = runner.invoke(app, ["lock", "-c", str(config_file), "--verify-vault"])

        assert result.exit_code == 1
        assert "key mismatch" in result.output.lower()

    def test_lock_skips_already_encrypted_file(self, monkeypatch, tmp_path: Path):
        """Lock should skip fully encrypted files."""
        service_dir = tmp_path / "service"
        service_dir.mkdir()
        env_file = service_dir / ".env.production"
        env_file.write_text("SECRET=encrypted:abc123")

        config_file = tmp_path / "envdrift.toml"
        config_file.write_text(
            dedent(
                f"""
                [vault]
                provider = "aws"

                [vault.aws]
                region = "us-east-1"

                [vault.sync]
                env_keys_filename = ".env.keys"

                [[vault.sync.mappings]]
                secret_name = "dotenv-key"
                folder_path = "{service_dir.as_posix()}"
                environment = "production"
                """
            ).lstrip()
        )

        monkeypatch.setattr("envdrift.vault.get_vault_client", lambda *_, **__: SimpleNamespace())
        _mock_encryption_backend(monkeypatch)

        result = runner.invoke(app, ["lock", "-c", str(config_file), "--force"])

        assert result.exit_code == 0
        assert "already encrypted" in result.output.lower()

    def test_lock_skips_empty_dotenvx_encrypted_file(self, monkeypatch, tmp_path: Path):
        """Lock should skip encrypted files with no value lines."""
        service_dir = tmp_path / "service"
        service_dir.mkdir()
        env_file = service_dir / ".env.production"
        env_file.write_text("#/---BEGIN DOTENV ENCRYPTED---/\n#/---END DOTENV ENCRYPTED---/\n")

        config_file = tmp_path / "envdrift.toml"
        config_file.write_text(
            dedent(
                f"""
                [vault]
                provider = "aws"

                [vault.aws]
                region = "us-east-1"

                [vault.sync]
                env_keys_filename = ".env.keys"

                [[vault.sync.mappings]]
                secret_name = "dotenv-key"
                folder_path = "{service_dir.as_posix()}"
                environment = "production"
                """
            ).lstrip()
        )

        monkeypatch.setattr("envdrift.vault.get_vault_client", lambda *_, **__: SimpleNamespace())
        _mock_encryption_backend(monkeypatch, provider=EncryptionProvider.DOTENVX)

        result = runner.invoke(app, ["lock", "-c", str(config_file), "--force"])

        assert result.exit_code == 0
        assert "already encrypted" in result.output.lower()

    def test_lock_errors_on_dotenvx_mismatch(self, monkeypatch, tmp_path: Path):
        """Lock should error when dotenvx files exist under sops config."""
        service_dir = tmp_path / "service"
        service_dir.mkdir()
        env_file = service_dir / ".env.production"
        env_file.write_text(
            "#/---BEGIN DOTENV ENCRYPTED---/\nDOTENV_PUBLIC_KEY=abc\nSECRET=encrypted:abc123\n"
        )

        config_file = tmp_path / "envdrift.toml"
        config_file.write_text(
            dedent(
                f"""
                [vault]
                provider = "aws"

                [vault.aws]
                region = "us-east-1"

                [vault.sync]
                env_keys_filename = ".env.keys"

                [[vault.sync.mappings]]
                secret_name = "dotenv-key"
                folder_path = "{service_dir.as_posix()}"
                environment = "production"

                [encryption]
                backend = "sops"
                """
            ).lstrip()
        )

        monkeypatch.setattr("envdrift.vault.get_vault_client", lambda *_, **__: SimpleNamespace())

        def sops_only_header(content: str) -> bool:
            return "ENC[AES256_GCM," in content or "sops:" in content

        dummy_backend = DummyEncryptionBackend(name="sops", has_encrypted_header=sops_only_header)
        monkeypatch.setattr(
            "envdrift.cli_commands.encryption_helpers.resolve_encryption_backend",
            lambda *_args, **_kwargs: (dummy_backend, EncryptionProvider.SOPS, None),
        )

        result = runner.invoke(app, ["lock", "-c", str(config_file), "--force"])

        assert result.exit_code == 1
        output = " ".join(result.output.lower().split())
        assert "encrypted with dotenvx" in output

    def test_lock_skips_sops_encrypted_file(self, monkeypatch, tmp_path: Path):
        """Lock should skip files already encrypted with sops."""
        service_dir = tmp_path / "service"
        service_dir.mkdir()
        env_file = service_dir / ".env.production"
        env_file.write_text("SECRET=ENC[AES256_GCM,data:abc,iv:def,tag:ghi,type:str]")

        config_file = tmp_path / "envdrift.toml"
        config_file.write_text(
            dedent(
                f"""
                [vault]
                provider = "aws"

                [vault.aws]
                region = "us-east-1"

                [vault.sync]
                env_keys_filename = ".env.keys"

                [[vault.sync.mappings]]
                secret_name = "sops-key"
                folder_path = "{service_dir.as_posix()}"
                environment = "production"

                [encryption]
                backend = "sops"
                """
            ).lstrip()
        )

        monkeypatch.setattr("envdrift.vault.get_vault_client", lambda *_, **__: SimpleNamespace())

        def sops_only_header(content: str) -> bool:
            return "ENC[AES256_GCM," in content or "sops:" in content

        dummy_backend = DummyEncryptionBackend(name="sops", has_encrypted_header=sops_only_header)
        monkeypatch.setattr(
            "envdrift.cli_commands.encryption_helpers.resolve_encryption_backend",
            lambda *_args, **_kwargs: (dummy_backend, EncryptionProvider.SOPS, None),
        )

        result = runner.invoke(app, ["lock", "-c", str(config_file), "--force"])

        assert result.exit_code == 0
        assert "already encrypted" in result.output.lower()

    def test_lock_force_uses_threadpool_when_configured(self, monkeypatch, tmp_path: Path):
        """Lock should use ThreadPoolExecutor when max_workers is configured."""
        service_a = tmp_path / "service-a"
        service_a.mkdir()
        env_a = service_a / ".env.production"
        env_a.write_text("SECRET=value")

        service_b = tmp_path / "service-b"
        service_b.mkdir()
        env_b = service_b / ".env.production"
        env_b.write_text("SECRET=other")

        from envdrift.sync.config import ServiceMapping, SyncConfig

        sync_config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="key-a", folder_path=service_a, environment="production"
                ),
                ServiceMapping(
                    secret_name="key-b", folder_path=service_b, environment="production"
                ),
            ],
            env_keys_filename=".env.keys",
            max_workers=2,
        )

        monkeypatch.setattr(
            "envdrift.cli_commands.sync.load_sync_config_and_client",
            lambda *args, **kwargs: (sync_config, SimpleNamespace(), "aws", None, None, None),
        )
        monkeypatch.setattr(
            "envdrift.integrations.hook_check.ensure_git_hook_setup",
            lambda **_kwargs: [],
        )

        captured = {}

        class DummyExecutor:
            def __init__(self, max_workers=None):
                captured["max_workers"] = max_workers

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def map(self, func, iterable):
                return [func(item) for item in iterable]

        monkeypatch.setattr("envdrift.cli_commands.sync.ThreadPoolExecutor", DummyExecutor)
        _mock_encryption_backend(monkeypatch)

        result = runner.invoke(app, ["lock", "--force"])

        assert result.exit_code == 0
        assert captured.get("max_workers") == 2

    def test_lock_non_force_prompts_and_encrypts(self, monkeypatch, tmp_path: Path):
        """Lock without --force should prompt and encrypt when accepted."""
        service_dir = tmp_path / "service"
        service_dir.mkdir()
        env_file = service_dir / ".env.production"
        env_file.write_text("SECRET=value")

        from envdrift.sync.config import ServiceMapping, SyncConfig

        sync_config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="dotenv-key",
                    folder_path=service_dir,
                    environment="production",
                )
            ],
            env_keys_filename=".env.keys",
        )

        monkeypatch.setattr(
            "envdrift.cli_commands.sync.load_sync_config_and_client",
            lambda *args, **kwargs: (sync_config, SimpleNamespace(), "aws", None, None, None),
        )
        monkeypatch.setattr(
            "envdrift.integrations.hook_check.ensure_git_hook_setup",
            lambda **_kwargs: [],
        )
        monkeypatch.setattr("envdrift.output.rich.console.input", lambda *_args, **_kwargs: "y")

        _mock_encryption_backend(monkeypatch)

        result = runner.invoke(app, ["lock"])

        assert result.exit_code == 0
        assert "encrypted" in result.output.lower()

    def test_lock_force_sops_encryption_path(self, monkeypatch, tmp_path: Path):
        """Lock with --force should use the non-dotenvx encrypt path when configured."""
        service_dir = tmp_path / "service"
        service_dir.mkdir()
        env_file = service_dir / ".env.production"
        env_file.write_text("SECRET=value")

        from envdrift.sync.config import ServiceMapping, SyncConfig

        sync_config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="sops-key",
                    folder_path=service_dir,
                    environment="production",
                )
            ],
            env_keys_filename=".env.keys",
        )

        monkeypatch.setattr(
            "envdrift.cli_commands.sync.load_sync_config_and_client",
            lambda *args, **kwargs: (sync_config, SimpleNamespace(), "aws", None, None, None),
        )
        monkeypatch.setattr(
            "envdrift.integrations.hook_check.ensure_git_hook_setup",
            lambda **_kwargs: [],
        )

        _mock_encryption_backend(monkeypatch, provider=EncryptionProvider.SOPS)

        result = runner.invoke(app, ["lock", "--force"])

        assert result.exit_code == 0
        assert "encrypted" in result.output.lower()

    def test_lock_force_reuses_dotenvx_lock(self, monkeypatch, tmp_path: Path):
        """Lock with multiple files should reuse the dotenvx lock."""
        service_dir = tmp_path / "service"
        service_dir.mkdir()
        env_prod = service_dir / ".env.production"
        env_prod.write_text("SECRET=value")
        env_staging = service_dir / ".env.staging"
        env_staging.write_text("SECRET=other")

        from envdrift.sync.config import ServiceMapping, SyncConfig

        sync_config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="dotenv-key-prod",
                    folder_path=service_dir,
                    environment="production",
                ),
                ServiceMapping(
                    secret_name="dotenv-key-staging",
                    folder_path=service_dir,
                    environment="staging",
                ),
            ],
            env_keys_filename=".env.keys",
        )

        monkeypatch.setattr(
            "envdrift.cli_commands.sync.load_sync_config_and_client",
            lambda *args, **kwargs: (sync_config, SimpleNamespace(), "aws", None, None, None),
        )
        monkeypatch.setattr(
            "envdrift.integrations.hook_check.ensure_git_hook_setup",
            lambda **_kwargs: [],
        )

        class DummyExecutor:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def map(self, func, iterable):
                return [func(item) for item in iterable]

        monkeypatch.setattr("envdrift.cli_commands.sync.ThreadPoolExecutor", DummyExecutor)
        _mock_encryption_backend(monkeypatch)

        result = runner.invoke(app, ["lock", "--force"])

        assert result.exit_code == 0

    def test_lock_force_falsey_lock_skips_context(self, monkeypatch, tmp_path: Path):
        """Lock should fall back to unlocked encrypt path when lock is falsey."""
        service_dir = tmp_path / "service"
        service_dir.mkdir()
        env_file = service_dir / ".env.production"
        env_file.write_text("SECRET=value")

        from envdrift.sync.config import ServiceMapping, SyncConfig

        sync_config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="dotenv-key",
                    folder_path=service_dir,
                    environment="production",
                )
            ],
            env_keys_filename=".env.keys",
        )

        monkeypatch.setattr(
            "envdrift.cli_commands.sync.load_sync_config_and_client",
            lambda *args, **kwargs: (sync_config, SimpleNamespace(), "aws", None, None, None),
        )
        monkeypatch.setattr(
            "envdrift.integrations.hook_check.ensure_git_hook_setup",
            lambda **_kwargs: [],
        )

        class FalseyLock:
            def __bool__(self):
                return False

        monkeypatch.setattr("envdrift.cli_commands.sync.Lock", FalseyLock)
        _mock_encryption_backend(monkeypatch)

        result = runner.invoke(app, ["lock", "--force"])

        assert result.exit_code == 0

    def test_lock_force_encrypt_error_reports(self, monkeypatch, tmp_path: Path):
        """Lock should report encryption errors from the worker path."""
        service_dir = tmp_path / "service"
        service_dir.mkdir()
        env_file = service_dir / ".env.production"
        env_file.write_text("SECRET=value")

        from envdrift.sync.config import ServiceMapping, SyncConfig

        sync_config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="dotenv-key",
                    folder_path=service_dir,
                    environment="production",
                )
            ],
            env_keys_filename=".env.keys",
        )

        monkeypatch.setattr(
            "envdrift.cli_commands.sync.load_sync_config_and_client",
            lambda *args, **kwargs: (sync_config, SimpleNamespace(), "aws", None, None, None),
        )
        monkeypatch.setattr(
            "envdrift.integrations.hook_check.ensure_git_hook_setup",
            lambda **_kwargs: [],
        )

        _mock_encryption_backend(monkeypatch, encrypt_side_effect=EncryptionBackendError("boom"))

        result = runner.invoke(app, ["lock", "--force"])

        assert result.exit_code == 1
        assert "boom" in result.output.lower()

    def test_lock_force_encrypt_result_failure_reports(self, monkeypatch, tmp_path: Path):
        """Lock should report unsuccessful encrypt results from the worker path."""
        service_dir = tmp_path / "service"
        service_dir.mkdir()
        env_file = service_dir / ".env.production"
        env_file.write_text("SECRET=value")

        from envdrift.sync.config import ServiceMapping, SyncConfig

        sync_config = SyncConfig(
            mappings=[
                ServiceMapping(
                    secret_name="dotenv-key",
                    folder_path=service_dir,
                    environment="production",
                )
            ],
            env_keys_filename=".env.keys",
        )

        monkeypatch.setattr(
            "envdrift.cli_commands.sync.load_sync_config_and_client",
            lambda *args, **kwargs: (sync_config, SimpleNamespace(), "aws", None, None, None),
        )
        monkeypatch.setattr(
            "envdrift.integrations.hook_check.ensure_git_hook_setup",
            lambda **_kwargs: [],
        )

        backend = DummyEncryptionBackend(name="dotenvx")

        def _encrypt_failure(env_path, **_kwargs):
            return EncryptionResult(success=False, message="bad encrypt", file_path=Path(env_path))

        backend.encrypt = _encrypt_failure  # type: ignore[method-assign]
        monkeypatch.setattr(
            "envdrift.cli_commands.encryption_helpers.resolve_encryption_backend",
            lambda *_args, **_kwargs: (backend, EncryptionProvider.DOTENVX, None),
        )

        result = runner.invoke(app, ["lock", "--force"])

        assert result.exit_code == 1
        assert "bad encrypt" in result.output.lower()


class TestVaultPushCommand:
    """Tests for vault-push command."""

    def test_vault_push_requires_provider(self, tmp_path: Path, monkeypatch):
        """vault-push should require a provider."""
        # Run from isolated tmp directory to prevent auto-discovery of parent config
        monkeypatch.chdir(tmp_path)
        # Create .env.keys file to pass file validation
        (tmp_path / ".env.keys").write_text("DOTENV_PRIVATE_KEY_SOAK=test")

        result = runner.invoke(
            app,
            ["vault-push", str(tmp_path), "secret-name", "--env", "soak"],
        )
        assert result.exit_code == 1
        assert "provider required" in result.output.lower()

    def test_vault_push_requires_vault_url_for_azure(self, tmp_path: Path, monkeypatch):
        """vault-push should require vault URL for azure provider."""
        # Run from isolated tmp directory to prevent auto-discovery of parent config
        monkeypatch.chdir(tmp_path)
        # Create .env.keys file to pass file validation
        (tmp_path / ".env.keys").write_text("DOTENV_PRIVATE_KEY_SOAK=test")

        result = runner.invoke(
            app,
            [
                "vault-push",
                str(tmp_path),
                "secret-name",
                "--env",
                "soak",
                "-p",
                "azure",
            ],
        )
        assert result.exit_code == 1
        assert "vault-url required" in result.output.lower()

    def test_vault_push_requires_project_id_for_gcp(self):
        """vault-push should require project ID for gcp provider."""
        result = runner.invoke(
            app,
            [
                "vault-push",
                "--direct",
                "secret-name",
                "value",
                "-p",
                "gcp",
            ],
        )
        assert result.exit_code == 1
        assert "project-id" in result.output.lower()

    def test_vault_push_normal_mode_requires_all_args(self, tmp_path: Path):
        """Normal mode requires folder, secret-name, and --env."""
        result = runner.invoke(
            app,
            [
                "vault-push",
                str(tmp_path),
                "-p",
                "aws",
            ],
        )
        assert result.exit_code == 1
        assert "required" in result.output.lower()

    def test_vault_push_file_not_found(self, tmp_path: Path):
        """vault-push should error when .env.keys file doesn't exist."""
        result = runner.invoke(
            app,
            [
                "vault-push",
                str(tmp_path / "nonexistent"),
                "secret-name",
                "--env",
                "soak",
                "-p",
                "aws",
            ],
        )
        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_vault_push_key_not_found(self, tmp_path: Path):
        """vault-push should error when key is not in .env.keys."""
        env_keys = tmp_path / ".env.keys"
        env_keys.write_text("DOTENV_PRIVATE_KEY_PRODUCTION=abc123")

        result = runner.invoke(
            app,
            [
                "vault-push",
                str(tmp_path),
                "secret-name",
                "--env",
                "soak",  # Looking for SOAK but file has PRODUCTION
                "-p",
                "aws",
            ],
        )
        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_vault_push_reads_key_from_env_keys(self, monkeypatch, tmp_path: Path):
        """vault-push should read key from .env.keys and push to vault."""
        env_keys = tmp_path / ".env.keys"
        env_keys.write_text("DOTENV_PRIVATE_KEY_SOAK=my-secret-key-value")

        pushed_secrets = {}

        class MockVaultClient:
            def authenticate(self):
                pass

            def set_secret(self, name, value):
                pushed_secrets[name] = value
                return SimpleNamespace(name=name, value=value, version="v1")

        monkeypatch.setattr(
            "envdrift.vault.get_vault_client",
            lambda *_, **__: MockVaultClient(),
        )

        result = runner.invoke(
            app,
            [
                "vault-push",
                str(tmp_path),
                "soak-machine",
                "--env",
                "soak",
                "-p",
                "aws",
            ],
        )

        assert result.exit_code == 0
        assert "soak-machine" in pushed_secrets
        assert pushed_secrets["soak-machine"] == "DOTENV_PRIVATE_KEY_SOAK=my-secret-key-value"

    def test_vault_push_direct_mode(self, monkeypatch):
        """vault-push --direct should push the value directly."""
        pushed_secrets = {}

        class MockVaultClient:
            def authenticate(self):
                pass

            def set_secret(self, name, value):
                pushed_secrets[name] = value
                return SimpleNamespace(name=name, value=value, version="v1")

        monkeypatch.setattr(
            "envdrift.vault.get_vault_client",
            lambda *_, **__: MockVaultClient(),
        )

        result = runner.invoke(
            app,
            [
                "vault-push",
                "--direct",
                "my-secret",
                "DOTENV_PRIVATE_KEY_PROD=abc123",
                "-p",
                "aws",
            ],
        )

        assert result.exit_code == 0
        assert "my-secret" in pushed_secrets
        assert pushed_secrets["my-secret"] == "DOTENV_PRIVATE_KEY_PROD=abc123"

    def test_vault_push_direct_uses_gcp_project_id_from_config(self, monkeypatch, tmp_path: Path):
        """vault-push should read gcp project_id from config when set."""
        config_file = tmp_path / "envdrift.toml"
        config_file.write_text(
            dedent(
                """
                [vault]
                provider = "gcp"

                [vault.gcp]
                project_id = "my-gcp-project"
                """
            )
        )

        monkeypatch.chdir(tmp_path)
        captured: dict[str, object] = {}

        class MockVaultClient:
            def authenticate(self):
                return None

            def set_secret(self, name, value):
                captured["set_secret"] = (name, value)
                return SimpleNamespace(name=name, value=value, version=None)

        def fake_get_vault_client(provider, **kwargs):
            captured["provider"] = provider
            captured["kwargs"] = kwargs
            return MockVaultClient()

        monkeypatch.setattr("envdrift.vault.get_vault_client", fake_get_vault_client)

        result = runner.invoke(
            app,
            [
                "vault-push",
                "--direct",
                "my-secret",
                "DOTENV_PRIVATE_KEY_PROD=abc123",
            ],
        )

        assert result.exit_code == 0
        assert captured["provider"] == "gcp"
        assert captured["kwargs"]["project_id"] == "my-gcp-project"

    def test_vault_push_all_uses_auto_install(self, monkeypatch, tmp_path: Path):
        """vault-push --all should honor dotenvx auto_install from config."""
        from envdrift.sync.config import ServiceMapping, SyncConfig
        from envdrift.vault.base import SecretNotFoundError

        service_dir = tmp_path / "service"
        service_dir.mkdir()
        env_file = service_dir / ".env.production"
        env_file.write_text("API_KEY=plaintext")
        (service_dir / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=abc123\n")

        mapping = ServiceMapping(secret_name="my-secret", folder_path=service_dir)
        sync_config = SyncConfig(mappings=[mapping], env_keys_filename=".env.keys")

        class DummyClient:
            def authenticate(self):
                pass

            def get_secret(self, _name):
                raise SecretNotFoundError("missing")

            def set_secret(self, _name, _value):
                return None

        dummy_client = DummyClient()
        monkeypatch.setattr(
            "envdrift.cli_commands.sync.load_sync_config_and_client",
            lambda **_kwargs: (sync_config, dummy_client, "azure", None, None, None),
        )

        config_file = tmp_path / "envdrift.toml"
        config_file.write_text(
            dedent(
                """
                [encryption.dotenvx]
                auto_install = true
                """
            ).strip()
            + "\n"
        )

        captured: dict[str, object] = {}

        dummy_backend = DummyEncryptionBackend()

        def fake_get_encryption_backend(provider, **config):
            captured["provider"] = provider
            captured["auto_install"] = config.get("auto_install")
            return dummy_backend

        monkeypatch.setattr(
            "envdrift.cli_commands.encryption_helpers.get_encryption_backend",
            fake_get_encryption_backend,
        )

        result = runner.invoke(
            app,
            [
                "vault-push",
                "--all",
                "-c",
                str(config_file),
                "-p",
                "azure",
                "--vault-url",
                "https://example.vault.azure.net/",
            ],
        )

        assert result.exit_code == 0
        assert captured["auto_install"] is True
        assert captured["provider"] == EncryptionProvider.DOTENVX
        assert dummy_backend.encrypt_calls == [env_file]

    def test_vault_push_all_auth_failure(self, monkeypatch, tmp_path: Path):
        """vault-push --all should surface authentication failures."""
        from envdrift.sync.config import ServiceMapping, SyncConfig
        from envdrift.vault import VaultError

        service_dir = tmp_path / "service"
        service_dir.mkdir()
        (service_dir / ".env.production").write_text("API_KEY=plaintext")
        (service_dir / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=abc123\n")

        mapping = ServiceMapping(secret_name="my-secret", folder_path=service_dir)
        sync_config = SyncConfig(mappings=[mapping], env_keys_filename=".env.keys")

        class DummyClient:
            def authenticate(self):
                raise VaultError("Auth failed")

        monkeypatch.setattr(
            "envdrift.cli_commands.sync.load_sync_config_and_client",
            lambda **_kwargs: (sync_config, DummyClient(), "azure", None, None, None),
        )

        config_file = tmp_path / "envdrift.toml"
        config_file.write_text(
            dedent(
                """
                [encryption.dotenvx]
                auto_install = true
                """
            ).strip()
            + "\n"
        )

        result = runner.invoke(
            app,
            [
                "vault-push",
                "--all",
                "-c",
                str(config_file),
                "-p",
                "azure",
                "--vault-url",
                "https://example.vault.azure.net/",
            ],
        )

        assert result.exit_code == 1
        assert "auth failed" in result.output.lower()

    def test_vault_push_auth_failure(self, monkeypatch, tmp_path: Path):
        """vault-push should handle authentication errors gracefully."""
        env_keys = tmp_path / ".env.keys"
        env_keys.write_text("DOTENV_PRIVATE_KEY_SOAK=abc")

        from envdrift.vault import VaultError

        def failing_client(*_, **__):
            client = SimpleNamespace()
            client.authenticate = lambda: (_ for _ in ()).throw(VaultError("Auth failed"))
            return client

        monkeypatch.setattr("envdrift.vault.get_vault_client", failing_client)

        result = runner.invoke(
            app,
            [
                "vault-push",
                str(tmp_path),
                "secret",
                "--env",
                "soak",
                "-p",
                "aws",
            ],
        )

        assert result.exit_code == 1
        assert "auth" in result.output.lower() or "failed" in result.output.lower()


class TestDetectEnvFile:
    """Tests for detect_env_file helper function."""

    def test_returns_plain_env_file(self, tmp_path: Path):
        """Test that plain .env file is found."""
        from envdrift.env_files import detect_env_file

        env_file = tmp_path / ".env"
        env_file.write_text("SECRET=value")

        detection = detect_env_file(tmp_path)

        assert detection.status == "found"
        assert detection.path == env_file
        assert detection.environment == "production"

    def test_returns_single_env_file(self, tmp_path: Path):
        """Test that single .env.* file is found."""
        from envdrift.env_files import detect_env_file

        env_file = tmp_path / ".env.production"
        env_file.write_text("SECRET=value")

        detection = detect_env_file(tmp_path)

        assert detection.status == "found"
        assert detection.path == env_file
        assert detection.environment == "production"

    def test_returns_multiple_found_status(self, tmp_path: Path):
        """Test that multiple .env.* files return multiple_found status."""
        from envdrift.env_files import detect_env_file

        (tmp_path / ".env.production").write_text("SECRET=value1")
        (tmp_path / ".env.staging").write_text("SECRET=value2")

        detection = detect_env_file(tmp_path)

        assert detection.status == "multiple_found"
        assert detection.path is None
        assert detection.environment is None

    def test_returns_not_found_status(self, tmp_path: Path):
        """Test that empty folder returns not_found status."""
        from envdrift.env_files import detect_env_file

        detection = detect_env_file(tmp_path)

        assert detection.status == "not_found"
        assert detection.path is None
        assert detection.environment is None

    def test_returns_folder_not_found_status(self, tmp_path: Path):
        """Test that non-existent folder returns folder_not_found status."""
        from envdrift.env_files import detect_env_file

        detection = detect_env_file(tmp_path / "nonexistent")

        assert detection.status == "folder_not_found"
        assert detection.path is None
        assert detection.environment is None

    def test_excludes_special_files(self, tmp_path: Path):
        """Test that .env.keys, .env.example etc are excluded."""
        from envdrift.env_files import detect_env_file

        (tmp_path / ".env.keys").write_text("KEY=value")
        (tmp_path / ".env.example").write_text("EXAMPLE=value")
        (tmp_path / ".env.production").write_text("SECRET=value")

        detection = detect_env_file(tmp_path)

        assert detection.status == "found"
        assert detection.path is not None
        assert detection.path.name == ".env.production"
        assert detection.environment == "production"

    def test_plain_env_takes_precedence(self, tmp_path: Path):
        """Test that plain .env takes precedence over .env.* files."""
        from envdrift.env_files import detect_env_file

        (tmp_path / ".env").write_text("PLAIN=value")
        (tmp_path / ".env.production").write_text("PROD=value")
        (tmp_path / ".env.staging").write_text("STAGING=value")

        detection = detect_env_file(tmp_path)

        assert detection.status == "found"
        assert detection.path is not None
        assert detection.path.name == ".env"
        assert detection.environment == "production"
