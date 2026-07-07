"""Tests for envdrift.cli module - Command Line Interface."""

from __future__ import annotations

import importlib.util
import json
import keyword
import shlex
import shutil
from pathlib import Path
from textwrap import dedent
from types import SimpleNamespace
from typing import Any, cast

import pytest
from typer.testing import CliRunner

from envdrift.cli import app
from envdrift.cli_commands.encryption import (
    _load_encryption_config,
    _resolve_config_path,
    _verify_decryption_with_vault,
)
from envdrift.encryption import EncryptionProvider
from envdrift.encryption.base import EncryptionBackendError, EncryptionResult
from envdrift.integrations.dotenvx import DotenvxError
from envdrift.vault import SecretValue, VaultError
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


def _fake_dotenvx_on_path(monkeypatch):
    """Make shutil.which report dotenvx as installed; other lookups stay real.

    Keeps the ``sync --check-decryption`` gate tests deterministic on hosts
    without the real dotenvx binary.
    """
    real_which = shutil.which
    monkeypatch.setattr(
        "shutil.which",
        lambda cmd, *args, **kwargs: (
            "/usr/bin/dotenvx" if cmd == "dotenvx" else real_which(cmd, *args, **kwargs)
        ),
    )


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

        assert sync_module._normalize_max_workers(cast(Any, "bad")) is None
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


class TestValidateConsumesValidationConfig:
    """`envdrift validate` consumes the [validation] config section (#413).

    Real in-process CLI invocations against a temp project; ``monkeypatch.chdir``
    makes ``find_config()`` resolve the temp ``envdrift.toml`` deterministically.
    """

    _FORBID_SCHEMA = """
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    APP_NAME: str
    DEBUG: bool = False
    model_config = {"extra": "forbid"}
"""

    _SENSITIVE_SCHEMA = """
from pydantic import Field
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    API_KEY: str = Field(json_schema_extra={"sensitive": True})
"""

    def _project(
        self, tmp_path: Path, schema_src: str, env_text: str, toml: str | None
    ) -> list[str]:
        (tmp_path / "settings.py").write_text(schema_src)
        (tmp_path / ".env").write_text(env_text)
        if toml is not None:
            (tmp_path / "envdrift.toml").write_text(toml)
        return [
            "validate",
            str(tmp_path / ".env"),
            "--schema",
            "settings:Settings",
            "--service-dir",
            str(tmp_path),
        ]

    def test_strict_extra_false_skips_extra_check(self, tmp_path: Path, monkeypatch):
        """strict_extra=false makes validate ignore variables absent from the schema."""
        args = self._project(
            tmp_path,
            self._FORBID_SCHEMA,
            "APP_NAME=MyApp\nDEBUG=true\nUNKNOWN_VAR=x\n",
            "[validation]\nstrict_extra = false\ncheck_encryption = false\n",
        )
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, [*args, "--ci"])
        assert result.exit_code == 0, result.output
        assert "UNKNOWN_VAR" not in result.output

    def test_strict_extra_true_rejects_extra(self, tmp_path: Path, monkeypatch):
        """strict_extra=true (default) rejects variables absent from a forbid schema."""
        args = self._project(
            tmp_path,
            self._FORBID_SCHEMA,
            "APP_NAME=MyApp\nDEBUG=true\nUNKNOWN_VAR=x\n",
            "[validation]\nstrict_extra = true\ncheck_encryption = false\n",
        )
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, [*args, "--ci"])
        assert result.exit_code == 1, result.output
        assert "UNKNOWN_VAR" in result.output

    def test_check_encryption_config_default_used(self, tmp_path: Path, monkeypatch):
        """check_encryption=false suppresses the unencrypted-secret check when no flag is passed."""
        args = self._project(
            tmp_path,
            self._SENSITIVE_SCHEMA,
            "API_KEY=plaintext_secret_value\n",
            "[validation]\ncheck_encryption = false\n",
        )
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, args)
        assert "UNENCRYPTED SECRETS" not in result.output, result.output

    def test_check_encryption_cli_overrides_config(self, tmp_path: Path, monkeypatch):
        """An explicit --check-encryption overrides check_encryption=false in config."""
        args = self._project(
            tmp_path,
            self._SENSITIVE_SCHEMA,
            "API_KEY=plaintext_secret_value\n",
            "[validation]\ncheck_encryption = false\n",
        )
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, [*args, "--check-encryption"])
        assert "UNENCRYPTED SECRETS" in result.output, result.output

    def test_no_config_uses_defaults(self, tmp_path: Path, monkeypatch):
        """With no envdrift.toml, defaults apply (extra vars checked) — backward compatible."""
        args = self._project(
            tmp_path,
            self._FORBID_SCHEMA,
            "APP_NAME=MyApp\nDEBUG=true\nUNKNOWN_VAR=x\n",
            None,
        )
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, [*args, "--no-check-encryption", "--ci"])
        assert result.exit_code == 1, result.output
        assert "UNKNOWN_VAR" in result.output

    def test_malformed_config_reports_error(self, tmp_path: Path, monkeypatch):
        """A malformed envdrift.toml surfaces a clean error, not a traceback."""
        args = self._project(
            tmp_path,
            self._FORBID_SCHEMA,
            "APP_NAME=MyApp\n",
            "[validation\ncheck_encryption = true\n",  # missing closing bracket
        )
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, args)
        assert result.exit_code == 1, result.output
        assert "Failed to load envdrift config" in result.output

    def test_config_not_found_race_handled_cleanly(self, tmp_path: Path, monkeypatch):
        """A ConfigNotFoundError from load_config (TOCTOU) is handled, not raised.

        find_config() and load_config() are two separate filesystem checks; if the
        file is removed in between, load_config raises ConfigNotFoundError (a plain
        Exception, not OSError/ValueError). It must surface the clean message.
        """
        from envdrift.config import ConfigNotFoundError

        args = self._project(
            tmp_path,
            self._FORBID_SCHEMA,
            "APP_NAME=MyApp\n",
            "[validation]\ncheck_encryption = true\n",
        )
        monkeypatch.chdir(tmp_path)

        def _raise_not_found(_path):
            raise ConfigNotFoundError("config vanished mid-call")

        monkeypatch.setattr("envdrift.cli_commands.validate.load_config", _raise_not_found)
        result = runner.invoke(app, args)
        assert result.exit_code == 1, result.output
        assert "Failed to load envdrift config" in result.output


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

    def test_diff_format_unknown_exits_1(self, tmp_path: Path):
        """diff --format <unknown> exits 1 instead of silently rendering a table (#413)."""
        env1 = tmp_path / "env1"
        env2 = tmp_path / "env2"
        env1.write_text("FOO=bar")
        env2.write_text("FOO=baz")

        result = runner.invoke(app, ["diff", str(env1), str(env2), "--format", "bogus"])
        assert result.exit_code == 1
        assert "invalid --format" in result.output.lower()

    def test_diff_directory_argument_errors_cleanly(self, tmp_path: Path):
        """#443: a directory where a file is expected -> clean error, not a traceback."""
        env1 = tmp_path / "env1"
        env1.write_text("FOO=bar")
        adir = tmp_path / "adir"
        adir.mkdir()

        result = runner.invoke(app, ["diff", str(env1), str(adir)])
        assert result.exit_code == 1
        assert result.exception is None or isinstance(result.exception, SystemExit)
        # stdout+stderr to stay neutral on which stream carries the error.
        assert "not a file" in (result.stdout + result.stderr).lower()

    def test_diff_binary_file_errors_cleanly(self, tmp_path: Path):
        """#443: a binary / non-UTF-8 file -> clean error, not a UnicodeDecodeError."""
        env1 = tmp_path / "env1"
        env1.write_text("FOO=bar")
        binf = tmp_path / "bin.env"
        binf.write_bytes(bytes(range(256)))

        result = runner.invoke(app, ["diff", str(env1), str(binf)])
        assert result.exit_code == 1
        assert result.exception is None or isinstance(result.exception, SystemExit)
        # stdout+stderr to stay neutral on which stream carries the error.
        assert "utf-8" in (result.stdout + result.stderr).lower()

    def test_diff_json_error_path_emits_json(self, tmp_path: Path):
        """#443: with --format json, an error is a clean {"error": ...} object, not prose."""
        env1 = tmp_path / "env1"
        env1.write_text("FOO=bar")

        result = runner.invoke(
            app, ["diff", str(env1), str(tmp_path / "missing.env"), "--format", "json"]
        )
        assert result.exit_code == 1
        payload = json.loads(result.output)
        assert "error" in payload

    def test_diff_format_uppercase_json(self, tmp_path: Path):
        """diff --format JSON is lowercased and produces JSON, not a table (#413)."""
        env1 = tmp_path / "env1"
        env2 = tmp_path / "env2"
        env1.write_text("FOO=bar")
        env2.write_text("FOO=baz")

        result = runner.invoke(app, ["diff", str(env1), str(env2), "--format", "JSON"])
        assert result.exit_code == 0
        assert json.loads(result.output)["summary"]["changed"] == 1

    def test_diff_json_schema_warning_not_on_stdout(self, tmp_path: Path):
        """A schema-load failure in --format json keeps stdout pure JSON (#413).

        CliRunner separates streams: the [WARN] line must land on stderr while
        stdout stays a parseable JSON document.
        """
        env1 = tmp_path / "env1"
        env2 = tmp_path / "env2"
        env1.write_text("FOO=bar")
        env2.write_text("FOO=baz")

        result = runner.invoke(
            app,
            [
                "diff",
                str(env1),
                str(env2),
                "--schema",
                "nonexistent.module:Settings",
                "--format",
                "json",
            ],
        )
        assert result.exit_code == 0
        # stdout is pure JSON, no warning text.
        assert "WARN" not in result.stdout
        assert "Could not load schema" not in result.stdout
        json.loads(result.stdout)
        # The warning is surfaced on stderr instead.
        assert "Could not load schema" in result.stderr

    def test_diff_table_schema_warning_inline(self, tmp_path: Path):
        """In table mode a schema-load failure stays an inline Rich warning (#413).

        The stderr routing is json-only; table output keeps the human-readable
        warning where a user expects it and still renders the diff (exit 0).
        """
        env1 = tmp_path / "env1"
        env2 = tmp_path / "env2"
        env1.write_text("FOO=bar")
        env2.write_text("FOO=baz")

        result = runner.invoke(
            app,
            ["diff", str(env1), str(env2), "--schema", "nonexistent.module:Settings"],
        )
        assert result.exit_code == 0
        assert "Could not load schema" in result.output


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

        called: dict[str, Any] = {"verify": False}

        def fake_verify(**kwargs):
            """
            Test stub that simulates a successful verification and records that it was invoked.

            Parameters:
                **kwargs: Arbitrary keyword arguments accepted and ignored by the stub.

            Returns:
                True indicating the verification succeeded.
            """
            called["verify"] = True
            called["kwargs"] = kwargs
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
        assert called["kwargs"]["config_path"] is None

    def test_decrypt_verify_vault_passes_discovered_config_path(self, monkeypatch, tmp_path: Path):
        """--verify-vault should pass the resolved TOML config path to repair hints."""

        env_file = tmp_path / ".env.production"
        env_file.write_text("SECRET=encrypted")

        config_path = tmp_path / "envdrift.toml"
        config_path.write_text('[encryption]\nbackend = "dotenvx"\n')

        captured: dict[str, Any] = {}

        def fake_verify(**kwargs):
            captured.update(kwargs)
            return True

        monkeypatch.setattr("envdrift.config.find_config", lambda: config_path)
        monkeypatch.setattr(
            "envdrift.cli_commands.encryption._verify_decryption_with_vault", fake_verify
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
        assert captured["config_path"] == config_path
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

    def test_load_encryption_config_aborts_on_toml_error(self, monkeypatch, tmp_path: Path):
        """Invalid TOML aborts instead of silently returning defaults (#491)."""
        import typer

        config_path = tmp_path / "envdrift.toml"
        config_path.write_text("invalid = [", encoding="utf-8")

        errors = []
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("envdrift.cli_commands.encryption.print_error", errors.append)

        with pytest.raises(typer.Exit) as exc_info:
            _load_encryption_config()

        assert exc_info.value.exit_code == 1
        assert any("TOML syntax error" in e for e in errors)

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

    def test_init_prints_next_step_and_names_sensitive(self, tmp_path: Path, monkeypatch):
        """init names the sensitive vars and prints the exact validate next-step."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text("APP_NAME=demo\nAPI_KEY=sk_live_abc123\n")

        result = runner.invoke(app, ["init"])

        assert result.exit_code == 0, result.output
        out = " ".join(result.output.split())
        assert "API_KEY" in out  # the sensitive var is named, not just counted
        assert "Next:" in out
        assert "envdrift validate --schema settings:Settings" in out

    def test_init_then_validate_natural_command_works(self, tmp_path: Path, monkeypatch):
        """First-run flow: init -> the suggested `validate --schema settings:Settings`
        (no --service-dir) imports the cwd schema and PASSES (dogfood fix)."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text("APP_NAME=demo\nDEBUG=true\n")

        init_result = runner.invoke(app, ["init"])
        assert init_result.exit_code == 0, init_result.output

        # Exactly what init told the user to run — no --service-dir flag.
        val_result = runner.invoke(app, ["validate", ".env", "--schema", "settings:Settings"])
        assert val_result.exit_code == 0, val_result.output
        assert "PASSED" in val_result.output

    def test_init_next_step_includes_service_dir_for_subdir_output(
        self, tmp_path: Path, monkeypatch
    ):
        """A subdir --output must add --service-dir to the hint, or it sends the
        user back into the No-module import error the hint is meant to avoid."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text("APP_NAME=demo\n")
        (tmp_path / "src").mkdir()

        result = runner.invoke(app, ["init", "--output", "src/settings.py"])

        assert result.exit_code == 0, result.output
        out = " ".join(result.output.split())
        assert "validate --schema settings:Settings --service-dir src" in out

    def test_init_next_step_includes_non_default_env_file(self, tmp_path: Path, monkeypatch):
        """`init prod.env` must suggest validating prod.env, not the default .env."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "prod.env").write_text("APP_NAME=demo\n")

        result = runner.invoke(app, ["init", "prod.env"])

        assert result.exit_code == 0, result.output
        out = " ".join(result.output.split())
        assert "envdrift validate prod.env --schema settings:Settings" in out

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

    def test_init_no_overwrite_without_force(self, tmp_path: Path) -> None:
        """#372: a 2nd init without --force errors and leaves settings.py intact."""
        env_file = tmp_path / ".env"
        env_file.write_text("FOO=bar\n")
        out = tmp_path / "settings.py"

        first = runner.invoke(
            app, ["init", str(env_file), "--output", str(out), "--class-name", "First"]
        )
        assert first.exit_code == 0
        original = out.read_text()
        assert "class First" in original

        second = runner.invoke(
            app, ["init", str(env_file), "--output", str(out), "--class-name", "Second"]
        )
        assert second.exit_code != 0
        assert "exist" in second.output.lower() or "force" in second.output.lower()
        # First file untouched.
        assert out.read_text() == original
        assert "class Second" not in out.read_text()

    def test_init_overwrites_with_force(self, tmp_path: Path) -> None:
        """#372: --force overwrites the existing settings.py."""
        env_file = tmp_path / ".env"
        env_file.write_text("FOO=bar\n")
        out = tmp_path / "settings.py"

        runner.invoke(app, ["init", str(env_file), "--output", str(out), "--class-name", "First"])
        second = runner.invoke(
            app,
            ["init", str(env_file), "--output", str(out), "--class-name", "Second", "--force"],
        )
        assert second.exit_code == 0
        content = out.read_text()
        assert "class Second" in content
        assert "class First" not in content

    def test_init_force_shorthand(self, tmp_path: Path) -> None:
        """#372: the `-f` shorthand also overwrites an existing file."""
        env_file = tmp_path / ".env"
        env_file.write_text("FOO=bar\n")
        out = tmp_path / "settings.py"

        runner.invoke(app, ["init", str(env_file), "--output", str(out), "--class-name", "First"])
        second = runner.invoke(
            app,
            ["init", str(env_file), "--output", str(out), "--class-name", "Second", "-f"],
        )
        assert second.exit_code == 0
        assert "class Second" in out.read_text()

    def test_init_unicode_digit_value_does_not_crash(self, tmp_path: Path) -> None:
        """#321: a Unicode-digit value (²=U+00B2) is inferred str, not a crashing int()."""
        env_file = tmp_path / ".env"
        # ² (U+00B2): str.isdigit() is True but int("²") raises ValueError.
        # Write UTF-8 explicitly: the default encoding is cp1252 on Windows,
        # which would emit byte 0xb2 and make the (UTF-8) reader choke.
        env_file.write_text("LEVEL=²\nPORT=8080\n", encoding="utf-8")
        out = tmp_path / "settings.py"

        result = runner.invoke(
            app, ["init", str(env_file), "--output", str(out), "--class-name", "Cfg"]
        )

        assert result.exit_code == 0, result.output
        content = out.read_text()
        # Unicode-digit value falls through to str (not int).
        assert "LEVEL: str" in content
        assert "LEVEL: int" not in content
        # Happy path: an ASCII digit is still inferred as int.
        assert "PORT: int = 8080" in content

    def test_init_keyword_var_name_produces_importable_module(self, tmp_path: Path) -> None:
        """#413: a .env key that is a Python keyword yields an importable module.

        Previously `class=...` / `import=...` produced raw `class: str` lines —
        a SyntaxError module that init still wrote with exit 0 and `[OK]`. The
        fix aliases such fields to a sanitized identifier so the module imports.
        """
        env_file = tmp_path / ".env"
        env_file.write_text("class=foo\nimport=bar\nVALID=baz\n")
        out = tmp_path / "settings.py"

        result = runner.invoke(
            app, ["init", str(env_file), "--output", str(out), "--class-name", "Cfg"]
        )
        assert result.exit_code == 0, result.output

        content = out.read_text()
        # The raw keyword name must NOT appear as a bare attribute annotation.
        assert "\n    class: " not in content
        assert "\n    import: " not in content
        # The original name is preserved as a Pydantic alias.
        assert "alias='class'" in content
        assert "alias='import'" in content

        # The generated module must be importable (no SyntaxError).
        spec = importlib.util.spec_from_file_location("gen_kw_settings", out)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        assert hasattr(module, "Cfg")

    def test_init_invalid_class_name_errors(self, tmp_path: Path) -> None:
        """#413: a class name that is not a valid identifier fails nonzero.

        `--class-name=123Bad` previously emitted `class 123Bad(...)` (a
        SyntaxError module) with exit 0. The fix rejects it before writing.
        """
        env_file = tmp_path / ".env"
        env_file.write_text("FOO=bar\n")
        out = tmp_path / "settings.py"

        result = runner.invoke(
            app, ["init", str(env_file), "--output", str(out), "--class-name=123Bad"]
        )
        assert result.exit_code != 0
        assert "invalid class name" in result.output.lower()
        # No broken module is left behind.
        assert not out.exists()

    def test_init_keyword_class_name_errors(self, tmp_path: Path) -> None:
        """#413: a class name that is a Python keyword fails nonzero."""
        env_file = tmp_path / ".env"
        env_file.write_text("FOO=bar\n")
        out = tmp_path / "settings.py"

        result = runner.invoke(
            app, ["init", str(env_file), "--output", str(out), "--class-name=class"]
        )
        assert result.exit_code != 0
        assert "invalid class name" in result.output.lower()
        assert not out.exists()

    def test_init_aliases_non_identifier_keys(self, tmp_path: Path) -> None:
        """#443: .env keys the parser cannot read are aliased in, not dropped.

        `2FA_ENABLED` (leading digit) and `MY-DASH-VAR` (dash) never enter the
        strict parser's variable set, so init used to omit them and warn. They are
        now emitted with a sanitized attribute name plus a Pydantic ``alias`` so the
        schema stays complete and the module still imports.
        """
        env_file = tmp_path / ".env"
        env_file.write_text("2FA_ENABLED=true\nMY-DASH-VAR=x\nVALID=keep\n", encoding="utf-8")
        out = tmp_path / "settings.py"

        result = runner.invoke(
            app, ["init", str(env_file), "--output", str(out), "--class-name", "Cfg"]
        )
        assert result.exit_code == 0, result.output
        content = out.read_text(encoding="utf-8")
        # Both keys are aliased into the schema rather than dropped/warned.
        assert "alias='2FA_ENABLED'" in content
        assert "alias='MY-DASH-VAR'" in content
        assert "VALID" in content

        # The generated module must still import (no SyntaxError from raw names).
        spec = importlib.util.spec_from_file_location("gen_alias_settings", out)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        aliases = {f.alias for f in module.Cfg.model_fields.values() if f.alias}
        assert {"2FA_ENABLED", "MY-DASH-VAR"} <= aliases

    def test_init_unicode_identifier_keys_become_bare_fields(self, tmp_path: Path) -> None:
        """#443: valid non-ASCII identifiers are real fields; only true non-identifiers alias.

        ``CAFÉ`` / ``ΑΛΦΑ`` pass ``str.isidentifier()`` and must become bare
        attributes (no alias); an emoji key ``KEY🔑`` is not an identifier and is
        sanitized + aliased like any other non-identifier key.
        """
        env_file = tmp_path / ".env"
        # Greek capital letters are intentional (testing non-ASCII identifiers).
        env_file.write_text("CAFÉ=a\nΑΛΦΑ=b\nKEY🔑=c\n", encoding="utf-8")  # noqa: RUF001
        out = tmp_path / "settings.py"

        result = runner.invoke(
            app, ["init", str(env_file), "--output", str(out), "--class-name", "Cfg"]
        )
        assert result.exit_code == 0, result.output

        spec = importlib.util.spec_from_file_location("gen_unicode_settings", out)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        fields = module.Cfg.model_fields
        # Unicode-letter identifiers are kept verbatim (no alias).
        assert "CAFÉ" in fields and fields["CAFÉ"].alias is None
        assert "ΑΛΦΑ" in fields and fields["ΑΛΦΑ"].alias is None
        # The emoji key is aliased back to its original name.
        assert {f.alias for f in fields.values() if f.alias == "KEY🔑"} == {"KEY🔑"}

    def test_init_nfkc_colliding_keys_stay_distinct_fields(self, tmp_path: Path) -> None:
        """#449: keys that NFKC-fold to the same identifier must NOT collapse.

        Python NFKC-normalizes identifiers at compile time, so an NFC vs NFD
        accented key, and a ligature vs its ASCII expansion, would otherwise merge
        into a single attribute on import -- silently dropping a var. Each of the
        four distinct env keys must survive as its own field, bound (by name or
        alias) to its exact original key. Built with escapes so the byte forms are
        deterministic regardless of this file's own normalization.
        """
        nfc = "CAF\u00c9"  # precomposed E-acute (U+00C9)
        nfd = "CAFE\u0301"  # E + combining acute (U+0301)
        lig = "\ufb01le"  # FB01 ligature, NFKC-folds to "file"
        env_file = tmp_path / ".env"
        env_file.write_text(f"{nfc}=a\n{nfd}=b\n{lig}=c\nfile=d\n", encoding="utf-8")
        out = tmp_path / "settings.py"

        result = runner.invoke(
            app, ["init", str(env_file), "--output", str(out), "--class-name", "Cfg"]
        )
        assert result.exit_code == 0, result.output

        spec = importlib.util.spec_from_file_location("gen_nfkc_settings", out)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        fields = module.Cfg.model_fields
        # No collapse: all four distinct keys survive as four distinct fields.
        assert len(fields) == 4
        # Each field binds (by alias, else attribute name) to an exact original key.
        recovered = {(f.alias if f.alias else name) for name, f in fields.items()}
        assert recovered == {nfc, nfd, lig, "file"}

    def test_init_then_validate_round_trip_with_non_identifier_keys(self, tmp_path: Path) -> None:
        """#443: the documented init→validate workflow PASSES for non-identifier keys.

        init aliases ``X-API-KEY`` / ``2FA_ENABLED`` and keeps ``CAFÉ``; validate
        parses the same .env leniently and matches by alias, so it validates
        cleanly instead of falsely reporting the aliased fields as MISSING (the
        regression this combined init+validate change fixes).
        """
        env_file = tmp_path / ".env"
        env_file.write_text(
            "DATABASE_URL=postgres://x\n2FA_ENABLED=true\nX-API-KEY=abc123\nCAFÉ=yes\n",
            encoding="utf-8",
        )
        out = tmp_path / "settings.py"

        init_res = runner.invoke(
            app, ["init", str(env_file), "--output", str(out), "--class-name", "Cfg"]
        )
        assert init_res.exit_code == 0, init_res.output

        val_res = runner.invoke(
            app,
            ["validate", str(env_file), "--schema", "settings:Cfg", "--service-dir", str(tmp_path)],
        )
        assert val_res.exit_code == 0, val_res.output
        # Width-independent: Rich may wrap the long tmp path before the verdict.
        assert "passed" in " ".join(val_res.output.lower().split())

    def test_sanitize_identifier_produces_valid_non_keyword_names(self) -> None:
        """#413: the sanitizer always yields a valid, non-keyword identifier."""
        from envdrift.cli_commands.init_cmd import _sanitize_identifier

        # Keyword -> suffixed identifier.
        assert _sanitize_identifier("class").isidentifier()
        assert not keyword.iskeyword(_sanitize_identifier("class"))
        # Leading digit / non-identifier chars -> prefixed/replaced.
        assert _sanitize_identifier("2FA").isidentifier()
        assert _sanitize_identifier("MY-DASH").isidentifier()
        assert _sanitize_identifier("123").isidentifier()
        # Soft keyword (`match`) is also avoided.
        assert not keyword.issoftkeyword(_sanitize_identifier("match"))
        # Empty-ish input still yields a usable identifier.
        assert _sanitize_identifier("@").isidentifier()

    def test_init_env_file_path_with_escapes_is_safe_literal(self, tmp_path: Path) -> None:
        """#423: an env_file path with backslash/quote escapes stays a valid literal.

        A raw `env_file="{path}"` interpolation would let a Windows-style path
        (`\\n`, `\\t`) or an embedded quote corrupt the generated module. The path
        is emitted via repr() so it round-trips to the exact original string.
        """
        from envdrift.cli_commands.init_cmd import _module_header

        # A path whose name contains escape-prone characters. It is never written
        # to disk (a literal `"` is an illegal filename char on Windows, and
        # `_module_header` only formats the path string), keeping this cross-platform.
        tricky = tmp_path / 'we"ird\tname'

        header = "\n".join(_module_header("Cfg", tricky))
        # The emitted literal must repr back to the exact path string.
        assert f"env_file={str(tricky)!r}" in header

        # The generated module must parse cleanly (no SyntaxError from a broken
        # string literal) and the model_config must hold the exact path.
        full = "\n".join(_module_header("Cfg", tricky) + ["    FOO: str", ""])
        ns: dict[str, object] = {}
        exec(compile(full, "<gen>", "exec"), ns)  # noqa: S102 - generated-module smoke test
        cfg_cls = ns["Cfg"]
        assert cfg_cls.model_config["env_file"] == str(tricky)  # type: ignore[index,attr-defined]

    def test_init_aliased_field_keeps_typed_default(self, tmp_path: Path) -> None:
        """#423: an aliased keyword field with an int/bool value keeps its default.

        `class=8080` must render `Field(alias='class', default=8080)` — the typed
        default has to survive the Field(...) path, not get dropped to required.
        """
        env_file = tmp_path / ".env"
        env_file.write_text("class=8080\nimport=true\n")
        out = tmp_path / "settings.py"

        result = runner.invoke(
            app, ["init", str(env_file), "--output", str(out), "--class-name", "Cfg"]
        )
        assert result.exit_code == 0, result.output

        content = out.read_text()
        assert "alias='class'" in content and "default=8080" in content
        assert "alias='import'" in content and "default=True" in content

        spec = importlib.util.spec_from_file_location("gen_typed_alias", out)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        cfg = module.Cfg()
        assert cfg.class_ == 8080
        assert cfg.import_ is True

    def test_init_keyword_collision_keeps_both_env_bindings(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#423: a key colliding with a keyword's sanitized form keeps its alias.

        `class` sanitizes to `class_`; a literal `class_` key then collides and is
        bumped to `class__`. Without an alias on the bumped field, pydantic-settings
        would look up the env var `CLASS__` and silently lose the `class_` value.
        Both fields must alias back to their original env var names so each binds.
        """
        env_file = tmp_path / ".env"
        env_file.write_text("class=fromkeyword\nclass_=fromcollision\n")
        out = tmp_path / "settings.py"

        result = runner.invoke(
            app, ["init", str(env_file), "--output", str(out), "--class-name", "Cfg"]
        )
        assert result.exit_code == 0, result.output

        content = out.read_text()
        # The keyword key keeps its alias to the original `class` env var.
        assert "alias='class'" in content
        # The colliding `class_` key, bumped to `class__`, must alias back to
        # `class_` rather than silently binding to `CLASS__`.
        assert "class__: " in content
        assert "alias='class_'" in content

        # Constructing the module resolves both env vars via their aliases — the
        # `class_` value is not dropped onto a phantom `CLASS__` lookup.
        monkeypatch.setenv("class", "fromkeyword")
        monkeypatch.setenv("class_", "fromcollision")
        spec = importlib.util.spec_from_file_location("gen_collide_settings", out)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        cfg = module.Cfg()
        assert cfg.class_ == "fromkeyword"
        assert cfg.class__ == "fromcollision"

    def test_init_pydantic_reserved_field_names_produce_importable_module(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """#423: .env keys colliding with pydantic reserved names stay importable.

        Valid, non-keyword identifiers that fall in pydantic's protected ``model_``
        namespace (``model_dump`` raises at import; ``model_config`` silently
        shadows the class's own ``model_config``) or reuse a BaseSettings/BaseModel
        attribute (``schema`` warns and shadows machinery) previously passed through
        ``_needs_sanitizing`` unsanitized and were emitted as bare annotations. The
        fix sanitizes + aliases them like keywords so the module imports and each
        field still binds to its original env var via the alias.
        """
        env_file = tmp_path / ".env"
        # model_dump -> raised ValueError at import before the fix; the others
        # shadowed real model machinery.
        env_file.write_text("model_dump=a\nmodel_config=b\nschema=c\nVALID=keep\n")
        out = tmp_path / "settings.py"

        result = runner.invoke(
            app, ["init", str(env_file), "--output", str(out), "--class-name", "Cfg"]
        )
        assert result.exit_code == 0, result.output

        content = out.read_text()
        # None of the reserved names may appear as a bare attribute annotation.
        assert "\n    model_dump: " not in content
        assert "\n    model_config: str" not in content
        assert "\n    schema: " not in content
        # A safe attribute name carries the original key as an alias.
        assert "field_model_dump" in content
        assert "alias='model_dump'" in content
        assert "alias='model_config'" in content
        assert "alias='schema'" in content
        # The class's own model_config (SettingsConfigDict) is untouched.
        assert "model_config = SettingsConfigDict(" in content

        # The generated module must import (no ValueError from the protected
        # namespace, no SyntaxError) and resolve every reserved key via its alias.
        monkeypatch.setenv("model_dump", "a")
        monkeypatch.setenv("model_config", "b")
        monkeypatch.setenv("schema", "c")
        spec = importlib.util.spec_from_file_location("gen_reserved_settings", out)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        cfg = module.Cfg()
        assert cfg.field_model_dump == "a"
        assert cfg.field_model_config == "b"
        assert cfg.field_schema == "c"

    def test_init_underscore_prefixed_key_produces_importable_module(self, tmp_path: Path) -> None:
        """#16: keys whose sanitized name starts with '_' stay importable.

        A dot/emoji-prefixed key (``.dotstart``, ``🔑EMOJI``) sanitizes to a
        leading-underscore name (``_dotstart``, ``_EMOJI``), which Pydantic
        rejects at import ("Fields must not use names with leading underscores").
        init exited 0 / [OK] while emitting an unimportable module; the sanitizer
        must prefix these like leading-digit keys so the schema imports.
        """
        env_file = tmp_path / ".env"
        # `.dotstart`/`🔑EMOJI` sanitize to a leading underscore; `_PRIVATE` already
        # starts with one natively — both must be prefixed so the module imports.
        env_file.write_text(
            ".dotstart=x\n🔑EMOJI=emojivalue\n_PRIVATE=secret\nNORMAL=ok\n", encoding="utf-8"
        )
        out = tmp_path / "settings.py"

        result = runner.invoke(
            app, ["init", str(env_file), "--output", str(out), "--class-name", "Cfg"]
        )
        assert result.exit_code == 0, result.output

        content = out.read_text(encoding="utf-8")
        # No field annotation may start with an underscore.
        assert "\n    _" not in content
        # The original keys survive as aliases (sanitized-to- and natively-leading _).
        assert "alias='.dotstart'" in content
        assert "alias='🔑EMOJI'" in content
        assert "alias='_PRIVATE'" in content

        # The generated module must import (raised NameError before the fix).
        spec = importlib.util.spec_from_file_location("gen_underscore_settings", out)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        assert hasattr(module, "Cfg")


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

    @pytest.mark.parametrize(
        (
            "provider",
            "vault_url",
            "region",
            "project_id",
            "config_filename",
            "expected_extra_options",
        ),
        [
            (
                "azure",
                "https://example.vault.azure.net",
                None,
                None,
                None,
                " --vault-url https://example.vault.azure.net",
            ),
            (
                "aws",
                None,
                "us-east-1",
                None,
                None,
                " --region us-east-1",
            ),
            (
                "gcp",
                None,
                None,
                "my-gcp-project",
                None,
                " --project-id my-gcp-project",
            ),
            (
                "azure",
                "https://example.vault.azure.net",
                None,
                None,
                "envdrift.toml",
                " --vault-url https://example.vault.azure.net",
            ),
            (
                "azure",
                "https://example.vault.azure.net",
                None,
                None,
                "env drift.toml",
                " --vault-url https://example.vault.azure.net",
            ),
        ],
    )
    def test_verify_vault_failure_suggests_restore(
        self,
        monkeypatch,
        tmp_path: Path,
        provider: str,
        vault_url: str | None,
        region: str | None,
        project_id: str | None,
        config_filename: str | None,
        expected_extra_options: str,
    ):
        """Vault verification failure should guide restoring encrypted file and keys."""

        env_file = tmp_path / ".env.production"
        env_file.write_text("SECRET=encrypted")
        config_path = tmp_path / config_filename if config_filename else None

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
            provider=provider,
            vault_url=vault_url,
            region=region,
            project_id=project_id,
            secret_name="env-drift-production-key",
            config_path=config_path,
        )

        assert result is False
        joined = " ".join(printed)
        expected_sync_cmd = "envdrift sync --force"
        if config_path:
            expected_sync_cmd += f" -c {shlex.quote(str(config_path))}"
        expected_sync_cmd += f" -p {provider}{expected_extra_options}"
        assert "git restore" in joined
        assert str(env_file) in joined
        assert expected_sync_cmd in joined
        assert "-c pair.txt" not in joined

    def test_verify_vault_gcp_passes_project_id(self, monkeypatch, tmp_path: Path):
        """GCP provider should pass project_id through to the vault client."""
        env_file = tmp_path / ".env.production"
        env_file.write_text("SECRET=encrypted")

        secret_value = SimpleNamespace(value="DOTENV_PRIVATE_KEY_PRODUCTION=vault-key")
        captured: dict[str, Any] = {}

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

    def test_verify_vault_aws_with_raw_secret(self, monkeypatch, tmp_path: Path):
        """Vault verification should accept raw secrets and derive key name.

        For a plain ``.env`` file dotenvx expects the suffix-less
        ``DOTENV_PRIVATE_KEY`` variable; the old ``env_file.stem`` derivation
        wrongly defaulted to ``DOTENV_PRIVATE_KEY_PRODUCTION`` (#473).
        """

        env_file = tmp_path / ".env"
        env_file.write_text("SECRET=encrypted")

        class DummyVault:
            def ensure_authenticated(self) -> None:
                """Pretend authentication always succeeds."""
                return None

            def get_secret(self, name: str):
                """Return the bare (prefix-less) key for the "dotenv-key" secret."""
                assert name == "dotenv-key"
                return "plainawskey"

        captured: dict = {}

        class DummyDotenvx:
            def is_installed(self):
                """Report dotenvx as installed."""
                return True

            def decrypt(
                self,
                env_path: Path,
                env_keys_file: object = None,
                env: dict[str, str] | None = None,
                cwd: object = None,
            ) -> None:
                """Record the suffix-less key var and cwd the verify passes in."""
                assert env is not None
                captured["env_var"] = env.get("DOTENV_PRIVATE_KEY")
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

    def test_sync_mapping_missing_secret_name_is_clean_error(self, tmp_path: Path, monkeypatch):
        """#32: a sync mapping missing secret_name surfaces a clean error, not a
        raw KeyError traceback (covers sync's new except ValueError branch)."""
        monkeypatch.chdir(tmp_path)
        cfg = tmp_path / "envdrift.toml"
        cfg.write_text(
            '[vault]\nprovider = "azure"\n\n[[vault.sync.mappings]]\nfolder_path = "services/app"\n'
        )

        result = runner.invoke(app, ["sync", "--config", str(cfg)])

        assert result.exit_code != 0
        assert "secret_name" in result.output
        assert "Traceback" not in result.output

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

    def test_sync_check_decryption_failure_exits_nonzero_without_ci(
        self, monkeypatch, tmp_path: Path
    ):
        """#473: a requested --check-decryption that FAILED must exit 1 even without --ci.

        The deep-review verifier reproduced "Decryption: FAILED / Failed: 1"
        with overall exit 0 — an untruthful verdict scripts silently miss.
        """
        from envdrift.sync.result import (
            DecryptionTestResult,
            ServiceSyncResult,
            SyncAction,
            SyncResult,
        )

        config_file = tmp_path / "pair.txt"
        config_file.write_text("secret=service")

        # The up-front --check-decryption gate needs dotenvx present; fake it
        # so this test exercises the FAILED-result gate on dotenvx-less hosts.
        _fake_dotenvx_on_path(monkeypatch)
        monkeypatch.setattr("envdrift.vault.get_vault_client", lambda *_, **__: SimpleNamespace())
        monkeypatch.setattr("envdrift.output.rich.print_service_sync_status", lambda *_, **__: None)
        monkeypatch.setattr("envdrift.output.rich.print_sync_result", lambda *_, **__: None)

        failed_check = SyncResult(
            services=[
                ServiceSyncResult(
                    secret_name="secret",
                    folder_path=tmp_path / "service",
                    action=SyncAction.SKIPPED,
                    message="up to date",
                    decryption_result=DecryptionTestResult.FAILED,
                )
            ]
        )

        class FailedCheckEngine:
            def __init__(self, *_args, **_kwargs):
                """Test stub returning a sync result with a failed decryption test."""

            def sync_all(self):
                return failed_check

        monkeypatch.setattr("envdrift.sync.engine.SyncEngine", FailedCheckEngine)

        common_args = [
            "sync",
            "-c",
            str(config_file),
            "-p",
            "hashicorp",
            "--vault-url",
            "http://localhost:8200",
        ]

        # Without --check-decryption the (stubbed) failed test is not an
        # explicitly requested check, so the historic exit contract holds.
        result = runner.invoke(app, common_args)
        assert result.exit_code == 0

        result = runner.invoke(app, [*common_args, "--check-decryption"])
        assert result.exit_code == 1

    def test_sync_check_decryption_without_dotenvx_exits_nonzero(self, monkeypatch):
        """#473: --check-decryption with dotenvx absent must fail loudly, not exit 0.

        Without dotenvx the engine degrades every per-service test to SKIPPED,
        so the run exited 0 having verified nothing - the same
        cannot-verify-downgraded-to-success class the rest of #473 fixes.
        `decrypt --verify-vault` already fails loudly for the identical state.
        """
        real_which = shutil.which
        monkeypatch.setattr(
            "shutil.which",
            lambda cmd, *args, **kwargs: (
                None if cmd == "dotenvx" else real_which(cmd, *args, **kwargs)
            ),
        )

        result = runner.invoke(app, ["sync", "--check-decryption"])

        assert result.exit_code == 1
        out = " ".join(result.output.split())
        assert "dotenvx is not installed" in out
        assert "cannot verify decryption" in out

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
        captured: dict[str, Any] = {}

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

        captured: dict[str, Any] = {}

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

    def test_sync_aborts_when_discovered_config_is_malformed(self, monkeypatch, tmp_path: Path):
        """A broken auto-discovered config is a hard error, not a fallback (#491).

        Pre-#491 sync warned about the parse failure and then re-read the same
        TOML for the [vault.sync] section — continuing with defaults for every
        other section the file configured.
        """

        config_file = tmp_path / "envdrift.toml"
        config_file.write_text(
            dedent(
                """
                [vault.sync
                default_vault_name = "fallback"
                """
            ),
            encoding="utf-8",
        )
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
        normalized = " ".join(result.output.split())
        assert "TOML syntax error in" in normalized
        assert "No sync configuration found" not in normalized

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
        captured: dict[str, Any] = {}

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
        captured: dict[str, Any] = {}

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

    def test_sync_unicode_decode_error_exits_cleanly(self, monkeypatch, tmp_path: Path):
        """A non-UTF-8 env file during sync exits 1, not a traceback (#413).

        Regression for #413: ``sync --check-decryption`` read env files outside any
        guard, so a non-UTF-8 file raised ``UnicodeDecodeError`` that escaped the
        CLI's narrow ``except (VaultError, SyncConfigError, SecretNotFoundError)``.
        The catch is now broadened to ``OSError``/``UnicodeDecodeError`` so the user
        gets a clean error and exit code 1 instead of a crash.
        """
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

        # The up-front --check-decryption gate needs dotenvx present; fake it
        # so this test still reaches the engine on dotenvx-less hosts.
        _fake_dotenvx_on_path(monkeypatch)
        monkeypatch.setattr(
            "envdrift.vault.get_vault_client",
            lambda *_a, **_k: SimpleNamespace(ensure_authenticated=lambda: None),
        )
        monkeypatch.setattr("envdrift.output.rich.print_service_sync_status", lambda *_, **__: None)
        monkeypatch.setattr("envdrift.output.rich.print_sync_result", lambda *_, **__: None)

        class DummyEngine:
            def __init__(self, config, vault_client, mode, prompt_callback, progress_callback):
                pass

            def sync_all(self):
                # Simulate the real engine hitting a non-UTF-8 env file.
                b"\xff\xfe".decode("utf-8")
                raise AssertionError("decode above should have raised")

        monkeypatch.setattr("envdrift.sync.engine.SyncEngine", DummyEngine)

        result = runner.invoke(app, ["sync", "--check-decryption"])

        assert result.exit_code == 1
        assert "sync failed" in result.output.lower()
        # No raw traceback leaked to the user.
        assert "Traceback" not in result.output

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

    def test_sync_errors_on_autodiscovered_toml_syntax_error(self, monkeypatch, tmp_path: Path):
        """Auto-discovery must hard-error on TOML syntax errors, not warn-and-continue (#491)."""

        bad_config = tmp_path / "envdrift.toml"
        bad_config.write_text("bad = [", encoding="utf-8")

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
        normalized = " ".join(result.output.split())
        assert "[ERROR] TOML syntax error in" in normalized
        assert "No sync configuration found" not in normalized


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

    def test_pull_skip_sync_decrypts_custom_env_file(self, monkeypatch, tmp_path: Path):
        """Pull should decrypt custom env_file mappings."""
        service_dir = tmp_path / "service"
        service_dir.mkdir()
        env_file = service_dir / "dotnet-service-template-local.env"
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
                environment = "local"
                env_file = "{env_file.name}"
                """
            ).lstrip()
        )

        monkeypatch.setattr("envdrift.vault.get_vault_client", lambda *_, **__: SimpleNamespace())
        _mock_sync_engine_success(monkeypatch)

        decrypted: list[Path] = []
        _mock_encryption_backend(monkeypatch, decrypted_paths=decrypted)

        result = runner.invoke(app, ["pull", "-c", str(config_file), "--skip-sync"])

        assert result.exit_code == 0, result.output
        assert env_file in decrypted
        assert "setup complete" in result.output.lower()

    def test_pull_reports_invalid_env_file(self, monkeypatch, tmp_path: Path):
        """An env_file that escapes folder_path is reported, not silently used."""
        service_dir = tmp_path / "service"
        service_dir.mkdir()

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
                environment = "local"
                env_file = "../escape.env"
                """
            ).lstrip()
        )

        monkeypatch.setattr("envdrift.vault.get_vault_client", lambda *_, **__: SimpleNamespace())
        _mock_sync_engine_success(monkeypatch)
        _mock_encryption_backend(monkeypatch, decrypted_paths=[])

        result = runner.invoke(app, ["pull", "-c", str(config_file), "--skip-sync"])

        assert "invalid env_file" in result.output.lower()

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
        # Collapse whitespace so Rich soft-wrap of long paths/messages at a narrow
        # CI width doesn't split the asserted phrases across lines.
        normalized = " ".join(result.output.lower().split())
        assert "activation failed" in normalized
        # An activation failure must not be reported as a decryption failure (#413).
        assert "could not be activated" in normalized
        assert "could not be decrypted" not in normalized

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
            return (True, True)  # (was_decrypted, protected)

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
            lambda _: (False, True),  # (was_decrypted, protected)
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

    @staticmethod
    def _write_partial_config(config_file: Path, service_dir: Path, paths: dict[str, Path]) -> None:
        """Write a sync TOML with one ``prod`` partial-encryption environment."""
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
                clear_file = "{paths["clear_file"].as_posix()}"
                secret_file = "{paths["secret_file"].as_posix()}"
                combined_file = "{paths["combined_file"].as_posix()}"
                """
            ).lstrip()
        )

    @staticmethod
    def _stub_merge_pull_seams(monkeypatch, service_dir: Path) -> None:
        """Stub only the vault/backend/hook seams for ``pull --merge`` tests.

        The gitignore + combined-file writing under test still runs for real.
        """
        from envdrift.sync.config import ServiceMapping, SyncConfig

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
        monkeypatch.setattr(
            "envdrift.core.partial_encryption.pull_partial_encryption",
            lambda _: (False, True),  # (was_decrypted, protected)
        )
        sync_config = SyncConfig(
            mappings=[
                ServiceMapping(secret_name="key", folder_path=service_dir, environment="prod")
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

    @classmethod
    def _setup_merge_pull_env(cls, monkeypatch, tmp_path: Path) -> dict[str, Path]:
        """Build a real git repo + config for the ``pull --merge`` regression test.

        Returns the clear/secret/combined paths and the config file. Only the
        vault/backend/hook seams are stubbed; the gitignore + combined-file
        writing under test runs for real.
        """
        import subprocess

        # A real git repo so ensure_gitignore_entries can resolve the git root and
        # write a real .gitignore (no mock of the behavior under test).
        subprocess.run(["git", "init"], cwd=str(tmp_path), capture_output=True, check=True)

        service_dir = tmp_path / "service"
        service_dir.mkdir()

        paths = {
            "clear_file": service_dir / ".env.prod.clear",
            "secret_file": service_dir / ".env.prod.secret",
            "combined_file": service_dir / ".env.prod",
            "config_file": tmp_path / "envdrift.toml",
        }
        paths["clear_file"].write_text("APP_NAME=myapp\n")
        paths["secret_file"].write_text("API_KEY=decrypted_key\n")

        cls._write_partial_config(paths["config_file"], service_dir, paths)
        cls._stub_merge_pull_seams(monkeypatch, service_dir)
        return paths

    def test_pull_merge_gitignores_combined_file(
        self,
        monkeypatch,
        tmp_path: Path,
    ):
        """Pull --merge must gitignore the decrypted combined file (#413).

        Regression for #413: the ``--merge`` branch wrote a combined file
        containing merged clear + DECRYPTED secret values but never added it to
        ``.gitignore`` (unlike ``push``, which calls ``_ensure_combined_gitignore``
        first). A routine ``git add .`` then staged plaintext secrets. This test
        runs the real ``pull --merge`` path against a real git repo and asserts the
        combined file lands in ``.gitignore``.
        """
        import subprocess

        env = self._setup_merge_pull_env(monkeypatch, tmp_path)
        combined_file = env["combined_file"]
        config_file = env["config_file"]

        result = runner.invoke(app, ["pull", "-c", str(config_file), "--skip-sync", "--merge"])

        assert result.exit_code == 0, result.output
        assert combined_file.exists()

        # The decrypted combined artifact must be gitignored, matching `push`.
        gitignore = tmp_path / ".gitignore"
        assert gitignore.exists(), ".gitignore was not created for the decrypted combined file"
        ignored = {line.strip() for line in gitignore.read_text().splitlines() if line.strip()}
        combined_rel = combined_file.resolve().relative_to(tmp_path.resolve()).as_posix()
        assert combined_rel in ignored, (
            f"{combined_rel} not gitignored; .gitignore has: {sorted(ignored)}"
        )

        # `git status` must NOT see the combined file as untracked-and-stageable.
        status = subprocess.run(
            ["git", "status", "--porcelain", "--", combined_rel],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            check=True,
        )
        assert status.stdout.strip() == "", (
            f"combined file is still visible to git: {status.stdout!r}"
        )

    def test_pull_merge_reports_error_on_non_utf8_secret(
        self,
        monkeypatch,
        tmp_path: Path,
    ):
        """A non-UTF-8 secret file must surface a partial error, not crash.

        The merge writer reads files as UTF-8; a decrypted secret with invalid
        bytes raises ``UnicodeDecodeError``. ``pull --merge`` must catch it,
        record a partial error, and exit 1 cleanly rather than propagating an
        unhandled exception out of the command.
        """
        env = self._setup_merge_pull_env(monkeypatch, tmp_path)
        # Overwrite the secret file with bytes that are not valid UTF-8 so the
        # real merge writer (read_text(encoding="utf-8")) raises.
        env["secret_file"].write_bytes(b"API_KEY=\xff\xfe_not_utf8\n")
        config_file = env["config_file"]

        result = runner.invoke(app, ["pull", "-c", str(config_file), "--skip-sync", "--merge"])

        assert result.exit_code == 1, result.output
        assert "merge failed" in result.output.lower()
        assert "partial encryption" in result.output.lower()
        # The decrypted combined artifact must not be left half-written.
        assert not env["combined_file"].exists()

    @staticmethod
    def test_write_merged_combined_file_handles_missing_inputs(tmp_path: Path):
        """The merge writer tolerates a missing clear and/or secret file.

        Exercises every existence branch of ``_write_merged_combined_file``:
        both present, only clear, only secret, and neither. The header lines
        from the secret file (``#/---`` banner, ``DOTENV_PUBLIC_KEY``) are
        always stripped.
        """
        from envdrift.cli_commands.sync import _write_merged_combined_file

        clear = tmp_path / ".env.clear"
        secret = tmp_path / ".env.secret"
        combined = tmp_path / ".env"

        # Both present: clear lines, a blank separator, then stripped secret lines.
        clear.write_text("APP=web\n")
        secret.write_text("#/--- banner\nDOTENV_PUBLIC_KEY=abc\nAPI_KEY=k\n")
        _write_merged_combined_file(clear, secret, combined)
        body = combined.read_text()
        assert "APP=web" in body
        assert "API_KEY=k" in body
        assert "banner" not in body
        assert "DOTENV_PUBLIC_KEY" not in body

        # Only the secret file present (clear missing): no separator needed.
        clear.unlink()
        _write_merged_combined_file(clear, secret, combined)
        assert combined.read_text().strip() == "API_KEY=k"

        # Only the clear file present (secret missing).
        clear.write_text("APP=web\n")
        secret.unlink()
        _write_merged_combined_file(clear, secret, combined)
        assert combined.read_text() == "APP=web\n\n"

        # Neither input present: an empty (single trailing newline) combined file.
        clear.unlink()
        _write_merged_combined_file(clear, secret, combined)
        assert combined.read_text() == "\n"


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

    def test_verify_vault_quoted_value_matches_no_false_mismatch(self, monkeypatch, tmp_path: Path):
        """lock --verify-vault: a quoted vault value matching the local key
        reports a match, not a false KEY MISMATCH (#413).

        Before the fix the inline parser didn't strip quotes (unlike read_key),
        so a vault value stored quoted always mismatched the unquoted local key.
        """
        secret = "abc" + "123" + "def"
        service_dir = tmp_path / "svc"
        service_dir.mkdir()
        (service_dir / ".env.keys").write_text(f"DOTENV_PRIVATE_KEY_PRODUCTION={secret}\n")
        (service_dir / ".env.production").write_text("SECRET=encrypted:xyz\n")

        from envdrift.sync.config import ServiceMapping, SyncConfig

        sync_config = SyncConfig(
            mappings=[
                ServiceMapping(secret_name="k", folder_path=service_dir, environment="production")
            ],
            env_keys_filename=".env.keys",
        )

        # Vault stores the key QUOTED; local stores it bare. A real SecretValue
        # (not a bare namespace) so the verify path's extract_key_material sees
        # the metadata attribute every provider's secret carries.
        vault_secret = SecretValue(name="k", value=f'"{secret}"')

        class _VaultClient:
            def ensure_authenticated(self) -> None:
                pass

            def get_secret(self, _name: str):
                return vault_secret

        monkeypatch.setattr(
            "envdrift.cli_commands.sync.load_sync_config_and_client",
            lambda *a, **k: (sync_config, _VaultClient(), "aws", None, None, None),
        )
        monkeypatch.setattr(
            "envdrift.integrations.hook_check.ensure_git_hook_setup", lambda **_k: []
        )
        _mock_encryption_backend(monkeypatch)

        config_file = tmp_path / "envdrift.toml"
        config_file.write_text('[vault]\nprovider = "aws"\n')

        result = runner.invoke(app, ["lock", "--verify-vault", "-c", str(config_file), "-p", "aws"])

        # Keys match -> verify raises no issue and lock proceeds to a clean exit.
        assert result.exit_code == 0, result.output
        # Collapse whitespace so a Rich soft-wrap of the long tmp path (CI runs
        # at a narrow width) doesn't split "keys match vault" across lines.
        normalized = " ".join(result.output.split())
        # The quoted vault value normalizes to the same bare key as local.
        assert "keys match vault" in normalized, result.output
        assert "KEY MISMATCH" not in normalized

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

    def test_lock_force_encrypts_custom_env_file(self, monkeypatch, tmp_path: Path):
        """Lock should encrypt custom env_file mappings."""
        service_dir = tmp_path / "service"
        service_dir.mkdir()
        env_file = service_dir / "dotnet-service-template.env.sqa"
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
                environment = "sqa"
                env_file = "{env_file.name}"
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

        result = runner.invoke(app, ["lock", "-c", str(config_file), "--force"])

        assert result.exit_code == 0, result.output
        assert env_file.resolve() in [path.resolve() for path in encrypted]

    def test_lock_reports_invalid_env_file(self, monkeypatch, tmp_path: Path):
        """An env_file that escapes folder_path is reported during lock."""
        service_dir = tmp_path / "service"
        service_dir.mkdir()

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
                environment = "sqa"
                env_file = "../escape.env"
                """
            ).lstrip()
        )

        monkeypatch.setattr("envdrift.vault.get_vault_client", lambda *_, **__: SimpleNamespace())
        monkeypatch.setattr(
            "envdrift.integrations.hook_check.ensure_git_hook_setup",
            lambda **_kwargs: [],
        )
        _mock_encryption_backend(monkeypatch, encrypted_paths=[])

        result = runner.invoke(app, ["lock", "-c", str(config_file), "--force"])

        assert "invalid env_file" in result.output.lower()

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

        # The .secret now goes through the partial-encryption lifecycle seam
        # (encrypt_secret_file), aligned with `envdrift push` (#507 review),
        # rather than the raw backend. Patch that seam to record + simulate it.
        partial_encrypted: list[Path] = []

        def _fake_encrypt_secret(env_config):
            partial_encrypted.append(Path(env_config.secret_file))

        monkeypatch.setattr(
            "envdrift.core.partial_encryption.encrypt_secret_file", _fake_encrypt_secret
        )

        result = runner.invoke(app, ["lock", "-c", str(config_file), "--force", "--all"])

        assert result.exit_code == 0
        # The main env file goes through the resolved backend...
        assert env_file.resolve() in [p.resolve() for p in encrypted]
        # ...and the .secret through the partial-encryption lifecycle seam.
        assert secret_file.resolve() in [p.resolve() for p in partial_encrypted]
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
        # has_encrypted_header is the API method called by production code (is_encrypted was a typo).
        dummy.has_encrypted_header = lambda content: "encrypted:" in content  # type: ignore[method-assign]

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
                    SecretValue: A secret whose value is "DOTENV_PRIVATE_KEY_PRODUCTION=remote".
                """
                return SecretValue(name="k", value="DOTENV_PRIVATE_KEY_PRODUCTION=remote")

        monkeypatch.setattr("envdrift.vault.get_vault_client", lambda *_, **__: DummyVault())

        result = runner.invoke(app, ["lock", "-c", str(config_file), "--verify-vault"])

        assert result.exit_code == 1
        # Collapse whitespace: Rich soft-wraps the long tmp_path service line
        # in CI, which can split the KEY MISMATCH phrase across a newline.
        out = " ".join(result.output.lower().split())
        assert "key mismatch" in out
        # The #473 contract: the gate reports that nothing was encrypted.
        assert "nothing was encrypted" in out

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
        captured: dict[str, Any] = {}

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

        captured: dict[str, Any] = {}

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

    def test_single_env_file_mismatched_environment_is_not_found(self, tmp_path: Path):
        """A lone .env.<other> must not be adopted for a different env (see #395)."""
        from envdrift.env_files import detect_env_file

        (tmp_path / ".env.staging").write_text("SECRET=value")

        detection = detect_env_file(tmp_path, default_environment="production")

        assert detection.status == "not_found"
        assert detection.path is None
        assert detection.environment is None

    def test_single_env_file_matching_environment_is_found(self, tmp_path: Path):
        """A lone .env.<env> is adopted when the requested env matches its suffix."""
        from envdrift.env_files import detect_env_file

        env_file = tmp_path / ".env.staging"
        env_file.write_text("SECRET=value")

        detection = detect_env_file(tmp_path, default_environment="staging")

        assert detection.status == "found"
        assert detection.path == env_file
        assert detection.environment == "staging"

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


class TestErrorPathHardening:
    """#26/#28: an unwritable init output and an invalid guard --fail-on are clean
    errors, not a PermissionError traceback / machine-output contamination."""

    def test_init_unwritable_output_is_clean_error(self, tmp_path: Path) -> None:
        env = tmp_path / ".env"
        env.write_text("API_KEY=abc\n")
        # A directory as the output path makes write_text raise OSError — the same
        # branch a read-only file hits, reliably and regardless of euid/platform.
        out_dir = tmp_path / "outdir"
        out_dir.mkdir()
        result = runner.invoke(app, ["init", str(env), "-o", str(out_dir), "--force"])
        assert result.exit_code == 1
        assert "Could not write" in result.output
        assert "Traceback" not in result.output

    def test_guard_invalid_fail_on_json_is_clean_error_doc(self, tmp_path: Path) -> None:
        env = tmp_path / ".env"
        env.write_text("API_KEY=sk-test\n")
        result = runner.invoke(
            app, ["guard", str(env), "--native-only", "--json", "--fail-on", "bogus"]
        )
        assert result.exit_code == 1
        # stdout must be a clean JSON error doc, not Rich/human prose (#28).
        doc = json.loads(result.output)
        assert "error" in doc and "bogus" in doc["error"]


class TestReadSeamGuards:
    """#24/#25: init/encrypt/validate surface a directory or a non-UTF-8 file as a
    clean error, not an uncaught IsADirectoryError / UnicodeDecodeError traceback."""

    def test_init_on_directory_is_clean_error(self, tmp_path: Path) -> None:
        a_dir = tmp_path / "adir"
        a_dir.mkdir()
        result = runner.invoke(app, ["init", str(a_dir), "-o", str(tmp_path / "o.py")])
        assert result.exit_code != 0
        assert "Not a file" in result.output
        assert result.exc_info is None or not isinstance(result.exception, IsADirectoryError)

    def test_init_on_non_utf8_is_clean_error(self, tmp_path: Path) -> None:
        bad = tmp_path / ".env.bad"
        bad.write_bytes(b"API_KEY=secret\nPASSWORD=p\xff\xc3ss\n")
        result = runner.invoke(app, ["init", str(bad), "-o", str(tmp_path / "o.py")])
        assert result.exit_code != 0
        assert "UTF-8" in result.output

    def test_validate_on_directory_is_clean_error(self, tmp_path: Path) -> None:
        env = tmp_path / ".env"
        env.write_text("FOO=bar\n")
        runner.invoke(app, ["init", str(env), "-o", str(tmp_path / "s.py"), "--class-name", "Cfg"])
        a_dir = tmp_path / "adir"
        a_dir.mkdir()
        result = runner.invoke(
            app, ["validate", str(a_dir), "--schema", "s:Cfg", "-d", str(tmp_path)]
        )
        assert result.exit_code != 0
        assert "Not a file" in result.output

    def test_validate_on_non_utf8_is_clean_error(self, tmp_path: Path) -> None:
        env = tmp_path / ".env"
        env.write_text("FOO=bar\n")
        runner.invoke(app, ["init", str(env), "-o", str(tmp_path / "s.py"), "--class-name", "Cfg"])
        bad = tmp_path / ".env.bad"
        bad.write_bytes(b"FOO=p\xff\xc3ss\n")
        result = runner.invoke(
            app, ["validate", str(bad), "--schema", "s:Cfg", "-d", str(tmp_path)]
        )
        assert result.exit_code != 0
        assert "UTF-8" in result.output

    def test_encrypt_check_on_directory_is_clean_error(self, tmp_path: Path) -> None:
        a_dir = tmp_path / "adir"
        a_dir.mkdir()
        result = runner.invoke(app, ["encrypt", "--check", str(a_dir)])
        assert result.exit_code != 0
        assert "Not a file" in result.output

    def test_encrypt_check_on_non_utf8_is_clean_error(self, tmp_path: Path) -> None:
        bad = tmp_path / ".env.bad"
        bad.write_bytes(b"FOO=p\xff\xc3ss\n")
        result = runner.invoke(app, ["encrypt", "--check", str(bad)])
        assert result.exit_code != 0
        assert "UTF-8" in result.output


class TestEncryptTruthfulness475:
    """Regressions for #475: encrypt must not report success without verifying
    the post-state, must refuse cross-backend double-encryption, and must
    surface auto-install failure causes."""

    def test_encrypt_refuses_cross_backend_double_encryption(self, monkeypatch, tmp_path: Path):
        """A dotenvx-encrypted file with ``--backend sops`` selected is refused
        before any backend runs — silently nesting sops over dotenvx bricks the
        file for ``decrypt`` auto-detect (#475)."""
        monkeypatch.chdir(tmp_path)
        env_file = tmp_path / ".env"
        original = (
            "#/---BEGIN DOTENV ENCRYPTED---/\n"
            'DOTENV_PUBLIC_KEY="03a5d2bc97e9f1c2"\n'
            'API_KEY="encrypted:BDqDBJaENb1cDe"\n'
        )
        env_file.write_text(original, encoding="utf-8")

        result = runner.invoke(app, ["encrypt", str(env_file), "--backend", "sops"])

        assert result.exit_code == 1
        out = " ".join(result.output.split())
        assert "dotenvx" in out
        assert "sops" in out
        # The file was not double-encrypted.
        assert env_file.read_text(encoding="utf-8") == original

    def test_encrypt_refuses_sops_file_with_dotenvx_backend(self, monkeypatch, tmp_path: Path):
        """The reverse direction is refused too: a SOPS-encrypted file must not be
        re-encrypted with dotenvx."""
        monkeypatch.chdir(tmp_path)
        env_file = tmp_path / ".env"
        original = (
            "DB_PASSWORD=ENC[AES256_GCM,data:abc,iv:def,tag:ghi,type:str]\nsops_version=3.13.1\n"
        )
        env_file.write_text(original, encoding="utf-8")

        result = runner.invoke(app, ["encrypt", str(env_file), "--backend", "dotenvx"])

        assert result.exit_code == 1
        out = " ".join(result.output.split())
        assert "sops" in out
        assert "dotenvx" in out
        assert env_file.read_text(encoding="utf-8") == original

    def test_encrypt_refuses_header_stripped_dotenvx_file_with_sops_backend(
        self, monkeypatch, tmp_path: Path
    ):
        """Value-level detection backs the cross-backend guard: a dotenvx file
        whose header lines were stripped (no banner, no DOTENV_PUBLIC_KEY) but
        whose values are still ``encrypted:`` ciphertext must be refused with
        ``--backend sops`` — the file-level header scan alone would miss it and
        sops would nest ciphertexts."""
        monkeypatch.chdir(tmp_path)
        env_file = tmp_path / ".env"
        original = 'API_KEY="encrypted:BDqDBJaENb1cDe"\n'
        env_file.write_text(original, encoding="utf-8")

        result = runner.invoke(app, ["encrypt", str(env_file), "--backend", "sops"])

        assert result.exit_code == 1
        out = " ".join(result.output.split())
        assert "dotenvx" in out
        assert env_file.read_text(encoding="utf-8") == original

    def test_encrypt_noop_result_message_is_not_discarded(self, monkeypatch, tmp_path: Path):
        """A successful no-change result prints the backend's honest message
        instead of an unconditional "Encrypted ... using ..." banner (#475)."""
        from unittest.mock import MagicMock

        from envdrift.encryption.base import EncryptionResult

        monkeypatch.chdir(tmp_path)
        env_file = tmp_path / ".env"
        env_file.write_text("FOO=bar\n", encoding="utf-8")

        mock_backend = MagicMock()
        mock_backend.name = "sops"
        mock_backend.is_installed.return_value = True
        mock_backend.encrypt.return_value = EncryptionResult(
            success=True,
            message=f"{env_file} is already encrypted (no change)",
            file_path=env_file,
            changed=False,
        )
        monkeypatch.setattr(
            "envdrift.cli_commands.encryption.get_encryption_backend",
            lambda *args, **kwargs: mock_backend,
        )

        result = runner.invoke(app, ["encrypt", str(env_file), "--backend", "sops"])

        assert result.exit_code == 0
        out = " ".join(result.output.split())
        assert "already encrypted (no change)" in out
        assert "Encrypted" not in out

    def test_encrypt_not_installed_surfaces_auto_install_failure(self, monkeypatch, tmp_path: Path):
        """When the backend recorded an auto-install failure, the not-installed
        error includes the cause instead of recommending the auto_install option
        that just failed (#475)."""
        from unittest.mock import MagicMock

        monkeypatch.chdir(tmp_path)
        env_file = tmp_path / ".env"
        env_file.write_text("FOO=bar\n", encoding="utf-8")

        mock_backend = MagicMock()
        mock_backend.name = "sops"
        mock_backend.is_installed.return_value = False
        mock_backend.install_error = "Failed to install SOPS from http://x: refused"
        mock_backend.install_instructions.return_value = "brew install sops"
        monkeypatch.setattr(
            "envdrift.cli_commands.encryption.get_encryption_backend",
            lambda *args, **kwargs: mock_backend,
        )

        result = runner.invoke(app, ["encrypt", str(env_file), "--backend", "sops"])

        assert result.exit_code == 1
        out = " ".join(result.output.split())
        assert "auto-install failed" in out
        assert "refused" in out
        assert "sops is not installed" in out
