"""Tests for envdrift.cli module - Command Line Interface."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from typer.testing import CliRunner

from envdrift.cli import _verify_decryption_with_vault, app
from envdrift.integrations.dotenvx import DotenvxError

runner = CliRunner()


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
        """Test encrypt without --check calls dotenvx.encrypt."""

        env_file = tmp_path / ".env"
        env_file.write_text("FOO=bar")

        class DummyDotenvx:
            def __init__(self):
                self.called = False

            def is_installed(self):
                return True

            def encrypt(self, file_path):
                self.called = True
                assert Path(file_path) == env_file

        dummy = DummyDotenvx()
        monkeypatch.setattr("envdrift.integrations.dotenvx.DotenvxWrapper", lambda: dummy)

        result = runner.invoke(app, ["encrypt", str(env_file)])

        assert result.exit_code == 0
        assert dummy.called is True

    def test_encrypt_prompts_install_when_missing_dotenvx(self, monkeypatch, tmp_path: Path):
        """Encrypt should surface install instructions when dotenvx is absent."""

        env_file = tmp_path / ".env"
        env_file.write_text("FOO=bar")

        class DummyDotenvx:
            def is_installed(self):
                return False

            def install_instructions(self):
                return "npm install -g dotenvx"

        monkeypatch.setattr("envdrift.integrations.dotenvx.DotenvxWrapper", lambda: DummyDotenvx())

        result = runner.invoke(app, ["encrypt", str(env_file)])

        assert result.exit_code == 1
        assert "dotenvx is not installed" in result.output
        assert "npm install" in result.output


class TestDecryptCommand:
    """Tests for the decrypt CLI command."""

    def test_decrypt_missing_file(self, tmp_path: Path):
        """Test decrypt with missing file."""
        result = runner.invoke(app, ["decrypt", str(tmp_path / "missing.env")])
        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_decrypt_verify_vault_only(self, monkeypatch, tmp_path: Path):
        """--verify-vault should call verification and not decrypt the file."""

        env_file = tmp_path / ".env.production"
        env_file.write_text("SECRET=encrypted")

        called = {"verify": False}

        def fake_verify(**kwargs):
            called["verify"] = True
            return True

        monkeypatch.setattr("envdrift.cli._verify_decryption_with_vault", fake_verify)

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

    def test_decrypt_calls_dotenvx_when_installed(self, monkeypatch, tmp_path: Path):
        """Decrypt should call dotenvx when available."""

        env_file = tmp_path / ".env"
        env_file.write_text("SECRET=encrypted")

        class DummyDotenvx:
            def __init__(self):
                self.decrypted = False

            def is_installed(self):
                return True

            def decrypt(self, file_path):
                self.decrypted = True
                assert Path(file_path) == env_file

        dummy = DummyDotenvx()
        monkeypatch.setattr("envdrift.integrations.dotenvx.DotenvxWrapper", lambda: dummy)

        result = runner.invoke(app, ["decrypt", str(env_file)])

        assert result.exit_code == 0
        assert dummy.decrypted is True

    def test_decrypt_verify_vault_requires_provider(self, tmp_path: Path):
        """Verify-vault should require provider and secret arguments."""

        env_file = tmp_path / ".env"
        env_file.write_text("SECRET=encrypted")

        result = runner.invoke(app, ["decrypt", str(env_file), "--verify-vault", "--secret", "key"])

        assert result.exit_code == 1
        assert "provider" in result.output.lower()


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
                return None

            def get_secret(self, name: str):
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
            provider="azure",
            vault_url="https://example.vault.azure.net",
            region=None,
            secret_name="env-drift-production-key",
        )

        assert result is False
        joined = " ".join(printed)
        assert "git restore" in joined
        assert str(env_file) in joined
        assert "envdrift sync --force" in joined

    def test_verify_vault_aws_with_raw_secret(self, monkeypatch, tmp_path: Path):
        """Vault verification should accept raw secrets and derive key name."""

        env_file = tmp_path / ".env"
        env_file.write_text("SECRET=encrypted")

        class DummyVault:
            def ensure_authenticated(self) -> None:
                return None

            def get_secret(self, name: str):
                assert name == "dotenv-key"
                return "plainawskey"

        captured: dict = {}

        class DummyDotenvx:
            def is_installed(self):
                return True

            def decrypt(self, env_path, env_keys_file=None, env=None, cwd=None):
                captured["env_var"] = env.get("DOTENV_PRIVATE_KEY_PRODUCTION")
                captured["cwd"] = cwd
                assert env_path.exists()

        monkeypatch.setattr("envdrift.vault.get_vault_client", lambda *_, **__: DummyVault())
        monkeypatch.setattr("envdrift.integrations.dotenvx.DotenvxWrapper", lambda: DummyDotenvx())

        result = _verify_decryption_with_vault(
            env_file=env_file,
            provider="aws",
            vault_url=None,
            region="us-east-1",
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
            called["installed"] = True
            return True

        monkeypatch.setattr("envdrift.integrations.precommit.install_hooks", fake_install_hooks)

        result = runner.invoke(app, ["hook", "--install"])

        assert result.exit_code == 0
        assert called["installed"] is True


class TestSyncCommand:
    """Tests for the sync CLI command."""

    def test_sync_requires_config_and_provider(self, tmp_path: Path):
        """Sync should enforce required options."""

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
                self.config = config
                self.vault_client = vault_client
                self.mode = mode
                self.prompt_callback = prompt_callback
                self.progress_callback = progress_callback

            def sync_all(self):
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
                pass

            def sync_all(self):
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
