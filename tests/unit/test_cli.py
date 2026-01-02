"""Tests for envdrift.cli module - Command Line Interface."""

from __future__ import annotations

import tomllib
from pathlib import Path
from textwrap import dedent
from types import SimpleNamespace

from typer.testing import CliRunner

from envdrift.cli import app
from envdrift.cli_commands.encryption import _verify_decryption_with_vault
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
                """
                Initialize the instance and set the `called` flag to False.

                This prepares the object in an uninvoked state by creating a boolean attribute
                `called` initialized to False.
                """
                self.called = False

            def is_installed(self):
                """
                Check whether the component is installed.

                This implementation always reports the component as installed.

                Returns:
                    `true` if the component is installed, `false` otherwise.
                """
                return True

            def encrypt(self, file_path):
                """
                Record that the encrypt method was invoked and assert the provided path matches the expected env file.

                Parameters:
                    file_path (str | pathlib.Path): Path passed to the encrypt method; must equal the test's expected `env_file`.
                """
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
                """
                Report whether the integration is installed and available for use.

                Returns:
                    `True` if the integration is installed and available, `False` otherwise.
                """
                return False

            def install_instructions(self):
                """
                Provide the installation command for the `dotenvx` CLI.

                Returns:
                    installation_command (str): The exact shell command "npm install -g dotenvx" to install dotenvx globally.
                """
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

    def test_decrypt_calls_dotenvx_when_installed(self, monkeypatch, tmp_path: Path):
        """Decrypt should call dotenvx when available."""

        env_file = tmp_path / ".env"
        env_file.write_text("SECRET=encrypted")

        class DummyDotenvx:
            def __init__(self):
                """
                Create a new instance with its decrypted state initialized to False.

                Attributes:
                    decrypted: Indicates whether the instance's content has been decrypted; starts as False.
                """
                self.decrypted = False

            def is_installed(self):
                """
                Check whether the component is installed.

                This implementation always reports the component as installed.

                Returns:
                    `true` if the component is installed, `false` otherwise.
                """
                return True

            def decrypt(self, file_path):
                """
                Mark this object as having performed decryption and verify the target file path.

                Parameters:
                    file_path (str | Path): Path to the file intended for decryption; must match the module-level `env_file`.

                Raises:
                    AssertionError: If `file_path` does not equal the expected `env_file`.
                """
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
                """
                Initialize the instance with runtime dependencies and callbacks.

                Parameters:
                    config: Configuration object or mapping that controls the instance's behavior and settings.
                    vault_client: Vault client used to retrieve or verify secrets; expected to expose the methods the instance uses to interact with the vault.
                    mode: Operation mode identifier that determines how the instance will perform its tasks (for example, different modes may enable verification, decryption, or sync behavior).
                    prompt_callback: Callable used to request interactive input from the user. Expected signature: prompt_callback(prompt: str) -> str.
                    progress_callback: Callable used to report progress or status updates. Expected signature: progress_callback(info: float | str) -> None.
                """
                self.config = config
                self.vault_client = vault_client
                self.mode = mode
                self.prompt_callback = prompt_callback
                self.progress_callback = progress_callback

            def sync_all(self):
                """
                Return a stubbed synchronization result indicating no errors.

                Returns:
                    SimpleNamespace: An object with attributes:
                        - services: an empty list representing synchronized services.
                        - has_errors: `False` indicating no synchronization errors occurred.
                """
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
                """
                Create a new instance that accepts arbitrary positional and keyword arguments but performs no additional initialization.
                """
                pass

            def sync_all(self):
                """
                Return a namespace representing a sync result with no services and an error state.

                Returns:
                    result (types.SimpleNamespace): An object with attributes:
                        - services (list): An empty list of synchronized services.
                        - has_errors (bool): True to indicate the sync encountered errors.
                """
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

        class DummyEngine:
            def __init__(self, *_args, **_kwargs):
                pass

            def sync_all(self):
                return SimpleNamespace(services=[], has_errors=False)

        monkeypatch.setattr("envdrift.sync.engine.SyncEngine", DummyEngine)

        class DummyDotenvx:
            def __init__(self):
                self.decrypted: list[Path] = []

            def is_installed(self):
                return True

            def decrypt(self, env_path):
                self.decrypted.append(Path(env_path))

        dummy = DummyDotenvx()
        monkeypatch.setattr("envdrift.integrations.dotenvx.DotenvxWrapper", lambda: dummy)

        result = runner.invoke(app, ["pull", "-c", str(config_file)])

        assert result.exit_code == 0
        assert env_file in dummy.decrypted
        assert "setup complete" in result.output.lower()

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

        class DummyEngine:
            def __init__(self, *_args, **_kwargs):
                pass

            def sync_all(self):
                return SimpleNamespace(services=[], has_errors=False)

        monkeypatch.setattr("envdrift.sync.engine.SyncEngine", DummyEngine)

        class DummyDotenvx:
            def __init__(self):
                self.decrypted: list[Path] = []

            def is_installed(self):
                return True

            def decrypt(self, env_path):
                self.decrypted.append(Path(env_path))

        dummy = DummyDotenvx()
        monkeypatch.setattr("envdrift.integrations.dotenvx.DotenvxWrapper", lambda: dummy)

        result = runner.invoke(app, ["pull", "-c", str(config_file), "--profile", "local"])

        assert result.exit_code == 1
        assert env_a in dummy.decrypted
        assert env_b in dummy.decrypted
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

        class DummyEngine:
            def __init__(self, *_args, **_kwargs):
                pass

            def sync_all(self):
                return SimpleNamespace(services=[], has_errors=False)

        monkeypatch.setattr("envdrift.sync.engine.SyncEngine", DummyEngine)
        monkeypatch.setattr("envdrift.output.rich.print_service_sync_status", lambda *_, **__: None)
        monkeypatch.setattr("envdrift.output.rich.print_sync_result", lambda *_, **__: None)

        class DummyDotenvx:
            def is_installed(self):
                return False

            def install_instructions(self):
                return "install dotenvx"

        monkeypatch.setattr("envdrift.integrations.dotenvx.DotenvxWrapper", lambda: DummyDotenvx())

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

        class DummyEngine:
            def __init__(self, *_args, **_kwargs):
                pass

            def sync_all(self):
                return SimpleNamespace(services=[], has_errors=False)

        monkeypatch.setattr("envdrift.sync.engine.SyncEngine", DummyEngine)
        monkeypatch.setattr("envdrift.output.rich.print_service_sync_status", lambda *_, **__: None)
        monkeypatch.setattr("envdrift.output.rich.print_sync_result", lambda *_, **__: None)

        class DummyDotenvx:
            def is_installed(self):
                return True

            def decrypt(self, _path):
                raise DotenvxError("boom")

        monkeypatch.setattr("envdrift.integrations.dotenvx.DotenvxWrapper", lambda: DummyDotenvx())

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

        class DummyEngine:
            def __init__(self, *_args, **_kwargs):
                pass

            def sync_all(self):
                return SimpleNamespace(services=[], has_errors=False)

        monkeypatch.setattr("envdrift.sync.engine.SyncEngine", DummyEngine)
        monkeypatch.setattr("envdrift.output.rich.print_service_sync_status", lambda *_, **__: None)
        monkeypatch.setattr("envdrift.output.rich.print_sync_result", lambda *_, **__: None)

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

        class DummyEngine:
            def __init__(self, *_args, **_kwargs):
                pass

            def sync_all(self):
                return SimpleNamespace(services=[], has_errors=False)

        monkeypatch.setattr("envdrift.sync.engine.SyncEngine", DummyEngine)
        monkeypatch.setattr("envdrift.output.rich.print_service_sync_status", lambda *_, **__: None)
        monkeypatch.setattr("envdrift.output.rich.print_sync_result", lambda *_, **__: None)

        class DummyDotenvx:
            def is_installed(self):
                return True

        monkeypatch.setattr("envdrift.integrations.dotenvx.DotenvxWrapper", lambda: DummyDotenvx())

        result = runner.invoke(app, ["pull", "-c", str(config_file)])

        assert result.exit_code == 0
        assert "multiple .env" in result.output.lower()


class TestLockCommand:
    """Tests for the lock CLI command."""

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

        class DummyDotenvx:
            def is_installed(self):
                return True

        monkeypatch.setattr("envdrift.integrations.dotenvx.DotenvxWrapper", lambda: DummyDotenvx())

        result = runner.invoke(app, ["lock", "-c", str(config_file), "--check"])

        assert result.exit_code == 1
        assert "need encryption" in result.output.lower()

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
                return None

            def get_secret(self, _name):
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

        class DummyDotenvx:
            def is_installed(self):
                return True

        monkeypatch.setattr("envdrift.integrations.dotenvx.DotenvxWrapper", lambda: DummyDotenvx())

        result = runner.invoke(app, ["lock", "-c", str(config_file), "--force"])

        assert result.exit_code == 0
        assert "already encrypted" in result.output.lower()


class TestVaultPushCommand:
    """Tests for vault-push command."""

    def test_vault_push_requires_provider(self, tmp_path: Path):
        """vault-push should require a provider."""
        result = runner.invoke(
            app,
            ["vault-push", str(tmp_path), "secret-name", "--env", "soak"],
        )
        assert result.exit_code == 1
        assert "provider required" in result.output.lower()

    def test_vault_push_requires_vault_url_for_azure(self, tmp_path: Path):
        """vault-push should require vault URL for azure provider."""
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
