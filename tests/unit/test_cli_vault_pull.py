"""Tests for vault-pull command (config-free single-secret pull)."""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from envdrift.cli import app
from envdrift.encryption import EncryptionProvider
from envdrift.encryption.base import EncryptionBackendError, EncryptionResult
from envdrift.vault.base import AuthenticationError, SecretNotFoundError, SecretValue, VaultError
from tests.helpers import DummyEncryptionBackend

runner = CliRunner()


def _make_client(value: str) -> MagicMock:
    client = MagicMock()
    client.get_secret.return_value = SecretValue(name="my-secret", value=value)
    return client


class TestVaultPullSingleSecret:
    """Tests for the single-secret config-free vault-pull command."""

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    @patch("envdrift.vault.get_vault_client")
    def test_pull_success_writes_key_and_decrypts(
        self,
        mock_get_client,
        mock_resolve_backend,
        tmp_path,
    ):
        """Happy path: writes DOTENV_PRIVATE_KEY_<ENV> to .env.keys and decrypts."""
        mock_get_client.return_value = _make_client("DOTENV_PRIVATE_KEY_PRODUCTION=abc123secret")
        backend = DummyEncryptionBackend()
        mock_resolve_backend.return_value = (backend, EncryptionProvider.DOTENVX, None)

        # An encrypted env file exists so decrypt runs
        env_file = tmp_path / ".env.production"
        env_file.write_text("SECRET=encrypted:xyz")

        result = runner.invoke(
            app,
            [
                "vault-pull",
                str(tmp_path),
                "my-secret",
                "--env",
                "production",
                "-p",
                "azure",
                "--vault-url",
                "https://myvault.vault.azure.net/",
            ],
        )

        assert result.exit_code == 0, result.output
        keys_content = (tmp_path / ".env.keys").read_text()
        assert "DOTENV_PRIVATE_KEY_PRODUCTION=abc123secret" in keys_content
        # decrypt was called on the env file
        assert backend.decrypt_calls == [env_file.resolve()]
        assert "Decrypted" in result.output

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    @patch("envdrift.vault.get_vault_client")
    def test_pull_decrypts_custom_env_file(
        self,
        mock_get_client,
        mock_resolve_backend,
        tmp_path,
    ):
        """--env-file decrypts the specified dotenv file with canonical key names."""
        mock_get_client.return_value = _make_client("DOTENV_PRIVATE_KEY_PRODUCTION=abc123secret")
        backend = DummyEncryptionBackend()
        mock_resolve_backend.return_value = (backend, EncryptionProvider.DOTENVX, None)

        env_file = tmp_path / "postgresql.env"
        env_file.write_text(
            "# postgresql.env\n"
            'DOTENV_PUBLIC_KEY_POSTGRESQLDEVELOPMENT="public"\n'
            "SECRET=encrypted:xyz\n"
        )

        result = runner.invoke(
            app,
            [
                "vault-pull",
                str(tmp_path),
                "my-secret",
                "--env",
                "production",
                "--env-file",
                env_file.name,
                "-p",
                "azure",
                "--vault-url",
                "https://myvault.vault.azure.net/",
            ],
        )

        assert result.exit_code == 0, result.output
        assert backend.decrypt_calls == [env_file.resolve()]
        assert "DOTENV_PRIVATE_KEY_PRODUCTION=abc123secret" in (tmp_path / ".env.keys").read_text()
        custom_content = env_file.read_text()
        assert "# .env.production" in custom_content
        assert "DOTENV_PUBLIC_KEY_PRODUCTION" in custom_content
        assert "POSTGRESQLDEVELOPMENT" not in custom_content

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    @patch("envdrift.vault.get_vault_client")
    def test_pull_value_without_prefix(
        self,
        mock_get_client,
        mock_resolve_backend,
        tmp_path,
    ):
        """Secret value with no KEY_NAME= prefix is treated as the bare key value."""
        mock_get_client.return_value = _make_client("barevalue999")
        backend = DummyEncryptionBackend()
        mock_resolve_backend.return_value = (backend, EncryptionProvider.DOTENVX, None)

        result = runner.invoke(
            app,
            [
                "vault-pull",
                str(tmp_path),
                "my-secret",
                "--env",
                "staging",
                "--no-decrypt",
                "-p",
                "azure",
                "--vault-url",
                "https://myvault.vault.azure.net/",
            ],
        )

        assert result.exit_code == 0, result.output
        keys_content = (tmp_path / ".env.keys").read_text()
        assert "DOTENV_PRIVATE_KEY_STAGING=barevalue999" in keys_content

    @patch("envdrift.vault.get_vault_client")
    def test_pull_no_decrypt_skips_decryption(
        self,
        mock_get_client,
        tmp_path,
    ):
        """--no-decrypt writes the key but does not attempt decryption."""
        mock_get_client.return_value = _make_client("DOTENV_PRIVATE_KEY_PRODUCTION=abc123")
        # Even with an env file present, decrypt should not run
        (tmp_path / ".env.production").write_text("SECRET=encrypted:xyz")

        result = runner.invoke(
            app,
            [
                "vault-pull",
                str(tmp_path),
                "my-secret",
                "--env",
                "production",
                "--no-decrypt",
                "-p",
                "azure",
                "--vault-url",
                "https://myvault.vault.azure.net/",
            ],
        )

        assert result.exit_code == 0, result.output
        assert "Decrypted" not in result.output
        assert "DOTENV_PRIVATE_KEY_PRODUCTION=abc123" in (tmp_path / ".env.keys").read_text()

    @patch("envdrift.vault.get_vault_client")
    def test_pull_no_env_file_to_decrypt(
        self,
        mock_get_client,
        tmp_path,
    ):
        """When no .env.<env> file exists, key is written and decrypt is skipped gracefully."""
        mock_get_client.return_value = _make_client("DOTENV_PRIVATE_KEY_PRODUCTION=abc123")

        result = runner.invoke(
            app,
            [
                "vault-pull",
                str(tmp_path),
                "my-secret",
                "--env",
                "production",
                "-p",
                "azure",
                "--vault-url",
                "https://myvault.vault.azure.net/",
            ],
        )

        assert result.exit_code == 0, result.output
        assert "found to decrypt" in result.output
        assert "DOTENV_PRIVATE_KEY_PRODUCTION=abc123" in (tmp_path / ".env.keys").read_text()

    @patch("envdrift.vault.get_vault_client")
    def test_pull_rejects_custom_env_file_outside_folder(
        self,
        mock_get_client,
        tmp_path,
    ):
        """--env-file must stay inside FOLDER."""
        mock_get_client.return_value = _make_client("DOTENV_PRIVATE_KEY_PRODUCTION=abc123")

        result = runner.invoke(
            app,
            [
                "vault-pull",
                str(tmp_path),
                "my-secret",
                "--env",
                "production",
                "--env-file",
                "../outside.env",
                "-p",
                "azure",
                "--vault-url",
                "https://myvault.vault.azure.net/",
            ],
        )

        assert result.exit_code == 1
        assert "invalid --env-file" in result.output.lower()

    def test_pull_missing_env_flag(self, tmp_path):
        """--env is required; omitting it fails."""
        result = runner.invoke(
            app,
            [
                "vault-pull",
                str(tmp_path),
                "my-secret",
                "-p",
                "azure",
                "--vault-url",
                "https://myvault.vault.azure.net/",
            ],
        )
        assert result.exit_code != 0

    @patch("envdrift.vault.get_vault_client")
    def test_pull_secret_not_found(
        self,
        mock_get_client,
        tmp_path,
    ):
        """SecretNotFoundError exits with code 1."""
        client = MagicMock()
        client.get_secret.side_effect = SecretNotFoundError("missing")
        mock_get_client.return_value = client

        result = runner.invoke(
            app,
            [
                "vault-pull",
                str(tmp_path),
                "my-secret",
                "--env",
                "production",
                "-p",
                "azure",
                "--vault-url",
                "https://myvault.vault.azure.net/",
            ],
        )

        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    @patch("envdrift.vault.get_vault_client")
    def test_pull_vault_error_on_fetch(
        self,
        mock_get_client,
        tmp_path,
    ):
        """VaultError during fetch exits with code 1."""
        client = MagicMock()
        client.get_secret.side_effect = VaultError("boom")
        mock_get_client.return_value = client

        result = runner.invoke(
            app,
            [
                "vault-pull",
                str(tmp_path),
                "my-secret",
                "--env",
                "production",
                "-p",
                "azure",
                "--vault-url",
                "https://myvault.vault.azure.net/",
            ],
        )

        assert result.exit_code == 1
        assert "Failed to fetch secret" in result.output

    def test_pull_azure_requires_vault_url(self, tmp_path):
        """Azure provider without --vault-url fails validation."""
        result = runner.invoke(
            app,
            [
                "vault-pull",
                str(tmp_path),
                "my-secret",
                "--env",
                "production",
                "-p",
                "azure",
            ],
        )
        assert result.exit_code == 1
        assert "azure provider requires --vault-url" in " ".join(result.output.split()).lower()

    def test_pull_gcp_requires_project_id(self, tmp_path):
        """GCP provider without --project-id fails validation."""
        result = runner.invoke(
            app,
            [
                "vault-pull",
                str(tmp_path),
                "my-secret",
                "--env",
                "production",
                "-p",
                "gcp",
            ],
        )
        assert result.exit_code == 1
        assert "gcp provider requires --project-id" in " ".join(result.output.split()).lower()

    def test_pull_missing_provider(self, tmp_path):
        """No provider and no config fails."""
        with patch("envdrift.config.find_config", return_value=None):
            result = runner.invoke(
                app,
                [
                    "vault-pull",
                    str(tmp_path),
                    "my-secret",
                    "--env",
                    "production",
                ],
            )
        assert result.exit_code == 1
        assert "provider required" in result.output.lower()

    @patch("envdrift.vault.get_vault_client")
    def test_pull_auth_failure(
        self,
        mock_get_client,
        tmp_path,
    ):
        """Authentication failure exits with code 1.

        Raises AuthenticationError (not a bare VaultError): only genuine auth
        failures carry the "authentication failed" label now (#441 audit).
        """
        client = MagicMock()
        client.authenticate.side_effect = AuthenticationError("auth failed")
        mock_get_client.return_value = client

        result = runner.invoke(
            app,
            [
                "vault-pull",
                str(tmp_path),
                "my-secret",
                "--env",
                "production",
                "-p",
                "azure",
                "--vault-url",
                "https://myvault.vault.azure.net/",
            ],
        )

        assert result.exit_code == 1
        assert "authentication failed" in result.output.lower()

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    @patch("envdrift.vault.get_vault_client")
    def test_pull_decrypt_backend_not_installed(
        self,
        mock_get_client,
        mock_resolve_backend,
        tmp_path,
    ):
        """If the encryption backend is not installed, exit with code 1."""
        mock_get_client.return_value = _make_client("DOTENV_PRIVATE_KEY_PRODUCTION=abc123")
        mock_resolve_backend.return_value = (
            DummyEncryptionBackend(installed=False),
            EncryptionProvider.DOTENVX,
            None,
        )
        (tmp_path / ".env.production").write_text("SECRET=encrypted:xyz")

        result = runner.invoke(
            app,
            [
                "vault-pull",
                str(tmp_path),
                "my-secret",
                "--env",
                "production",
                "-p",
                "azure",
                "--vault-url",
                "https://myvault.vault.azure.net/",
            ],
        )

        assert result.exit_code == 1
        assert "not installed" in result.output.lower()

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    @patch("envdrift.vault.get_vault_client")
    def test_pull_decrypt_failure(
        self,
        mock_get_client,
        mock_resolve_backend,
        tmp_path,
    ):
        """A failed decrypt result exits with code 1."""
        mock_get_client.return_value = _make_client("DOTENV_PRIVATE_KEY_PRODUCTION=abc123")
        backend = DummyEncryptionBackend()

        def fail_decrypt(env_file, **kwargs):
            return EncryptionResult(success=False, message="bad key", file_path=env_file)

        backend.decrypt = fail_decrypt  # type: ignore[method-assign]
        mock_resolve_backend.return_value = (backend, EncryptionProvider.DOTENVX, None)
        (tmp_path / ".env.production").write_text("SECRET=encrypted:xyz")

        result = runner.invoke(
            app,
            [
                "vault-pull",
                str(tmp_path),
                "my-secret",
                "--env",
                "production",
                "-p",
                "azure",
                "--vault-url",
                "https://myvault.vault.azure.net/",
            ],
        )

        assert result.exit_code == 1
        assert "failed to decrypt" in result.output.lower()

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    @patch("envdrift.vault.get_vault_client")
    def test_pull_decrypt_raises_backend_error(
        self,
        mock_get_client,
        mock_resolve_backend,
        tmp_path,
    ):
        """An EncryptionBackendError during decrypt exits with code 1."""
        mock_get_client.return_value = _make_client("DOTENV_PRIVATE_KEY_PRODUCTION=abc123")
        backend = DummyEncryptionBackend(
            decrypt_side_effect=EncryptionBackendError("decrypt blew up")
        )
        mock_resolve_backend.return_value = (backend, EncryptionProvider.DOTENVX, None)
        (tmp_path / ".env.production").write_text("SECRET=encrypted:xyz")

        result = runner.invoke(
            app,
            [
                "vault-pull",
                str(tmp_path),
                "my-secret",
                "--env",
                "production",
                "-p",
                "azure",
                "--vault-url",
                "https://myvault.vault.azure.net/",
            ],
        )

        assert result.exit_code == 1
        assert "failed to decrypt" in result.output.lower()

    @patch("envdrift.vault.get_vault_client")
    def test_pull_aws_provider(
        self,
        mock_get_client,
        tmp_path,
    ):
        """AWS provider works with --region and no vault-url."""
        mock_get_client.return_value = _make_client("DOTENV_PRIVATE_KEY_PRODUCTION=awssecret")

        result = runner.invoke(
            app,
            [
                "vault-pull",
                str(tmp_path),
                "my-secret",
                "--env",
                "production",
                "--no-decrypt",
                "-p",
                "aws",
                "--region",
                "us-west-2",
            ],
        )

        assert result.exit_code == 0, result.output
        mock_get_client.assert_called_once_with("aws", region="us-west-2")
        assert "DOTENV_PRIVATE_KEY_PRODUCTION=awssecret" in (tmp_path / ".env.keys").read_text()

    @patch("envdrift.vault.get_vault_client")
    def test_pull_hashicorp_provider(
        self,
        mock_get_client,
        tmp_path,
    ):
        """HashiCorp provider passes url through to the client."""
        mock_get_client.return_value = _make_client("DOTENV_PRIVATE_KEY_PRODUCTION=hcvalue")

        result = runner.invoke(
            app,
            [
                "vault-pull",
                str(tmp_path),
                "my-secret",
                "--env",
                "production",
                "--no-decrypt",
                "-p",
                "hashicorp",
                "--vault-url",
                "https://vault.example.com:8200",
            ],
        )

        assert result.exit_code == 0, result.output
        mock_get_client.assert_called_once_with("hashicorp", url="https://vault.example.com:8200")

    @patch("envdrift.vault.get_vault_client")
    def test_pull_gcp_provider(
        self,
        mock_get_client,
        tmp_path,
    ):
        """GCP provider passes project_id through to the client."""
        mock_get_client.return_value = _make_client("DOTENV_PRIVATE_KEY_PRODUCTION=gcpvalue")

        result = runner.invoke(
            app,
            [
                "vault-pull",
                str(tmp_path),
                "my-secret",
                "--env",
                "production",
                "--no-decrypt",
                "-p",
                "gcp",
                "--project-id",
                "my-project",
            ],
        )

        assert result.exit_code == 0, result.output
        mock_get_client.assert_called_once_with("gcp", project_id="my-project")

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    @patch("envdrift.vault.get_vault_client")
    def test_pull_unsupported_backend(
        self,
        mock_get_client,
        mock_resolve_backend,
        tmp_path,
    ):
        """A ValueError from backend resolution exits with code 1."""
        mock_get_client.return_value = _make_client("DOTENV_PRIVATE_KEY_PRODUCTION=abc123")
        mock_resolve_backend.side_effect = ValueError("nope")
        (tmp_path / ".env.production").write_text("SECRET=encrypted:xyz")

        result = runner.invoke(
            app,
            [
                "vault-pull",
                str(tmp_path),
                "my-secret",
                "--env",
                "production",
                "-p",
                "azure",
                "--vault-url",
                "https://myvault.vault.azure.net/",
            ],
        )

        assert result.exit_code == 1
        assert "unsupported encryption backend" in result.output.lower()

    @patch("envdrift.vault.get_vault_client")
    def test_pull_uses_config_defaults(
        self,
        mock_get_client,
        tmp_path,
    ):
        """When --provider/--vault-url are omitted, values come from envdrift.toml [vault]."""
        mock_get_client.return_value = _make_client("DOTENV_PRIVATE_KEY_PRODUCTION=cfgvalue")

        config_file = tmp_path / "envdrift.toml"
        config_file.write_text(
            '[vault]\nprovider = "azure"\n\n[vault.azure]\nvault_url = "https://cfg.vault.azure.net/"\n'
        )

        result = runner.invoke(
            app,
            [
                "vault-pull",
                str(tmp_path),
                "my-secret",
                "--env",
                "production",
                "--no-decrypt",
                "-c",
                str(config_file),
            ],
        )

        assert result.exit_code == 0, result.output
        mock_get_client.assert_called_once_with("azure", vault_url="https://cfg.vault.azure.net/")

    @patch("envdrift.vault.get_vault_client")
    def test_pull_import_error(
        self,
        mock_get_client,
        tmp_path,
    ):
        """ImportError (missing SDK extras) exits with code 1."""
        mock_get_client.side_effect = ImportError("Azure vault support requires extras")

        result = runner.invoke(
            app,
            [
                "vault-pull",
                str(tmp_path),
                "my-secret",
                "--env",
                "production",
                "-p",
                "azure",
                "--vault-url",
                "https://myvault.vault.azure.net/",
            ],
        )

        assert result.exit_code == 1
        assert "Azure vault support" in result.output


class _InMemoryVault:
    """A tiny in-memory vault used to exercise a push -> pull round-trip."""

    def __init__(self) -> None:
        self.store: dict[str, str] = {}

    def authenticate(self) -> None:
        return None

    def set_secret(self, name: str, value: str) -> SecretValue:
        self.store[name] = value
        return SecretValue(name=name, value=value, version="1")

    def get_secret(self, name: str) -> SecretValue:
        if name not in self.store:
            raise SecretNotFoundError(name)
        return SecretValue(name=name, value=self.store[name])


class TestVaultPushPullRoundTrip:
    """vault-push then vault-pull should reproduce the original key."""

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    @patch("envdrift.vault.get_vault_client")
    def test_push_then_pull_roundtrip(
        self,
        mock_get_client,
        mock_resolve_backend,
        tmp_path,
    ):
        """A key pushed from one folder is recovered identically by vault-pull."""
        vault = _InMemoryVault()
        mock_get_client.return_value = vault
        mock_resolve_backend.return_value = (
            DummyEncryptionBackend(),
            EncryptionProvider.DOTENVX,
            None,
        )

        # Source folder with a real key in .env.keys
        src = tmp_path / "src"
        src.mkdir()
        (src / ".env.keys").write_text("DOTENV_PRIVATE_KEY_PRODUCTION=roundtripsecret\n")

        push = runner.invoke(
            app,
            [
                "vault-push",
                str(src),
                "shared-key",
                "--env",
                "production",
                "-p",
                "azure",
                "--vault-url",
                "https://myvault.vault.azure.net/",
            ],
        )
        assert push.exit_code == 0, push.output
        assert vault.store["shared-key"] == ("DOTENV_PRIVATE_KEY_PRODUCTION=roundtripsecret")

        # Destination folder receives the key via vault-pull
        dst = tmp_path / "dst"
        dst.mkdir()

        pull = runner.invoke(
            app,
            [
                "vault-pull",
                str(dst),
                "shared-key",
                "--env",
                "production",
                "--no-decrypt",
                "-p",
                "azure",
                "--vault-url",
                "https://myvault.vault.azure.net/",
            ],
        )
        assert pull.exit_code == 0, pull.output

        recovered = (dst / ".env.keys").read_text()
        assert "DOTENV_PRIVATE_KEY_PRODUCTION=roundtripsecret" in recovered


class TestVaultPullReviewFixes:
    """Regression tests for issues raised in PR review."""

    @patch("envdrift.vault.get_vault_client")
    def test_pull_fails_fast_on_env_prefix_mismatch(self, mock_get_client, tmp_path):
        """Pulling --env production a secret pushed --env staging fails fast, writes nothing."""
        mock_get_client.return_value = _make_client("DOTENV_PRIVATE_KEY_STAGING=abc123")

        result = runner.invoke(
            app,
            [
                "vault-pull",
                str(tmp_path),
                "my-secret",
                "--env",
                "production",
                "--no-decrypt",
                "-p",
                "azure",
                "--vault-url",
                "https://myvault.vault.azure.net/",
            ],
        )

        assert result.exit_code == 1, result.output
        # The error names both the stored prefix and the requested env.
        assert "DOTENV_PRIVATE_KEY_STAGING" in result.output
        assert "production" in result.output.lower()
        # No mismatched key is written.
        assert not (tmp_path / ".env.keys").exists()

    @patch("envdrift.cli_commands.encryption_helpers.resolve_encryption_backend")
    @patch("envdrift.vault.get_vault_client")
    def test_pull_passes_keys_file_to_decrypt(
        self,
        mock_get_client,
        mock_resolve_backend,
        tmp_path,
    ):
        """Decrypt is pointed at the .env.keys we just wrote (monorepo / folder != cwd)."""
        mock_get_client.return_value = _make_client("DOTENV_PRIVATE_KEY_PRODUCTION=abc123")
        backend = DummyEncryptionBackend()
        mock_resolve_backend.return_value = (backend, EncryptionProvider.DOTENVX, None)

        folder = tmp_path / "services" / "myapp"
        folder.mkdir(parents=True)
        (folder / ".env.production").write_text("SECRET=encrypted:xyz")

        result = runner.invoke(
            app,
            [
                "vault-pull",
                str(folder),
                "my-secret",
                "--env",
                "production",
                "-p",
                "azure",
                "--vault-url",
                "https://myvault.vault.azure.net/",
            ],
        )

        assert result.exit_code == 0, result.output
        assert backend.decrypt_kwargs, "decrypt was not called"
        assert backend.decrypt_kwargs[0]["keys_file"] == (folder / ".env.keys").resolve()

    def test_pull_invalid_provider_exits_cleanly(self, tmp_path):
        """An unsupported provider raises ValueError in get_vault_client; the CLI exits cleanly."""
        # `bogus` is not azure/hashicorp/gcp, so it reaches get_vault_client, where
        # VaultProvider("bogus") raises a real ValueError — no mock needed.
        result = runner.invoke(
            app,
            [
                "vault-pull",
                str(tmp_path),
                "my-secret",
                "--env",
                "production",
                "-p",
                "bogus",
            ],
        )

        assert result.exit_code == 1
        assert "Invalid vault configuration" in result.output
        # No unhandled exception leaked through.
        assert result.exception is None or isinstance(result.exception, SystemExit)


class TestVaultPullKeyMaterialNormalization:
    """Regression tests for #480: vault-pull normalizes and shape-validates the
    fetched key material before writing .env.keys, instead of installing
    quoted/JSON/multi-line/binary payloads verbatim under a success banner."""

    def _pull(self, tmp_path, *extra):
        return runner.invoke(
            app,
            [
                "vault-pull",
                str(tmp_path),
                "my-secret",
                "--env",
                "production",
                "--no-decrypt",
                "-p",
                "azure",
                "--vault-url",
                "https://myvault.vault.azure.net/",
                *extra,
            ],
        )

    @patch("envdrift.vault.get_vault_client")
    def test_quoted_full_line_value_writes_bare_key(self, mock_get_client, tmp_path):
        """A whole-line-quoted vault value must be normalized like sync does (#356),
        not written as DOTENV_PRIVATE_KEY_X="DOTENV_PRIVATE_KEY_X=<key>"."""
        mock_get_client.return_value = _make_client('"DOTENV_PRIVATE_KEY_PRODUCTION=abc123secret"')

        result = self._pull(tmp_path)

        assert result.exit_code == 0, result.output
        lines = (tmp_path / ".env.keys").read_text(encoding="utf-8").splitlines()
        assert "DOTENV_PRIVATE_KEY_PRODUCTION=abc123secret" in lines

    @patch("envdrift.vault.get_vault_client")
    def test_whitespace_wrapped_bare_value_is_stripped(self, mock_get_client, tmp_path):
        mock_get_client.return_value = _make_client("  abc123secret  \n")

        result = self._pull(tmp_path)

        assert result.exit_code == 0, result.output
        lines = (tmp_path / ".env.keys").read_text(encoding="utf-8").splitlines()
        assert "DOTENV_PRIVATE_KEY_PRODUCTION=abc123secret" in lines

    @patch("envdrift.vault.get_vault_client")
    def test_json_document_secret_extracts_matching_field(self, mock_get_client, tmp_path):
        """AWS-console-style JSON key/value SecretString: extract the key field."""
        mock_get_client.return_value = _make_client(
            '{"DOTENV_PRIVATE_KEY_PRODUCTION": "abc123secret"}'
        )

        result = self._pull(tmp_path)

        assert result.exit_code == 0, result.output
        lines = (tmp_path / ".env.keys").read_text(encoding="utf-8").splitlines()
        assert "DOTENV_PRIVATE_KEY_PRODUCTION=abc123secret" in lines

    @patch("envdrift.vault.get_vault_client")
    def test_json_document_without_key_field_fails_loudly(self, mock_get_client, tmp_path):
        """A JSON document with no DOTENV_PRIVATE_KEY field is rejected with a
        clear shape error — never installed under [OK] / exit 0."""
        mock_get_client.return_value = _make_client('{"username": "admin", "password": "hunter2"}')

        result = self._pull(tmp_path)

        assert result.exit_code == 1, result.output
        normalized = " ".join(result.output.split())
        assert "JSON" in normalized
        # Field names are named, secret values are not leaked.
        assert "username" in normalized
        assert "hunter2" not in normalized
        assert not (tmp_path / ".env.keys").exists()

    @patch("envdrift.vault.get_vault_client")
    def test_multiline_keys_blob_extracts_matching_line(self, mock_get_client, tmp_path):
        """A secret holding whole .env.keys file content (e.g. pushed via
        `az keyvault secret set --file .env.keys`) yields the bare key line."""
        blob = (
            "#/------------------!DOTENV_PRIVATE_KEYS!-------------------/\n"
            "#/ private decryption keys. DO NOT commit to source control /\n"
            "# .env.production\n"
            'DOTENV_PRIVATE_KEY_PRODUCTION="abc123secret"\n'
        )
        mock_get_client.return_value = _make_client(blob)

        result = self._pull(tmp_path)

        assert result.exit_code == 0, result.output
        content = (tmp_path / ".env.keys").read_text(encoding="utf-8")
        lines = content.splitlines()
        assert "DOTENV_PRIVATE_KEY_PRODUCTION=abc123secret" in lines
        # Only the extracted key line was installed (a single key line, not the
        # blob's quoted line); the file's own header is freshly generated.
        key_lines = [line for line in lines if line.startswith("DOTENV_PRIVATE_KEY_")]
        assert key_lines == ["DOTENV_PRIVATE_KEY_PRODUCTION=abc123secret"]

    @patch("envdrift.vault.get_vault_client")
    def test_multiline_blob_without_key_line_fails_loudly(self, mock_get_client, tmp_path):
        mock_get_client.return_value = _make_client("# a comment\nFOO=bar\nBAZ=qux\n")

        result = self._pull(tmp_path)

        assert result.exit_code == 1, result.output
        assert "multi-line" in " ".join(result.output.split())
        assert not (tmp_path / ".env.keys").exists()

    @patch("envdrift.vault.get_vault_client")
    def test_base64_marked_binary_secret_rejected(self, mock_get_client, tmp_path):
        """A provider-marked binary payload (SecretBinary / non-UTF-8 GCP payload)
        is rejected — its base64 transform is never installed as a key."""
        client = MagicMock()
        client.get_secret.return_value = SecretValue(
            name="my-secret", value="//4=", metadata={"encoding": "base64"}
        )
        mock_get_client.return_value = client

        result = self._pull(tmp_path)

        assert result.exit_code == 1, result.output
        assert "binary" in " ".join(result.output.split()).lower()
        assert not (tmp_path / ".env.keys").exists()

    @patch("envdrift.vault.get_vault_client")
    def test_empty_value_key_line_fails_loudly(self, mock_get_client, tmp_path):
        """A secret of exactly 'DOTENV_PRIVATE_KEY_PRODUCTION=' (e.g. pushed via
        `vault kv put ... DOTENV_PRIVATE_KEY_PRODUCTION=$KEY` with $KEY unset)
        must fail, not be written back as a doubled-prefix .env.keys line."""
        mock_get_client.return_value = _make_client("DOTENV_PRIVATE_KEY_PRODUCTION=")

        result = self._pull(tmp_path)

        assert result.exit_code == 1, result.output
        assert "empty" in " ".join(result.output.split()).lower()
        assert not (tmp_path / ".env.keys").exists()

    @patch("envdrift.vault.get_vault_client")
    def test_json_field_carrying_full_line_writes_bare_key(self, mock_get_client, tmp_path):
        """A JSON field value holding the whole 'DOTENV_PRIVATE_KEY_X=<key>' line
        (a copy-pasted .env.keys line in the console value box) is reduced to
        the bare key — never written with a doubled prefix."""
        mock_get_client.return_value = _make_client(
            '{"DOTENV_PRIVATE_KEY_PRODUCTION": "DOTENV_PRIVATE_KEY_PRODUCTION=abc123secret"}'
        )

        result = self._pull(tmp_path)

        assert result.exit_code == 0, result.output
        lines = (tmp_path / ".env.keys").read_text(encoding="utf-8").splitlines()
        assert "DOTENV_PRIVATE_KEY_PRODUCTION=abc123secret" in lines
        assert not any("DOTENV_PRIVATE_KEY_PRODUCTION=DOTENV_PRIVATE_KEY" in line for line in lines)

    @patch("envdrift.vault.get_vault_client")
    def test_pretty_printed_json_document_extracts_key(self, mock_get_client, tmp_path):
        """Pretty-printed JSON (embedded newlines) must reach the JSON handler,
        not the keys-blob handler that cannot see the key field."""
        mock_get_client.return_value = _make_client(
            '{\n  "DOTENV_PRIVATE_KEY_PRODUCTION": "abc123secret"\n}\n'
        )

        result = self._pull(tmp_path)

        assert result.exit_code == 0, result.output
        lines = (tmp_path / ".env.keys").read_text(encoding="utf-8").splitlines()
        assert "DOTENV_PRIVATE_KEY_PRODUCTION=abc123secret" in lines

    @patch("envdrift.vault.get_vault_client")
    def test_json_blob_with_mismatched_env_field_still_fails_env_check(
        self, mock_get_client, tmp_path
    ):
        """A JSON document holding only a STAGING key pulled --env production hits
        the established env-mismatch error rather than being relabeled."""
        mock_get_client.return_value = _make_client(
            '{"DOTENV_PRIVATE_KEY_STAGING": "stagingkey123"}'
        )

        result = self._pull(tmp_path)

        assert result.exit_code == 1, result.output
        assert "DOTENV_PRIVATE_KEY_STAGING" in result.output
        assert not (tmp_path / ".env.keys").exists()


class TestVaultPullTargetFolderAndWriteErrors:
    """#487: bad target folders / unwritable .env.keys must fail cleanly.

    Pre-fix, ``vault-pull`` fetched the secret successfully and then dumped a
    raw ``OSError`` / ``PermissionError`` / ``UnicodeDecodeError`` Rich
    traceback from the unguarded ``EnvKeysFile.write_key`` call. The vault
    client is mocked only as a value source; the behavior under test is the
    CLI's folder validation and file-write error boundary, exercised with real
    files in ``tmp_path``.
    """

    def _pull_args(self, folder):
        return [
            "vault-pull",
            str(folder),
            "my-secret",
            "--env",
            "production",
            "--no-decrypt",
            "-p",
            "azure",
            "--vault-url",
            "https://myvault.vault.azure.net/",
        ]

    @patch("envdrift.vault.get_vault_client")
    def test_pull_nonexistent_folder_fails_before_fetch(self, mock_get_client, tmp_path):
        """A missing target folder exits 1 cleanly without any vault call (#487)."""
        client = _make_client("DOTENV_PRIVATE_KEY_PRODUCTION=abc123secret")
        mock_get_client.return_value = client

        result = runner.invoke(app, self._pull_args(tmp_path / "no-such-dir"))

        assert result.exit_code == 1
        out = " ".join(result.output.split())
        assert "Folder not found" in out, out
        # Fail-fast: the folder is validated before any vault round-trip.
        client.get_secret.assert_not_called()
        assert not isinstance(result.exception, OSError), result.exception

    @patch("envdrift.vault.get_vault_client")
    def test_pull_folder_is_a_file_fails_cleanly(self, mock_get_client, tmp_path):
        """A non-directory target exits 1 cleanly without any vault call (#487)."""
        client = _make_client("DOTENV_PRIVATE_KEY_PRODUCTION=abc123secret")
        mock_get_client.return_value = client
        target = tmp_path / "afile"
        target.write_text("not a folder", encoding="utf-8")

        result = runner.invoke(app, self._pull_args(target))

        assert result.exit_code == 1
        out = " ".join(result.output.split())
        assert "Not a directory" in out, out
        client.get_secret.assert_not_called()

    @patch("envdrift.vault.get_vault_client")
    def test_pull_env_keys_is_directory_clean_error(self, mock_get_client, tmp_path):
        """.env.keys as a directory exits 1 with a one-line error (#487)."""
        mock_get_client.return_value = _make_client("DOTENV_PRIVATE_KEY_PRODUCTION=abc123secret")
        (tmp_path / ".env.keys").mkdir()

        result = runner.invoke(app, self._pull_args(tmp_path))

        assert result.exit_code == 1
        out = " ".join(result.output.split())
        assert "Cannot write" in out, out
        assert ".env.keys" in out, out
        assert not isinstance(result.exception, OSError), result.exception

    @patch("envdrift.vault.get_vault_client")
    def test_pull_env_keys_non_utf8_clean_error(self, mock_get_client, tmp_path):
        """A non-UTF-8 .env.keys exits 1 with a one-line error (#487)."""
        mock_get_client.return_value = _make_client("DOTENV_PRIVATE_KEY_PRODUCTION=abc123secret")
        (tmp_path / ".env.keys").write_bytes(b"DOTENV_PRIVATE_KEY_PRODUCTION=caf\xe9\n")

        result = runner.invoke(app, self._pull_args(tmp_path))

        assert result.exit_code == 1
        out = " ".join(result.output.split())
        assert "Cannot write" in out, out
        assert not isinstance(result.exception, ValueError), result.exception

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
    @patch("envdrift.vault.get_vault_client")
    def test_pull_unwritable_folder_clean_error(self, mock_get_client, tmp_path):
        """A read-only target folder exits 1 with a one-line error (#487)."""
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            pytest.skip("root ignores permission bits")
        mock_get_client.return_value = _make_client("DOTENV_PRIVATE_KEY_PRODUCTION=abc123secret")
        target = tmp_path / "readonly"
        target.mkdir()
        target.chmod(0o555)

        try:
            result = runner.invoke(app, self._pull_args(target))
        finally:
            target.chmod(0o755)

        assert result.exit_code == 1
        out = " ".join(result.output.split())
        assert "Cannot write" in out, out
        assert not isinstance(result.exception, OSError), result.exception


class TestVaultPullNotFoundNamesRegion:
    """#487: the AWS not-found error must name the region that was searched."""

    @patch("envdrift.vault.get_vault_client")
    def test_pull_aws_not_found_message_names_region(self, mock_get_client, tmp_path):
        """vault-pull -p aws --region eu-west-1 names eu-west-1 on not-found (#487)."""
        client = MagicMock()
        client.region = "eu-west-1"
        client.get_secret.side_effect = SecretNotFoundError("Secret not found: my-secret")
        mock_get_client.return_value = client

        result = runner.invoke(
            app,
            [
                "vault-pull",
                str(tmp_path),
                "my-secret",
                "--env",
                "production",
                "--no-decrypt",
                "-p",
                "aws",
                "--region",
                "eu-west-1",
            ],
        )

        assert result.exit_code == 1
        out = " ".join(result.output.split())
        assert "not found in aws vault" in out, out
        assert "(region eu-west-1)" in out, out
