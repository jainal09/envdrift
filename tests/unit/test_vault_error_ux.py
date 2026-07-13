"""CLI-level regression tests for vault config/error UX (#441 dogfood audit).

Each test pins one confirmed finding:

- omitting ``[vault] provider`` with a single ``[vault.<provider>]`` section
  must not silently default to azure,
- a network/DNS failure must not be labeled an authentication failure,
- the standard ``VAULT_ADDR`` env var is honored for the HashiCorp vault URL,
- the same missing-vault-URL condition reads identically across commands.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import typer
from typer.testing import CliRunner

from envdrift.cli import app
from envdrift.vault.base import AuthenticationError, SecretNotFoundError, VaultError

runner = CliRunner()

AZURE_URL_MESSAGE = "Azure provider requires --vault-url (or [vault.azure] vault_url in config)"


def _flat(output: str) -> str:
    """Collapse whitespace so assertions stay width-independent."""
    return " ".join(output.split())


class TestProviderInferenceCli:
    """Omitted provider must resolve to the configured section's provider."""

    def test_gcp_only_config_resolves_gcp_not_azure(self, tmp_path, monkeypatch):
        """A [vault.gcp]-only config must not demand an Azure vault URL."""
        (tmp_path / "envdrift.toml").write_text(
            "[vault]\n\n"
            '[vault.gcp]\nproject_id = "my-gcp-project"\n\n'
            '[[vault.sync.mappings]]\nsecret_name = "s"\nfolder_path = "."\n'
            'environment = "production"\n',
            encoding="utf-8",
        )
        monkeypatch.chdir(tmp_path)
        captured = {}

        def fake_get_client(provider, **kwargs):
            captured["provider"] = provider
            captured["kwargs"] = kwargs
            client = MagicMock()
            client.get_secret.side_effect = SecretNotFoundError("not there")
            return client

        with patch("envdrift.vault.get_vault_client", side_effect=fake_get_client):
            result = runner.invoke(app, ["sync", "--verify"])
        assert captured["provider"] == "gcp"
        assert captured["kwargs"] == {"project_id": "my-gcp-project"}
        assert "Azure provider requires" not in _flat(result.output)


class TestAuthLabelTruthfulness:
    """Only real authentication failures may carry the authentication label."""

    def _invoke_push(self):
        with patch("envdrift.config.find_config", return_value=None):
            return runner.invoke(
                app,
                [
                    "vault-push",
                    "--direct",
                    "soak-machine",
                    "DOTENV_PRIVATE_KEY_SOAK=abc123",
                    "-p",
                    "azure",
                    "--vault-url",
                    "https://myvault.vault.azure.net/",
                ],
            )

    def test_network_failure_not_labeled_authentication(self):
        """A DNS/connection VaultError surfaces without the auth label."""
        client = MagicMock()
        client.authenticate.side_effect = VaultError(
            "Azure Key Vault error: Failed to resolve 'myvault.vault.azure.net'"
        )
        with patch("envdrift.vault.get_vault_client", return_value=client):
            result = self._invoke_push()
        flat = _flat(result.output)
        assert result.exit_code == 1
        assert "authentication failed" not in flat.lower()
        assert "Failed to resolve" in flat

    def test_authentication_failure_keeps_auth_label(self):
        """A genuine AuthenticationError still reads as an auth failure."""
        client = MagicMock()
        client.authenticate.side_effect = AuthenticationError("Vault token is invalid or expired")
        with patch("envdrift.vault.get_vault_client", return_value=client):
            result = self._invoke_push()
        flat = _flat(result.output)
        assert result.exit_code == 1
        assert "Vault authentication failed" in flat


class TestVaultAddrFallback:
    """VAULT_ADDR (honored by every HashiCorp tool) supplies the vault URL."""

    def _options(self, **overrides):
        from envdrift.cli_commands.vault_helpers import VaultConnectionOptions

        base = {
            "config": None,
            "provider": "hashicorp",
            "vault_url": None,
            "region": None,
            "project_id": None,
        }
        base.update(overrides)
        return VaultConnectionOptions(**base)

    def test_resolve_vault_settings_falls_back_to_vault_addr(self, monkeypatch):
        from envdrift.cli_commands.vault_helpers import resolve_vault_settings

        monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:8200")
        with patch("envdrift.config.find_config", return_value=None):
            settings = resolve_vault_settings(self._options())
        assert settings.vault_url == "http://127.0.0.1:8200"

    def test_explicit_vault_url_beats_vault_addr(self, monkeypatch):
        from envdrift.cli_commands.vault_helpers import resolve_vault_settings

        monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:8200")
        with patch("envdrift.config.find_config", return_value=None):
            settings = resolve_vault_settings(
                self._options(vault_url="http://vault.example.com:8200")
            )
        assert settings.vault_url == "http://vault.example.com:8200"

    def test_config_url_beats_vault_addr(self, tmp_path, monkeypatch):
        from envdrift.cli_commands.vault_helpers import resolve_vault_settings

        monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:8200")
        cfg = tmp_path / "envdrift.toml"
        cfg.write_text(
            '[vault]\nprovider = "hashicorp"\n\n'
            '[vault.hashicorp]\nurl = "http://cfg.example.com:8200"\n',
            encoding="utf-8",
        )
        settings = resolve_vault_settings(self._options(config=cfg))
        assert settings.vault_url == "http://cfg.example.com:8200"

    def test_empty_vault_addr_is_ignored(self, monkeypatch):
        from envdrift.cli_commands.vault_helpers import resolve_vault_settings

        monkeypatch.setenv("VAULT_ADDR", "")
        with patch("envdrift.config.find_config", return_value=None):
            with pytest.raises(typer.Exit):
                resolve_vault_settings(self._options())

    def test_whitespace_only_vault_addr_is_ignored(self, monkeypatch):
        """A whitespace-only VAULT_ADDR hits the missing-URL guard, not the client.

        A bare truthiness check let " " through as the vault URL, turning a
        clear config error into a late connection failure (#652 review).
        """
        from envdrift.cli_commands.vault_helpers import resolve_vault_settings

        monkeypatch.setenv("VAULT_ADDR", "   ")
        with patch("envdrift.config.find_config", return_value=None):
            with pytest.raises(typer.Exit):
                resolve_vault_settings(self._options())

    def test_padded_vault_addr_is_stripped_and_used(self, monkeypatch):
        """A padded-but-valid VAULT_ADDR is stripped, not passed through raw."""
        from envdrift.cli_commands.vault_helpers import resolve_vault_settings

        monkeypatch.setenv("VAULT_ADDR", "  http://127.0.0.1:8200  ")
        with patch("envdrift.config.find_config", return_value=None):
            settings = resolve_vault_settings(self._options())
        assert settings.vault_url == "http://127.0.0.1:8200"

    def test_sync_seam_whitespace_only_vault_addr_is_ignored(self, tmp_path, monkeypatch):
        """The sync-family seam rejects a whitespace-only VAULT_ADDR too."""
        from envdrift.cli_commands.sync import load_sync_config_and_client

        monkeypatch.setenv("VAULT_ADDR", "   ")
        cfg = tmp_path / "sync.toml"
        cfg.write_text(
            '[vault]\nprovider = "hashicorp"\n\n'
            '[[vault.sync.mappings]]\nsecret_name = "s"\nfolder_path = "svc"\n',
            encoding="utf-8",
        )
        with patch("envdrift.vault.get_vault_client") as mock_get_client:
            with pytest.raises(typer.Exit):
                load_sync_config_and_client(
                    config_file=cfg,
                    provider=None,
                    vault_url=None,
                    region=None,
                    project_id=None,
                )
        mock_get_client.assert_not_called()

    def test_sync_seam_padded_vault_addr_is_stripped(self, tmp_path, monkeypatch):
        """The sync-family seam strips a padded VAULT_ADDR before use."""
        from envdrift.cli_commands.sync import load_sync_config_and_client

        monkeypatch.setenv("VAULT_ADDR", "  http://127.0.0.1:8200  ")
        cfg = tmp_path / "sync.toml"
        cfg.write_text(
            '[vault]\nprovider = "hashicorp"\n\n'
            '[[vault.sync.mappings]]\nsecret_name = "s"\nfolder_path = "svc"\n',
            encoding="utf-8",
        )
        captured = {}

        def fake_get_client(provider, **kwargs):
            captured["kwargs"] = kwargs
            return MagicMock()

        with patch("envdrift.vault.get_vault_client", side_effect=fake_get_client):
            _, _, _, vault_url, *_ = load_sync_config_and_client(
                config_file=cfg,
                provider=None,
                vault_url=None,
                region=None,
                project_id=None,
            )
        assert vault_url == "http://127.0.0.1:8200"
        assert captured["kwargs"]["url"] == "http://127.0.0.1:8200"

    def test_sync_seam_falls_back_to_vault_addr(self, tmp_path, monkeypatch):
        """The sync-family seam honors VAULT_ADDR too, not just vault-push/pull."""
        from envdrift.cli_commands.sync import load_sync_config_and_client

        monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:8200")
        cfg = tmp_path / "sync.toml"
        cfg.write_text(
            '[vault]\nprovider = "hashicorp"\n\n'
            '[[vault.sync.mappings]]\nsecret_name = "s"\nfolder_path = "svc"\n',
            encoding="utf-8",
        )
        captured = {}

        def fake_get_client(provider, **kwargs):
            captured["kwargs"] = kwargs
            return MagicMock()

        with patch("envdrift.vault.get_vault_client", side_effect=fake_get_client):
            _, _, provider, vault_url, *_ = load_sync_config_and_client(
                config_file=cfg,
                provider=None,
                vault_url=None,
                region=None,
                project_id=None,
            )
        assert provider == "hashicorp"
        assert vault_url == "http://127.0.0.1:8200"
        assert captured["kwargs"]["url"] == "http://127.0.0.1:8200"

    def test_missing_url_error_mentions_vault_addr(self, tmp_path, monkeypatch):
        """Without any URL source, the error names all three remedies."""
        monkeypatch.delenv("VAULT_ADDR", raising=False)
        with patch("envdrift.config.find_config", return_value=None):
            result = runner.invoke(
                app,
                ["vault-pull", str(tmp_path), "s", "--env", "production", "-p", "hashicorp"],
            )
        flat = _flat(result.output)
        assert result.exit_code == 1
        assert "HashiCorp provider requires --vault-url" in flat
        assert "VAULT_ADDR" in flat


class TestMissingUrlMessageParity:
    """The same missing-URL condition must read identically across commands."""

    def test_sync_and_vault_pull_emit_same_azure_message(self, tmp_path, monkeypatch):
        (tmp_path / "envdrift.toml").write_text(
            '[vault]\nprovider = "azure"\n\n'
            '[[vault.sync.mappings]]\nsecret_name = "s"\nfolder_path = "."\n'
            'environment = "production"\n',
            encoding="utf-8",
        )
        monkeypatch.chdir(tmp_path)

        sync_result = runner.invoke(app, ["sync", "--verify"])
        pull_result = runner.invoke(app, ["vault-pull", ".", "s", "--env", "production"])

        assert sync_result.exit_code == 1
        assert pull_result.exit_code == 1
        assert AZURE_URL_MESSAGE in _flat(sync_result.output)
        assert AZURE_URL_MESSAGE in _flat(pull_result.output)
