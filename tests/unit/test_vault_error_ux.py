"""CLI-level regression tests for vault config/error UX (#441 dogfood audit).

Each test pins one confirmed finding:

- omitting ``[vault] provider`` with a single ``[vault.<provider>]`` section
  must not silently default to azure,
- a network/DNS failure must not be labeled an authentication failure,
- the standard ``VAULT_ADDR`` env var is honored for the HashiCorp vault URL,
- the same missing-vault-URL condition reads identically across commands.
"""

from __future__ import annotations

from dataclasses import dataclass
from unittest.mock import MagicMock, patch

import pytest
import typer
from typer.testing import CliRunner

from envdrift.cli import app
from envdrift.cli_commands.sync_config_helpers import (
    AZURE_VAULT_URL_REQUIRED,
    GCP_PROJECT_ID_REQUIRED,
    HASHICORP_VAULT_URL_REQUIRED,
)
from envdrift.vault.base import AuthenticationError, SecretNotFoundError, VaultError

runner = CliRunner()


@dataclass(frozen=True)
class _ProviderCase:
    """One provider-specific config resolution case."""

    provider: str
    config_text: str
    setting_name: str
    expected_value: str


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

    @pytest.mark.parametrize(
        "vault_addr",
        ["http://127.0.0.1:8200", "  http://127.0.0.1:8200  "],
        ids=["plain", "padded"],
    )
    def test_resolve_vault_settings_falls_back_to_vault_addr(self, monkeypatch, vault_addr):
        """VAULT_ADDR supplies the URL; a padded value is stripped, not passed raw."""
        from envdrift.cli_commands.vault_helpers import resolve_vault_settings

        monkeypatch.setenv("VAULT_ADDR", vault_addr)
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

    @pytest.mark.parametrize(
        "vault_addr",
        ["http://127.0.0.1:8200", "  http://127.0.0.1:8200  "],
        ids=["plain", "padded"],
    )
    def test_sync_seam_falls_back_to_vault_addr(self, tmp_path, monkeypatch, vault_addr):
        """The sync-family seam honors VAULT_ADDR too, stripping a padded value."""
        from envdrift.cli_commands.sync import load_sync_config_and_client

        monkeypatch.setenv("VAULT_ADDR", vault_addr)
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

    @pytest.mark.parametrize(
        ("provider", "required_message"),
        [
            ("azure", AZURE_VAULT_URL_REQUIRED),
            ("hashicorp", HASHICORP_VAULT_URL_REQUIRED),
            ("gcp", GCP_PROJECT_ID_REQUIRED),
        ],
    )
    def test_sync_vault_pull_and_decrypt_emit_same_message(
        self, tmp_path, monkeypatch, provider, required_message
    ):
        """All three CLI seams use the shared provider-setting message."""
        (tmp_path / "envdrift.toml").write_text(
            f'[vault]\nprovider = "{provider}"\n\n'
            '[[vault.sync.mappings]]\nsecret_name = "s"\nfolder_path = "."\n'
            'environment = "production"\n',
            encoding="utf-8",
        )
        env_file = tmp_path / ".env.production"
        env_file.write_text("SECRET=encrypted\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("VAULT_ADDR", raising=False)

        sync_result = runner.invoke(app, ["sync", "--verify"])
        pull_result = runner.invoke(app, ["vault-pull", ".", "s", "--env", "production"])
        decrypt_result = runner.invoke(
            app,
            [
                "decrypt",
                str(env_file),
                "--backend",
                "dotenvx",
                "--verify-vault",
                "--provider",
                provider,
                "--secret",
                "s",
            ],
        )

        assert sync_result.exit_code == 1
        assert pull_result.exit_code == 1
        assert decrypt_result.exit_code == 1
        assert required_message in _flat(sync_result.output)
        assert required_message in _flat(pull_result.output)
        assert required_message in _flat(decrypt_result.output)


class TestDecryptVerifyVaultSettings:
    """decrypt --verify-vault shares provider-setting resolution with vault commands."""

    @staticmethod
    def _invoke(tmp_path, provider, monkeypatch, *extra_args):
        env_file = tmp_path / ".env.production"
        env_file.write_text("SECRET=encrypted\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        return runner.invoke(
            app,
            [
                "decrypt",
                str(env_file),
                "--backend",
                "dotenvx",
                "--verify-vault",
                "--provider",
                provider,
                "--secret",
                "s",
                *extra_args,
            ],
        )

    @pytest.mark.parametrize(
        "case",
        [
            pytest.param(
                _ProviderCase(
                    provider="azure",
                    config_text='[vault.azure]\nvault_url = "https://config.vault.azure.net"\n',
                    setting_name="vault_url",
                    expected_value="https://config.vault.azure.net",
                ),
                id="azure",
            ),
            pytest.param(
                _ProviderCase(
                    provider="aws",
                    config_text='[vault.aws]\nregion = "eu-west-2"\n',
                    setting_name="region",
                    expected_value="eu-west-2",
                ),
                id="aws",
            ),
            pytest.param(
                _ProviderCase(
                    provider="hashicorp",
                    config_text='[vault.hashicorp]\nurl = "http://config-vault:8200"\n',
                    setting_name="vault_url",
                    expected_value="http://config-vault:8200",
                ),
                id="hashicorp",
            ),
            pytest.param(
                _ProviderCase(
                    provider="gcp",
                    config_text='[vault.gcp]\nproject_id = "config-project"\n',
                    setting_name="project_id",
                    expected_value="config-project",
                ),
                id="gcp",
            ),
        ],
    )
    def test_provider_settings_resolve_from_config(self, tmp_path, monkeypatch, case):
        """Every verify-vault provider consumes its setting from config."""
        (tmp_path / "envdrift.toml").write_text(
            f'[vault]\nprovider = "{case.provider}"\n\n{case.config_text}',
            encoding="utf-8",
        )
        monkeypatch.setenv("VAULT_ADDR", "http://environment-vault:8200")
        verify = MagicMock(return_value=True)
        monkeypatch.setattr(
            "envdrift.cli_commands.encryption._verify_decryption_with_vault",
            verify,
        )

        result = self._invoke(tmp_path, case.provider, monkeypatch)

        assert result.exit_code == 0
        assert verify.call_args.kwargs[case.setting_name] == case.expected_value

    @pytest.mark.parametrize(
        "vault_addr",
        ["http://environment-vault:8200", "  http://environment-vault:8200  "],
        ids=["plain", "padded"],
    )
    def test_hashicorp_falls_back_to_vault_addr(self, tmp_path, monkeypatch, vault_addr):
        """VAULT_ADDR supplies and normalizes the HashiCorp URL on this seam."""
        monkeypatch.setenv("VAULT_ADDR", vault_addr)
        verify = MagicMock(return_value=True)
        monkeypatch.setattr(
            "envdrift.cli_commands.encryption._verify_decryption_with_vault",
            verify,
        )

        result = self._invoke(tmp_path, "hashicorp", monkeypatch)

        assert result.exit_code == 0
        assert verify.call_args.kwargs["vault_url"] == "http://environment-vault:8200"

    def test_hashicorp_explicit_url_beats_config_and_vault_addr(self, tmp_path, monkeypatch):
        """The explicit URL retains precedence over both lower-priority sources."""
        (tmp_path / "envdrift.toml").write_text(
            '[vault]\nprovider = "hashicorp"\n\n'
            '[vault.hashicorp]\nurl = "http://config-vault:8200"\n',
            encoding="utf-8",
        )
        monkeypatch.setenv("VAULT_ADDR", "http://environment-vault:8200")
        verify = MagicMock(return_value=True)
        monkeypatch.setattr(
            "envdrift.cli_commands.encryption._verify_decryption_with_vault",
            verify,
        )

        result = self._invoke(
            tmp_path,
            "hashicorp",
            monkeypatch,
            "--vault-url",
            "http://explicit-vault:8200",
        )

        assert result.exit_code == 0
        assert verify.call_args.kwargs["vault_url"] == "http://explicit-vault:8200"

    def test_hashicorp_whitespace_only_vault_addr_is_missing(self, tmp_path, monkeypatch):
        """Whitespace-only VAULT_ADDR fails at validation before client creation."""
        monkeypatch.setenv("VAULT_ADDR", "   ")
        verify = MagicMock(return_value=True)
        monkeypatch.setattr(
            "envdrift.cli_commands.encryption._verify_decryption_with_vault",
            verify,
        )

        result = self._invoke(tmp_path, "hashicorp", monkeypatch)

        assert result.exit_code == 1
        assert HASHICORP_VAULT_URL_REQUIRED in _flat(result.output)
        verify.assert_not_called()
