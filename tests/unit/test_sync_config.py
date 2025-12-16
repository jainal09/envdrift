"""Tests for sync configuration parsing."""

from __future__ import annotations

from pathlib import Path

import pytest

from envdrift.sync.config import ServiceMapping, SyncConfig, SyncConfigError


class TestServiceMapping:
    """Tests for ServiceMapping dataclass."""

    def test_env_key_name_production(self) -> None:
        """Test environment key name for production."""
        mapping = ServiceMapping(
            secret_name="my-key",
            folder_path=Path("services/myapp"),
            environment="production",
        )
        assert mapping.env_key_name == "DOTENV_PRIVATE_KEY_PRODUCTION"

    def test_env_key_name_staging(self) -> None:
        """Test environment key name for staging."""
        mapping = ServiceMapping(
            secret_name="my-key",
            folder_path=Path("services/myapp"),
            environment="staging",
        )
        assert mapping.env_key_name == "DOTENV_PRIVATE_KEY_STAGING"

    def test_env_key_name_lowercase_converted(self) -> None:
        """Test that environment is uppercased in key name."""
        mapping = ServiceMapping(
            secret_name="my-key",
            folder_path=Path("services/myapp"),
            environment="development",
        )
        assert mapping.env_key_name == "DOTENV_PRIVATE_KEY_DEVELOPMENT"

    def test_default_environment_is_production(self) -> None:
        """Test default environment is production."""
        mapping = ServiceMapping(
            secret_name="my-key",
            folder_path=Path("services/myapp"),
        )
        assert mapping.environment == "production"


class TestSyncConfigFromFile:
    """Tests for SyncConfig.from_file()."""

    def test_from_pair_txt_simple(self, tmp_path: Path) -> None:
        """Test loading simple pair.txt format."""
        config_file = tmp_path / "pair.txt"
        config_file.write_text("myapp-key=services/myapp\nauth-key=services/auth\n")

        config = SyncConfig.from_file(config_file)

        assert len(config.mappings) == 2
        assert config.mappings[0].secret_name == "myapp-key"
        assert config.mappings[0].folder_path == Path("services/myapp")
        assert config.mappings[1].secret_name == "auth-key"
        assert config.mappings[1].folder_path == Path("services/auth")

    def test_from_pair_txt_with_vault_name(self, tmp_path: Path) -> None:
        """Test loading pair.txt with vault name prefix."""
        config_file = tmp_path / "pair.txt"
        config_file.write_text("myvault/api-key=services/api\n")

        config = SyncConfig.from_file(config_file)

        assert len(config.mappings) == 1
        assert config.mappings[0].secret_name == "api-key"
        assert config.mappings[0].vault_name == "myvault"
        assert config.mappings[0].folder_path == Path("services/api")

    def test_from_pair_txt_comments_ignored(self, tmp_path: Path) -> None:
        """Test that comments are ignored."""
        config_file = tmp_path / "pair.txt"
        config_file.write_text(
            "# This is a comment\n"
            "myapp-key=services/myapp\n"
            "# Another comment\n"
            "auth-key=services/auth\n"
        )

        config = SyncConfig.from_file(config_file)

        assert len(config.mappings) == 2

    def test_from_pair_txt_empty_lines_ignored(self, tmp_path: Path) -> None:
        """Test that empty lines are ignored."""
        config_file = tmp_path / "pair.txt"
        config_file.write_text("myapp-key=services/myapp\n\n\nauth-key=services/auth\n")

        config = SyncConfig.from_file(config_file)

        assert len(config.mappings) == 2

    def test_from_pair_txt_whitespace_trimmed(self, tmp_path: Path) -> None:
        """Test that whitespace is trimmed."""
        config_file = tmp_path / "pair.txt"
        config_file.write_text("  myapp-key  =  services/myapp  \n")

        config = SyncConfig.from_file(config_file)

        assert config.mappings[0].secret_name == "myapp-key"
        assert config.mappings[0].folder_path == Path("services/myapp")

    def test_from_pair_txt_file_not_found(self, tmp_path: Path) -> None:
        """Test error when file not found."""
        config_file = tmp_path / "nonexistent.txt"

        with pytest.raises(SyncConfigError, match="Config file not found"):
            SyncConfig.from_file(config_file)

    def test_from_pair_txt_invalid_format(self, tmp_path: Path) -> None:
        """Test error on invalid line format."""
        config_file = tmp_path / "pair.txt"
        config_file.write_text("invalid-line-without-equals\n")

        with pytest.raises(SyncConfigError, match="Invalid format"):
            SyncConfig.from_file(config_file)

    def test_from_pair_txt_empty_value(self, tmp_path: Path) -> None:
        """Test error on empty value."""
        config_file = tmp_path / "pair.txt"
        config_file.write_text("mykey=\n")

        with pytest.raises(SyncConfigError, match="Empty value"):
            SyncConfig.from_file(config_file)

    def test_from_pair_txt_empty_key(self, tmp_path: Path) -> None:
        """Test error on empty key."""
        config_file = tmp_path / "pair.txt"
        config_file.write_text("=services/myapp\n")

        with pytest.raises(SyncConfigError, match="Empty value"):
            SyncConfig.from_file(config_file)


class TestSyncConfigFromToml:
    """Tests for SyncConfig.from_toml()."""

    def test_from_toml_basic(self) -> None:
        """Test loading basic TOML config."""
        data = {
            "mappings": [
                {"secret_name": "myapp-key", "folder_path": "services/myapp"},
                {"secret_name": "auth-key", "folder_path": "services/auth"},
            ]
        }

        config = SyncConfig.from_toml(data)

        assert len(config.mappings) == 2
        assert config.mappings[0].secret_name == "myapp-key"
        assert config.mappings[0].environment == "production"

    def test_from_toml_with_environment(self) -> None:
        """Test TOML config with environment override."""
        data = {
            "mappings": [
                {
                    "secret_name": "myapp-key",
                    "folder_path": "services/myapp",
                    "environment": "staging",
                },
            ]
        }

        config = SyncConfig.from_toml(data)

        assert config.mappings[0].environment == "staging"

    def test_from_toml_with_vault_name(self) -> None:
        """Test TOML config with vault name override."""
        data = {
            "default_vault_name": "default-vault",
            "mappings": [
                {
                    "secret_name": "myapp-key",
                    "folder_path": "services/myapp",
                    "vault_name": "other-vault",
                },
            ],
        }

        config = SyncConfig.from_toml(data)

        assert config.default_vault_name == "default-vault"
        assert config.mappings[0].vault_name == "other-vault"

    def test_from_toml_missing_secret_name(self) -> None:
        """Test error when secret_name is missing."""
        data = {"mappings": [{"folder_path": "services/myapp"}]}

        with pytest.raises(SyncConfigError, match="Missing 'secret_name'"):
            SyncConfig.from_toml(data)

    def test_from_toml_missing_folder_path(self) -> None:
        """Test error when folder_path is missing."""
        data = {"mappings": [{"secret_name": "mykey"}]}

        with pytest.raises(SyncConfigError, match="Missing 'folder_path'"):
            SyncConfig.from_toml(data)

    def test_from_toml_empty_mappings(self) -> None:
        """Test TOML config with empty mappings."""
        data = {"mappings": []}

        config = SyncConfig.from_toml(data)

        assert len(config.mappings) == 0


class TestSyncConfigEffectiveVaultName:
    """Tests for get_effective_vault_name()."""

    def test_uses_mapping_vault_name_when_set(self) -> None:
        """Test that mapping vault_name takes precedence."""
        config = SyncConfig(default_vault_name="default-vault")
        mapping = ServiceMapping(
            secret_name="key",
            folder_path=Path("path"),
            vault_name="override-vault",
        )

        result = config.get_effective_vault_name(mapping)

        assert result == "override-vault"

    def test_uses_default_vault_name_when_mapping_is_none(self) -> None:
        """Test that default vault name is used when mapping has no vault_name."""
        config = SyncConfig(default_vault_name="default-vault")
        mapping = ServiceMapping(
            secret_name="key",
            folder_path=Path("path"),
            vault_name=None,
        )

        result = config.get_effective_vault_name(mapping)

        assert result == "default-vault"

    def test_returns_none_when_both_are_none(self) -> None:
        """Test returns None when no vault names are set."""
        config = SyncConfig(default_vault_name=None)
        mapping = ServiceMapping(
            secret_name="key",
            folder_path=Path("path"),
            vault_name=None,
        )

        result = config.get_effective_vault_name(mapping)

        assert result is None


class TestSyncConfigFromTomlFile:
    """Tests for SyncConfig.from_toml_file()."""

    def test_from_toml_file_envdrift_toml(self, tmp_path: Path) -> None:
        """Test loading from envdrift.toml with [vault.sync] section."""
        config_file = tmp_path / "envdrift.toml"
        config_file.write_text("""
[vault.sync]
default_vault_name = "my-vault"
env_keys_filename = ".env.keys"

[[vault.sync.mappings]]
secret_name = "app-key"
folder_path = "services/app"
environment = "production"

[[vault.sync.mappings]]
secret_name = "api-key"
folder_path = "services/api"
vault_name = "other-vault"
environment = "staging"
""")

        config = SyncConfig.from_toml_file(config_file)

        assert config.default_vault_name == "my-vault"
        assert config.env_keys_filename == ".env.keys"
        assert len(config.mappings) == 2
        assert config.mappings[0].secret_name == "app-key"
        assert config.mappings[1].vault_name == "other-vault"

    def test_from_toml_file_pyproject_toml(self, tmp_path: Path) -> None:
        """Test loading from pyproject.toml with [tool.envdrift.vault.sync] section."""
        config_file = tmp_path / "pyproject.toml"
        config_file.write_text("""
[tool.envdrift.vault.sync]
default_vault_name = "pyproject-vault"

[[tool.envdrift.vault.sync.mappings]]
secret_name = "test-key"
folder_path = "."
""")

        config = SyncConfig.from_toml_file(config_file)

        assert config.default_vault_name == "pyproject-vault"
        assert len(config.mappings) == 1
        assert config.mappings[0].secret_name == "test-key"

    def test_from_toml_file_standalone_sync_toml(self, tmp_path: Path) -> None:
        """Test loading from standalone sync.toml with top-level mappings."""
        config_file = tmp_path / "sync.toml"
        config_file.write_text("""
default_vault_name = "standalone-vault"

[[mappings]]
secret_name = "standalone-key"
folder_path = "."
""")

        config = SyncConfig.from_toml_file(config_file)

        assert config.default_vault_name == "standalone-vault"
        assert len(config.mappings) == 1
        assert config.mappings[0].secret_name == "standalone-key"

    def test_from_toml_file_not_found(self, tmp_path: Path) -> None:
        """Test error when TOML file not found."""
        config_file = tmp_path / "nonexistent.toml"

        with pytest.raises(SyncConfigError, match="Config file not found"):
            SyncConfig.from_toml_file(config_file)

    def test_from_toml_file_invalid_syntax(self, tmp_path: Path) -> None:
        """Test error on invalid TOML syntax."""
        config_file = tmp_path / "invalid.toml"
        config_file.write_text("this is not valid [ toml")

        with pytest.raises(SyncConfigError, match="Invalid TOML syntax"):
            SyncConfig.from_toml_file(config_file)

    def test_from_toml_file_no_sync_section(self, tmp_path: Path) -> None:
        """Test error when no sync section found."""
        config_file = tmp_path / "empty.toml"
        config_file.write_text("""
[vault]
provider = "azure"
""")

        with pytest.raises(SyncConfigError, match="No sync configuration found"):
            SyncConfig.from_toml_file(config_file)

    def test_from_toml_file_missing_required_field(self, tmp_path: Path) -> None:
        """Test error when required field missing in mapping."""
        config_file = tmp_path / "missing.toml"
        config_file.write_text("""
[vault.sync]
[[vault.sync.mappings]]
folder_path = "."
""")

        with pytest.raises(SyncConfigError, match="Missing 'secret_name'"):
            SyncConfig.from_toml_file(config_file)
