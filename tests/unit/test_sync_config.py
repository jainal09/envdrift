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

    def test_effective_environment_defaults_to_production(self) -> None:
        """Test effective_environment defaults to production when no environment or profile."""
        mapping = ServiceMapping(
            secret_name="my-key",
            folder_path=Path("services/myapp"),
        )
        assert mapping.environment is None
        assert mapping.effective_environment == "production"
        assert mapping.env_key_name == "DOTENV_PRIVATE_KEY_PRODUCTION"

    def test_effective_environment_from_explicit_environment(self) -> None:
        """Test effective_environment uses explicit environment."""
        mapping = ServiceMapping(
            secret_name="my-key",
            folder_path=Path("services/myapp"),
            environment="staging",
        )
        assert mapping.effective_environment == "staging"

    def test_effective_environment_from_profile(self) -> None:
        """Test effective_environment derives from profile when environment is None."""
        mapping = ServiceMapping(
            secret_name="my-key",
            folder_path=Path("services/myapp"),
            profile="local",
        )
        assert mapping.environment is None
        assert mapping.effective_environment == "local"
        assert mapping.env_key_name == "DOTENV_PRIVATE_KEY_LOCAL"

    def test_effective_environment_explicit_overrides_profile(self) -> None:
        """Test explicit environment takes priority over profile."""
        mapping = ServiceMapping(
            secret_name="my-key",
            folder_path=Path("services/myapp"),
            environment="staging",
            profile="local",
        )
        assert mapping.effective_environment == "staging"

    def test_profile_and_activate_to(self) -> None:
        """Test ServiceMapping with profile and activate_to fields."""
        mapping = ServiceMapping(
            secret_name="local-key",
            folder_path=Path("services/myapp"),
            profile="local",
            activate_to=Path(".env"),
        )
        assert mapping.profile == "local"
        assert mapping.activate_to == Path(".env")


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
        assert config.mappings[0].environment is None  # Derives from effective_environment
        assert config.mappings[0].effective_environment == "production"

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

    def test_from_toml_with_max_workers(self) -> None:
        """Test TOML config with max_workers."""
        data = {
            "max_workers": 4,
            "mappings": [
                {"secret_name": "myapp-key", "folder_path": "services/myapp"},
            ],
        }

        config = SyncConfig.from_toml(data)

        assert config.max_workers == 4

    def test_from_toml_with_invalid_max_workers(self) -> None:
        """Test TOML config with invalid max_workers values."""
        data = {
            "max_workers": 0,
            "mappings": [
                {"secret_name": "myapp-key", "folder_path": "services/myapp"},
            ],
        }

        config = SyncConfig.from_toml(data)

        assert config.max_workers is None

    def test_from_toml_with_non_int_max_workers(self) -> None:
        """Test TOML config with non-integer max_workers."""
        data = {
            "max_workers": "fast",
            "mappings": [
                {"secret_name": "myapp-key", "folder_path": "services/myapp"},
            ],
        }

        config = SyncConfig.from_toml(data)

        assert config.max_workers is None

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

    def test_from_toml_with_profile(self) -> None:
        """Test TOML config with profile field."""
        data = {
            "mappings": [
                {
                    "secret_name": "local-key",
                    "folder_path": ".",
                    "profile": "local",
                },
            ]
        }

        config = SyncConfig.from_toml(data)

        assert config.mappings[0].profile == "local"
        assert config.mappings[0].environment is None
        assert config.mappings[0].effective_environment == "local"

    def test_from_toml_with_profile_and_activate_to(self) -> None:
        """Test TOML config with profile and activate_to."""
        data = {
            "mappings": [
                {
                    "secret_name": "local-key",
                    "folder_path": ".",
                    "profile": "local",
                    "activate_to": ".env",
                },
            ]
        }

        config = SyncConfig.from_toml(data)

        assert config.mappings[0].profile == "local"
        assert config.mappings[0].activate_to == Path(".env")


class TestSyncConfigFilterByProfile:
    """Tests for filter_by_profile()."""

    def test_no_profile_returns_non_profile_mappings(self) -> None:
        """Test filter_by_profile(None) returns only mappings without a profile."""
        config = SyncConfig(
            mappings=[
                ServiceMapping(secret_name="regular", folder_path=Path()),
                ServiceMapping(secret_name="local", folder_path=Path(), profile="local"),
                ServiceMapping(secret_name="prod", folder_path=Path(), profile="prod"),
            ]
        )

        result = config.filter_by_profile(None)

        assert len(result) == 1
        assert result[0].secret_name == "regular"

    def test_profile_returns_non_profile_plus_matching(self) -> None:
        """Test filter_by_profile('local') returns non-profile + matching profile."""
        config = SyncConfig(
            mappings=[
                ServiceMapping(secret_name="regular", folder_path=Path()),
                ServiceMapping(secret_name="local", folder_path=Path(), profile="local"),
                ServiceMapping(secret_name="prod", folder_path=Path(), profile="prod"),
            ]
        )

        result = config.filter_by_profile("local")

        assert len(result) == 2
        names = [m.secret_name for m in result]
        assert "regular" in names
        assert "local" in names
        assert "prod" not in names

    def test_profile_only_mappings(self) -> None:
        """Test filter_by_profile when all mappings have profiles."""
        config = SyncConfig(
            mappings=[
                ServiceMapping(secret_name="local", folder_path=Path(), profile="local"),
                ServiceMapping(secret_name="prod", folder_path=Path(), profile="prod"),
            ]
        )

        result = config.filter_by_profile("prod")

        assert len(result) == 1
        assert result[0].secret_name == "prod"

    def test_no_matching_profile(self) -> None:
        """Test filter_by_profile with non-matching profile."""
        config = SyncConfig(
            mappings=[
                ServiceMapping(secret_name="local", folder_path=Path(), profile="local"),
            ]
        )

        result = config.filter_by_profile("prod")

        assert len(result) == 0


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
max_workers = 3

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
        assert config.max_workers == 3
        assert len(config.mappings) == 2
        assert config.mappings[0].secret_name == "app-key"
        assert config.mappings[1].vault_name == "other-vault"

    def test_from_toml_file_pyproject_toml(self, tmp_path: Path) -> None:
        """Test loading from pyproject.toml with [tool.envdrift.vault.sync] section."""
        config_file = tmp_path / "pyproject.toml"
        config_file.write_text("""
[tool.envdrift.vault.sync]
default_vault_name = "pyproject-vault"
max_workers = 2

[[tool.envdrift.vault.sync.mappings]]
secret_name = "test-key"
folder_path = "."
""")

        config = SyncConfig.from_toml_file(config_file)

        assert config.default_vault_name == "pyproject-vault"
        assert config.max_workers == 2
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


class TestSyncConfigEphemeralKeys:
    """Tests for ephemeral_keys configuration."""

    def test_from_toml_with_central_ephemeral_keys(self) -> None:
        """Test parsing central ephemeral_keys setting."""
        data = {
            "ephemeral_keys": True,
            "mappings": [
                {"secret_name": "key", "folder_path": "."},
            ],
        }

        config = SyncConfig.from_toml(data)

        assert config.ephemeral_keys is True

    def test_from_toml_with_per_mapping_ephemeral_keys(self) -> None:
        """Test parsing per-mapping ephemeral_keys setting."""
        data = {
            "mappings": [
                {"secret_name": "key", "folder_path": ".", "ephemeral_keys": True},
            ],
        }

        config = SyncConfig.from_toml(data)

        assert config.ephemeral_keys is False  # Central default
        assert config.mappings[0].ephemeral_keys is True

    def test_get_effective_ephemeral_central(self) -> None:
        """Test get_effective_ephemeral uses central setting."""
        config = SyncConfig(ephemeral_keys=True)
        mapping = ServiceMapping(
            secret_name="key",
            folder_path=Path(),
            ephemeral_keys=None,  # Inherit
        )

        result = config.get_effective_ephemeral(mapping)

        assert result is True

    def test_get_effective_ephemeral_mapping_override(self) -> None:
        """Test per-mapping ephemeral_keys overrides central."""
        config = SyncConfig(ephemeral_keys=False)
        mapping = ServiceMapping(
            secret_name="key",
            folder_path=Path(),
            ephemeral_keys=True,  # Override
        )

        result = config.get_effective_ephemeral(mapping)

        assert result is True

    def test_get_effective_ephemeral_mapping_explicit_false(self) -> None:
        """Test per-mapping can explicitly disable ephemeral."""
        config = SyncConfig(ephemeral_keys=True)
        mapping = ServiceMapping(
            secret_name="key",
            folder_path=Path(),
            ephemeral_keys=False,  # Explicit disable
        )

        result = config.get_effective_ephemeral(mapping)

        assert result is False

    def test_from_toml_file_with_ephemeral_keys(self, tmp_path: Path) -> None:
        """Test loading ephemeral_keys from TOML file."""
        config_file = tmp_path / "envdrift.toml"
        config_file.write_text("""
[vault.sync]
ephemeral_keys = true

[[vault.sync.mappings]]
secret_name = "key"
folder_path = "."
""")

        config = SyncConfig.from_toml_file(config_file)

        assert config.ephemeral_keys is True
