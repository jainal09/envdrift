"""Tests for envdrift configuration loading."""

from __future__ import annotations

from pathlib import Path

import pytest

from envdrift.config import (
    ConfigNotFoundError,
    EnvdriftConfig,
    PrecommitConfig,
    ValidationConfig,
    VaultConfig,
    find_config,
    load_config,
)


class TestVaultConfig:
    """Tests for VaultConfig dataclass."""

    def test_default_values(self):
        """Test default VaultConfig values."""
        config = VaultConfig()
        assert config.provider == "azure"
        assert config.azure_vault_url is None
        assert config.aws_region == "us-east-1"
        assert config.hashicorp_url is None
        assert config.mappings == {}

    def test_custom_values(self):
        """Test VaultConfig with custom values."""
        config = VaultConfig(
            provider="aws",
            azure_vault_url="https://myvault.vault.azure.net",
            aws_region="us-west-2",
            hashicorp_url="https://vault.example.com",
            mappings={"DB_PASSWORD": "database/password"},
        )
        assert config.provider == "aws"
        assert config.azure_vault_url == "https://myvault.vault.azure.net"
        assert config.aws_region == "us-west-2"
        assert config.hashicorp_url == "https://vault.example.com"
        assert config.mappings == {"DB_PASSWORD": "database/password"}


class TestValidationConfig:
    """Tests for ValidationConfig dataclass."""

    def test_default_values(self):
        """Test default ValidationConfig values."""
        config = ValidationConfig()
        assert config.check_encryption is True
        assert config.strict_extra is True
        assert config.secret_patterns == []

    def test_custom_values(self):
        """Test ValidationConfig with custom values."""
        config = ValidationConfig(
            check_encryption=False,
            strict_extra=False,
            secret_patterns=["*_KEY", "*_SECRET"],
        )
        assert config.check_encryption is False
        assert config.strict_extra is False
        assert config.secret_patterns == ["*_KEY", "*_SECRET"]


class TestPrecommitConfig:
    """Tests for PrecommitConfig dataclass."""

    def test_default_values(self):
        """Test default PrecommitConfig values."""
        config = PrecommitConfig()
        assert config.files == []
        assert config.schemas == {}

    def test_custom_values(self):
        """Test PrecommitConfig with custom values."""
        config = PrecommitConfig(
            files=[".env", ".env.production"],
            schemas={".env": "config:Settings"},
        )
        assert config.files == [".env", ".env.production"]
        assert config.schemas == {".env": "config:Settings"}


class TestEnvdriftConfig:
    """Tests for EnvdriftConfig dataclass."""

    def test_default_values(self):
        """Test default EnvdriftConfig values."""
        config = EnvdriftConfig()
        assert config.schema is None
        assert config.environments == ["development", "staging", "production"]
        assert config.env_file_pattern == ".env.{environment}"
        assert isinstance(config.validation, ValidationConfig)
        assert isinstance(config.vault, VaultConfig)
        assert isinstance(config.precommit, PrecommitConfig)
        assert config.raw == {}

    def test_from_dict_empty(self):
        """Test from_dict with empty dict."""
        config = EnvdriftConfig.from_dict({})
        assert config.schema is None
        assert config.environments == ["development", "staging", "production"]

    def test_from_dict_full(self):
        """Test from_dict with full configuration."""
        data = {
            "envdrift": {
                "schema": "app.config:Settings",
                "environments": ["dev", "prod"],
                "env_file_pattern": ".env.{env}",
            },
            "validation": {
                "check_encryption": False,
                "strict_extra": False,
                "secret_patterns": ["*_TOKEN"],
            },
            "vault": {
                "provider": "aws",
                "aws": {"region": "eu-west-1"},
                "azure": {"vault_url": "https://test.vault.azure.net"},
                "hashicorp": {"url": "https://vault.test.com"},
                "mappings": {"SECRET": "path/to/secret"},
            },
            "precommit": {
                "files": [".env.dev"],
                "schemas": {".env.dev": "config:DevSettings"},
            },
        }
        config = EnvdriftConfig.from_dict(data)

        assert config.schema == "app.config:Settings"
        assert config.environments == ["dev", "prod"]
        assert config.env_file_pattern == ".env.{env}"

        assert config.validation.check_encryption is False
        assert config.validation.strict_extra is False
        assert config.validation.secret_patterns == ["*_TOKEN"]

        assert config.vault.provider == "aws"
        assert config.vault.aws_region == "eu-west-1"
        assert config.vault.azure_vault_url == "https://test.vault.azure.net"
        assert config.vault.hashicorp_url == "https://vault.test.com"
        assert config.vault.mappings == {"SECRET": "path/to/secret"}

        assert config.precommit.files == [".env.dev"]
        assert config.precommit.schemas == {".env.dev": "config:DevSettings"}

        assert config.raw == data


class TestFindConfig:
    """Tests for find_config function."""

    def test_find_config_not_found(self, tmp_path: Path):
        """Test find_config when no config exists."""
        result = find_config(tmp_path)
        assert result is None

    def test_find_config_envdrift_toml(self, tmp_path: Path):
        """Test find_config finds envdrift.toml."""
        config_file = tmp_path / "envdrift.toml"
        config_file.write_text('[envdrift]\nschema = "test"')

        result = find_config(tmp_path)
        assert result == config_file

    def test_find_config_pyproject_toml(self, tmp_path: Path):
        """Test find_config finds pyproject.toml with [tool.envdrift]."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text('[tool.envdrift]\nschema = "test"')

        result = find_config(tmp_path)
        assert result == pyproject

    def test_find_config_pyproject_without_envdrift(self, tmp_path: Path):
        """Test find_config ignores pyproject.toml without [tool.envdrift]."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text('[tool.poetry]\nname = "test"')

        result = find_config(tmp_path)
        assert result is None

    def test_find_config_parent_directory(self, tmp_path: Path):
        """Test find_config searches parent directories."""
        config_file = tmp_path / "envdrift.toml"
        config_file.write_text('[envdrift]\nschema = "test"')

        subdir = tmp_path / "src" / "app"
        subdir.mkdir(parents=True)

        result = find_config(subdir)
        assert result == config_file

    def test_find_config_prefers_envdrift_toml(self, tmp_path: Path):
        """Test find_config prefers envdrift.toml over pyproject.toml."""
        config_file = tmp_path / "envdrift.toml"
        config_file.write_text('[envdrift]\nschema = "from_envdrift"')

        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text('[tool.envdrift]\nschema = "from_pyproject"')

        result = find_config(tmp_path)
        assert result == config_file


class TestLoadConfig:
    """Tests for load_config function."""

    def test_load_config_not_found_raises(self, tmp_path: Path):
        """Test load_config raises ConfigNotFoundError for missing file."""
        with pytest.raises(ConfigNotFoundError) as exc_info:
            load_config(tmp_path / "nonexistent.toml")
        assert "not found" in str(exc_info.value)

    def test_load_config_default_when_not_found(self, tmp_path: Path, monkeypatch):
        """Test load_config returns default config when no file found."""
        monkeypatch.chdir(tmp_path)
        config = load_config()
        assert isinstance(config, EnvdriftConfig)
        assert config.schema is None

    def test_load_config_envdrift_toml(self, tmp_path: Path):
        """Test load_config from envdrift.toml."""
        config_file = tmp_path / "envdrift.toml"
        config_file.write_text("""
[envdrift]
schema = "app.config:Settings"
environments = ["dev", "staging", "prod"]

[validation]
check_encryption = false
""")

        config = load_config(config_file)
        assert config.schema == "app.config:Settings"
        assert config.environments == ["dev", "staging", "prod"]
        assert config.validation.check_encryption is False

    def test_load_config_pyproject_toml(self, tmp_path: Path):
        """Test load_config from pyproject.toml with [tool.envdrift]."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text("""
[tool.envdrift]
schema = "myapp.settings:Config"

[tool.envdrift.validation]
check_encryption = true
strict_extra = false
""")

        config = load_config(pyproject)
        assert config.schema == "myapp.settings:Config"
        assert config.validation.check_encryption is True
        assert config.validation.strict_extra is False
