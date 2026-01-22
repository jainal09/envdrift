"""Tests for envdrift configuration loading."""

from __future__ import annotations

from pathlib import Path

import pytest

from envdrift.config import (
    ConfigNotFoundError,
    EnvdriftConfig,
    GitHookCheckConfig,
    GuardianWatchConfig,
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
        assert config.gcp_project_id is None
        assert config.mappings == {}

    def test_custom_values(self):
        """Test VaultConfig with custom values."""
        config = VaultConfig(
            provider="aws",
            azure_vault_url="https://myvault.vault.azure.net",
            aws_region="us-west-2",
            hashicorp_url="https://vault.example.com",
            gcp_project_id="my-gcp-project",
            mappings={"DB_PASSWORD": "database/password"},
        )
        assert config.provider == "aws"
        assert config.azure_vault_url == "https://myvault.vault.azure.net"
        assert config.aws_region == "us-west-2"
        assert config.hashicorp_url == "https://vault.example.com"
        assert config.gcp_project_id == "my-gcp-project"
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
        assert isinstance(config.git_hook_check, GitHookCheckConfig)
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
                "gcp": {"project_id": "test-gcp-project"},
                "mappings": {"SECRET": "path/to/secret"},
            },
            "precommit": {
                "files": [".env.dev"],
                "schemas": {".env.dev": "config:DevSettings"},
            },
            "git_hook_check": {
                "method": "precommit.yaml",
                "precommit_config": ".pre-commit-config.yaml",
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
        assert config.vault.gcp_project_id == "test-gcp-project"
        assert config.vault.mappings == {"SECRET": "path/to/secret"}

        assert config.precommit.files == [".env.dev"]
        assert config.precommit.schemas == {".env.dev": "config:DevSettings"}
        assert config.git_hook_check.method == "precommit.yaml"
        assert config.git_hook_check.precommit_config == ".pre-commit-config.yaml"

        assert config.raw == data

    def test_from_dict_encryption_config(self):
        """Test from_dict parses encryption settings."""
        data = {
            "encryption": {
                "backend": "sops",
                "dotenvx": {"auto_install": True},
                "sops": {
                    "auto_install": True,
                    "config_file": ".sops.yaml",
                    "age_key_file": "age.key",
                    "age_recipients": "age1example",
                    "kms_arn": "arn:aws:kms:us-east-1:123:key/abc",
                    "gcp_kms": "projects/p/locations/l/keyRings/r/cryptoKeys/k",
                    "azure_kv": "https://vault.vault.azure.net/keys/key",
                },
            }
        }

        config = EnvdriftConfig.from_dict(data)

        assert config.encryption.backend == "sops"
        assert config.encryption.dotenvx_auto_install is True
        assert config.encryption.sops_auto_install is True
        assert config.encryption.sops_config_file == ".sops.yaml"
        assert config.encryption.sops_age_key_file == "age.key"
        assert config.encryption.sops_age_recipients == "age1example"
        assert config.encryption.sops_kms_arn == "arn:aws:kms:us-east-1:123:key/abc"
        assert config.encryption.sops_gcp_kms == "projects/p/locations/l/keyRings/r/cryptoKeys/k"
        assert config.encryption.sops_azure_kv == "https://vault.vault.azure.net/keys/key"


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
        assert config.git_hook_check.method is None

    def test_load_config_pyproject_with_git_hook_check(self, tmp_path: Path):
        """pyproject.toml should map git_hook_check correctly."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text("""
[tool.envdrift]
schema = "myapp.settings:Config"

[tool.envdrift.git_hook_check]
method = "precommit.yaml"
precommit_config = ".pre-commit-config.yaml"
""")

        config = load_config(pyproject)
        assert config.git_hook_check.method == "precommit.yaml"
        assert config.git_hook_check.precommit_config == ".pre-commit-config.yaml"

    def test_load_config_pyproject_with_encryption(self, tmp_path: Path):
        """pyproject.toml should map encryption sections correctly."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text("""
[tool.envdrift]
schema = "myapp.settings:Config"

[tool.envdrift.encryption]
backend = "sops"

[tool.envdrift.encryption.dotenvx]
auto_install = true

[tool.envdrift.encryption.sops]
auto_install = true
config_file = ".sops.yaml"
age_key_file = "age.key"
age_recipients = "age1example"
""")

        config = load_config(pyproject)
        assert config.encryption.backend == "sops"
        assert config.encryption.dotenvx_auto_install is True
        assert config.encryption.sops_auto_install is True
        assert config.encryption.sops_config_file == ".sops.yaml"
        assert config.encryption.sops_age_key_file == "age.key"
        assert config.encryption.sops_age_recipients == "age1example"


class TestSyncConfig:
    """Tests for SyncConfig and SyncMappingConfig dataclasses."""

    def test_sync_mapping_config_defaults(self):
        """Test default SyncMappingConfig values."""
        from envdrift.config import SyncMappingConfig

        mapping = SyncMappingConfig(secret_name="test-key", folder_path=".")
        assert mapping.secret_name == "test-key"
        assert mapping.folder_path == "."
        assert mapping.vault_name is None
        assert mapping.environment is None  # None = use effective_environment
        assert mapping.profile is None
        assert mapping.activate_to is None

    def test_sync_mapping_config_custom(self):
        """Test SyncMappingConfig with custom values."""
        from envdrift.config import SyncMappingConfig

        mapping = SyncMappingConfig(
            secret_name="api-key",
            folder_path="services/api",
            vault_name="other-vault",
            environment="staging",
        )
        assert mapping.secret_name == "api-key"
        assert mapping.folder_path == "services/api"
        assert mapping.vault_name == "other-vault"
        assert mapping.environment == "staging"

    def test_sync_mapping_config_with_profile(self):
        """Test SyncMappingConfig with profile and activate_to."""
        from envdrift.config import SyncMappingConfig

        mapping = SyncMappingConfig(
            secret_name="local-key",
            folder_path=".",
            profile="local",
            activate_to=".env",
        )
        assert mapping.secret_name == "local-key"
        assert mapping.folder_path == "."
        assert mapping.profile == "local"
        assert mapping.activate_to == ".env"
        # environment is None, so effective_environment should derive from profile
        assert mapping.environment is None

    def test_sync_config_defaults(self):
        """Test default SyncConfig values."""
        from envdrift.config import SyncConfig

        config = SyncConfig()
        assert config.mappings == []
        assert config.default_vault_name is None
        assert config.env_keys_filename == ".env.keys"
        assert config.max_workers is None

    def test_vault_config_with_sync(self):
        """Test VaultConfig includes SyncConfig."""
        config = VaultConfig()
        assert hasattr(config, "sync")
        assert config.sync.mappings == []
        assert config.sync.default_vault_name is None
        assert config.sync.max_workers is None

    def test_from_dict_with_sync_mappings(self):
        """Test from_dict parses vault.sync section."""
        data = {
            "vault": {
                "provider": "azure",
                "azure": {"vault_url": "https://test.vault.azure.net"},
                "sync": {
                    "default_vault_name": "my-vault",
                    "env_keys_filename": ".env.keys.custom",
                    "max_workers": 3,
                    "mappings": [
                        {
                            "secret_name": "app-key",
                            "folder_path": "services/app",
                            "environment": "production",
                        },
                        {
                            "secret_name": "api-key",
                            "folder_path": "services/api",
                            "vault_name": "other-vault",
                            "environment": "staging",
                        },
                    ],
                },
            },
        }
        config = EnvdriftConfig.from_dict(data)

        assert config.vault.sync.default_vault_name == "my-vault"
        assert config.vault.sync.env_keys_filename == ".env.keys.custom"
        assert config.vault.sync.max_workers == 3
        assert len(config.vault.sync.mappings) == 2

        first_mapping = config.vault.sync.mappings[0]
        assert first_mapping.secret_name == "app-key"
        assert first_mapping.folder_path == "services/app"
        assert first_mapping.vault_name is None
        assert first_mapping.environment == "production"

        second_mapping = config.vault.sync.mappings[1]
        assert second_mapping.secret_name == "api-key"
        assert second_mapping.vault_name == "other-vault"
        assert second_mapping.environment == "staging"

    def test_from_dict_with_invalid_max_workers(self):
        """Test from_dict normalizes invalid max_workers values."""
        data = {
            "vault": {
                "sync": {
                    "max_workers": 0,
                    "mappings": [
                        {
                            "secret_name": "app-key",
                            "folder_path": "services/app",
                        }
                    ],
                },
            },
        }

        config = EnvdriftConfig.from_dict(data)

        assert config.vault.sync.max_workers is None

    def test_load_config_with_sync_from_toml(self, tmp_path: Path):
        """Test load_config parses sync mappings from TOML file."""
        config_file = tmp_path / "envdrift.toml"
        config_file.write_text("""
[vault]
provider = "azure"

[vault.azure]
vault_url = "https://test.vault.azure.net"

[vault.sync]
default_vault_name = "test-vault"
max_workers = 2

[[vault.sync.mappings]]
secret_name = "myapp-key"
folder_path = "."
environment = "production"

[[vault.sync.mappings]]
secret_name = "service-key"
folder_path = "services/backend"
vault_name = "backend-vault"
environment = "staging"
""")

        config = load_config(config_file)
        assert config.vault.provider == "azure"
        assert config.vault.azure_vault_url == "https://test.vault.azure.net"
        assert config.vault.sync.default_vault_name == "test-vault"
        assert config.vault.sync.max_workers == 2
        assert len(config.vault.sync.mappings) == 2
        assert config.vault.sync.mappings[0].secret_name == "myapp-key"
        assert config.vault.sync.mappings[1].vault_name == "backend-vault"


class TestGuardianWatchConfig:
    """Tests for GuardianWatchConfig dataclass (background agent settings)."""

    def test_default_values(self):
        """Test default GuardianWatchConfig values."""
        config = GuardianWatchConfig()
        assert config.enabled is False
        assert config.idle_timeout == "5m"
        assert config.patterns == [".env*"]
        assert config.exclude == [".env.example", ".env.sample", ".env.keys"]
        assert config.notify is True

    def test_custom_values(self):
        """Test GuardianWatchConfig with custom values."""
        config = GuardianWatchConfig(
            enabled=True,
            idle_timeout="10m",
            patterns=[".env", ".env.*"],
            exclude=[".env.template"],
            notify=False,
        )
        assert config.enabled is True
        assert config.idle_timeout == "10m"
        assert config.patterns == [".env", ".env.*"]
        assert config.exclude == [".env.template"]
        assert config.notify is False

    def test_envdrift_config_has_guardian(self):
        """Test EnvdriftConfig includes GuardianWatchConfig."""
        config = EnvdriftConfig()
        assert hasattr(config, "guardian")
        assert isinstance(config.guardian, GuardianWatchConfig)
        assert config.guardian.enabled is False

    def test_from_dict_with_guardian(self):
        """Test from_dict parses guardian section."""
        data = {
            "guardian": {
                "enabled": True,
                "idle_timeout": "3m",
                "patterns": [".env.*"],
                "exclude": [".env.test"],
                "notify": False,
            }
        }
        config = EnvdriftConfig.from_dict(data)

        assert config.guardian.enabled is True
        assert config.guardian.idle_timeout == "3m"
        assert config.guardian.patterns == [".env.*"]
        assert config.guardian.exclude == [".env.test"]
        assert config.guardian.notify is False

    def test_from_dict_guardian_defaults(self):
        """Test from_dict uses defaults when guardian section is empty."""
        data = {"guardian": {}}
        config = EnvdriftConfig.from_dict(data)

        assert config.guardian.enabled is False
        assert config.guardian.idle_timeout == "5m"
        assert config.guardian.patterns == [".env*"]
        assert config.guardian.exclude == [".env.example", ".env.sample", ".env.keys"]
        assert config.guardian.notify is True

    def test_from_dict_guardian_idle_timeout_normalized(self):
        """Test guardian idle_timeout normalization."""
        data = {"guardian": {"idle_timeout": "10M"}}
        config = EnvdriftConfig.from_dict(data)

        assert config.guardian.idle_timeout == "10m"

    def test_from_dict_guardian_invalid_idle_timeout(self):
        """Test guardian idle_timeout validation."""
        data = {"guardian": {"idle_timeout": "five minutes"}}

        with pytest.raises(ValueError, match=r"guardian\.idle_timeout"):
            EnvdriftConfig.from_dict(data)

    def test_from_dict_no_guardian_section(self):
        """Test from_dict provides defaults when guardian section is missing."""
        data = {}
        config = EnvdriftConfig.from_dict(data)

        assert config.guardian.enabled is False
        assert config.guardian.idle_timeout == "5m"

    def test_load_config_with_guardian_from_toml(self, tmp_path: Path):
        """Test load_config parses guardian section from TOML file."""
        config_file = tmp_path / "envdrift.toml"
        config_file.write_text("""
[envdrift]
schema = "app:Settings"

[guardian]
enabled = true
idle_timeout = "10m"
patterns = [".env", ".env.*"]
exclude = [".env.example", ".env.template"]
notify = true
""")

        config = load_config(config_file)
        assert config.schema == "app:Settings"
        assert config.guardian.enabled is True
        assert config.guardian.idle_timeout == "10m"
        assert config.guardian.patterns == [".env", ".env.*"]
        assert config.guardian.exclude == [".env.example", ".env.template"]
        assert config.guardian.notify is True

    def test_load_config_with_invalid_guardian_idle_timeout(self, tmp_path: Path):
        """Test load_config raises on invalid guardian idle_timeout."""
        config_file = tmp_path / "envdrift.toml"
        config_file.write_text("""
[guardian]
idle_timeout = "invalid"
""")

        with pytest.raises(ValueError, match=r"guardian\.idle_timeout"):
            load_config(config_file)

    def test_load_config_pyproject_with_guardian(self, tmp_path: Path):
        """Test load_config parses guardian from pyproject.toml."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text("""
[tool.envdrift]
schema = "myapp:Settings"

[tool.envdrift.guardian]
enabled = true
idle_timeout = "2m"
notify = false
""")

        config = load_config(pyproject)
        assert config.guardian.enabled is True
        assert config.guardian.idle_timeout == "2m"
        assert config.guardian.notify is False
