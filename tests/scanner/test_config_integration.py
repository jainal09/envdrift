"""Tests for guard configuration integration."""

from __future__ import annotations

from pathlib import Path

from envdrift.config import EnvdriftConfig, GuardConfig, load_config


class TestGuardConfigDataclass:
    """Tests for GuardConfig dataclass."""

    def test_default_values(self):
        """Test default guard config values."""
        config = GuardConfig()
        assert config.scanners == ["native", "gitleaks"]
        assert config.auto_install is True
        assert config.include_history is False
        assert config.check_entropy is False
        assert config.entropy_threshold == 4.5
        assert config.fail_on_severity == "high"
        assert config.ignore_paths == []
        assert config.ignore_rules == {}
        assert config.skip_clear_files is False
        assert config.verify_secrets is False

    def test_custom_values(self):
        """Test guard config with custom values."""
        config = GuardConfig(
            scanners=["native", "trufflehog"],
            auto_install=False,
            include_history=True,
            check_entropy=True,
            entropy_threshold=5.0,
            fail_on_severity="critical",
            ignore_paths=["tests/**"],
            verify_secrets=True,
        )
        assert config.scanners == ["native", "trufflehog"]
        assert config.auto_install is False
        assert config.include_history is True
        assert config.verify_secrets is True

    def test_skip_clear_files_option(self):
        """Test skip_clear_files config option."""
        config = GuardConfig(skip_clear_files=True)
        assert config.skip_clear_files is True

    def test_ignore_rules_option(self):
        """Test ignore_rules config option."""
        config = GuardConfig(
            ignore_rules={
                "ftp-password": ["**/*.json"],
                "django-secret-key": ["**/test_settings.py"],
            }
        )
        assert config.ignore_rules == {
            "ftp-password": ["**/*.json"],
            "django-secret-key": ["**/test_settings.py"],
        }


class TestEnvdriftConfigWithGuard:
    """Tests for EnvdriftConfig with guard section."""

    def test_envdrift_config_has_guard_field(self):
        """Test that EnvdriftConfig includes guard config."""
        config = EnvdriftConfig()
        assert hasattr(config, "guard")
        assert isinstance(config.guard, GuardConfig)

    def test_from_dict_parses_guard_section(self):
        """Test that from_dict correctly parses guard section."""
        data = {
            "envdrift": {},
            "guard": {
                "scanners": ["native", "gitleaks", "trufflehog"],
                "auto_install": False,
                "include_history": True,
                "check_entropy": True,
                "entropy_threshold": 5.5,
                "fail_on_severity": "critical",
                "ignore_paths": ["tests/**", "*.test.py"],
                "verify_secrets": True,
            },
        }
        config = EnvdriftConfig.from_dict(data)

        assert config.guard.scanners == ["native", "gitleaks", "trufflehog"]
        assert config.guard.auto_install is False
        assert config.guard.include_history is True
        assert config.guard.check_entropy is True
        assert config.guard.entropy_threshold == 5.5
        assert config.guard.fail_on_severity == "critical"
        assert config.guard.ignore_paths == ["tests/**", "*.test.py"]
        assert config.guard.verify_secrets is True

    def test_from_dict_defaults_when_guard_missing(self):
        """Test that from_dict uses defaults when guard section is missing."""
        data = {"envdrift": {}}
        config = EnvdriftConfig.from_dict(data)

        assert config.guard.scanners == ["native", "gitleaks"]
        assert config.guard.auto_install is True

    def test_from_dict_handles_string_scanner(self):
        """Test that single scanner string is converted to list."""
        data = {
            "envdrift": {},
            "guard": {
                "scanners": "native",  # String instead of list
            },
        }
        config = EnvdriftConfig.from_dict(data)
        assert config.guard.scanners == ["native"]


class TestLoadConfigWithGuard:
    """Tests for load_config with guard section."""

    def test_load_config_without_file_returns_defaults(self, tmp_path: Path, monkeypatch):
        """Test that load_config returns defaults when no config file."""
        monkeypatch.chdir(tmp_path)
        config = load_config()
        assert config.guard.scanners == ["native", "gitleaks"]

    def test_load_config_with_guard_section(self, tmp_path: Path):
        """Test loading config with guard section from TOML file."""
        config_file = tmp_path / "envdrift.toml"
        config_file.write_text("""
[envdrift]
environments = ["dev", "prod"]

[guard]
scanners = ["native", "trufflehog"]
auto_install = false
include_history = true
fail_on_severity = "medium"
ignore_paths = ["vendor/**"]
""")
        config = load_config(config_file)

        assert config.guard.scanners == ["native", "trufflehog"]
        assert config.guard.auto_install is False
        assert config.guard.include_history is True
        assert config.guard.fail_on_severity == "medium"
        assert config.guard.ignore_paths == ["vendor/**"]

    def test_load_config_from_pyproject_guard_section(self, tmp_path: Path, monkeypatch):
        """Test loading guard settings from pyproject.toml."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text("""
[tool.envdrift]
schema = "config.settings:ProductionSettings"

[tool.envdrift.guard]
scanners = ["native", "trufflehog"]
include_history = true
fail_on_severity = "medium"
ignore_paths = ["vendor/**"]
""")
        monkeypatch.chdir(tmp_path)
        config = load_config(pyproject)

        assert config.guard.scanners == ["native", "trufflehog"]
        assert config.guard.include_history is True
        assert config.guard.fail_on_severity == "medium"
        assert config.guard.ignore_paths == ["vendor/**"]


class TestGuardConfigToScannerConfig:
    """Tests for converting config.GuardConfig to scanner.engine.GuardConfig."""

    def test_scanner_list_contains_native(self):
        """Test that native scanner is correctly identified."""
        config = GuardConfig(scanners=["native"])
        assert "native" in config.scanners

    def test_scanner_list_contains_gitleaks(self):
        """Test that gitleaks scanner is correctly identified."""
        config = GuardConfig(scanners=["native", "gitleaks"])
        assert "gitleaks" in config.scanners

    def test_scanner_list_contains_trufflehog(self):
        """Test that trufflehog scanner is correctly identified."""
        config = GuardConfig(scanners=["native", "trufflehog"])
        assert "trufflehog" in config.scanners


class TestLoadConfigWithNewFeatures:
    """Tests for loading config with skip_clear_files and ignore_rules."""

    def test_load_config_with_skip_clear_files(self, tmp_path: Path):
        """Test loading config with skip_clear_files from TOML file."""
        config_file = tmp_path / "envdrift.toml"
        config_file.write_text("""
[envdrift]
environments = ["dev", "prod"]

[guard]
scanners = ["native"]
skip_clear_files = true
""")
        config = load_config(config_file)

        assert config.guard.skip_clear_files is True

    def test_load_config_with_ignore_rules(self, tmp_path: Path):
        """Test loading config with ignore_rules from TOML file."""
        config_file = tmp_path / "envdrift.toml"
        config_file.write_text("""
[envdrift]
environments = ["dev", "prod"]

[guard]
scanners = ["native"]

[guard.ignore_rules]
"ftp-password" = ["**/*.json", "**/locales/**"]
"django-secret-key" = ["**/test_settings.py"]
""")
        config = load_config(config_file)

        assert config.guard.ignore_rules == {
            "ftp-password": ["**/*.json", "**/locales/**"],
            "django-secret-key": ["**/test_settings.py"],
        }

    def test_load_config_with_all_new_features(self, tmp_path: Path):
        """Test loading config with all new guard features."""
        config_file = tmp_path / "envdrift.toml"
        config_file.write_text("""
[envdrift]
environments = ["dev", "prod"]

[guard]
scanners = ["native", "gitleaks"]
auto_install = true
skip_clear_files = true
ignore_paths = ["**/tests/**", "**/fixtures/**"]

[guard.ignore_rules]
"high-entropy-string" = ["**/*.clear"]
"ftp-password" = ["**/*.json"]
""")
        config = load_config(config_file)

        assert config.guard.skip_clear_files is True
        assert config.guard.ignore_paths == ["**/tests/**", "**/fixtures/**"]
        assert config.guard.ignore_rules == {
            "high-entropy-string": ["**/*.clear"],
            "ftp-password": ["**/*.json"],
        }

    def test_load_config_from_pyproject_with_new_features(self, tmp_path: Path, monkeypatch):
        """Test loading new features from pyproject.toml."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text("""
[tool.envdrift]
schema = "config.settings:ProductionSettings"

[tool.envdrift.guard]
scanners = ["native"]
skip_clear_files = true

[tool.envdrift.guard.ignore_rules]
"ftp-password" = ["**/*.json"]
""")
        monkeypatch.chdir(tmp_path)
        config = load_config(pyproject)

        assert config.guard.skip_clear_files is True
        assert config.guard.ignore_rules == {
            "ftp-password": ["**/*.json"],
        }
