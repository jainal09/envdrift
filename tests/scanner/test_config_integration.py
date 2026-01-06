"""Tests for guard configuration integration."""

from __future__ import annotations

from pathlib import Path

import pytest

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
