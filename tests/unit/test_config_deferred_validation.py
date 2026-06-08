"""Deferred guardian / partial_encryption validation and EXAMPLE_CONFIG tests.

Split out of test_config.py (which kept growing past the single-file size
threshold). These cover the #413 fix: from_dict parses leniently and the
consuming command surfaces the error via .validate().
"""

from __future__ import annotations

from pathlib import Path

import pytest

from envdrift.config import (
    EXAMPLE_CONFIG,
    EnvdriftConfig,
    GuardianWatchConfig,
    load_config,
)


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

    def test_from_dict_guardian_idle_timeout_preserved_raw(self):
        """idle_timeout is stored raw; normalization happens in validate() (#413)."""
        data = {"guardian": {"idle_timeout": "10M"}}
        config = EnvdriftConfig.from_dict(data)

        # Deferred: from_dict no longer normalizes; validate() returns the
        # normalized value.
        assert config.guardian.idle_timeout == "10M"
        assert config.guardian.validate() == "10m"

    def test_from_dict_guardian_invalid_idle_timeout_deferred(self):
        """A bad guardian idle_timeout no longer crashes from_dict (#413).

        Validation is deferred to GuardianWatchConfig.validate() so a typo in
        this agent-only knob does not crash unrelated commands.
        """
        data = {"guardian": {"idle_timeout": "five minutes"}}

        # from_dict must NOT raise — it only parses.
        config = EnvdriftConfig.from_dict(data)
        assert config.guardian.idle_timeout == "five minutes"

        # validate() is where the error surfaces.
        with pytest.raises(ValueError, match=r"guardian\.idle_timeout"):
            config.guardian.validate()

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

    def test_load_config_with_invalid_guardian_idle_timeout_deferred(self, tmp_path: Path):
        """load_config no longer raises on a bad guardian idle_timeout (#413).

        The error is deferred to GuardianWatchConfig.validate() so unrelated
        commands that never read [guardian] don't crash on this agent-only typo.
        """
        config_file = tmp_path / "envdrift.toml"
        config_file.write_text("""
[guardian]
idle_timeout = "invalid"
""")

        # load_config succeeds (deferred validation).
        config = load_config(config_file)
        assert config.guardian.idle_timeout == "invalid"

        # validate() surfaces the error when the agent consumes the section.
        with pytest.raises(ValueError, match=r"guardian\.idle_timeout"):
            config.guardian.validate()

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


class TestPartialEncryptionConfig:
    """Tests for partial_encryption config validation (deferred to validate())."""

    def test_secrets_only_requires_secrets_dir(self):
        """secrets_only=True without secrets_dir is rejected by validate() (#413).

        from_dict parses leniently so an unrelated partial_encryption typo can't
        crash commands that never read this section; the error surfaces only
        when the partial-encryption commands call validate().
        """
        data = {
            "partial_encryption": {
                "enabled": True,
                "environments": [{"name": "prod", "secrets_only": True}],
            }
        }
        # Deferred: from_dict does NOT raise.
        config = EnvdriftConfig.from_dict(data)
        with pytest.raises(ValueError, match=r"secrets_dir is required"):
            config.partial_encryption.validate()

    def test_combine_mode_requires_all_paths(self):
        """Combine mode missing required paths is rejected by validate() (#413)."""
        data = {
            "partial_encryption": {
                "enabled": True,
                "environments": [{"name": "prod", "clear_file": ".env.prod.clear"}],
            }
        }
        # Deferred: from_dict does NOT raise.
        config = EnvdriftConfig.from_dict(data)
        with pytest.raises(ValueError, match=r"missing required field"):
            config.partial_encryption.validate()

    def test_secrets_only_loads_with_secrets_dir(self):
        """Valid secrets_only environment loads cleanly."""
        data = {
            "partial_encryption": {
                "enabled": True,
                "environments": [
                    {
                        "name": "prod",
                        "secrets_only": True,
                        "secrets_dir": "secrets/prod/",
                    }
                ],
            }
        }
        config = EnvdriftConfig.from_dict(data)
        env = config.partial_encryption.environments[0]
        assert env.secrets_only is True
        assert env.secrets_dir == "secrets/prod/"
        assert env.pattern == ".env*"

        # A valid config validates cleanly (no exception).
        config.partial_encryption.validate()

    def test_missing_name_is_deferred_not_eager_keyerror(self):
        """A [[partial_encryption.environments]] without `name` must not crash from_dict.

        Previously from_dict did `name=env["name"]`, so a missing name raised an
        eager KeyError on *every* load_config — defeating the whole deferral and
        breaking unrelated commands (encrypt/decrypt/guard/pull/sync) that never
        read this section (#413). from_dict now parses leniently; validate()
        surfaces the missing name.
        """
        data = {
            "partial_encryption": {
                "enabled": True,
                # No "name" key — the original bug.
                "environments": [{"clear_file": ".env.prod.clear"}],
            }
        }
        # from_dict must NOT raise (no eager KeyError).
        config = EnvdriftConfig.from_dict(data)
        assert config.partial_encryption.environments[0].name == ""

        # The missing name surfaces only when a partial command validates.
        with pytest.raises(ValueError, match=r"missing the required 'name' field"):
            config.partial_encryption.validate()

    def test_load_config_with_bad_partial_encryption_does_not_raise(self, tmp_path: Path):
        """A bad [[partial_encryption.environments]] no longer crashes load_config (#413).

        Other commands (encrypt/decrypt/guard/pull/sync) never read this
        section, so a typo here must not be fatal to them. The error is deferred
        to PartialEncryptionConfig.validate(), which the partial commands call.
        """
        config_file = tmp_path / "envdrift.toml"
        config_file.write_text("""
[partial_encryption]
enabled = true

[[partial_encryption.environments]]
name = "production"
secrets_only = true
# secrets_dir intentionally omitted — invalid for secrets_only mode
""")

        # load_config must NOT raise (deferred validation).
        config = load_config(config_file)
        assert config.partial_encryption.enabled is True

        # The error surfaces only when a partial command validates the section.
        with pytest.raises(ValueError, match=r"secrets_dir is required"):
            config.partial_encryption.validate()


class TestExampleConfig:
    """Tests for the in-source EXAMPLE_CONFIG template."""

    def test_validation_keys_documented_as_not_consumed(self):
        """EXAMPLE_CONFIG must not misrepresent [validation] keys (#413).

        No command reads validation.check_encryption/strict_extra/secret_patterns,
        so the example comments must say so (matching docs/reference/configuration.md)
        rather than implying they take effect.
        """
        assert "parsed into the config object but are\n# NOT currently consumed" in EXAMPLE_CONFIG
        assert "Parsed but not consumed" in EXAMPLE_CONFIG
        # Guard against the old misleading comments coming back.
        assert "# Check encryption by default" not in EXAMPLE_CONFIG
        assert "# Treat extra vars as errors" not in EXAMPLE_CONFIG
        assert "# Additional secret detection patterns" not in EXAMPLE_CONFIG

    def test_example_config_loads_cleanly(self, tmp_path: Path):
        """The shipped EXAMPLE_CONFIG must parse without raising."""
        config_file = tmp_path / "envdrift.toml"
        config_file.write_text(EXAMPLE_CONFIG)

        config = load_config(config_file)
        # guardian/partial sections present but inert; load must not raise.
        assert config.guardian.idle_timeout == "5m"
        assert config.partial_encryption.enabled is False
