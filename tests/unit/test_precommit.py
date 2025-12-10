"""Tests for envdrift.integrations.precommit module."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from envdrift.integrations.precommit import (
    HOOK_CONFIG,
    HOOK_ENTRY,
    find_precommit_config,
    get_hook_config,
    install_hooks,
    uninstall_hooks,
    verify_hooks_installed,
)


class TestGetHookConfig:
    """Tests for get_hook_config function."""

    def test_returns_hook_config(self):
        """Test get_hook_config returns the HOOK_CONFIG constant."""
        result = get_hook_config()
        assert result == HOOK_CONFIG
        assert "envdrift-validate" in result
        assert "envdrift-encryption" in result

    def test_contains_yaml_structure(self):
        """Test the config contains valid YAML structure markers."""
        config = get_hook_config()
        assert "repos:" in config
        assert "hooks:" in config
        assert "entry: envdrift" in config


class TestHookEntry:
    """Tests for HOOK_ENTRY constant."""

    def test_hook_entry_structure(self):
        """Test HOOK_ENTRY has correct structure."""
        assert HOOK_ENTRY["repo"] == "local"
        assert "hooks" in HOOK_ENTRY
        assert len(HOOK_ENTRY["hooks"]) == 2

    def test_validate_hook_entry(self):
        """Test envdrift-validate hook entry."""
        validate_hook = next(
            h for h in HOOK_ENTRY["hooks"] if h["id"] == "envdrift-validate"
        )
        assert validate_hook["language"] == "system"
        assert "validate" in validate_hook["entry"]

    def test_encryption_hook_entry(self):
        """Test envdrift-encryption hook entry."""
        encrypt_hook = next(
            h for h in HOOK_ENTRY["hooks"] if h["id"] == "envdrift-encryption"
        )
        assert encrypt_hook["language"] == "system"
        assert "encrypt" in encrypt_hook["entry"]


class TestFindPrecommitConfig:
    """Tests for find_precommit_config function."""

    def test_find_config_in_current_dir(self, tmp_path: Path):
        """Test finding config in start directory."""
        config_file = tmp_path / ".pre-commit-config.yaml"
        config_file.write_text("repos: []")

        result = find_precommit_config(tmp_path)
        assert result == config_file

    def test_find_config_in_parent_dir(self, tmp_path: Path):
        """Test finding config in parent directory."""
        # Create config in parent
        config_file = tmp_path / ".pre-commit-config.yaml"
        config_file.write_text("repos: []")

        # Start from child directory
        child_dir = tmp_path / "src" / "subdir"
        child_dir.mkdir(parents=True)

        result = find_precommit_config(child_dir)
        assert result == config_file

    def test_returns_none_when_not_found(self, tmp_path: Path):
        """Test returns None when config not found."""
        # tmp_path has no config file
        result = find_precommit_config(tmp_path)
        assert result is None


class TestInstallHooks:
    """Tests for install_hooks function."""

    def test_creates_new_config(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Test creates new config file if missing."""
        monkeypatch.chdir(tmp_path)

        result = install_hooks(config_path=tmp_path / ".pre-commit-config.yaml")

        assert result is True
        config_file = tmp_path / ".pre-commit-config.yaml"
        assert config_file.exists()
        content = config_file.read_text()
        assert "envdrift-validate" in content

    def test_adds_to_existing_config(self, tmp_path: Path):
        """Test adds hooks to existing config."""

        config_file = tmp_path / ".pre-commit-config.yaml"
        existing_config = {
            "repos": [
                {"repo": "https://github.com/pre-commit/pre-commit-hooks", "rev": "v4.0.0", "hooks": [{"id": "trailing-whitespace"}]}
            ]
        }
        with open(config_file, "w") as f:
            yaml.dump(existing_config, f)

        result = install_hooks(config_path=config_file)

        assert result is True
        with open(config_file) as f:
            updated_config = yaml.safe_load(f)

        # Should have original repo plus local repo with envdrift hooks
        repo_ids = [r.get("repo") for r in updated_config["repos"]]
        assert "local" in repo_ids

    def test_adds_to_existing_local_repo(self, tmp_path: Path):
        """Test adds hooks to existing local repo."""

        config_file = tmp_path / ".pre-commit-config.yaml"
        existing_config = {
            "repos": [
                {"repo": "local", "hooks": [{"id": "custom-hook", "entry": "echo test"}]}
            ]
        }
        with open(config_file, "w") as f:
            yaml.dump(existing_config, f)

        result = install_hooks(config_path=config_file)

        assert result is True
        with open(config_file) as f:
            updated_config = yaml.safe_load(f)

        local_repo = next(r for r in updated_config["repos"] if r["repo"] == "local")
        hook_ids = [h["id"] for h in local_repo["hooks"]]
        assert "custom-hook" in hook_ids
        assert "envdrift-validate" in hook_ids

    def test_raises_when_config_not_found_and_no_create(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Test raises FileNotFoundError when config not found and create_if_missing=False."""
        monkeypatch.chdir(tmp_path)

        with pytest.raises(FileNotFoundError):
            install_hooks(create_if_missing=False)

    def test_idempotent_install(self, tmp_path: Path):
        """Test installing hooks twice doesn't duplicate them."""

        config_file = tmp_path / ".pre-commit-config.yaml"

        # Install twice
        install_hooks(config_path=config_file)
        install_hooks(config_path=config_file)

        with open(config_file) as f:
            config = yaml.safe_load(f)

        # Count envdrift hooks
        envdrift_hooks = []
        for repo in config["repos"]:
            for hook in repo.get("hooks", []):
                if hook.get("id", "").startswith("envdrift-"):
                    envdrift_hooks.append(hook)

        # Should only have 2 hooks (validate and encryption), not 4
        assert len(envdrift_hooks) == 2


class TestUninstallHooks:
    """Tests for uninstall_hooks function."""

    def test_removes_envdrift_hooks(self, tmp_path: Path):
        """Test removes envdrift hooks from config."""

        config_file = tmp_path / ".pre-commit-config.yaml"
        # First install hooks
        install_hooks(config_path=config_file)

        # Then uninstall
        result = uninstall_hooks(config_path=config_file)

        assert result is True
        with open(config_file) as f:
            config = yaml.safe_load(f)

        # Check no envdrift hooks remain
        for repo in config.get("repos", []):
            for hook in repo.get("hooks", []):
                assert not hook.get("id", "").startswith("envdrift-")

    def test_returns_false_when_no_config(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Test returns False when config not found."""
        monkeypatch.chdir(tmp_path)

        result = uninstall_hooks()
        assert result is False

    def test_returns_false_when_no_envdrift_hooks(self, tmp_path: Path):
        """Test returns False when no envdrift hooks to remove."""

        config_file = tmp_path / ".pre-commit-config.yaml"
        existing_config = {
            "repos": [
                {"repo": "local", "hooks": [{"id": "other-hook", "entry": "echo test"}]}
            ]
        }
        with open(config_file, "w") as f:
            yaml.dump(existing_config, f)

        result = uninstall_hooks(config_path=config_file)
        assert result is False


class TestVerifyHooksInstalled:
    """Tests for verify_hooks_installed function."""

    def test_both_hooks_installed(self, tmp_path: Path):
        """Test detects both hooks when installed."""
        config_file = tmp_path / ".pre-commit-config.yaml"
        install_hooks(config_path=config_file)

        result = verify_hooks_installed(config_path=config_file)

        assert result["envdrift-validate"] is True
        assert result["envdrift-encryption"] is True

    def test_no_hooks_installed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Test returns False for both when no config."""
        monkeypatch.chdir(tmp_path)

        result = verify_hooks_installed()

        assert result["envdrift-validate"] is False
        assert result["envdrift-encryption"] is False

    def test_partial_hooks_installed(self, tmp_path: Path):
        """Test detects partial installation."""

        config_file = tmp_path / ".pre-commit-config.yaml"
        config = {
            "repos": [
                {
                    "repo": "local",
                    "hooks": [{"id": "envdrift-validate", "entry": "envdrift validate"}]
                }
            ]
        }
        with open(config_file, "w") as f:
            yaml.dump(config, f)

        result = verify_hooks_installed(config_path=config_file)

        assert result["envdrift-validate"] is True
        assert result["envdrift-encryption"] is False
