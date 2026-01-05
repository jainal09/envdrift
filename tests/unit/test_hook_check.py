"""Tests for envdrift.integrations.hook_check."""

from __future__ import annotations

from pathlib import Path

import pytest

from envdrift.config import EnvdriftConfig, GitHookCheckConfig
from envdrift.integrations.hook_check import (
    check_direct_hooks,
    ensure_git_hook_setup,
    normalize_hook_method,
)


def _write_hook(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(0o700)


class TestNormalizeHookMethod:
    """Tests for normalize_hook_method."""

    def test_precommit_aliases(self):
        assert normalize_hook_method("precommit.yaml") == "precommit"
        assert normalize_hook_method("pre-commit") == "precommit"

    def test_direct_aliases(self):
        assert normalize_hook_method("direct git hook") == "direct"
        assert normalize_hook_method("git hooks") == "direct"

    def test_unknown(self):
        assert normalize_hook_method("unknown") is None


class TestCheckDirectHooks:
    """Tests for check_direct_hooks."""

    def test_detects_envdrift_hooks(self, tmp_path: Path):
        hooks_dir = tmp_path / "hooks"
        hooks_dir.mkdir()
        _write_hook(hooks_dir / "pre-commit", "#!/bin/sh\nenvdrift encrypt --check\n")
        _write_hook(hooks_dir / "pre-push", "#!/bin/sh\nenvdrift lock --check\n")

        result = check_direct_hooks(hooks_dir)

        assert result["pre-commit"] is True
        assert result["pre-push"] is True

    def test_missing_envdrift_hooks(self, tmp_path: Path):
        hooks_dir = tmp_path / "hooks"
        hooks_dir.mkdir()
        _write_hook(hooks_dir / "pre-commit", "#!/bin/sh\necho noop\n")

        result = check_direct_hooks(hooks_dir)

        assert result["pre-commit"] is False
        assert result["pre-push"] is False


class TestEnsureGitHookSetup:
    """Tests for ensure_git_hook_setup."""

    def test_ensure_precommit_installs_hooks(self, tmp_path: Path):
        pytest.importorskip("yaml")
        config = EnvdriftConfig(
            git_hook_check=GitHookCheckConfig(
                method="precommit.yaml",
                precommit_config=".pre-commit-config.yaml",
            )
        )
        config_path = tmp_path / "envdrift.toml"
        config_path.write_text('[git_hook_check]\nmethod = "precommit.yaml"\n')

        errors = ensure_git_hook_setup(config=config, config_path=config_path)

        assert errors == []
        content = (tmp_path / ".pre-commit-config.yaml").read_text()
        assert "envdrift-encryption" in content

    def test_ensure_direct_installs_hooks(self, tmp_path: Path):
        hooks_dir = tmp_path / ".git" / "hooks"
        hooks_dir.mkdir(parents=True)

        config = EnvdriftConfig(git_hook_check=GitHookCheckConfig(method="direct git hook"))

        errors = ensure_git_hook_setup(config=config, start_dir=tmp_path)

        assert errors == []
        pre_commit = hooks_dir / "pre-commit"
        pre_push = hooks_dir / "pre-push"
        assert pre_commit.exists()
        assert pre_push.exists()
        assert "envdrift encrypt --check" in pre_commit.read_text()
        assert "envdrift lock --check" in pre_push.read_text()
