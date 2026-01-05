"""Tests for envdrift.integrations.hook_check."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from envdrift.config import EnvdriftConfig, GitHookCheckConfig
from envdrift.integrations import hook_check
from envdrift.integrations.hook_check import (
    check_direct_hooks,
    check_git_hook_setup,
    check_precommit_hooks,
    ensure_git_hook_setup,
    install_direct_hooks,
    normalize_hook_method,
    resolve_git_hooks_path,
    resolve_precommit_config_path,
)


def _write_hook(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(0o700)


class TestResolvePrecommitConfigPath:
    """Tests for resolve_precommit_config_path."""

    def test_relative_path_resolves_from_config(self, tmp_path: Path):
        config_path = tmp_path / "envdrift.toml"
        target = resolve_precommit_config_path(config_path, ".pre-commit-config.yaml")
        assert target == (tmp_path / ".pre-commit-config.yaml").resolve()

    def test_missing_precommit_config_returns_none(self, tmp_path: Path):
        config_path = tmp_path / "envdrift.toml"

        assert resolve_precommit_config_path(config_path, None) is None


class TestInjectHookBlock:
    """Tests for hook block insertion."""

    def test_noop_when_marker_present(self):
        content = "#!/bin/sh\n# >>> envdrift hook: pre-commit\n# <<< envdrift hook: pre-commit\n"
        new_content, updated = hook_check._inject_hook_block(
            content, hook_check._PRE_COMMIT_HOOK_LINES
        )

        assert new_content == content
        assert updated is False

    def test_inserts_before_exit_zero(self):
        content = "#!/bin/sh\n\necho ok\nexit 0\n"
        new_content, updated = hook_check._inject_hook_block(
            content, hook_check._PRE_COMMIT_HOOK_LINES
        )

        assert updated is True
        assert "# >>> envdrift hook: pre-commit" in new_content
        assert new_content.index("# >>> envdrift hook: pre-commit") < new_content.index("exit 0")

    def test_inserts_into_empty_content(self):
        new_content, updated = hook_check._inject_hook_block("", hook_check._PRE_COMMIT_HOOK_LINES)

        assert updated is True
        assert new_content.startswith("# >>> envdrift hook: pre-commit")

    def test_appends_when_missing_trailing_newline(self):
        content = "#!/bin/sh\n\necho ok"
        new_content, updated = hook_check._inject_hook_block(
            content, hook_check._PRE_COMMIT_HOOK_LINES
        )

        assert updated is True
        assert new_content.endswith("\n")
        assert "# >>> envdrift hook: pre-commit" in new_content


class TestEnsureHookFile:
    """Tests for _ensure_hook_file and installer helpers."""

    def test_creates_executable_hook(self, tmp_path: Path):
        hook_path = tmp_path / "hooks" / "pre-commit"

        updated = hook_check._ensure_hook_file(hook_path, hook_check._PRE_COMMIT_HOOK_LINES)

        assert updated is True
        assert hook_path.exists()
        assert os.access(hook_path, os.X_OK)
        content = hook_path.read_text()
        assert content.startswith("#!/bin/sh")
        assert "# >>> envdrift hook: pre-commit" in content

    def test_install_direct_hooks_creates_files(self, tmp_path: Path):
        hooks_dir = tmp_path / "hooks"

        result = install_direct_hooks(hooks_dir)

        assert result["pre-commit"] is True
        assert result["pre-push"] is True
        assert (hooks_dir / "pre-commit").exists()
        assert (hooks_dir / "pre-push").exists()


class TestReadGitPath:
    """Tests for _read_git_path handling."""

    def test_strips_git_env(self, monkeypatch, tmp_path: Path):
        work_tree = tmp_path / "worktree"
        git_dir = work_tree / ".git"
        index_file = tmp_path / "index"
        common_dir = tmp_path / "common"

        monkeypatch.setenv("GIT_DIR", str(git_dir))
        monkeypatch.setenv("GIT_WORK_TREE", str(work_tree))
        monkeypatch.setenv("GIT_INDEX_FILE", str(index_file))
        monkeypatch.setenv("GIT_COMMON_DIR", str(common_dir))

        captured = {}

        def fake_run(args, check, capture_output, text, env):
            captured["env"] = env
            return SimpleNamespace(stdout=str(tmp_path / ".git" / "hooks") + "\n")

        monkeypatch.setattr(hook_check.shutil, "which", lambda _name: "/usr/bin/git")
        monkeypatch.setattr(hook_check.subprocess, "run", fake_run)

        result = hook_check._read_git_path("rev-parse", "--git-path", "hooks")

        assert result == tmp_path / ".git" / "hooks"
        assert "GIT_DIR" not in captured["env"]
        assert "GIT_WORK_TREE" not in captured["env"]
        assert "GIT_INDEX_FILE" not in captured["env"]
        assert "GIT_COMMON_DIR" not in captured["env"]

    def test_returns_none_when_git_missing(self, monkeypatch):
        monkeypatch.setattr(hook_check.shutil, "which", lambda _name: None)

        assert hook_check._read_git_path("rev-parse") is None


class TestResolveGitHooksPath:
    """Tests for resolve_git_hooks_path fallback behavior."""

    def test_resolves_gitdir_file(self, monkeypatch, tmp_path: Path):
        git_dir = tmp_path / ".repo"
        hooks_dir = git_dir / "hooks"
        hooks_dir.mkdir(parents=True)

        git_file = tmp_path / ".git"
        git_file.write_text(f"gitdir: {git_dir}\n")

        monkeypatch.setattr(hook_check, "_read_git_path", lambda *args: None)

        resolved = resolve_git_hooks_path(start_dir=tmp_path)

        assert resolved == hooks_dir

    def test_resolves_commondir(self, monkeypatch, tmp_path: Path):
        git_dir = tmp_path / ".git"
        common_dir = tmp_path / ".common"
        common_hooks = common_dir / "hooks"
        common_hooks.mkdir(parents=True)
        git_dir.mkdir()
        (git_dir / "commondir").write_text(str(common_dir))

        monkeypatch.setattr(hook_check, "_read_git_path", lambda *args: None)

        resolved = resolve_git_hooks_path(start_dir=tmp_path)

        assert resolved == common_hooks

    def test_resolves_from_git_command_paths(self, monkeypatch, tmp_path: Path):
        root = tmp_path / "repo"
        root.mkdir()
        hooks_path = Path("custom/hooks")
        (root / hooks_path).mkdir(parents=True)

        def fake_read_git_path(*args):
            if "--show-toplevel" in args:
                return root
            if "--git-path" in args:
                return hooks_path
            return None

        monkeypatch.setattr(hook_check, "_read_git_path", fake_read_git_path)

        resolved = resolve_git_hooks_path(start_dir=root)

        assert resolved == (root / hooks_path).resolve()


class TestCheckPrecommitHooks:
    """Tests for pre-commit hook checks."""

    def test_missing_config_returns_false(self):
        result = check_precommit_hooks(None)

        assert result["envdrift-encryption"] is False

    def test_reports_installed_hooks(self, monkeypatch, tmp_path: Path):
        config_path = tmp_path / ".pre-commit-config.yaml"
        config_path.write_text("repos: []\n")
        monkeypatch.setattr(
            hook_check,
            "verify_hooks_installed",
            lambda config_path: {"envdrift-encryption": True},
        )

        result = check_precommit_hooks(config_path)

        assert result["envdrift-encryption"] is True

    def test_custom_required_hooks(self, monkeypatch, tmp_path: Path):
        config_path = tmp_path / ".pre-commit-config.yaml"
        config_path.write_text("repos: []\n")
        monkeypatch.setattr(
            hook_check,
            "verify_hooks_installed",
            lambda config_path: {"envdrift-encryption": True, "envdrift-lock": False},
        )

        result = check_precommit_hooks(
            config_path, required_hooks=("envdrift-encryption", "envdrift-lock")
        )

        assert result["envdrift-encryption"] is True
        assert result["envdrift-lock"] is False


class TestLoadConfigForHookCheck:
    """Tests for configuration loading helper."""

    def test_ignores_non_toml_config(self, tmp_path: Path):
        config_file = tmp_path / "config.yaml"

        config, path = hook_check._load_config_for_hook_check(config_file)

        assert config is None
        assert path is None

    def test_missing_config_returns_path(self, tmp_path: Path):
        config_file = tmp_path / "envdrift.toml"

        config, path = hook_check._load_config_for_hook_check(config_file)

        assert config is None
        assert path == config_file

    def test_autodiscovery_returns_none_when_missing(self, monkeypatch):
        monkeypatch.setattr(hook_check, "find_config", lambda *args, **kwargs: None)

        config, path = hook_check._load_config_for_hook_check(None)

        assert config is None
        assert path is None


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

    def test_non_executable_hooks_are_skipped(self, tmp_path: Path):
        hooks_dir = tmp_path / "hooks"
        hooks_dir.mkdir()
        hook_path = hooks_dir / "pre-commit"
        hook_path.write_text("#!/bin/sh\nenvdrift encrypt --check\n")
        hook_path.chmod(0o600)

        result = check_direct_hooks(hooks_dir)

        assert result["pre-commit"] is False


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

    def test_unknown_method_returns_error(self):
        config = EnvdriftConfig(git_hook_check=GitHookCheckConfig(method="mystery"))

        errors = ensure_git_hook_setup(config=config)

        assert errors
        assert "unknown git_hook_check.method" in errors[0].lower()

    def test_precommit_requires_config_path(self):
        config = EnvdriftConfig(git_hook_check=GitHookCheckConfig(method="precommit.yaml"))

        errors = ensure_git_hook_setup(config=config)

        assert errors
        assert "precommit_config is required" in errors[0]

    def test_precommit_missing_file_without_autofix(self, tmp_path: Path):
        config = EnvdriftConfig(
            git_hook_check=GitHookCheckConfig(
                method="precommit.yaml",
                precommit_config=".pre-commit-config.yaml",
            )
        )
        config_path = tmp_path / "envdrift.toml"
        config_path.write_text('[git_hook_check]\nmethod = "precommit.yaml"\n')

        errors = ensure_git_hook_setup(
            config=config,
            config_path=config_path,
            auto_fix=False,
        )

        assert errors
        assert "pre-commit config not found" in errors[0].lower()

    def test_direct_reports_missing_git_dir(self, monkeypatch, tmp_path: Path):
        config = EnvdriftConfig(git_hook_check=GitHookCheckConfig(method="direct git hook"))
        monkeypatch.setattr(hook_check, "resolve_git_hooks_path", lambda **_: None)

        errors = ensure_git_hook_setup(config=config, start_dir=tmp_path)

        assert errors
        assert "git hooks directory not found" in errors[0].lower()

    def test_precommit_install_failure_surfaces_error(self, monkeypatch, tmp_path: Path):
        config = EnvdriftConfig(
            git_hook_check=GitHookCheckConfig(
                method="precommit.yaml",
                precommit_config=".pre-commit-config.yaml",
            )
        )
        config_path = tmp_path / "envdrift.toml"
        config_path.write_text('[git_hook_check]\nmethod = "precommit.yaml"\n')

        def fail_install(*_args, **_kwargs):
            raise OSError("boom")

        monkeypatch.setattr("envdrift.integrations.precommit.install_hooks", fail_install)

        errors = ensure_git_hook_setup(config=config, config_path=config_path)

        assert errors
        assert "failed to update pre-commit config" in errors[0].lower()

    def test_direct_install_failure_surfaces_error(self, monkeypatch, tmp_path: Path):
        config = EnvdriftConfig(git_hook_check=GitHookCheckConfig(method="direct git hook"))
        hooks_dir = tmp_path / ".git" / "hooks"
        hooks_dir.mkdir(parents=True)

        def fail_install(*_args, **_kwargs):
            raise OSError("boom")

        monkeypatch.setattr(hook_check, "install_direct_hooks", fail_install)

        errors = ensure_git_hook_setup(config=config, start_dir=tmp_path)

        assert errors
        assert "failed to update git hooks" in errors[0].lower()

    def test_direct_missing_hooks_without_autofix(self, tmp_path: Path):
        hooks_dir = tmp_path / ".git" / "hooks"
        hooks_dir.mkdir(parents=True)
        _write_hook(hooks_dir / "pre-commit", "#!/bin/sh\nenvdrift encrypt --check\n")

        config = EnvdriftConfig(git_hook_check=GitHookCheckConfig(method="direct git hook"))

        errors = ensure_git_hook_setup(
            config=config,
            start_dir=tmp_path,
            auto_fix=False,
        )

        assert errors
        assert "missing envdrift git hook" in errors[0].lower()


class TestCheckGitHookSetup:
    """Tests for check_git_hook_setup wrapper."""

    def test_check_git_hook_setup_disables_autofix(self, monkeypatch):
        captured = {}

        def fake_ensure(**kwargs):
            captured["auto_fix"] = kwargs.get("auto_fix")
            return []

        monkeypatch.setattr(hook_check, "ensure_git_hook_setup", fake_ensure)

        errors = check_git_hook_setup(config=EnvdriftConfig())

        assert errors == []
        assert captured["auto_fix"] is False
