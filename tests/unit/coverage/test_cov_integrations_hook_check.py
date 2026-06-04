"""Coverage-focused unit tests for envdrift.integrations.hook_check.

These tests target previously-uncovered branches: absolute-path resolution,
the existing-hook-file injection path, OSError handlers in the git-dir/commondir/
gitdir parsing helpers, the chmod best-effort fallback, empty git output, the
absolute-hooks-path branch of resolve_git_hooks_path, the walk-to-root fallback,
and the precommit error branches (unresolvable path, ImportError, missing hooks).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from envdrift.config import EnvdriftConfig, GitHookCheckConfig
from envdrift.integrations import hook_check
from envdrift.integrations.hook_check import (
    check_direct_hooks,
    ensure_git_hook_setup,
    install_direct_hooks,
    resolve_git_hooks_path,
    resolve_precommit_config_path,
)


class TestResolvePrecommitConfigPathAbsolute:
    """Cover the absolute-path return (line 102)."""

    def test_absolute_path_returned_as_is(self, tmp_path: Path):
        config_path = tmp_path / "envdrift.toml"
        absolute = (tmp_path / ".pre-commit-config.yaml").resolve()

        result = resolve_precommit_config_path(config_path, str(absolute))

        assert result == absolute

    def test_relative_path_without_config_path_returned_as_is(self):
        # config_path is None -> the `if config_path and ...` guard is false,
        # so the relative path falls through to `return path` (line 102).
        result = resolve_precommit_config_path(None, ".pre-commit-config.yaml")

        assert result == Path(".pre-commit-config.yaml")


class TestInjectHookBlockNewlineEnding:
    """Cover the content-ends-with-newline append branch (line 129)."""

    def test_appends_block_when_content_ends_with_newline_no_exit(self):
        content = "#!/bin/sh\n\necho hello\n"
        new_content, updated = hook_check._inject_hook_block(
            content, hook_check._PRE_COMMIT_HOOK_LINES
        )

        assert updated is True
        # No "exit 0" present, content already ends with newline, so the block
        # is appended directly with no extra inserted newline.
        assert new_content == content + hook_check._format_hook_block(
            hook_check._PRE_COMMIT_HOOK_LINES
        )
        assert "# >>> envdrift hook: pre-commit" in new_content


class TestEnsureHookFileExisting:
    """Cover the existing-file read/inject path (lines 138-139)."""

    def test_updates_existing_hook_file(self, tmp_path: Path):
        hook_path = tmp_path / "pre-commit"
        hook_path.write_text("#!/bin/sh\necho existing\n")

        updated = hook_check._ensure_hook_file(hook_path, hook_check._PRE_COMMIT_HOOK_LINES)

        assert updated is True
        content = hook_path.read_text()
        assert "echo existing" in content
        assert "# >>> envdrift hook: pre-commit" in content

    def test_existing_hook_with_marker_is_not_rewritten(self, tmp_path: Path):
        hook_path = tmp_path / "pre-commit"
        original = "#!/bin/sh\n# >>> envdrift hook: pre-commit\n# <<< envdrift hook: pre-commit\n"
        hook_path.write_text(original)
        hook_path.chmod(0o755)

        updated = hook_check._ensure_hook_file(hook_path, hook_check._PRE_COMMIT_HOOK_LINES)

        assert updated is False
        assert hook_path.read_text() == original


class TestEnsureHookFileChmodFallback:
    """Cover the OSError chmod best-effort fallback (lines 151-152)."""

    def test_chmod_oserror_is_swallowed(self, monkeypatch, tmp_path: Path):
        hook_path = tmp_path / "pre-commit"

        def fake_chmod(self, _mode):
            raise OSError("read-only fs")

        monkeypatch.setattr(Path, "chmod", fake_chmod)

        # Should not raise even though chmod fails.
        updated = hook_check._ensure_hook_file(hook_path, hook_check._PRE_COMMIT_HOOK_LINES)

        assert updated is True
        assert hook_path.exists()


class TestReadGitPathEmptyOutput:
    """Cover the empty-stdout return None branch (line 203)."""

    def test_empty_output_returns_none(self, monkeypatch):
        from types import SimpleNamespace

        monkeypatch.setattr(hook_check.shutil, "which", lambda _name: "/usr/bin/git")
        monkeypatch.setattr(
            hook_check.subprocess,
            "run",
            lambda *a, **k: SimpleNamespace(stdout="   \n"),
        )

        assert hook_check._read_git_path("rev-parse") is None


class TestResolveGitHooksPathAbsolute:
    """Cover absolute hooks_path branch (line 216) and final None (line 235)."""

    def test_absolute_hooks_path_returned_directly(self, monkeypatch, tmp_path: Path):
        root = tmp_path / "repo"
        root.mkdir()
        abs_hooks = (tmp_path / "abs_hooks").resolve()

        def fake_read_git_path(*args):
            if "--show-toplevel" in args:
                return root
            if "--git-path" in args:
                return abs_hooks
            return None

        monkeypatch.setattr(hook_check, "_read_git_path", fake_read_git_path)

        resolved = resolve_git_hooks_path(start_dir=root)

        assert resolved == abs_hooks

    def test_returns_none_when_no_git_dir_found(self, monkeypatch, tmp_path: Path):
        # No git metadata from git command and no .git anywhere -> None (line 221).
        monkeypatch.setattr(hook_check, "_read_git_path", lambda *args: None)
        monkeypatch.setattr(hook_check, "_find_git_dir", lambda _start: None)

        assert resolve_git_hooks_path(start_dir=tmp_path) is None

    def test_returns_none_when_git_dir_has_no_hooks(self, monkeypatch, tmp_path: Path):
        # git_dir exists but has neither hooks/ nor a resolvable commondir -> line 235.
        git_dir = tmp_path / ".git"
        git_dir.mkdir()

        monkeypatch.setattr(hook_check, "_read_git_path", lambda *args: None)
        monkeypatch.setattr(hook_check, "_find_git_dir", lambda _start: git_dir)

        assert resolve_git_hooks_path(start_dir=tmp_path) is None


class TestFindGitDirWalkToRoot:
    """Cover the walk-up-to-filesystem-root branch (lines 248-250)."""

    def test_walks_up_and_returns_none_at_root(self, tmp_path: Path):
        nested = tmp_path / "a" / "b" / "c"
        nested.mkdir(parents=True)

        # No .git anywhere up the tree under tmp_path; eventually reaches the
        # filesystem root (current == current.parent) and returns None.
        assert hook_check._find_git_dir(nested) is None

    def test_finds_git_dir_in_parent(self, tmp_path: Path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        nested = tmp_path / "sub" / "dir"
        nested.mkdir(parents=True)

        assert hook_check._find_git_dir(nested) == git_dir


class TestParseGitdirFile:
    """Cover OSError, non-gitdir, and relative-path branches (lines 256-263)."""

    def test_oserror_returns_none(self, monkeypatch, tmp_path: Path):
        git_file = tmp_path / ".git"
        git_file.write_text("gitdir: somewhere\n")

        def boom(self, *a, **k):
            raise OSError("cannot read")

        monkeypatch.setattr(Path, "read_text", boom)

        assert hook_check._parse_gitdir_file(tmp_path, git_file) is None

    def test_non_gitdir_content_returns_none(self, tmp_path: Path):
        git_file = tmp_path / ".git"
        git_file.write_text("not a gitdir pointer\n")

        assert hook_check._parse_gitdir_file(tmp_path, git_file) is None

    def test_relative_gitdir_is_resolved_against_root(self, tmp_path: Path):
        root = tmp_path / "worktree"
        root.mkdir()
        git_file = root / ".git"
        git_file.write_text("gitdir: ../actual_git\n")

        result = hook_check._parse_gitdir_file(root, git_file)

        assert result == (root / "../actual_git").resolve()


class TestResolveCommondir:
    """Cover OSError, empty, and relative-path branches (lines 270-276)."""

    def test_oserror_returns_none(self, monkeypatch, tmp_path: Path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        commondir = git_dir / "commondir"
        commondir.write_text("../common\n")

        def boom(self, *a, **k):
            raise OSError("cannot read")

        monkeypatch.setattr(Path, "read_text", boom)

        assert hook_check._resolve_commondir(git_dir, commondir) is None

    def test_empty_commondir_returns_none(self, tmp_path: Path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        commondir = git_dir / "commondir"
        commondir.write_text("   \n")

        assert hook_check._resolve_commondir(git_dir, commondir) is None

    def test_relative_commondir_resolved_against_git_dir(self, tmp_path: Path):
        git_dir = tmp_path / ".git" / "worktrees" / "wt"
        git_dir.mkdir(parents=True)
        commondir = git_dir / "commondir"
        commondir.write_text("../..\n")

        result = hook_check._resolve_commondir(git_dir, commondir)

        assert result == (git_dir / "../..").resolve()


class TestHookContainsEnvdriftOSError:
    """Cover the OSError-on-read branch (lines 283-284)."""

    def test_unreadable_hook_returns_false(self, monkeypatch, tmp_path: Path):
        hook_path = tmp_path / "pre-commit"
        hook_path.write_text("envdrift encrypt --check\n")

        def boom(self, *a, **k):
            raise OSError("permission denied")

        monkeypatch.setattr(Path, "read_text", boom)

        assert hook_check._hook_contains_envdrift(hook_path) is False


class TestCheckDirectHooksMissingDir:
    """Cover the missing-hooks-dir early return (line 292)."""

    def test_nonexistent_dir_returns_all_false(self, tmp_path: Path):
        result = check_direct_hooks(tmp_path / "does_not_exist")

        assert result == {"pre-commit": False, "pre-push": False}

    def test_none_dir_returns_all_false(self):
        result = check_direct_hooks(None)

        assert result == {"pre-commit": False, "pre-push": False}


class TestEnsureGitHookSetupPrecommitBranches:
    """Cover precommit error branches (lines 348, 356, 365-366)."""

    def test_unresolvable_precommit_path_returns_error(self, monkeypatch):
        config = EnvdriftConfig(
            git_hook_check=GitHookCheckConfig(
                method="precommit.yaml",
                precommit_config=".pre-commit-config.yaml",
            )
        )
        # Force resolve_precommit_config_path to return None to hit line 348.
        monkeypatch.setattr(hook_check, "resolve_precommit_config_path", lambda *a, **k: None)

        errors = ensure_git_hook_setup(config=config, config_path=None)

        assert errors
        assert "could not be resolved" in errors[0].lower()

    def test_install_hooks_import_error_surfaces(self, monkeypatch, tmp_path: Path):
        config = EnvdriftConfig(
            git_hook_check=GitHookCheckConfig(
                method="precommit.yaml",
                precommit_config=".pre-commit-config.yaml",
            )
        )
        config_path = tmp_path / "envdrift.toml"
        config_path.write_text('[git_hook_check]\nmethod = "precommit.yaml"\n')

        def raise_import_error(*_a, **_k):
            raise ImportError("pyyaml is required")

        monkeypatch.setattr("envdrift.integrations.precommit.install_hooks", raise_import_error)

        errors = ensure_git_hook_setup(config=config, config_path=config_path)

        assert errors
        assert "pyyaml is required" in errors[0]

    def test_missing_precommit_hooks_reported(self, monkeypatch, tmp_path: Path):
        config = EnvdriftConfig(
            git_hook_check=GitHookCheckConfig(
                method="precommit.yaml",
                precommit_config=".pre-commit-config.yaml",
            )
        )
        config_path = tmp_path / "envdrift.toml"
        config_path.write_text('[git_hook_check]\nmethod = "precommit.yaml"\n')
        precommit_file = tmp_path / ".pre-commit-config.yaml"
        precommit_file.write_text("repos: []\n")

        # install_hooks is a no-op so auto_fix succeeds, but the verification
        # reports the hook missing -> the missing-hooks error branch (365-366).
        monkeypatch.setattr("envdrift.integrations.precommit.install_hooks", lambda *a, **k: None)
        monkeypatch.setattr(
            hook_check, "check_precommit_hooks", lambda _p: {"envdrift-encryption": False}
        )

        errors = ensure_git_hook_setup(config=config, config_path=config_path)

        assert errors
        assert "missing envdrift pre-commit hook" in errors[0].lower()
        assert "envdrift-encryption" in errors[0]


class TestInstallDirectHooksSmoke:
    """Sanity check that install + check round-trips through targeted helpers."""

    def test_install_then_check_reports_present(self, tmp_path: Path):
        hooks_dir = tmp_path / "hooks"
        install_direct_hooks(hooks_dir)

        status = check_direct_hooks(hooks_dir)

        assert status["pre-commit"] is True
        assert status["pre-push"] is True


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
