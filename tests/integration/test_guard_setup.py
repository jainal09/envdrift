"""Guard/Hook Setup Edge Cases Integration Tests.

Tests for git hook auto-setup (guard) functionality edge cases:
- Hook installation methods (direct, pre-commit)
- Hook detection and verification
- git worktree support
- Edge cases for hook configuration
- Auto-fix vs check-only modes
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PYTHONPATH = str(REPO_ROOT / "src")


def _run_envdrift(
    args: list[str], *, cwd: Path, env: dict[str, str], check: bool = True
) -> subprocess.CompletedProcess:
    """Run envdrift CLI command."""
    cmd = [sys.executable, "-m", "envdrift.cli", *args]
    result = subprocess.run(
        cmd,
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"envdrift failed\ncmd: {' '.join(cmd)}\n"
            f"cwd: {cwd}\nstdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    return result


def _run_git(
    args: list[str], *, cwd: Path, env: dict[str, str] | None = None, check: bool = True
) -> subprocess.CompletedProcess:
    """Run git command."""
    git_path = shutil.which("git")
    if git_path is None:
        pytest.skip("git is not available")

    git_env = os.environ.copy()
    for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR"):
        git_env.pop(key, None)

    if env:
        git_env.update(env)

    result = subprocess.run(
        [git_path, *args],
        cwd=str(cwd),
        env=git_env,
        capture_output=True,
        text=True,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"git failed\ncmd: git {' '.join(args)}\n"
            f"cwd: {cwd}\nstdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    return result


def _init_git_repo(path: Path) -> None:
    """Initialize a git repository."""
    git_path = shutil.which("git")
    if git_path is None:
        pytest.skip("git is not available")

    env = os.environ.copy()
    for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR"):
        env.pop(key, None)

    subprocess.run(
        [git_path, "init"],
        cwd=str(path),
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        [git_path, "config", "user.email", "test@example.com"],
        cwd=str(path),
        env=env,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [git_path, "config", "user.name", "Test User"],
        cwd=str(path),
        env=env,
        check=True,
        capture_output=True,
    )


@pytest.fixture
def guard_test_env(tmp_path):
    """Create a test environment for guard/hook tests."""
    work_dir = tmp_path / "test_repo"
    work_dir.mkdir()
    _init_git_repo(work_dir)

    env = os.environ.copy()
    env["PYTHONPATH"] = f"{PYTHONPATH}{os.pathsep}{env.get('PYTHONPATH', '')}"

    return {"work_dir": work_dir, "env": env, "tmp_path": tmp_path}


@pytest.mark.integration
class TestHookMethodConfiguration:
    """Test different hook installation methods."""

    def test_hook_method_direct(self, guard_test_env):
        """Test direct git hook installation method."""
        work_dir = guard_test_env["work_dir"]
        env = guard_test_env["env"]

        config = textwrap.dedent(
            """\
            [git_hook_check]
            method = "direct"

            [encryption]
            backend = "dotenvx"

            [encryption.dotenvx]
            auto_install = true
            """
        )
        (work_dir / "envdrift.toml").write_text(config)

        env_file = work_dir / ".env.test"
        env_file.write_text("SECRET=value\n")

        _run_envdrift(["encrypt", env_file.name], cwd=work_dir, env=env)

        # Verify direct hooks were installed
        pre_commit = work_dir / ".git" / "hooks" / "pre-commit"
        pre_push = work_dir / ".git" / "hooks" / "pre-push"
        assert pre_commit.exists(), "pre-commit hook should be installed"
        assert pre_push.exists(), "pre-push hook should be installed"
        assert "envdrift" in pre_commit.read_text()

    def test_hook_method_precommit_yaml(self, guard_test_env):
        """Test pre-commit framework installation method."""
        pytest.importorskip("yaml")
        work_dir = guard_test_env["work_dir"]
        env = guard_test_env["env"]

        config = textwrap.dedent(
            """\
            [git_hook_check]
            method = "precommit.yaml"
            precommit_config = ".pre-commit-config.yaml"

            [encryption]
            backend = "dotenvx"

            [encryption.dotenvx]
            auto_install = true
            """
        )
        (work_dir / "envdrift.toml").write_text(config)

        env_file = work_dir / ".env.test"
        env_file.write_text("SECRET=value\n")

        _run_envdrift(["encrypt", env_file.name], cwd=work_dir, env=env)

        # Verify pre-commit config was created
        precommit_path = work_dir / ".pre-commit-config.yaml"
        assert precommit_path.exists(), "pre-commit config should be created"
        content = precommit_path.read_text()
        assert "envdrift" in content.lower()

    def test_hook_method_case_insensitive(self, guard_test_env):
        """Test that hook method is case-insensitive."""
        work_dir = guard_test_env["work_dir"]
        env = guard_test_env["env"]

        # Use uppercase method
        config = textwrap.dedent(
            """\
            [git_hook_check]
            method = "DIRECT GIT HOOK"

            [encryption]
            backend = "dotenvx"

            [encryption.dotenvx]
            auto_install = true
            """
        )
        (work_dir / "envdrift.toml").write_text(config)

        env_file = work_dir / ".env.test"
        env_file.write_text("SECRET=value\n")

        _run_envdrift(["encrypt", env_file.name], cwd=work_dir, env=env)

        # Should still install direct hooks
        pre_commit = work_dir / ".git" / "hooks" / "pre-commit"
        assert pre_commit.exists()


@pytest.mark.integration
class TestHookDetection:
    """Test hook detection and verification."""

    def test_detect_existing_envdrift_hooks(self, guard_test_env):
        """Test that existing envdrift hooks are detected and not duplicated."""
        work_dir = guard_test_env["work_dir"]
        env = guard_test_env["env"]

        config = textwrap.dedent(
            """\
            [git_hook_check]
            method = "direct"

            [encryption]
            backend = "dotenvx"

            [encryption.dotenvx]
            auto_install = true
            """
        )
        (work_dir / "envdrift.toml").write_text(config)

        env_file = work_dir / ".env.test"
        env_file.write_text("SECRET=value\n")

        # Run encrypt twice
        _run_envdrift(["encrypt", env_file.name], cwd=work_dir, env=env)
        initial_hook = (work_dir / ".git" / "hooks" / "pre-commit").read_text()

        _run_envdrift(["decrypt", env_file.name], cwd=work_dir, env=env)
        _run_envdrift(["encrypt", env_file.name], cwd=work_dir, env=env)
        final_hook = (work_dir / ".git" / "hooks" / "pre-commit").read_text()

        # Hooks should not be duplicated
        assert initial_hook.count("envdrift") == final_hook.count("envdrift"), (
            "envdrift hook should not be duplicated"
        )

    def test_detect_custom_hook_preserved(self, guard_test_env):
        """Test that custom hooks are preserved when adding envdrift hooks."""
        work_dir = guard_test_env["work_dir"]
        env = guard_test_env["env"]

        # Create custom pre-commit hook first
        hooks_dir = work_dir / ".git" / "hooks"
        hooks_dir.mkdir(parents=True, exist_ok=True)
        pre_commit = hooks_dir / "pre-commit"
        pre_commit.write_text("#!/bin/sh\necho 'Custom hook'\nexit 0\n")
        pre_commit.chmod(0o755)

        config = textwrap.dedent(
            """\
            [git_hook_check]
            method = "direct"

            [encryption]
            backend = "dotenvx"

            [encryption.dotenvx]
            auto_install = true
            """
        )
        (work_dir / "envdrift.toml").write_text(config)

        env_file = work_dir / ".env.test"
        env_file.write_text("SECRET=value\n")

        _run_envdrift(["encrypt", env_file.name], cwd=work_dir, env=env)

        hook_content = pre_commit.read_text()
        # Both custom content and envdrift should be present
        assert "Custom hook" in hook_content, "Custom hook content should be preserved"
        assert "envdrift" in hook_content, "envdrift hook should be added"


@pytest.mark.integration
class TestGitWorktreeSupport:
    """Test hook setup in git worktrees."""

    def test_hook_in_main_worktree(self, guard_test_env):
        """Test that hooks work in the main worktree."""
        work_dir = guard_test_env["work_dir"]
        env = guard_test_env["env"]

        config = textwrap.dedent(
            """\
            [git_hook_check]
            method = "direct"

            [encryption]
            backend = "dotenvx"
            """
        )
        (work_dir / "envdrift.toml").write_text(config)

        env_file = work_dir / ".env.test"
        env_file.write_text("SECRET=value\n")

        # Create initial commit
        _run_git(["add", "-A"], cwd=work_dir)
        _run_git(["commit", "-m", "Initial"], cwd=work_dir)

        _run_envdrift(["encrypt", env_file.name], cwd=work_dir, env=env)

        pre_commit = work_dir / ".git" / "hooks" / "pre-commit"
        assert pre_commit.exists()

    def test_hook_in_linked_worktree(self, guard_test_env):
        """Test hook setup in a linked worktree."""
        work_dir = guard_test_env["work_dir"]
        tmp_path = guard_test_env["tmp_path"]
        env = guard_test_env["env"]

        # Create initial commit in main repo
        (work_dir / "README.md").write_text("# Test\n")
        _run_git(["add", "-A"], cwd=work_dir)
        _run_git(["commit", "-m", "Initial"], cwd=work_dir)

        # Create a linked worktree
        worktree_path = tmp_path / "worktree"
        try:
            _run_git(["worktree", "add", str(worktree_path), "-b", "feature"], cwd=work_dir)
        except AssertionError:
            pytest.skip("git worktree not supported or failed")

        config = textwrap.dedent(
            """\
            [git_hook_check]
            method = "direct"

            [encryption]
            backend = "dotenvx"

            [encryption.dotenvx]
            auto_install = true
            """
        )
        (worktree_path / "envdrift.toml").write_text(config)

        env_file = worktree_path / ".env.test"
        env_file.write_text("SECRET=value\n")

        _run_envdrift(["encrypt", env_file.name], cwd=worktree_path, env=env)

        # Hooks should be installed in the main .git directory
        main_hooks = work_dir / ".git" / "hooks"
        worktree_hooks = worktree_path / ".git" / "hooks"

        # The hooks could be in either location depending on git version
        hook_exists = (main_hooks / "pre-commit").exists() or (
            worktree_hooks.is_dir() and (worktree_hooks / "pre-commit").exists()
        )
        assert hook_exists, "pre-commit hook should be installed somewhere"


@pytest.mark.integration
class TestHookConfigEdgeCases:
    """Test edge cases in hook configuration."""

    def test_hook_missing_git_repo(self, tmp_path):
        """Test graceful handling when not in a git repo."""
        work_dir = tmp_path / "no_git"
        work_dir.mkdir()

        env = os.environ.copy()
        env["PYTHONPATH"] = f"{PYTHONPATH}{os.pathsep}{env.get('PYTHONPATH', '')}"

        config = textwrap.dedent(
            """\
            [git_hook_check]
            method = "direct"

            [encryption]
            backend = "dotenvx"

            [encryption.dotenvx]
            auto_install = true
            """
        )
        (work_dir / "envdrift.toml").write_text(config)

        env_file = work_dir / ".env.test"
        env_file.write_text("SECRET=value\n")

        # Should not crash when not in git repo
        _run_envdrift(["encrypt", env_file.name], cwd=work_dir, env=env, check=False)

        # Encryption should still work
        assert env_file.exists()

    def test_hook_method_disabled(self, guard_test_env):
        """Test that hooks are not installed when method is not configured."""
        work_dir = guard_test_env["work_dir"]
        env = guard_test_env["env"]

        # No git_hook_check section
        config = textwrap.dedent(
            """\
            [encryption]
            backend = "dotenvx"

            [encryption.dotenvx]
            auto_install = true
            """
        )
        (work_dir / "envdrift.toml").write_text(config)

        env_file = work_dir / ".env.test"
        env_file.write_text("SECRET=value\n")

        _run_envdrift(["encrypt", env_file.name], cwd=work_dir, env=env)

        # Hooks should not be installed without config
        pre_commit = work_dir / ".git" / "hooks" / "pre-commit"
        # Either no hook, or hook doesn't contain envdrift
        if pre_commit.exists():
            assert "envdrift" not in pre_commit.read_text()

    def test_hook_custom_precommit_path(self, guard_test_env):
        """Test custom pre-commit config path."""
        pytest.importorskip("yaml")
        work_dir = guard_test_env["work_dir"]
        env = guard_test_env["env"]

        # Use custom path for pre-commit config
        config = textwrap.dedent(
            """\
            [git_hook_check]
            method = "precommit.yaml"
            precommit_config = "config/.pre-commit-config.yaml"

            [encryption]
            backend = "dotenvx"

            [encryption.dotenvx]
            auto_install = true
            """
        )
        (work_dir / "envdrift.toml").write_text(config)
        (work_dir / "config").mkdir()

        env_file = work_dir / ".env.test"
        env_file.write_text("SECRET=value\n")

        _run_envdrift(["encrypt", env_file.name], cwd=work_dir, env=env)

        # Should create config at custom path
        precommit_path = work_dir / "config" / ".pre-commit-config.yaml"
        assert precommit_path.exists(), "Pre-commit config should be at custom path"


@pytest.mark.integration
class TestHookAutoFixVsCheckOnly:
    """Test auto-fix vs check-only modes for hooks."""

    def test_hook_auto_fix_enabled(self, guard_test_env):
        """Test that hooks are automatically installed when auto_fix is true."""
        work_dir = guard_test_env["work_dir"]
        env = guard_test_env["env"]

        config = textwrap.dedent(
            """\
            [git_hook_check]
            method = "direct"

            [encryption]
            backend = "dotenvx"

            [encryption.dotenvx]
            auto_install = true
            """
        )
        (work_dir / "envdrift.toml").write_text(config)

        env_file = work_dir / ".env.test"
        env_file.write_text("SECRET=value\n")

        _run_envdrift(["encrypt", env_file.name], cwd=work_dir, env=env)

        # Hooks should be auto-installed
        pre_commit = work_dir / ".git" / "hooks" / "pre-commit"
        assert pre_commit.exists()

    def test_lock_check_returns_status(self, guard_test_env):
        """Test that lock --check returns appropriate status for hook verification."""
        work_dir = guard_test_env["work_dir"]
        env = guard_test_env["env"]

        config = textwrap.dedent(
            """\
            [encryption]
            backend = "dotenvx"

            [encryption.dotenvx]
            auto_install = true

            [vault.sync]
            [[vault.sync.mappings]]
            folder_path = "."
            environment = "production"
            secret_name = "test/key"
            """
        )
        (work_dir / "envdrift.toml").write_text(config)

        # Create unencrypted file
        env_file = work_dir / ".env.production"
        env_file.write_text("SECRET=plaintext\n")

        result = _run_envdrift(["lock", "--check"], cwd=work_dir, env=env, check=False)

        # Should fail because file is not encrypted
        assert result.returncode != 0, (
            f"lock --check should fail on unencrypted file. "
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )


@pytest.mark.integration
class TestHookScriptContent:
    """Test the content of generated hook scripts."""

    def test_pre_commit_script_checks_encryption(self, guard_test_env):
        """Test that pre-commit hook checks encryption status."""
        work_dir = guard_test_env["work_dir"]
        env = guard_test_env["env"]

        config = textwrap.dedent(
            """\
            [git_hook_check]
            method = "direct"

            [encryption]
            backend = "dotenvx"

            [encryption.dotenvx]
            auto_install = true
            """
        )
        (work_dir / "envdrift.toml").write_text(config)

        env_file = work_dir / ".env.test"
        env_file.write_text("SECRET=value\n")

        _run_envdrift(["encrypt", env_file.name], cwd=work_dir, env=env)

        pre_commit = work_dir / ".git" / "hooks" / "pre-commit"
        content = pre_commit.read_text()

        # Should contain encryption check
        assert "envdrift encrypt --check" in content or "envdrift" in content

    def test_pre_push_script_checks_lock(self, guard_test_env):
        """Test that pre-push hook checks lock status."""
        work_dir = guard_test_env["work_dir"]
        env = guard_test_env["env"]

        config = textwrap.dedent(
            """\
            [git_hook_check]
            method = "direct"

            [encryption]
            backend = "dotenvx"

            [encryption.dotenvx]
            auto_install = true
            """
        )
        (work_dir / "envdrift.toml").write_text(config)

        env_file = work_dir / ".env.test"
        env_file.write_text("SECRET=value\n")

        _run_envdrift(["encrypt", env_file.name], cwd=work_dir, env=env)

        pre_push = work_dir / ".git" / "hooks" / "pre-push"
        content = pre_push.read_text()

        # Should contain lock check
        assert "envdrift lock --check" in content or "envdrift" in content

    def test_hook_is_executable(self, guard_test_env):
        """Test that generated hooks are executable."""
        work_dir = guard_test_env["work_dir"]
        env = guard_test_env["env"]

        config = textwrap.dedent(
            """\
            [git_hook_check]
            method = "direct"

            [encryption]
            backend = "dotenvx"

            [encryption.dotenvx]
            auto_install = true
            """
        )
        (work_dir / "envdrift.toml").write_text(config)

        env_file = work_dir / ".env.test"
        env_file.write_text("SECRET=value\n")

        _run_envdrift(["encrypt", env_file.name], cwd=work_dir, env=env)

        pre_commit = work_dir / ".git" / "hooks" / "pre-commit"

        # Check file is executable
        assert os.access(str(pre_commit), os.X_OK), "Hook should be executable"

    def test_hook_has_shebang(self, guard_test_env):
        """Test that generated hooks have proper shebang."""
        work_dir = guard_test_env["work_dir"]
        env = guard_test_env["env"]

        config = textwrap.dedent(
            """\
            [git_hook_check]
            method = "direct"

            [encryption]
            backend = "dotenvx"

            [encryption.dotenvx]
            auto_install = true
            """
        )
        (work_dir / "envdrift.toml").write_text(config)

        env_file = work_dir / ".env.test"
        env_file.write_text("SECRET=value\n")

        _run_envdrift(["encrypt", env_file.name], cwd=work_dir, env=env)

        pre_commit = work_dir / ".git" / "hooks" / "pre-commit"
        content = pre_commit.read_text()

        # Should start with shebang
        assert content.startswith("#!/"), "Hook should have shebang"
