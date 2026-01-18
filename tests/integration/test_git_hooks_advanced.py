"""Advanced integration tests for git hook functionality.

Tests Category H: Git Integration
- test_hook_blocks_unencrypted_commit (P0)
- test_hook_allows_encrypted_commit (P0)
- test_hook_pre_push_lock_check (P1)
- test_smart_encrypt_dirty_workdir (P1)
- test_smart_encrypt_no_git_repo (P2)
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
    # Clear git-specific env vars to avoid interference
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
def git_hook_env(tmp_path):
    """Create a test environment with git repo and envdrift config."""
    work_dir = tmp_path / "test_repo"
    work_dir.mkdir()
    _init_git_repo(work_dir)

    env = os.environ.copy()
    env["PYTHONPATH"] = f"{PYTHONPATH}{os.pathsep}{env.get('PYTHONPATH', '')}"

    return {"work_dir": work_dir, "env": env}


@pytest.mark.integration
def test_hook_blocks_unencrypted_commit(git_hook_env):
    """Test that pre-commit hook blocks commits with unencrypted secrets.

    Creates a .env file with plaintext secrets, installs git hooks,
    and verifies that attempting to commit fails with appropriate error.
    """
    work_dir = git_hook_env["work_dir"]
    env = git_hook_env["env"]

    # Create envdrift config with direct git hooks
    config = textwrap.dedent(
        """\
        [git_hook_check]
        method = "direct git hook"

        [encryption]
        backend = "dotenvx"

        [encryption.dotenvx]
        auto_install = true
        """
    )
    (work_dir / "envdrift.toml").write_text(config)

    # Create a plaintext .env file
    env_file = work_dir / ".env.production"
    env_file.write_text("API_KEY=supersecret123\nDB_PASSWORD=hunter2\n")

    # Install hooks by running encrypt --check (which auto-installs hooks)
    _run_envdrift(["encrypt", "--check", env_file.name], cwd=work_dir, env=env, check=False)

    # Verify hooks were installed
    pre_commit = work_dir / ".git" / "hooks" / "pre-commit"
    assert pre_commit.exists(), "pre-commit hook should be installed"
    assert "envdrift encrypt --check" in pre_commit.read_text()

    # Stage the plaintext file
    _run_git(["add", env_file.name], cwd=work_dir)

    # Attempt to commit - should fail
    result = _run_git(
        ["commit", "-m", "Add unencrypted secrets"],
        cwd=work_dir,
        check=False,
    )

    assert result.returncode != 0, "Commit should be blocked by pre-commit hook"
    assert (
        "encryption check failed" in result.stderr or "encryption check failed" in result.stdout
    ), "Error message should mention encryption check failure"


@pytest.mark.integration
def test_hook_allows_encrypted_commit(git_hook_env):
    """Test that pre-commit hook allows commits with encrypted files.

    Creates a .env file, encrypts it, installs hooks, and verifies
    that committing the encrypted file succeeds.
    """
    work_dir = git_hook_env["work_dir"]
    env = git_hook_env["env"]

    # Create envdrift config
    config = textwrap.dedent(
        """\
        [git_hook_check]
        method = "direct git hook"

        [encryption]
        backend = "dotenvx"

        [encryption.dotenvx]
        auto_install = true
        """
    )
    (work_dir / "envdrift.toml").write_text(config)

    # Create and encrypt a .env file
    env_file = work_dir / ".env.production"
    env_file.write_text("API_KEY=supersecret123\nDB_PASSWORD=hunter2\n")

    # Encrypt the file
    _run_envdrift(["encrypt", env_file.name], cwd=work_dir, env=env)

    # Verify file is encrypted
    content = env_file.read_text()
    assert "encrypted:" in content.lower(), "File should be encrypted"

    # Verify hooks were installed
    pre_commit = work_dir / ".git" / "hooks" / "pre-commit"
    assert pre_commit.exists(), "pre-commit hook should be installed"

    # Stage the encrypted file
    _run_git(["add", env_file.name], cwd=work_dir)

    # Also stage the config file for a complete commit
    _run_git(["add", "envdrift.toml"], cwd=work_dir)

    # Commit should succeed
    result = _run_git(
        ["commit", "-m", "Add encrypted secrets"],
        cwd=work_dir,
        check=False,
    )

    assert result.returncode == 0, f"Commit should succeed. stderr: {result.stderr}"


@pytest.mark.integration
def test_hook_pre_push_lock_check(git_hook_env):
    """Test that pre-push hook verifies lock --check passes.

    This test creates a scenario where some files are not encrypted,
    and verifies that the pre-push hook blocks the push.
    """
    work_dir = git_hook_env["work_dir"]
    env = git_hook_env["env"]

    # Create envdrift config
    config = textwrap.dedent(
        """\
        [git_hook_check]
        method = "direct git hook"

        [encryption]
        backend = "dotenvx"

        [encryption.dotenvx]
        auto_install = true

        [vault.sync]
        [[vault.sync.mappings]]
        folder_path = "."
        environment = "production"
        secret_name = "test/dotenv-key"
        """
    )
    (work_dir / "envdrift.toml").write_text(config)

    # Create and encrypt a .env file to install hooks
    env_file = work_dir / ".env.production"
    env_file.write_text("API_KEY=supersecret123\n")
    _run_envdrift(["encrypt", env_file.name], cwd=work_dir, env=env)

    # Verify pre-push hook was installed
    pre_push = work_dir / ".git" / "hooks" / "pre-push"
    assert pre_push.exists(), "pre-push hook should be installed"
    assert "envdrift lock --check" in pre_push.read_text()

    # Commit the encrypted file
    _run_git(["add", env_file.name, "envdrift.toml"], cwd=work_dir)
    _run_git(["commit", "-m", "Initial commit"], cwd=work_dir)

    # Now decrypt the file to create a "lock check" failure scenario
    _run_envdrift(["decrypt", env_file.name], cwd=work_dir, env=env)

    # Verify file is decrypted
    content = env_file.read_text()
    assert "encrypted:" not in content.lower(), "File should be decrypted"

    # Stage and commit the decrypted file (pre-commit passes because we bypass it)
    _run_git(["add", env_file.name], cwd=work_dir)
    _run_git(["commit", "-m", "Decrypted file", "--no-verify"], cwd=work_dir)

    # Set up a fake remote
    remote_dir = work_dir.parent / "remote.git"
    remote_dir.mkdir()
    _run_git(["init", "--bare"], cwd=remote_dir)
    _run_git(["remote", "add", "origin", str(remote_dir)], cwd=work_dir)

    # Get current branch name (handles both "master" and "main" defaults)
    branch_result = _run_git(["branch", "--show-current"], cwd=work_dir)
    current_branch = branch_result.stdout.strip()

    # Try to push - should fail due to lock --check
    result = _run_git(
        ["push", "origin", current_branch],
        cwd=work_dir,
        check=False,
    )

    assert result.returncode != 0, "Push should be blocked by pre-push hook"
    assert "lock --check failed" in result.stderr or "lock --check failed" in result.stdout, (
        "Error message should mention lock check failure"
    )


@pytest.mark.integration
def test_smart_encrypt_dirty_workdir(git_hook_env):
    """Test smart encryption behavior with uncommitted changes in working directory.

    Smart encryption should skip re-encryption if the file content hasn't changed,
    even when there are other uncommitted changes in the working directory.
    """
    work_dir = git_hook_env["work_dir"]
    env = git_hook_env["env"]

    # Create envdrift config with smart_encryption enabled
    config = textwrap.dedent(
        """\
        [encryption]
        backend = "dotenvx"
        smart_encryption = true

        [encryption.dotenvx]
        auto_install = true
        """
    )
    (work_dir / "envdrift.toml").write_text(config)

    # Create and encrypt a .env file
    env_file = work_dir / ".env.production"
    env_file.write_text("API_KEY=supersecret123\n")
    _run_envdrift(["encrypt", env_file.name], cwd=work_dir, env=env)

    # Commit the encrypted file
    _run_git(["add", "-A"], cwd=work_dir)
    _run_git(["commit", "-m", "Initial encrypted file"], cwd=work_dir)

    # Decrypt and re-encrypt without changing content
    _run_envdrift(["decrypt", env_file.name], cwd=work_dir, env=env)

    # Create another unrelated file to make working directory dirty
    (work_dir / "README.md").write_text("# Test Project\n")

    # Re-encrypt - should use smart encryption and skip re-encryption
    result = _run_envdrift(["encrypt", env_file.name], cwd=work_dir, env=env)

    # Smart encryption should skip re-encryption
    assert "Skipped re-encryption" in result.stdout or "Skipped re-encryption" in result.stderr, (
        "Smart encryption should skip re-encryption when content unchanged"
    )


@pytest.mark.integration
def test_smart_encrypt_no_git_repo(tmp_path):
    """Test that smart encryption gracefully handles non-git directories.

    When running outside a git repository, smart encryption should
    fall back to normal encryption behavior without errors.
    """
    work_dir = tmp_path / "no_git"
    work_dir.mkdir()

    env = os.environ.copy()
    env["PYTHONPATH"] = f"{PYTHONPATH}{os.pathsep}{env.get('PYTHONPATH', '')}"

    # Create envdrift config with smart_encryption enabled (no git repo)
    config = textwrap.dedent(
        """\
        [encryption]
        backend = "dotenvx"
        smart_encryption = true

        [encryption.dotenvx]
        auto_install = true
        """
    )
    (work_dir / "envdrift.toml").write_text(config)

    # Create and encrypt a .env file
    env_file = work_dir / ".env.production"
    env_file.write_text("API_KEY=supersecret123\n")

    # Encrypt should work even without git
    result = _run_envdrift(["encrypt", env_file.name], cwd=work_dir, env=env)

    assert result.returncode == 0, "Encryption should succeed outside git repo"

    # Verify file is encrypted
    content = env_file.read_text()
    assert "encrypted:" in content.lower(), "File should be encrypted"

    # Decrypt and re-encrypt to test smart encryption behavior
    _run_envdrift(["decrypt", env_file.name], cwd=work_dir, env=env)

    # Re-encrypt - without git, it should always re-encrypt (no smart skip)
    result = _run_envdrift(["encrypt", env_file.name], cwd=work_dir, env=env)

    assert result.returncode == 0, "Re-encryption should succeed"
    # Outside git repo, smart encryption can't determine if content changed,
    # so it performs encryption normally
    content = env_file.read_text()
    assert "encrypted:" in content.lower(), "File should be re-encrypted"


@pytest.mark.integration
def test_hook_blocks_env_keys_commit(git_hook_env):
    """Test that pre-commit hook blocks commits containing .env.keys files.

    The .env.keys file contains private keys and should never be committed.
    """
    work_dir = git_hook_env["work_dir"]
    env = git_hook_env["env"]

    # Create envdrift config
    config = textwrap.dedent(
        """\
        [git_hook_check]
        method = "direct git hook"

        [encryption]
        backend = "dotenvx"

        [encryption.dotenvx]
        auto_install = true
        """
    )
    (work_dir / "envdrift.toml").write_text(config)

    # Create and encrypt a .env file (this installs hooks)
    env_file = work_dir / ".env.production"
    env_file.write_text("API_KEY=secret\n")
    _run_envdrift(["encrypt", env_file.name], cwd=work_dir, env=env)

    # Verify hooks were installed
    pre_commit = work_dir / ".git" / "hooks" / "pre-commit"
    assert pre_commit.exists()

    # Stage .env.keys file
    env_keys = work_dir / ".env.keys"
    assert env_keys.exists(), ".env.keys should be created by encryption"
    _run_git(["add", env_keys.name], cwd=work_dir)

    # Attempt to commit - should fail
    result = _run_git(
        ["commit", "-m", "Add keys (should fail)"],
        cwd=work_dir,
        check=False,
    )

    assert result.returncode != 0, "Commit should be blocked"
    assert (
        "refusing to commit .env.keys" in result.stderr
        or "refusing to commit .env.keys" in result.stdout
    ), "Error should mention .env.keys"
