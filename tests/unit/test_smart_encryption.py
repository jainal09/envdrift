"""Tests for the should_skip_reencryption helper function."""

from __future__ import annotations

import shutil
import subprocess  # nosec B404
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from envdrift.cli_commands.encryption_helpers import should_skip_reencryption
from envdrift.utils.git import without_git_location


class TestShouldSkipReencryption:
    """Tests for should_skip_reencryption function."""

    def test_returns_false_when_disabled(self, tmp_path: Path):
        """Should return False when smart encryption is disabled."""
        mock_backend = MagicMock()
        mock_backend.name = "dotenvx"

        env_file = tmp_path / ".env.production"
        env_file.write_text("SECRET=value")

        should_skip, reason = should_skip_reencryption(env_file, mock_backend, enabled=False)

        assert should_skip is False
        assert "disabled" in reason

    def test_returns_false_for_unsupported_backend(self, tmp_path: Path):
        """Should return False for unsupported backends."""
        mock_backend = MagicMock()
        mock_backend.name = "unsupported_backend"

        env_file = tmp_path / ".env.production"
        env_file.write_text("SECRET=value")

        should_skip, reason = should_skip_reencryption(env_file, mock_backend, enabled=True)

        assert should_skip is False
        assert "not supported" in reason

    def test_returns_false_for_untracked_file(self, tmp_path: Path):
        """Should return False for files not tracked in git."""
        mock_backend = MagicMock()
        mock_backend.name = "dotenvx"

        env_file = tmp_path / ".env.production"
        env_file.write_text("SECRET=value")

        should_skip, reason = should_skip_reencryption(env_file, mock_backend, enabled=True)

        assert should_skip is False
        assert "not tracked" in reason

    def test_returns_false_when_git_version_not_encrypted(self, tmp_path: Path):
        """Should return False when the git version is not encrypted."""
        # Setup git repo
        subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True, check=True)
        subprocess.run(
            ["git", "config", "user.email", "test@test.com"],
            cwd=tmp_path,
            capture_output=True,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Test"], cwd=tmp_path, capture_output=True, check=True
        )

        env_file = tmp_path / ".env.production"
        env_file.write_text("SECRET=plaintext_value")  # Not encrypted
        subprocess.run(
            ["git", "add", ".env.production"], cwd=tmp_path, capture_output=True, check=True
        )
        subprocess.run(
            ["git", "commit", "-m", "initial"], cwd=tmp_path, capture_output=True, check=True
        )

        mock_backend = MagicMock()
        mock_backend.name = "dotenvx"

        should_skip, reason = should_skip_reencryption(env_file, mock_backend, enabled=True)

        assert should_skip is False
        assert "not encrypted" in reason

    def test_returns_true_when_content_unchanged(self, tmp_path: Path):
        """Should return True and restore from git when content is unchanged."""
        # Setup git repo
        subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True, check=True)
        subprocess.run(
            ["git", "config", "user.email", "test@test.com"],
            cwd=tmp_path,
            capture_output=True,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Test"], cwd=tmp_path, capture_output=True, check=True
        )

        # Commit encrypted version
        env_file = tmp_path / ".env.production"
        encrypted_content = 'SECRET="encrypted:abc123xyz"'
        env_file.write_text(encrypted_content)
        subprocess.run(
            ["git", "add", ".env.production"], cwd=tmp_path, capture_output=True, check=True
        )
        subprocess.run(
            ["git", "commit", "-m", "initial"], cwd=tmp_path, capture_output=True, check=True
        )

        # Simulate decrypted file (same as what would be decrypted from git)
        decrypted_content = "SECRET=actual_secret_value"
        env_file.write_text(decrypted_content)

        # Mock the backend
        mock_backend = MagicMock()
        mock_backend.name = "dotenvx"

        # Mock decrypt to return the same content as the current file
        def mock_decrypt(path):
            path.write_text(decrypted_content)
            return SimpleNamespace(success=True, message="")

        mock_backend.decrypt = mock_decrypt

        should_skip, reason = should_skip_reencryption(env_file, mock_backend, enabled=True)

        assert should_skip is True
        assert "content unchanged" in reason
        # File should be restored to encrypted version
        assert env_file.read_text() == encrypted_content

    def test_returns_false_when_content_changed(self, tmp_path: Path):
        """Should return False when content has changed."""
        # Setup git repo
        subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True, check=True)
        subprocess.run(
            ["git", "config", "user.email", "test@test.com"],
            cwd=tmp_path,
            capture_output=True,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Test"], cwd=tmp_path, capture_output=True, check=True
        )

        # Commit encrypted version
        env_file = tmp_path / ".env.production"
        encrypted_content = 'SECRET="encrypted:abc123xyz"'
        env_file.write_text(encrypted_content)
        subprocess.run(
            ["git", "add", ".env.production"], cwd=tmp_path, capture_output=True, check=True
        )
        subprocess.run(
            ["git", "commit", "-m", "initial"], cwd=tmp_path, capture_output=True, check=True
        )

        # Simulate decrypted file with DIFFERENT content
        current_content = "SECRET=new_secret_value\nNEW_VAR=added"
        env_file.write_text(current_content)

        # Mock the backend
        mock_backend = MagicMock()
        mock_backend.name = "dotenvx"

        # Mock decrypt to return different content (the old value)
        def mock_decrypt(path):
            path.write_text("SECRET=old_secret_value")
            return SimpleNamespace(success=True, message="")

        mock_backend.decrypt = mock_decrypt

        should_skip, reason = should_skip_reencryption(env_file, mock_backend, enabled=True)

        assert should_skip is False
        assert "content has changed" in reason

    def test_returns_false_when_decrypt_fails(self, tmp_path: Path):
        """Should return False when decryption of git version fails."""
        # Setup git repo
        subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True, check=True)
        subprocess.run(
            ["git", "config", "user.email", "test@test.com"],
            cwd=tmp_path,
            capture_output=True,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Test"], cwd=tmp_path, capture_output=True, check=True
        )

        # Commit encrypted version
        env_file = tmp_path / ".env.production"
        encrypted_content = 'SECRET="encrypted:abc123xyz"'
        env_file.write_text(encrypted_content)
        subprocess.run(
            ["git", "add", ".env.production"], cwd=tmp_path, capture_output=True, check=True
        )
        subprocess.run(
            ["git", "commit", "-m", "initial"], cwd=tmp_path, capture_output=True, check=True
        )

        # Simulate decrypted file
        env_file.write_text("SECRET=value")

        # Mock the backend
        mock_backend = MagicMock()
        mock_backend.name = "dotenvx"

        # Mock decrypt to fail
        mock_backend.decrypt.return_value = SimpleNamespace(success=False, message="Bad key")

        should_skip, reason = should_skip_reencryption(env_file, mock_backend, enabled=True)

        assert should_skip is False
        assert "could not decrypt" in reason

    def test_returns_false_when_restore_fails(self, tmp_path: Path):
        """Should return False if restoring fails despite content match."""
        # Setup git repo
        subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True, check=True)
        subprocess.run(
            ["git", "config", "user.email", "test@test.com"],
            cwd=tmp_path,
            capture_output=True,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Test"], cwd=tmp_path, capture_output=True, check=True
        )

        env_file = tmp_path / ".env.production"
        encrypted_content = 'SECRET="encrypted:abc123xyz"'
        env_file.write_text(encrypted_content)
        subprocess.run(
            ["git", "add", ".env.production"], cwd=tmp_path, capture_output=True, check=True
        )
        subprocess.run(
            ["git", "commit", "-m", "initial"], cwd=tmp_path, capture_output=True, check=True
        )

        decrypted_content = "SECRET=actual_secret_value"
        env_file.write_text(decrypted_content)

        mock_backend = MagicMock()
        mock_backend.name = "dotenvx"

        def mock_decrypt(path):
            path.write_text(decrypted_content)
            return SimpleNamespace(success=True, message="")

        mock_backend.decrypt = mock_decrypt

        # Mock restore failure
        with patch(
            "envdrift.cli_commands.encryption_helpers.restore_file_from_git", return_value=False
        ):
            should_skip, reason = should_skip_reencryption(env_file, mock_backend, enabled=True)

        assert should_skip is False
        assert "failed to restore" in reason

    def test_handles_comparison_exception(self, tmp_path: Path):
        """Should return False if an exception occurs during comparison."""
        # Setup basic file
        env_file = tmp_path / ".env.production"
        env_file.write_text("SECRET=value")

        mock_backend = MagicMock()
        mock_backend.name = "dotenvx"

        # Mock early checks to pass
        with (
            patch("envdrift.cli_commands.encryption_helpers.is_file_tracked", return_value=True),
            patch(
                "envdrift.cli_commands.encryption_helpers.get_file_from_git",
                return_value="encrypted:content",
            ),
        ):
            # Mock backend.decrypt to raise exception
            mock_backend.decrypt.side_effect = Exception("Unexpected error")

            should_skip, reason = should_skip_reencryption(env_file, mock_backend, enabled=True)

        assert should_skip is False
        assert "error comparing content" in reason

    def test_works_with_sops_backend(self, tmp_path: Path):
        """Should also work with SOPS backend."""
        mock_backend = MagicMock()
        mock_backend.name = "sops"
        mock_backend.has_encrypted_header.return_value = False

        env_file = tmp_path / ".env.production"
        env_file.write_text("SECRET=value")

        # Mock to pass early checks but fail on encryption check
        with (
            patch("envdrift.cli_commands.encryption_helpers.is_file_tracked", return_value=True),
            patch(
                "envdrift.cli_commands.encryption_helpers.get_file_from_git",
                return_value="SECRET=plaintext",  # Not encrypted
            ),
        ):
            should_skip, reason = should_skip_reencryption(env_file, mock_backend, enabled=True)

        assert should_skip is False
        assert "not encrypted" in reason


def _git(cwd: Path, *args: str, index: Path | None = None) -> str:
    """Run git in ``cwd``, on the index file ``index`` when one is given."""
    env = without_git_location()
    if index is not None:
        env["GIT_INDEX_FILE"] = str(index)
    config = ["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"]
    return subprocess.run(
        ["git", *config, *args], cwd=cwd, env=env, check=True, capture_output=True, text=True
    ).stdout


class TestSmartEncryptionInAGitHook:
    """A git hook's GIT_INDEX_FILE is the index git is about to commit (#915).

    Smart encryption restores an unchanged file into that index, so the commit holds the
    encrypted version. A file of another repository must never land in it.
    """

    _ENCRYPTED = 'SECRET="encrypted:abc123xyz"'
    _DECRYPTED = "SECRET=actual_secret_value"

    def _decrypted_env_file(self, repo: Path) -> Path:
        """``repo`` as a repository that commits an encrypted ``.env.production``, now decrypted."""
        repo.mkdir()
        _git(repo, "init", "-q")
        env_file = repo / ".env.production"
        env_file.write_text(self._ENCRYPTED)
        _git(repo, "add", ".env.production")
        _git(repo, "commit", "-qm", "init")
        env_file.write_text(self._DECRYPTED)
        return env_file

    def _backend(self) -> MagicMock:
        """A dotenvx backend whose decrypt gives back the decrypted file."""
        backend = MagicMock()
        backend.name = "dotenvx"

        def decrypt(path: Path) -> SimpleNamespace:
            path.write_text(self._DECRYPTED)
            return SimpleNamespace(success=True, message="")

        backend.decrypt = decrypt
        return backend

    def test_restores_the_file_into_the_index_being_committed(self, tmp_path: Path, monkeypatch):
        """``git commit -a`` staged the decrypted file in the hook's index; the restore undoes it."""
        env_file = self._decrypted_env_file(tmp_path / "repo")
        repo = env_file.parent
        index = repo / ".git" / "index.lock"
        shutil.copyfile(repo / ".git" / "index", index)
        _git(repo, "add", ".env.production", index=index)
        monkeypatch.setenv("GIT_INDEX_FILE", str(index))

        should_skip, reason = should_skip_reencryption(env_file, self._backend(), enabled=True)

        assert should_skip is True, reason
        assert env_file.read_text() == self._ENCRYPTED
        committed = _git(repo, "rev-parse", "HEAD:.env.production").strip()
        assert _git(repo, "ls-files", "-s", index=index).split()[1] == committed

    def test_leaves_a_file_of_another_repository_out_of_it(self, tmp_path: Path, monkeypatch):
        """A hook in one repository encrypts a file of another one, a submodule say.

        The hook's variables name another repository, so smart encryption drops them and the
        restore never puts the other repository's file into the hook's index.
        """
        hook_repo = tmp_path / "hook"
        hook_repo.mkdir()
        _git(hook_repo, "init", "-q")
        (hook_repo / "app.txt").write_text("hello\n")
        _git(hook_repo, "add", "app.txt")
        index = hook_repo / ".git" / "index"
        staged = index.read_bytes()
        env_file = self._decrypted_env_file(tmp_path / "other")
        monkeypatch.setenv("GIT_INDEX_FILE", str(index))

        should_skip_reencryption(env_file, self._backend(), enabled=True)

        assert index.read_bytes() == staged

    @pytest.mark.parametrize("hook", ["commit -a", "linked worktree"])
    def test_leaves_it_alone_when_the_hook_repository_tracks_the_same_path(
        self, tmp_path: Path, monkeypatch, hook: str
    ):
        """The file is restored in its own repository, though the hook's tracks the same path (#919).

        is_file_tracked, asking the hook's index, found the hook repository's file there, and the
        restore wrote the other repository's file into that index. In a linked worktree the hook's
        GIT_DIR also made the committed version the hook repository's, so that file was checked
        out over the other repository's.
        """
        env_file = self._decrypted_env_file(tmp_path / "other")
        hook_repo = tmp_path / "hook"
        hook_repo.mkdir()
        _git(hook_repo, "init", "-q")
        hook_file = 'SECRET="encrypted:hook"'
        (hook_repo / ".env.production").write_text(hook_file)
        _git(hook_repo, "add", ".env.production")
        _git(hook_repo, "commit", "-qm", "init")
        if hook == "linked worktree":
            worktree = tmp_path / "worktree"
            _git(hook_repo, "worktree", "add", "-q", str(worktree))
            git_dir = Path((worktree / ".git").read_text().split(":", 1)[1].strip())
            index = git_dir / "index"
            monkeypatch.setenv("GIT_DIR", str(git_dir))
        else:
            index = hook_repo / ".git" / "index.lock"
            shutil.copyfile(hook_repo / ".git" / "index", index)
        staged = index.read_bytes()
        monkeypatch.setenv("GIT_INDEX_FILE", str(index))

        should_skip, reason = should_skip_reencryption(env_file, self._backend(), enabled=True)

        assert env_file.read_text() != hook_file, "the hook repository's file was checked out"
        assert index.read_bytes() == staged, "the restore wrote into the hook's index"
        assert should_skip is True, reason
        assert env_file.read_text() == self._ENCRYPTED

    @pytest.mark.parametrize("in_hook", [False, True], ids=["no hook", "outer repository's hook"])
    def test_restores_a_submodules_file_in_the_submodule(
        self, tmp_path: Path, monkeypatch, in_hook: bool
    ):
        """A file of a real submodule is checked and restored in the submodule's own repository.

        The outer repository tracks the same relative path. In its ``git commit -a`` hook, the
        restore wrote the submodule's file into the outer repository's index (#919).
        """
        other = self._decrypted_env_file(tmp_path / "other").parent
        outer = tmp_path / "outer"
        outer.mkdir()
        _git(outer, "init", "-q")
        (outer / ".env.production").write_text('SECRET="encrypted:outer"')
        _git(outer, "add", ".env.production")
        _git(outer, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(other), "sub")
        _git(outer, "commit", "-qm", "init")
        env_file = outer / "sub" / ".env.production"
        env_file.write_text(self._DECRYPTED)
        index = outer / ".git" / "index.lock"
        shutil.copyfile(outer / ".git" / "index", index)
        staged = index.read_bytes()
        if in_hook:
            monkeypatch.setenv("GIT_INDEX_FILE", str(index))

        should_skip, reason = should_skip_reencryption(env_file, self._backend(), enabled=True)

        assert index.read_bytes() == staged, "the restore wrote into the outer repository's index"
        assert should_skip is True, reason
        assert env_file.read_text() == self._ENCRYPTED
