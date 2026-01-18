"""Tests for the should_skip_reencryption helper function."""

from __future__ import annotations

import subprocess  # nosec B404
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from envdrift.cli_commands.encryption_helpers import should_skip_reencryption


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
