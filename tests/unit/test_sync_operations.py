"""Tests for sync file operations."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from envdrift.sync.operations import (
    DOTENVX_HEADER,
    EnvKeysFile,
    atomic_write,
    preview_value,
)


class TestEnvKeysFile:
    """Tests for .env.keys file operations."""

    def test_exists_true_when_file_exists(self, tmp_path: Path) -> None:
        """Test exists() returns True when file exists."""
        env_keys = tmp_path / ".env.keys"
        env_keys.write_text("DOTENV_PRIVATE_KEY_PRODUCTION=abc123")

        file = EnvKeysFile(env_keys)

        assert file.exists() is True

    def test_exists_false_when_file_missing(self, tmp_path: Path) -> None:
        """Test exists() returns False when file missing."""
        env_keys = tmp_path / ".env.keys"

        file = EnvKeysFile(env_keys)

        assert file.exists() is False

    def test_read_key_existing(self, tmp_path: Path) -> None:
        """Test reading existing key from file."""
        env_keys = tmp_path / ".env.keys"
        env_keys.write_text(
            "# Comment\n"
            "DOTENV_PRIVATE_KEY_PRODUCTION=abc123\n"
            "DOTENV_PRIVATE_KEY_STAGING=def456\n"
        )

        file = EnvKeysFile(env_keys)

        assert file.read_key("DOTENV_PRIVATE_KEY_PRODUCTION") == "abc123"
        assert file.read_key("DOTENV_PRIVATE_KEY_STAGING") == "def456"

    def test_read_key_missing(self, tmp_path: Path) -> None:
        """Test reading missing key returns None."""
        env_keys = tmp_path / ".env.keys"
        env_keys.write_text("DOTENV_PRIVATE_KEY_PRODUCTION=abc123\n")

        file = EnvKeysFile(env_keys)

        assert file.read_key("DOTENV_PRIVATE_KEY_STAGING") is None

    def test_read_key_file_not_exists(self, tmp_path: Path) -> None:
        """Test reading from non-existent file returns None."""
        env_keys = tmp_path / ".env.keys"

        file = EnvKeysFile(env_keys)

        assert file.read_key("DOTENV_PRIVATE_KEY_PRODUCTION") is None

    def test_read_key_with_quotes(self, tmp_path: Path) -> None:
        """Test reading key with quoted value."""
        env_keys = tmp_path / ".env.keys"
        env_keys.write_text('DOTENV_PRIVATE_KEY_PRODUCTION="abc123"\n')

        file = EnvKeysFile(env_keys)

        assert file.read_key("DOTENV_PRIVATE_KEY_PRODUCTION") == "abc123"

    def test_read_key_with_single_quotes(self, tmp_path: Path) -> None:
        """Test reading key with single-quoted value."""
        env_keys = tmp_path / ".env.keys"
        env_keys.write_text("DOTENV_PRIVATE_KEY_PRODUCTION='abc123'\n")

        file = EnvKeysFile(env_keys)

        assert file.read_key("DOTENV_PRIVATE_KEY_PRODUCTION") == "abc123"

    def test_write_key_new_file(self, tmp_path: Path) -> None:
        """Test writing key to new file creates header."""
        env_keys = tmp_path / ".env.keys"

        file = EnvKeysFile(env_keys)
        file.write_key("DOTENV_PRIVATE_KEY_PRODUCTION", "abc123")

        content = env_keys.read_text()
        assert "DOTENV_PRIVATE_KEYS" in content
        assert "DOTENV_PRIVATE_KEY_PRODUCTION=abc123" in content
        assert "# .env.production" in content

    def test_write_key_preserves_header(self, tmp_path: Path) -> None:
        """Test writing key preserves existing header."""
        env_keys = tmp_path / ".env.keys"
        env_keys.write_text(f"{DOTENVX_HEADER}\nDOTENV_PRIVATE_KEY_STAGING=old\n")

        file = EnvKeysFile(env_keys)
        file.write_key("DOTENV_PRIVATE_KEY_PRODUCTION", "abc123")

        content = env_keys.read_text()
        assert "DOTENV_PRIVATE_KEYS" in content
        assert "DOTENV_PRIVATE_KEY_STAGING=old" in content
        assert "DOTENV_PRIVATE_KEY_PRODUCTION=abc123" in content

    def test_write_key_updates_existing(self, tmp_path: Path) -> None:
        """Test updating existing key."""
        env_keys = tmp_path / ".env.keys"
        env_keys.write_text("DOTENV_PRIVATE_KEY_PRODUCTION=old_value\n")

        file = EnvKeysFile(env_keys)
        file.write_key("DOTENV_PRIVATE_KEY_PRODUCTION", "new_value")

        content = env_keys.read_text()
        assert "DOTENV_PRIVATE_KEY_PRODUCTION=new_value" in content
        assert "old_value" not in content

    def test_write_key_different_environment(self, tmp_path: Path) -> None:
        """Test writing key with different environment."""
        env_keys = tmp_path / ".env.keys"

        file = EnvKeysFile(env_keys)
        file.write_key("DOTENV_PRIVATE_KEY_STAGING", "abc123", environment="staging")

        content = env_keys.read_text()
        assert "# .env.staging" in content
        assert "DOTENV_PRIVATE_KEY_STAGING=abc123" in content

    def test_has_dotenvx_header_true(self, tmp_path: Path) -> None:
        """Test has_dotenvx_header returns True when header present."""
        env_keys = tmp_path / ".env.keys"
        env_keys.write_text(f"{DOTENVX_HEADER}\nKEY=value\n")

        file = EnvKeysFile(env_keys)

        assert file.has_dotenvx_header() is True

    def test_has_dotenvx_header_false(self, tmp_path: Path) -> None:
        """Test has_dotenvx_header returns False when no header."""
        env_keys = tmp_path / ".env.keys"
        env_keys.write_text("KEY=value\n")

        file = EnvKeysFile(env_keys)

        assert file.has_dotenvx_header() is False

    def test_create_backup(self, tmp_path: Path) -> None:
        """Test creating backup file."""
        env_keys = tmp_path / ".env.keys"
        env_keys.write_text("ORIGINAL_CONTENT")

        file = EnvKeysFile(env_keys)
        backup_path = file.create_backup()

        assert backup_path.exists()
        assert backup_path.read_text() == "ORIGINAL_CONTENT"
        assert ".backup." in str(backup_path)

    def test_create_backup_file_not_exists(self, tmp_path: Path) -> None:
        """Test creating backup raises error when file doesn't exist."""
        env_keys = tmp_path / ".env.keys"

        file = EnvKeysFile(env_keys)

        with pytest.raises(FileNotFoundError):
            file.create_backup()


class TestAtomicWrite:
    """Tests for atomic file writing."""

    def test_atomic_write_creates_file(self, tmp_path: Path) -> None:
        """Test atomic_write creates file."""
        file_path = tmp_path / "test.txt"

        atomic_write(file_path, "Hello, World!")

        assert file_path.exists()
        assert file_path.read_text() == "Hello, World!"

    def test_atomic_write_sets_permissions(self, tmp_path: Path) -> None:
        """Test atomic_write sets file permissions."""
        file_path = tmp_path / "test.txt"

        atomic_write(file_path, "Secret content", permissions=0o600)

        # Check permissions (on Unix systems)
        if os.name != "nt":  # Skip on Windows
            stat = file_path.stat()
            assert stat.st_mode & 0o777 == 0o600

    def test_atomic_write_creates_parent_dirs(self, tmp_path: Path) -> None:
        """Test atomic_write creates parent directories."""
        file_path = tmp_path / "nested" / "dirs" / "test.txt"

        atomic_write(file_path, "Content")

        assert file_path.exists()

    def test_atomic_write_overwrites_existing(self, tmp_path: Path) -> None:
        """Test atomic_write overwrites existing file."""
        file_path = tmp_path / "test.txt"
        file_path.write_text("Old content")

        atomic_write(file_path, "New content")

        assert file_path.read_text() == "New content"


class TestPreviewValue:
    """Tests for preview_value function."""

    def test_short_value_unchanged(self) -> None:
        """Test short value is returned unchanged."""
        result = preview_value("short", length=32)
        assert result == "short"

    def test_long_value_truncated(self) -> None:
        """Test long value is truncated with ellipsis."""
        long_value = "a" * 50
        result = preview_value(long_value, length=32)
        assert result == "a" * 32 + "..."

    def test_exact_length_unchanged(self) -> None:
        """Test value of exact length is unchanged."""
        value = "a" * 32
        result = preview_value(value, length=32)
        assert result == value

    def test_custom_length(self) -> None:
        """Test custom preview length."""
        result = preview_value("abcdefghij", length=5)
        assert result == "abcde..."
