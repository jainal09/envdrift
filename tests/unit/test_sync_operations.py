"""Tests for sync file operations."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from envdrift.sync.operations import (
    DOTENVX_HEADER,
    EnvKeysFile,
    atomic_write,
    redact_value,
)


def _fake_private_key(seed: str) -> str:
    """Build a 64-hex value shaped like a DOTENV_PRIVATE_KEY_* secret.

    Constructed by repetition so the literal never appears as one token in
    source, and so callers can vary ``seed`` to get distinct secrets.
    """
    return (seed * 64)[:64]


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
            "# Comment\nDOTENV_PRIVATE_KEY_PRODUCTION=abc123\nDOTENV_PRIVATE_KEY_STAGING=def456\n"
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

    @pytest.mark.skipif(os.name == "nt", reason="symlink/fchmod semantics differ on non-POSIX")
    def test_atomic_write_does_not_follow_predictable_tmp_symlink(self, tmp_path: Path) -> None:
        """A pre-planted symlink at the predictable temp name is not written through.

        The old implementation wrote to ``path.with_suffix('.tmp')`` with
        ``write_text``, which follows a symlink and clobbers its target. An
        attacker who can create ``<dest>.tmp`` (or ``.env.tmp`` for ``.env.keys``)
        as a symlink to a file they don't own could redirect the secret write.
        """
        dest = tmp_path / ".env.keys"

        outside = tmp_path / "outside_target"
        outside.write_text("ORIGINAL_OUTSIDE")

        # Plant symlinks at every predictable sibling the old code could pick.
        for predictable in (dest.with_suffix(".tmp"), Path(str(dest) + ".tmp")):
            if not predictable.exists():
                predictable.symlink_to(outside)

        atomic_write(dest, "SECRET_DEST_CONTENT")

        # The real destination got the content; the outside target is untouched.
        assert dest.read_text() == "SECRET_DEST_CONTENT"
        assert outside.read_text() == "ORIGINAL_OUTSIDE"
        # The destination is a real file, not a symlink to the outside file.
        assert not dest.is_symlink()

    @pytest.mark.skipif(os.name == "nt", reason="symlink/fchmod semantics differ on non-POSIX")
    def test_atomic_write_does_not_use_literal_predictable_tmp_name(self, tmp_path: Path) -> None:
        """The temp file used is not the literal ``path.with_suffix('.tmp')``.

        We block ``os.replace`` from completing so the temp file is left behind,
        then assert the leftover is an unguessable ``mkstemp`` name rather than
        the predictable sibling the vulnerable code used.
        """
        dest = tmp_path / "secret.txt"
        predictable = dest.with_suffix(".tmp")

        # Make os.replace fail so the temp file is not consumed/renamed away.
        original_replace = os.replace

        def boom(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> None:
            raise OSError("blocked replace for test")

        os.replace = boom  # type: ignore[assignment]
        try:
            with pytest.raises(OSError, match="blocked replace"):
                atomic_write(dest, "data")
        finally:
            os.replace = original_replace  # type: ignore[assignment]

        # The vulnerable predictable name must never have been created...
        assert not predictable.exists()
        # ...and atomic_write cleans up its own (unguessable) temp file on failure.
        leftovers = [
            p
            for p in tmp_path.iterdir()
            if p.name.startswith(".secret.txt.") and p.name.endswith(".envdrift-tmp")
        ]
        assert leftovers == []

    @pytest.mark.skipif(os.name == "nt", reason="symlink/fchmod semantics differ on non-POSIX")
    def test_atomic_write_chmod_targets_destination_not_symlink(self, tmp_path: Path) -> None:
        """chmod is applied to the file we create, not a followed symlink target."""
        dest = tmp_path / "new_secret.txt"

        outside = tmp_path / "victim"
        outside.write_text("victim content")
        outside.chmod(0o644)

        # Plant a symlink at the predictable temp name pointing at the victim.
        dest.with_suffix(".tmp").symlink_to(outside)

        atomic_write(dest, "secret", permissions=0o600)

        # Destination has the tight mode; the victim's mode is unchanged.
        assert dest.stat().st_mode & 0o777 == 0o600
        assert outside.stat().st_mode & 0o777 == 0o644
        assert outside.read_text() == "victim content"

    @pytest.mark.skipif(os.name == "nt", reason="POSIX mode semantics")
    def test_atomic_write_preserves_existing_destination_mode(self, tmp_path: Path) -> None:
        """Overwriting an existing file preserves its current mode (no force 0o600)."""
        dest = tmp_path / "existing.txt"
        dest.write_text("old")
        dest.chmod(0o640)

        atomic_write(dest, "new", permissions=0o600)

        assert dest.read_text() == "new"
        assert dest.stat().st_mode & 0o777 == 0o640


class TestRedactValue:
    """Tests for redact_value -- the non-reversible secret discriminator."""

    def test_none_passes_through(self) -> None:
        """None stays None (no preview for a missing value)."""
        assert redact_value(None) is None

    def test_empty_string_marked_empty(self) -> None:
        """Empty string renders as a distinct marker, never as plaintext."""
        assert redact_value("") == "<empty>"

    def test_redacted_shape_carries_length(self) -> None:
        """Output is the redacted discriminator with the real length."""
        secret = _fake_private_key("ab")
        out = redact_value(secret)
        assert out is not None
        assert out.startswith("<redacted len=64 sha=")
        assert out.endswith(">")

    def test_no_substring_of_secret_leaks(self) -> None:
        """No >=8-char window of a 64-hex secret appears in the output.

        This is the core no-leak property: the previous truncating preview
        printed the first 32 hex chars verbatim (half the private key).
        """
        secret = _fake_private_key("ab")
        out = redact_value(secret)
        assert out is not None
        for i in range(len(secret) - 7):
            assert secret[i : i + 8] not in out

    def test_different_values_produce_different_output(self) -> None:
        """Distinct secrets must still yield a visible mismatch signal."""
        a = _fake_private_key("ab")
        b = _fake_private_key("cd")
        assert a != b
        assert redact_value(a) != redact_value(b)

    def test_same_value_produces_identical_output(self) -> None:
        """Equal values produce identical output (within a single run)."""
        secret = _fake_private_key("ab")
        assert redact_value(secret) == redact_value(secret)

    def test_same_length_different_value_still_differs(self) -> None:
        """Length collisions alone do not mask a value difference."""
        a = "a" * 40
        b = "b" * 40
        out_a = redact_value(a)
        out_b = redact_value(b)
        assert out_a is not None and out_b is not None
        assert "len=40" in out_a and "len=40" in out_b
        assert out_a != out_b
