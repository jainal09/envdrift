"""Tests for sync file operations."""

from __future__ import annotations

import os
import tempfile
from datetime import datetime
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


class TestDotenvxHeaderFormat:
    """#474: the header constant must match what dotenvx itself writes."""

    def test_header_lines_match_dotenvx_box_style(self) -> None:
        """Every header line is a ``#/ ... /`` box line — never ``\\#``.

        envdrift previously wrote header lines ending in ``\\#`` (and dropped
        dotenvx's padding), so a later dotenvx append produced a .env.keys with
        two visibly different header styles despite the ``EnvKeysFile``
        format-preservation contract.
        """
        lines = DOTENVX_HEADER.splitlines()
        assert len(lines) == 4
        for line in lines:
            assert line.startswith("#/"), line
            assert line.endswith("/"), line
            assert "\\" not in line, line
        # dotenvx pads the link line so the box edges align.
        assert lines[2] == "#/     [how it works](https://dotenvx.com/encryption)       /"

    def test_write_key_new_file_blank_line_after_header(self, tmp_path: Path) -> None:
        """A fresh .env.keys reproduces dotenvx's blank line after the header."""
        env_keys = tmp_path / ".env.keys"

        EnvKeysFile(env_keys).write_key("DOTENV_PRIVATE_KEY_PRODUCTION", _fake_private_key("a"))

        lines = env_keys.read_text(encoding="utf-8").splitlines()
        assert lines[:4] == DOTENVX_HEADER.splitlines()
        assert lines[4] == ""
        assert lines[5] == "# .env.production"


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

    def test_read_key_empty_value_returns_empty_string(self, tmp_path: Path) -> None:
        """A present-but-empty key (``KEY=``) reads back "" not None (#413).

        None means "key absent"; conflating it with a present empty value made
        an empty vault secret re-sync forever as CREATED and report a false
        "Key file does not exist" in verify-only mode.
        """
        env_keys = tmp_path / ".env.keys"
        env_keys.write_text("DOTENV_PRIVATE_KEY_PRODUCTION=\nDOTENV_PRIVATE_KEY_STAGING=def456\n")

        file = EnvKeysFile(env_keys)

        # Present but empty -> "" (not None); a genuinely absent key -> None.
        assert file.read_key("DOTENV_PRIVATE_KEY_PRODUCTION") == ""
        assert file.read_key("DOTENV_PRIVATE_KEY_STAGING") == "def456"
        assert file.read_key("DOTENV_PRIVATE_KEY_DEV") is None

    def test_write_then_read_empty_value_roundtrips(self, tmp_path: Path) -> None:
        """Writing an empty value and reading it back yields "" (#413)."""
        env_keys = tmp_path / ".env.keys"
        file = EnvKeysFile(env_keys)

        file.write_key("DOTENV_PRIVATE_KEY_PRODUCTION", "")

        assert file.read_key("DOTENV_PRIVATE_KEY_PRODUCTION") == ""

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

    def test_create_backup_same_timestamp_no_overwrite(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Two backups at the same timestamp don't clobber each other (#413).

        Freezes the clock so both backups derive the same timestamp string,
        forcing the uniqueness path; mocking time (not the backup logic) is the
        deterministic way to exercise the same-tick collision.
        """
        import envdrift.sync.operations as ops

        env_keys = tmp_path / ".env.keys"
        env_keys.write_text("ORIGINAL_CONTENT")
        file = EnvKeysFile(env_keys)

        fixed = datetime(2026, 6, 8, 12, 0, 0, 0)

        class _FrozenDatetime:
            @classmethod
            def now(cls, tz: object = None) -> datetime:
                return fixed

        monkeypatch.setattr(ops, "datetime", _FrozenDatetime)

        first = file.create_backup()
        # Change the source so we can prove the first backup was not overwritten.
        env_keys.write_text("UPDATED_CONTENT")
        second = file.create_backup()

        assert first != second
        assert first.exists() and second.exists()
        assert first.read_text() == "ORIGINAL_CONTENT"
        assert second.read_text() == "UPDATED_CONTENT"

    def test_create_backup_removes_placeholder_on_copy_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A failed copy must not leave the empty O_EXCL placeholder behind (#413)."""
        import envdrift.sync.operations as ops

        env_keys = tmp_path / ".env.keys"
        env_keys.write_text("ORIGINAL")
        file = EnvKeysFile(env_keys)

        def _boom(*_args: object, **_kwargs: object) -> None:
            raise OSError("disk full")

        # Inject a copy failure (not a mock of the backup logic itself).
        monkeypatch.setattr(ops.shutil, "copy2", _boom)

        with pytest.raises(OSError, match="disk full"):
            file.create_backup()

        # No zero-byte placeholder left behind.
        leftovers = list(tmp_path.glob(".env.keys.backup.*"))
        assert leftovers == [], leftovers


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
    def test_atomic_write_does_not_write_through_predictable_tmp_name(self, tmp_path: Path) -> None:
        """A symlink planted at the predictable temp name is never written through.

        The vulnerable implementation wrote to ``path.with_suffix('.tmp')`` (i.e.
        ``secret.tmp``) via a path-based ``write_text``, which follows a symlink
        and clobbers its target. ``mkstemp`` instead picks an unguessable name
        with ``O_EXCL``, so a symlink pre-planted at the predictable sibling is
        left untouched. This assertion fails against the old code (it follows the
        symlink and overwrites the victim) and passes against the mkstemp fix.
        """
        dest = tmp_path / "secret.txt"
        predictable = dest.with_suffix(".tmp")  # 'secret.tmp'

        victim = tmp_path / "victim"
        victim.write_text("ORIGINAL_VICTIM")
        predictable.symlink_to(victim)

        atomic_write(dest, "SECRET_DEST_CONTENT")

        # The destination got the content; the predictable-name symlink's target
        # was never written through and the symlink itself still dangles intact.
        assert dest.read_text() == "SECRET_DEST_CONTENT"
        assert victim.read_text() == "ORIGINAL_VICTIM"
        assert predictable.is_symlink()

    @pytest.mark.skipif(os.name == "nt", reason="symlink/fchmod semantics differ on non-POSIX")
    def test_atomic_write_uses_unguessable_tmp_name_and_cleans_up_on_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The temp file is an unguessable ``mkstemp`` name, removed on failure.

        We capture the temp name actually created (while it still exists) and
        block ``os.replace`` so the temp file is left for cleanup. The captured
        name must be the ``mkstemp`` form, never the predictable
        ``path.with_suffix('.tmp')`` the vulnerable code used, and the cleanup
        path must leave nothing behind.
        """
        dest = tmp_path / "secret.txt"
        predictable = dest.with_suffix(".tmp")

        # Capture the temp name(s) created during the write, before cleanup runs.
        real_mkstemp = tempfile.mkstemp
        created: list[str] = []

        def spy_mkstemp(*args: object, **kwargs: object) -> tuple[int, str]:
            fd, name = real_mkstemp(*args, **kwargs)  # type: ignore[arg-type]
            created.append(name)
            return fd, name

        monkeypatch.setattr(tempfile, "mkstemp", spy_mkstemp)

        def boom(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> None:
            raise OSError("blocked replace for test")

        monkeypatch.setattr(os, "replace", boom)
        with pytest.raises(OSError, match="blocked replace"):
            atomic_write(dest, "data")

        # An unguessable mkstemp name was used, never the predictable sibling.
        assert len(created) == 1
        tmp_name = Path(created[0]).name
        assert tmp_name != predictable.name
        assert tmp_name.startswith(".secret.txt.")
        assert tmp_name.endswith(".envdrift-tmp")
        # The predictable name was never created, and the temp file is gone.
        assert not predictable.exists()
        leftovers = [
            p
            for p in tmp_path.iterdir()
            if p.name.startswith(".secret.txt.") and p.name.endswith(".envdrift-tmp")
        ]
        assert leftovers == []

    @pytest.mark.skipif(os.name == "nt", reason="POSIX fd/error semantics")
    def test_atomic_write_propagates_write_error_without_leaking_temp(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A write failure propagates the *original* error and leaves no temp file.

        Regression for the fd double-close/leak: the vulnerable code closed the
        fd a second time in the failure path (after ``fdopen`` had already closed
        it), raising ``EBADF`` -- which both masked the real error (e.g. ENOSPC)
        and aborted cleanup before the temp file was unlinked, leaking it. The fix
        lets the ``fdopen`` wrapper own/close the fd exactly once, so the original
        error survives and the temp file is always cleaned up.
        """
        dest = tmp_path / "secret.txt"

        real_open = os.fdopen

        class FailingWriter:
            """Wraps a real file object but raises on ``write`` (disk-full sim)."""

            def __init__(self, fileobj: object) -> None:
                self._f = fileobj

            def __enter__(self) -> FailingWriter:
                return self

            def __exit__(self, *exc: object) -> None:
                self._f.__exit__(*exc)  # type: ignore[attr-defined]

            def fileno(self) -> int:
                return self._f.fileno()  # type: ignore[attr-defined]

            def write(self, _data: str) -> int:
                raise OSError("No space left on device")

        def fake_fdopen(fd: int, *args: object, **kwargs: object) -> FailingWriter:
            return FailingWriter(real_open(fd, *args, **kwargs))  # type: ignore[arg-type]

        monkeypatch.setattr(os, "fdopen", fake_fdopen)

        with pytest.raises(OSError, match="No space left on device"):
            atomic_write(dest, "secret-data")

        # The destination was never created, and no mkstemp temp file leaked.
        assert not dest.exists()
        leftovers = [p for p in tmp_path.iterdir() if p.name.endswith(".envdrift-tmp")]
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

    @pytest.mark.skipif(os.name == "nt", reason="POSIX mode/symlink semantics")
    def test_atomic_write_symlinked_destination_does_not_inject_permissive_mode(
        self, tmp_path: Path
    ) -> None:
        """A pre-planted destination symlink cannot force a permissive mode.

        Regression for the ``path.stat()`` (symlink-following) mode preservation:
        if an attacker plants a symlink at the destination pointing at a 0o777
        file they own, the vulnerable code copied that 0o777 onto the freshly
        written secret. The fix uses ``lstat`` and skips mode preservation for a
        symlinked destination, so the requested tight default is applied instead.
        """
        attacker_owned = tmp_path / "attacker_owned"
        attacker_owned.write_text("attacker content")
        attacker_owned.chmod(0o777)

        dest = tmp_path / "secret.txt"
        dest.symlink_to(attacker_owned)

        atomic_write(dest, "TOPSECRET", permissions=0o600)

        # The new secret got the tight requested mode, not the injected 0o777,
        # and the destination is a real file (the symlink was replaced).
        assert not dest.is_symlink()
        assert dest.read_text() == "TOPSECRET"
        assert dest.stat().st_mode & 0o777 == 0o600
        # The attacker's file is untouched (content and mode).
        assert attacker_owned.read_text() == "attacker content"
        assert attacker_owned.stat().st_mode & 0o777 == 0o777


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
